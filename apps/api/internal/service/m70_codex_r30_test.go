package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// r30Pager serves a two-page package answer; version(walk) gives record A's
// modified for each complete walk.
func r30Pager(t *testing.T, version func(walk int) string) (*httptest.Server, *int32) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n := int(atomic.AddInt32(&calls, 1))
		walk := (n - 1) / 2
		if !strings.Contains(string(body), "page_token") {
			_, _ = io.WriteString(w, `{"vulns":[{"id":"DSA-1","modified":"`+version(walk)+`","affected":[{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]}]}],"aliases":["CVE-2021-0001"]}],"next_page_token":"t"}`)
			return
		}
		_, _ = io.WriteString(w, `{"vulns":[{"id":"DSA-2","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}],"aliases":["CVE-2021-0002"]}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// Codex M70 R30 High-1: a multi-page answer is accepted only when two
// complete walks agree; one that keeps changing fails.
func TestM70R30_MultiPageConsistency(t *testing.T) {
	stable, calls := r30Pager(t, func(int) string { return "2026-11-02T00:00:00Z" })
	s := NewDistroService(nil, stable.URL, nil, false)
	s.gap = 0
	k := distroFetchKey{ecosystem: "Debian", pkg: "p"}
	if _, _, _, err := s.loadFetch(context.Background(), k, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("stable answer refused: %v", err)
	}
	if *calls != 4 {
		t.Errorf("%d requests, want two complete walks of two pages", *calls)
	}

	changesOnce, _ := r30Pager(t, func(w int) string {
		if w == 0 {
			return "2026-11-02T00:00:00Z"
		}
		return "2026-11-03T00:00:00Z"
	})
	s = NewDistroService(nil, changesOnce.URL, nil, false)
	s.gap = 0
	l, _, _, err := s.loadFetch(context.Background(), k, func(context.Context) error { return nil })
	if err != nil || l.revision != "2026-11-03T00:00:00.000000000Z" {
		t.Errorf("rev=%s err=%v, want the agreed later snapshot", l.revision, err)
	}

	always, _ := r30Pager(t, func(w int) string { return "2026-11-0" + string(rune('2'+w)) + "T00:00:00Z" })
	s = NewDistroService(nil, always.URL, nil, false)
	s.gap = 0
	if _, _, _, err := s.loadFetch(context.Background(), k, func(context.Context) error { return nil }); err == nil {
		t.Error("an answer that never settles was accepted")
	}
}

// Codex M70 R30 Low-3 / R32 Low-4: clears and relabels are counted from
// what was written, per savepoint group, and only for released groups.
func TestM70R30_ClearedCountsOnlyRealClears(t *testing.T) {
	var tl writeTally
	tl.note(true, true, true)   // watermark merged, label kept
	tl.note(true, true, false)  // label cleared
	tl.note(false, true, false) // a non-distro link's watermark
	tl.note(false, true, true)  // a relabel
	tl.note(true, false, false) // nothing changed
	tl.curSkipped++
	tl.groupDone(true)
	tl.note(true, true, false)
	tl.curSkipped++
	tl.groupDone(false) // rolled back
	if tl.relabelled != 4 || tl.cleared != 1 || tl.skipped != 1 {
		t.Errorf("relabelled=%d cleared=%d skipped=%d, want 4 / 1 / 1", tl.relabelled, tl.cleared, tl.skipped)
	}
}

// Codex M70 R32 Medium-3: the write order is fixed.
func TestM70R32_PendingGroupsSorted(t *testing.T) {
	a, b := uuid.MustParse("00000000-0000-0000-0000-000000000001"), uuid.MustParse("00000000-0000-0000-0000-000000000002")
	groups := [][]pendingLink{{{componentID: b, vulnID: b}, {componentID: b, vulnID: a}}, {{componentID: a, vulnID: b}}}
	sortPendingGroups(groups)
	if groups[0][0].componentID != a || groups[1][0].vulnID != a || groups[1][1].vulnID != b {
		t.Errorf("not sorted: %+v", groups)
	}
	_ = repository.SbomLink{}
	_ = json.RawMessage(nil)
}
