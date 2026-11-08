//go:build integration

// Package scheduler — M57: a CVE the scanner created AFTER the sync passed it
// must still receive the record the sync passed over.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M57CVESync' ./internal/scheduler
package scheduler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// m57WindowedFeed answers like NVD's /cves/2.0: it returns the record only
// when the requested lastModStartDate..lastModEndDate window contains the
// record's lastModified. That is the property the delta reader's reach
// depends on, so a fake that ignored the window could not measure it.
func m57WindowedFeed(t *testing.T, modified time.Time, body string) *httptest.Server {
	t.Helper()
	empty := `{"totalResults": 0, "startIndex": 0, "resultsPerPage": 2000, "vulnerabilities": []}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const layout = "2006-01-02T15:04:05.000"
		start, err1 := time.Parse(layout, r.URL.Query().Get("lastModStartDate"))
		end, err2 := time.Parse(layout, r.URL.Query().Get("lastModEndDate"))
		if err1 != nil || err2 != nil {
			t.Errorf("m57: unparseable window %q..%q", r.URL.Query().Get("lastModStartDate"), r.URL.Query().Get("lastModEndDate"))
		}
		w.Header().Set("Content-Type", "application/json")
		if !modified.Before(start) && !modified.After(end) {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(empty))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestM57CVESync_ScannerRowCreatedAfterTheSyncPassedIsStillRefreshed is the
// part of M55 residual High (2) — the delta reader's reach — that is not a
// fetch-policy question.
//
// The sequence, all of it ordinary:
//
//  1. NVD re-scores CVE X (no CPE data, so cve_sync's keyword list is empty)
//     LOW -> CRITICAL at time M.
//  2. The daily sync's window contains M. X is not in the catalogue yet, so
//     the update-only refresh reports MetadataRowAbsent and skips it — by
//     design: inserting keyword-less CVEs would import NVD's whole window.
//     The watermark advances past M.
//  3. A tenant uploads an SBOM. The NVD scanner answers from its Redis cache,
//     which holds the component's result for up to cache.NVDCacheTTL (24h) —
//     fetched BEFORE M. X is created at LOW.
//  4. Every later sync asks for modifications after the watermark. M is
//     before it, so X is never offered again until NVD modifies it again.
//
// High (1)'s fix does not reach this: there is no uncommitted row in step 2,
// there is no row at all. The scanner's copy is older than a record the sync
// has already consumed, and the only thing that can bring the newer one back
// is reading that part of the window again.
func TestM57CVESync_ScannerRowCreatedAfterTheSyncPassedIsStillRefreshed(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup: delete %s: %v", cveID, err)
		}
	})

	// 1. Re-scored an hour ago. Truncated to the millisecond because that is
	// the precision the window parameters travel at.
	modified := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	body := m55Feed(cveID, "CRITICAL", 9.8, "re-scored upstream", "2026-01-01T00:00:00.000",
		modified.Format("2006-01-02T15:04:05.000"), m55CPEEmpty)
	srv := m57WindowedFeed(t, modified, body)
	sync := func() {
		t.Helper()
		j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour, nil, srv.URL, false)
		if err := j.Run(context.Background()); err != nil {
			t.Fatalf("CVESyncJob.Run: %v", err)
		}
	}

	// 2. The sync whose window contains M, while X is absent.
	m55PinWatermark(t, migDB, modified.Add(-2*time.Hour))
	sync()
	var n int
	if err := migDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("precondition: the keyword-less refresh inserted %s; it must be update-only", cveID)
	}

	// 3. The scanner creates X from its cached, pre-M copy — through the
	// production entry point, on a bare context as it now is (M57).
	score := 2.0
	now := time.Now().UTC()
	if err := repository.NewVulnerabilityRepository(appDB).Create(context.Background(), &model.Vulnerability{
		ID: uuid.New(), CVEID: cveID, Description: "scanner's cached copy", Severity: "LOW",
		CVSSScore: &score, Source: "NVD", UpdatedAt: &now,
	}); err != nil {
		t.Fatalf("scanner Create: %v", err)
	}

	// 4. The next sync.
	sync()

	if row := m55Read(t, migDB, cveID); row.severity != "CRITICAL" {
		t.Errorf("severity after the next sync = %q, want CRITICAL: the record the sync passed over while %s was "+
			"absent is never offered again, so the scanner's older copy stands until NVD next modifies the CVE",
			row.severity, cveID)
	}
}

// TestM57CVESync_ABufferedOlderRecordIsRepairedByTheNextTick pins the bound on
// the race Codex M57 R1 (High) raised, and is the reason it is recorded as an
// accepted, bounded limitation rather than fixed with more guard machinery.
//
// The interleaving: tick k fetches its window, which holds X's record at M1
// (LOW). While tick k is still writing, NVD re-scores X at M2 (CRITICAL) and a
// scanner creates X live from M2 — committed immediately since M57, with
// source_modified_at NULL as every scanner row is. Tick k then applies its
// buffered M1: a stored NULL is writable once, so X reads LOW until the next
// tick.
//
// What bounds it: M2 is later than tick k's fetch, so it is later than the
// watermark tick k stores, so tick k+1's window contains it whatever the
// replay overlap is — and M2 > M1 passes the guard. The exposure is at most
// one sync interval, the same order as the staleness the scanner already
// accepts from its own 24h NVD cache. Closing it would mean letting a NULL row
// refuse an owner record on a second clock (our updated_at), i.e. new guard
// state of exactly the kind M55 wave O removed; it would also only move the
// one-tick window, not remove it (a scanner answering from cache then refuses
// a NEWER owner record until the following tick).
func TestM57CVESync_ABufferedOlderRecordIsRepairedByTheNextTick(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m55ProtectWatermark(t, migDB)

	cveID := m55CVEID(t)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup: delete %s: %v", cveID, err)
		}
	})

	// The scanner's live M2 copy, committed while tick k is mid-flight.
	score := 9.8
	now := time.Now().UTC()
	if err := repository.NewVulnerabilityRepository(appDB).Create(context.Background(), &model.Vulnerability{
		ID: uuid.New(), CVEID: cveID, Description: "scanner's live M2 copy", Severity: "CRITICAL",
		CVSSScore: &score, Source: "NVD", UpdatedAt: &now,
	}); err != nil {
		t.Fatalf("scanner Create: %v", err)
	}

	m1 := now.Add(-2 * time.Hour).Truncate(time.Millisecond)
	m2 := now.Add(-time.Minute).Truncate(time.Millisecond)
	const layout = "2006-01-02T15:04:05.000"

	// Tick k applies its buffered M1.
	m55Sync(t, appDB, m55Feed(cveID, "LOW", 2.0, "buffered M1", "2026-01-01T00:00:00.000", m1.Format(layout), m55CPEEmpty))
	if got := m55Read(t, migDB, cveID).severity; got != "LOW" {
		t.Fatalf("precondition: tick k left %q; the scenario needs the transient LOW to have happened", got)
	}

	// Tick k+1 is offered NVD's current record.
	m55Sync(t, appDB, m55Feed(cveID, "CRITICAL", 9.8, "current M2", "2026-01-01T00:00:00.000", m2.Format(layout), m55CPEEmpty))
	row := m55Read(t, migDB, cveID)
	if row.severity != "CRITICAL" {
		t.Errorf("severity after tick k+1 = %q, want CRITICAL: the transient downgrade must not outlive one tick", row.severity)
	}
	if !row.sourceModAt.Valid || !row.sourceModAt.Time.UTC().Equal(m2) {
		t.Errorf("source_modified_at = %v, want M2 %v", row.sourceModAt.Time.UTC(), m2)
	}
}
