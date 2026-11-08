//go:build integration

// Package handler — M62: no database transaction is open while a
// vulnerability scan waits on NVD.
//
// Until M62 both scan routes wrapped the whole NVD + JVN sweep in ONE tenant
// transaction (SbomHandler.runScan, VulnerabilityHandler.runScan), so while
// NVD was answering — 14 min 24 s for a cold keyless kernel scan (M60) — the
// app role held a backend `idle in transaction` with its locks. These tests
// block a stubbed NVD request and look at PostgreSQL while it is blocked.
//
// This file uses only APIs that predate M62, so it can be run against the
// pre-M62 handlers as a negative control (it fails there: one backend in a
// transaction, with locks).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 -run 'M62' ./internal/handler
package handler

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// m62NVD is a stub NVD keyed by keyword prefix. A prefix listed in block
// signals `entered` and holds its response until `release` closes (or the
// request is cancelled).
type m62NVD struct {
	cves    map[string]string // keyword prefix -> CVE id answered
	block   map[string]bool
	entered chan string
	release chan struct{}
	once    sync.Once
}

func newM62NVD(t *testing.T, cves map[string]string, block ...string) (*m62NVD, *httptest.Server) {
	t.Helper()
	n := &m62NVD{cves: cves, block: map[string]bool{}, entered: make(chan string, 16), release: make(chan struct{})}
	for _, b := range block {
		n.block[b] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kw := r.URL.Query().Get("keywordSearch")
		for prefix, cve := range n.cves {
			if !strings.HasPrefix(kw, prefix) {
				continue
			}
			if n.block[prefix] {
				select {
				case n.entered <- prefix:
				default:
				}
				select {
				case <-n.release:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "vulnerabilities": [
				{"cve": {"id": %q, "published": "2093-01-01T00:00:00.000", "descriptions": [{"lang": "en", "value": "m62"}],
				  "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]}`, cve)
			return
		}
		_, _ = w.Write([]byte(`{"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}`))
	}))
	t.Cleanup(func() { n.releaseAll(); srv.Close() })
	return n, srv
}

func (n *m62NVD) releaseAll() { n.once.Do(func() { close(n.release) }) }

func (n *m62NVD) waitEntered(t *testing.T, prefix string) {
	t.Helper()
	select {
	case got := <-n.entered:
		if got != prefix {
			t.Fatalf("blocked request for %q, want %q", got, prefix)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("NVD request for %q never arrived", prefix)
	}
}

// waitEnteredAny waits for n blocked requests, whichever prefixes.
func (n *m62NVD) waitEnteredAny(t *testing.T, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		select {
		case <-n.entered:
		case <-time.After(30 * time.Second):
			t.Fatalf("only %d of %d blocked NVD requests arrived", i, count)
		}
	}
}

func m62CVE(t *testing.T, migDB *sql.DB) string {
	t.Helper()
	cve := fmt.Sprintf("CVE-2093-%07d", uuid.New().ID()%10000000)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cve); err != nil {
			t.Errorf("C27 cleanup: %v", err)
		}
	})
	return cve
}

// m62AppSessionState reports, for every OTHER backend of the app role, how
// many are inside a transaction and how many locks they hold. It runs as the
// app role itself: pg_stat_activity shows state/xact_start only for the
// viewer's own role unless the viewer is privileged, and the scan runs as
// that role.
type m62SessionState struct {
	inTx   int
	locks  int
	detail string
}

func m62AppSessionState(t *testing.T, appDB *sql.DB) m62SessionState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := appDB.Conn(ctx)
	if err != nil {
		t.Fatalf("probe conn: %v", err)
	}
	defer conn.Close()
	var st m62SessionState
	var detail sql.NullString
	if err := conn.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE xact_start IS NOT NULL),
		       string_agg(state || ' xact_age=' || COALESCE(round(extract(epoch FROM now() - xact_start))::text, '-')
		                  || ' q=' || left(regexp_replace(query, '\s+', ' ', 'g'), 80), ' | ')
		  FROM pg_stat_activity
		 WHERE usename = current_user AND pid <> pg_backend_pid() AND backend_type = 'client backend'`,
	).Scan(&st.inTx, &detail); err != nil {
		t.Fatalf("pg_stat_activity: %v", err)
	}
	st.detail = detail.String
	if err := conn.QueryRowContext(ctx, `
		SELECT count(*) FROM pg_locks l
		 WHERE l.pid <> pg_backend_pid()
		   AND l.pid IN (SELECT pid FROM pg_stat_activity WHERE usename = current_user)`,
	).Scan(&st.locks); err != nil {
		t.Fatalf("pg_locks: %v", err)
	}
	return st
}

func m62LinkCount(t *testing.T, migDB *sql.DB, componentID uuid.UUID, cve string) int {
	t.Helper()
	var n int
	if err := migDB.QueryRow(`SELECT count(*) FROM component_vulnerabilities cv JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.component_id = $1 AND v.cve_id = $2`, componentID, cve).Scan(&n); err != nil {
		t.Fatalf("count links: %v", err)
	}
	return n
}

// The upload path and the manual route, each with NVD blocked mid-sweep.
func TestM62Scan_NoTransactionIsOpenWhileNVDFetchBlocks(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	for _, route := range []string{"upload", "manual"} {
		t.Run(route, func(t *testing.T) {
			seed := m47SeedAll(t, migDB, "m62notx"+route)
			// A second component, answered first, so the blocked request
			// comes AFTER the sweep has already matched (and, pre-M62,
			// written) something — the case where a held transaction also
			// holds row locks.
			m54AddComponent(t, migDB, seed, "m62first")
			cveFirst, cveBlocked := m62CVE(t, migDB), m62CVE(t, migDB)
			nvdStub, srv := newM62NVD(t, map[string]string{"m62first": cveFirst, "libm47": cveBlocked}, "libm47")

			// An API key selects 5 workers and the 700 ms tick, so the
			// first component does not wait 6 s; the blocked one is held by
			// the server, not by the pacer.
			nvd := service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
				repository.NewComponentRepository(appDB), "m62-fake-api-key", srv.URL, false)
			tracker := service.NewScanTracker()
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch route {
				case "upload":
					h := &SbomHandler{db: appDB, nvdService: nvd, scanTracker: tracker}
					tracker.MarkRunning(seed.sbomID)
					h.runScan(context.Background(), seed.sbomID, seed.tenantID)
				case "manual":
					h := &VulnerabilityHandler{db: appDB, nvdService: nvd}
					h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")
				}
			}()

			nvdStub.waitEntered(t, "libm47")
			// Give the first component's answer time to be processed (its
			// request was issued before the blocked one).
			time.Sleep(1500 * time.Millisecond)
			st := m62AppSessionState(t, appDB)
			nvdStub.releaseAll()
			<-done

			if st.inTx != 0 || st.locks != 0 {
				t.Errorf("while NVD was blocked, %d app-role backend(s) were inside a transaction holding %d lock(s): %s",
					st.inTx, st.locks, st.detail)
			}
			// And the scan still did its job once NVD answered.
			if n := m62LinkCount(t, migDB, seed.componentID, cveBlocked); n != 1 {
				t.Errorf("blocked component's link count = %d, want 1", n)
			}
			after := m62AppSessionState(t, appDB)
			if after.inTx != 0 {
				t.Errorf("after the scan, %d app-role backend(s) still in a transaction: %s", after.inTx, after.detail)
			}
		})
	}
}
