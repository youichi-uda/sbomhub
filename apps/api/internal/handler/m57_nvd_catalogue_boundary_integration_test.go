//go:build integration

// Package handler — M57: the NVD scanner's catalogue writes, driven end to end
// through VulnerabilityHandler.runScan with the real NVDService.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M57NVDScan' ./internal/handler
//
// internal/repository/m57_catalogue_tx_boundary_integration_test.go pins the
// boundary at the repository; this file measures what it changes on the
// production path, where the scanner holds ONE tenant transaction for the whole
// sweep (see the M54 file header for why it must).
package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// TestM57NVDScan_OwnerRefreshSeesTheScannersRowMidSweep is M55 residual High
// (1), end to end.
//
// Two work items, one worker (no API key, so the pool is single-threaded and
// the order is fixed by the fake server rather than by scheduling): the FIRST
// NVD request answers with CVE X at LOW, the SECOND is held open. While it is
// held, the scanner has already persisted X and is waiting on the network —
// the ordinary state of a real sweep — and the test runs exactly what the
// catalogue's owner (cve_sync) runs on its own tx-free connection:
// UpdateMetadata with a newer CRITICAL record.
//
// Pre-fix the owner reads MetadataRowAbsent (the row is an uncommitted insert
// in the scanner's tenant tx), skips, and the scanner's LOW is what commits.
//
// Cost: ~12s, two 6s rate-limiter ticks (rateLimitWithoutKey).
func TestM57NVDScan_OwnerRefreshSeesTheScannersRowMidSweep(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m57vis")
	m54AddComponent(t, migDB, seed, "m57other")

	ns := m54NewNamespace()
	cveID := ns.m54CVEID(0, 0)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("C27 cleanup: %v", err)
		}
	})

	secondArrived := make(chan struct{})
	release := make(chan struct{})
	var seq int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var entries []m54Entry
		if atomic.AddInt64(&seq, 1) == 1 {
			entries = []m54Entry{{CVE: m54CVE{
				ID: cveID, Published: "2093-01-01T00:00:00.000", LastModified: "2026-01-01T00:00:00.000",
				Descriptions: []m54Desc{{Lang: "en", Value: "scanner's copy"}},
				Metrics:      m54Metrics{V31: []m54Metric{{CvssData: m54CvssData{BaseScore: 2.0, BaseSeverity: "LOW"}}}},
			}}}
		} else {
			close(secondArrived)
			select {
			case <-release:
			case <-time.After(30 * time.Second):
				t.Error("m57: the test never released the second NVD request")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(m54Response{
			ResultsPerPage: len(entries), TotalResults: len(entries), Vulnerabilities: entries,
		}); err != nil {
			t.Errorf("encode fake NVD response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	nvd := service.NewNVDService(
		repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB),
		"", srv.URL, false,
	)
	h := &VulnerabilityHandler{db: appDB, nvdService: nvd}

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")
	}()

	select {
	case <-secondArrived:
	case <-time.After(40 * time.Second):
		close(release)
		t.Fatal("precondition: the scanner never issued its second NVD request")
	}

	// Mid-sweep: X has been persisted by the scanner, whose tenant tx is open.
	july := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	score := 9.8
	outcome, err := repository.NewVulnerabilityRepository(appDB).UpdateMetadata(context.Background(),
		repository.VulnerabilityMetadata{
			CVEID: cveID, Description: "owner's newer record", Severity: "CRITICAL",
			CVSSScore: &score, Source: "NVD", SourceModifiedAt: &july,
		})
	close(release)
	<-scanDone
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if outcome != repository.MetadataWritten {
		t.Errorf("owner refresh mid-sweep = %v, want %v: the row the scanner created was an uncommitted insert "+
			"inside one tenant's sweep, so the catalogue's owner saw no row and skipped the CVE", outcome, repository.MetadataWritten)
	}

	var severity string
	if err := migDB.QueryRow(`SELECT severity FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&severity); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if severity != "CRITICAL" {
		t.Errorf("severity after the sweep = %q, want CRITICAL: the scanner's older LOW is what committed", severity)
	}
	var links int
	if err := migDB.QueryRow(`
		SELECT count(*) FROM component_vulnerabilities cv JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE v.cve_id = $1`, cveID).Scan(&links); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if links != 1 {
		t.Errorf("links = %d, want 1 — the scanner must still link the component to the row", links)
	}
}

// TestM57NVDScan_ACatalogueRefusalDoesNotDiscardTheSweep is M55 residual High
// (3), end to end: one refused CATALOGUE write must not take the tenant
// sweep's links with it.
//
// Same poison as TestM54NVDScan_RefusedWritesAreReportedAsFailure (a cve_id
// one character past VARCHAR(50)), same three-record page. Pre-fix the refused
// INSERT aborts the tenant transaction, the CVE after it is refused too, the
// commit fails, and 0 of the 2 valid CVEs and 0 of their 2 links survive.
//
// The scan must STILL report failure: a match the database refused is lost
// data, and that is escalated whatever it costs (M54 R1).
func TestM57NVDScan_ACatalogueRefusalDoesNotDiscardTheSweep(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m57refuse")
	ns := m54NewNamespace()
	okIDs := []string{ns.m54CVEID(0, 0), ns.m54CVEID(0, 1)}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, m54TextArray(okIDs)); err != nil {
			t.Errorf("C27 cleanup: %v", err)
		}
	})
	tooLong := "CVE-2900-" + strings.Repeat("9", 42)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entries := []m54Entry{
			{CVE: m54CVE{ID: okIDs[0], Published: "2093-01-01T00:00:00.000", Descriptions: []m54Desc{{Lang: "en", Value: "ok"}}}},
			{CVE: m54CVE{ID: tooLong, Published: "2093-01-01T00:00:00.000", Descriptions: []m54Desc{{Lang: "en", Value: "refused"}}}},
			{CVE: m54CVE{ID: okIDs[1], Published: "2093-01-01T00:00:00.000", Descriptions: []m54Desc{{Lang: "en", Value: "after"}}}},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(m54Response{
			ResultsPerPage: len(entries), TotalResults: len(entries), Vulnerabilities: entries,
		}); err != nil {
			t.Errorf("encode fake NVD response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	nvd := service.NewNVDService(
		repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB),
		"m57-fake-api-key", srv.URL, false,
	)
	h := &VulnerabilityHandler{db: appDB, nvdService: nvd}

	var logged strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	func() {
		defer slog.SetDefault(prev)
		h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")
	}()
	logs := logged.String()

	if !strings.Contains(logs, "value too long") {
		t.Fatalf("precondition: the over-long cve_id was not refused. digest = %s", m54Digest(logs))
	}
	if !strings.Contains(logs, "NVD scan failed") || strings.Contains(logs, "NVD scan completed") {
		t.Errorf("a scan that lost a match must still report failure. digest = %s", m54Digest(logs))
	}

	var durable, links int
	if err := appDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = ANY($1)`, m54TextArray(okIDs)).
		Scan(&durable); err != nil {
		t.Fatalf("count durable: %v", err)
	}
	if err := migDB.QueryRow(`
		SELECT count(*) FROM component_vulnerabilities cv JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE v.cve_id = ANY($1)`, m54TextArray(okIDs)).Scan(&links); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if durable != len(okIDs) || links != len(okIDs) {
		t.Errorf("durable vulnerabilities = %d, links = %d, want %d / %d: one refused catalogue write aborted the "+
			"tenant transaction and discarded the whole sweep. digest = %s",
			durable, links, len(okIDs), len(okIDs), m54Digest(logs))
	}
	if strings.Contains(logs, "tenant transaction failed") {
		t.Errorf("the tenant transaction's commit failed. digest = %s", m54Digest(logs))
	}
}
