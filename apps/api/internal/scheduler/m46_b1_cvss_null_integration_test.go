//go:build integration

// Package scheduler — M46 Codex round B-1 High-3: NVD CVEs with no CVSS
// metrics ("Awaiting Analysis") must persist cvss_score = NULL, not the
// 0.0 sentinel.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M46B1' ./internal/scheduler
//
// Pre-fix, extractCVSSFromMetrics returned a bare float64 (0 when the
// metrics block was empty) and upsertVulnerability INSERTed/UPDATEd that 0
// into vulnerabilities.cvss_score. 0.0 is a REAL score (CVSS "None"), so
// the read-side *float64 contract (wave 3 / f97c7fa) never saw a NULL for
// these rows and every un-triaged CVE surfaced as a scored, safe-looking
// vulnerability. Post-fix CVEInfo.CVSSScore is *float64 and a metrics-less
// CVE stores NULL end-to-end (measured red pre-fix: cvss_score = 0.0).
package scheduler

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestM46B1_UpsertVulnerability_UnscoredCVEStoresNULL(t *testing.T) {
	appURL, migURL := schedIntEnv(t)

	appDB, err := sql.Open("postgres", appURL)
	if err != nil {
		t.Skipf("sql.Open(app) failed (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(mig) failed (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = migDB.Close() })
	if err := appDB.Ping(); err != nil {
		t.Skipf("DB unreachable (%v) - skipping", err)
	}

	cveID := "CVE-M46B1-" + uuid.New().String()[:8]
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("C27 cleanup: delete vulnerability %s: %v", cveID, err)
		}
	})

	// Drive the REAL NVD feed shape through the REAL fetch path so the
	// extractor branch that produced the sentinel is exercised, not
	// bypassed (codex round 1 / Low-1: a hand-built CVEInfo{CVSSScore:
	// nil} would stay green even if extractCVSSFromMetrics regressed to
	// returning a pointer to 0.0). "metrics": {} is the "Awaiting
	// Analysis" payload.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1, "startIndex": 0, "resultsPerPage": 2000,
			"vulnerabilities": [{"cve": {
				"id": "` + cveID + `",
				"published": "2026-07-01T00:00:00Z",
				"lastModified": "2026-07-01T00:00:00Z",
				"descriptions": [{"lang": "en", "value": "m46b1 awaiting analysis fixture"}],
				"metrics": {},
				"configurations": []
			}}]
		}`))
	}))
	defer server.Close()

	j := NewCVESyncJob(appDB, nil, "", 24*time.Hour, nil, server.URL, false)

	fetched, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("fetchModifiedCVEs: %v", err)
	}
	if len(fetched) != 1 {
		t.Fatalf("fetched %d CVEs, want 1", len(fetched))
	}
	unscored := fetched[0]
	if unscored.CVSSScore != nil {
		t.Fatalf("extractCVSSFromMetrics returned %v for an empty metrics block; want nil (0.0 is a real 'None' score)", *unscored.CVSSScore)
	}
	if unscored.Severity != "UNKNOWN" {
		t.Errorf("severity for an empty metrics block = %q, want UNKNOWN", unscored.Severity)
	}

	// INSERT path.
	if _, _, err := j.upsertVulnerability(context.Background(), unscored); err != nil {
		t.Fatalf("upsertVulnerability (insert): %v", err)
	}
	var score sql.NullFloat64
	var severity sql.NullString
	if err := migDB.QueryRow(
		`SELECT cvss_score, severity FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&score, &severity); err != nil {
		t.Fatalf("read back %s: %v", cveID, err)
	}
	if score.Valid {
		t.Errorf("un-scored CVE persisted cvss_score = %v, want NULL (0.0 is a real 'None' score — the sentinel masquerades as a safe vulnerability)", score.Float64)
	}
	if severity.String != "UNKNOWN" {
		t.Errorf("un-scored CVE severity = %q, want UNKNOWN", severity.String)
	}

	// UPDATE path: re-syncing the same still-unscored CVE must keep NULL.
	if _, _, err := j.upsertVulnerability(context.Background(), unscored); err != nil {
		t.Fatalf("upsertVulnerability (update): %v", err)
	}
	if err := migDB.QueryRow(
		`SELECT cvss_score FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&score); err != nil {
		t.Fatalf("read back after update: %v", err)
	}
	if score.Valid {
		t.Errorf("un-scored CVE re-sync persisted cvss_score = %v, want NULL", score.Float64)
	}
}

// TestM46B1_CVSSv4MetricsAreScored pins codex round 3 / Medium-2: NVD
// publishes cvssMetricV40 alongside v3.1, and a CVE carrying ONLY v4
// metrics used to fall through every extractor branch. Before High-3 that
// silently became the 0.0 sentinel; after High-3 it would have become
// NULL — i.e. a real, possibly CRITICAL score demoted to "un-scored" and
// sorted to the tail of every NULLS LAST vulnerability list.
func TestM46B1_CVSSv4MetricsAreScored(t *testing.T) {
	appURL, migURL := schedIntEnv(t)

	appDB, err := sql.Open("postgres", appURL)
	if err != nil {
		t.Skipf("sql.Open(app) failed (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(mig) failed (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = migDB.Close() })
	if err := appDB.Ping(); err != nil {
		t.Skipf("DB unreachable (%v) - skipping", err)
	}

	cveID := "CVE-M46B1V4-" + uuid.New().String()[:8]
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("C27 cleanup: delete vulnerability %s: %v", cveID, err)
		}
	})

	// v4-ONLY payload: no cvssMetricV31 / V30 / V2 at all.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1, "startIndex": 0, "resultsPerPage": 2000,
			"vulnerabilities": [{"cve": {
				"id": "` + cveID + `",
				"published": "2026-07-01T00:00:00Z",
				"lastModified": "2026-07-01T00:00:00Z",
				"descriptions": [{"lang": "en", "value": "m46b1 cvss v4 only fixture"}],
				"metrics": {"cvssMetricV40": [
					{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}
				]},
				"configurations": []
			}}]
		}`))
	}))
	defer server.Close()

	j := NewCVESyncJob(appDB, nil, "", 24*time.Hour, nil, server.URL, false)

	fetched, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("fetchModifiedCVEs: %v", err)
	}
	if len(fetched) != 1 {
		t.Fatalf("fetched %d CVEs, want 1", len(fetched))
	}
	v4 := fetched[0]
	if v4.CVSSScore == nil {
		t.Fatalf("a CVE with only cvssMetricV40 extracted as un-scored — a real CRITICAL score would be demoted to NULL and sorted last")
	}
	if *v4.CVSSScore != 9.3 {
		t.Errorf("CVSS v4 score = %v, want 9.3", *v4.CVSSScore)
	}
	if v4.Severity != "CRITICAL" {
		t.Errorf("CVSS v4 severity = %q, want CRITICAL", v4.Severity)
	}

	if _, _, err := j.upsertVulnerability(context.Background(), v4); err != nil {
		t.Fatalf("upsertVulnerability: %v", err)
	}
	var score sql.NullFloat64
	var severity sql.NullString
	if err := migDB.QueryRow(
		`SELECT cvss_score, severity FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&score, &severity); err != nil {
		t.Fatalf("read back %s: %v", cveID, err)
	}
	if !score.Valid || score.Float64 != 9.3 || severity.String != "CRITICAL" {
		t.Errorf("persisted v4 CVE = (score %v valid=%v, severity %q), want (9.3, true, CRITICAL)",
			score.Float64, score.Valid, severity.String)
	}
}
