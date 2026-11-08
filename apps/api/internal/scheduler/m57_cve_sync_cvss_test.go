package scheduler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestM57CVESync_PrimaryCVSSOutranksASecondaryListedFirst (Codex M57 R1,
// Critical).
//
// NVD attaches several assessments per CVSS version — its own ("Primary") and
// CNA / third-party ones ("Secondary") — and does not order them. cve_sync took
// element zero, so a Secondary 6.3/MEDIUM listed before NVD's Primary
// 9.8/CRITICAL was what it extracted. The scanner fixed exactly this in M54
// (service.preferPrimary); the sync was never given it.
//
// Before M57 the defect could only reach rows the sync INSERTED, because the
// refresh refused every real (zoneless-timestamp) record. M57 made the refresh
// live, so without this the sync would now actively DOWNGRADE a CRITICAL the
// scanner stored correctly, and stamp source_modified_at so that a replay of
// the same record cannot repair it.
func TestM57CVESync_PrimaryCVSSOutranksASecondaryListedFirst(t *testing.T) {
	cases := map[string]string{
		"v3.1": `"cvssMetricV31": [
			{"source": "cna@example.org", "type": "Secondary", "cvssData": {"baseScore": 6.3, "baseSeverity": "MEDIUM"}},
			{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
		]`,
		"v4.0": `"cvssMetricV40": [
			{"source": "cna@example.org", "type": "Secondary", "cvssData": {"baseScore": 6.3, "baseSeverity": "MEDIUM"}},
			{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
		]`,
	}
	for name, metrics := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"totalResults": 1, "startIndex": 0, "resultsPerPage": 2000,
					"vulnerabilities": [{"cve": {"id": "CVE-2026-0001",
						"published": "2026-01-01T00:00:00.000", "lastModified": "2026-07-01T00:00:00.000",
						"descriptions": [{"lang": "en", "value": "x"}],
						"metrics": {` + metrics + `}, "configurations": []}}]}`))
			}))
			defer srv.Close()

			j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, srv.URL, false)
			cves, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
			if err != nil {
				t.Fatalf("fetchModifiedCVEs: %v", err)
			}
			if len(cves) != 1 {
				t.Fatalf("fetched %d CVEs, want 1", len(cves))
			}
			if cves[0].Severity != "CRITICAL" || cves[0].CVSSScore == nil || *cves[0].CVSSScore != 9.8 {
				t.Errorf("extracted %s / %v, want NVD's Primary CRITICAL / 9.8 — a Secondary assessment listed first "+
					"was taken instead", cves[0].Severity, cves[0].CVSSScore)
			}
		})
	}
}
