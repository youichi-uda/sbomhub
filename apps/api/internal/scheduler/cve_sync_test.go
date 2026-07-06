package scheduler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewCVESyncJob_DefaultBaseURL asserts an empty baseURL falls back to the
// cveSyncAPIURL const (M40 Wave B).
func TestNewCVESyncJob_DefaultBaseURL(t *testing.T) {
	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "", false)
	if j.baseURL != cveSyncAPIURL {
		t.Errorf("expected default baseURL %q, got %q", cveSyncAPIURL, j.baseURL)
	}
	if j.offline {
		t.Error("expected offline false by default")
	}

	j2 := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "https://mirror.example/cves", true)
	if j2.baseURL != "https://mirror.example/cves" {
		t.Errorf("expected overridden baseURL, got %q", j2.baseURL)
	}
	if !j2.offline {
		t.Error("expected offline true")
	}
}

// TestCVESyncJob_Offline_RunSkips asserts offline mode short-circuits Run at the
// top before any DB or network access (M40 Wave B). A nil *sql.DB proves no DB
// path is reached.
func TestCVESyncJob_Offline_RunSkips(t *testing.T) {
	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "", true)
	if err := j.Run(context.Background()); err != nil {
		t.Fatalf("offline Run should return nil, got %v", err)
	}
}

// TestCVESyncJob_FetchModifiedCVEs_HTTPMock drives fetchModifiedCVEs against an
// injected httptest base URL and asserts the NVD modified-feed JSON parses
// (M40 Wave B). fetchModifiedCVEs touches only the HTTP client + baseURL, so no
// DB is required.
func TestCVESyncJob_FetchModifiedCVEs_HTTPMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("startIndex") == "" {
			t.Error("expected startIndex query param")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"startIndex": 0,
			"resultsPerPage": 2000,
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2023-1234",
						"published": "2023-01-15T10:15:00Z",
						"lastModified": "2023-06-20T15:45:00Z",
						"descriptions": [
							{"lang": "en", "value": "Test vuln in libfoo"}
						],
						"metrics": {
							"cvssMetricV31": [
								{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
							]
						},
						"configurations": [
							{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:foo:libfoo:1.0.0:*:*:*:*:*:*:*", "vulnerable": true}]}]}
						]
					}
				}
			]
		}`))
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, server.URL, false)
	cves, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("fetchModifiedCVEs returned error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("expected 1 CVE, got %d", len(cves))
	}
	if cves[0].ID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", cves[0].ID)
	}
	if cves[0].Description != "Test vuln in libfoo" {
		t.Errorf("unexpected description: %q", cves[0].Description)
	}
	if cves[0].Severity != "HIGH" || cves[0].CVSSScore != 7.5 {
		t.Errorf("expected HIGH/7.5, got %s/%f", cves[0].Severity, cves[0].CVSSScore)
	}
	// Keywords should include the CPE product for downstream matching.
	found := false
	for _, kw := range cves[0].Keywords {
		if kw == "libfoo" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'libfoo' keyword extracted from CPE, got %v", cves[0].Keywords)
	}
}
