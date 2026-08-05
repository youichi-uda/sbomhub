package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNVDResponse_Parsing(t *testing.T) {
	jsonData := `{
		"resultsPerPage": 2,
		"startIndex": 0,
		"totalResults": 2,
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2023-1234",
					"published": "2023-01-15T10:30:00.000",
					"lastModified": "2023-06-20T15:45:00.000",
					"descriptions": [
						{"lang": "en", "value": "A critical vulnerability in test package"},
						{"lang": "ja", "value": "テストパッケージの重大な脆弱性"}
					],
					"metrics": {
						"cvssMetricV31": [
							{
								"cvssData": {
									"baseScore": 9.8,
									"baseSeverity": "CRITICAL"
								}
							}
						]
					}
				}
			}
		]
	}`

	var resp NVDResponse
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("failed to unmarshal NVD response: %v", err)
	}

	if resp.TotalResults == nil || *resp.TotalResults != 2 {
		t.Errorf("expected TotalResults 2, got %v", resp.TotalResults)
	}
	// entries() is the nil-safe accessor: Vulnerabilities is a pointer so an
	// ABSENT array is distinguishable from a present empty one (M54, Codex R5).
	if len(resp.entries()) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(resp.entries()))
	}

	vuln := resp.entries()[0]
	if vuln.CVE.ID != "CVE-2023-1234" {
		t.Errorf("expected CVE ID 'CVE-2023-1234', got '%s'", vuln.CVE.ID)
	}
	if len(vuln.CVE.Descriptions) != 2 {
		t.Errorf("expected 2 descriptions, got %d", len(vuln.CVE.Descriptions))
	}
	if vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore != 9.8 {
		t.Errorf("expected CVSS score 9.8, got %f", vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore)
	}
}

func TestExtractCvss_V31(t *testing.T) {
	metrics := NVDMetrics{
		CvssMetricV31: []CvssMetric{
			{CvssData: CvssData{BaseScore: 9.8, BaseSeverity: "critical"}},
		},
	}

	score, severity := extractCvss(metrics)
	if score == nil || *score != 9.8 {
		t.Errorf("expected score 9.8, got %v", score)
	}
	if severity != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %s", severity)
	}
}

func TestExtractCvss_V30(t *testing.T) {
	metrics := NVDMetrics{
		CvssMetricV30: []CvssMetric{
			{CvssData: CvssData{BaseScore: 7.5, BaseSeverity: "high"}},
		},
	}

	score, severity := extractCvss(metrics)
	if score == nil || *score != 7.5 {
		t.Errorf("expected score 7.5, got %v", score)
	}
	if severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", severity)
	}
}

func TestExtractCvss_V2(t *testing.T) {
	metrics := NVDMetrics{
		CvssMetricV2: []CvssMetric{
			{CvssData: CvssData{BaseScore: 5.0}},
		},
	}

	score, severity := extractCvss(metrics)
	if score == nil || *score != 5.0 {
		t.Errorf("expected score 5.0, got %v", score)
	}
	if severity != "MEDIUM" {
		t.Errorf("expected severity MEDIUM, got %s", severity)
	}
}

func TestExtractCvss_NoMetrics(t *testing.T) {
	metrics := NVDMetrics{}

	// M46 B2: no metrics means un-scored -> nil, NOT a 0.0 sentinel
	// (CVSS 0.0 is a real "None" score).
	score, severity := extractCvss(metrics)
	if score != nil {
		t.Errorf("expected nil score for no metrics, got %v", *score)
	}
	if severity != "UNKNOWN" {
		t.Errorf("expected severity UNKNOWN, got %s", severity)
	}
}

func TestExtractCvss_PreferV31OverV30(t *testing.T) {
	metrics := NVDMetrics{
		CvssMetricV31: []CvssMetric{
			{CvssData: CvssData{BaseScore: 9.0, BaseSeverity: "critical"}},
		},
		CvssMetricV30: []CvssMetric{
			{CvssData: CvssData{BaseScore: 7.0, BaseSeverity: "high"}},
		},
	}

	score, severity := extractCvss(metrics)
	if score == nil || *score != 9.0 {
		t.Errorf("expected V31 score 9.0, got %v", score)
	}
	if severity != "CRITICAL" {
		t.Errorf("expected CRITICAL from V31, got %s", severity)
	}
}

func TestScoreToCvss2Severity(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{10.0, "HIGH"},
		{9.5, "HIGH"},
		{7.0, "HIGH"},
		{6.9, "MEDIUM"},
		{5.0, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.9, "LOW"},
		{2.0, "LOW"},
		{0.0, "LOW"},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := scoreToCvss2Severity(tt.score)
			if result != tt.expected {
				t.Errorf("scoreToCvss2Severity(%f) = %s, want %s", tt.score, result, tt.expected)
			}
		})
	}
}

func TestConvertToVulnerabilities(t *testing.T) {
	svc := &NVDService{}

	entries := []NVDVulnEntry{
		{
			CVE: NVDCVE{
				ID:        "CVE-2023-1234",
				Published: "2023-01-15T10:30:00.000",
				Descriptions: []NVDDesc{
					{Lang: "en", Value: "Test vulnerability description"},
					{Lang: "ja", Value: "テスト脆弱性説明"},
				},
				Metrics: NVDMetrics{
					CvssMetricV31: []CvssMetric{
						{CvssData: CvssData{BaseScore: 8.5, BaseSeverity: "HIGH"}},
					},
				},
			},
		},
		{
			CVE: NVDCVE{
				ID:        "CVE-2023-5678",
				Published: "2023-02-20T08:00:00.000",
				Descriptions: []NVDDesc{
					{Lang: "es", Value: "Spanish description"},
					{Lang: "en", Value: "English description"},
				},
				Metrics: NVDMetrics{},
			},
		},
	}

	vulns := svc.convertToVulnerabilities(entries)

	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(vulns))
	}

	// Check first vulnerability
	v1 := vulns[0]
	if v1.CVEID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", v1.CVEID)
	}
	if v1.Description != "Test vulnerability description" {
		t.Errorf("expected English description, got %s", v1.Description)
	}
	if v1.CVSSScore == nil || *v1.CVSSScore != 8.5 {
		t.Errorf("expected CVSS 8.5, got %v", v1.CVSSScore)
	}
	if v1.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", v1.Severity)
	}
	if v1.Source != "NVD" {
		t.Errorf("expected source NVD, got %s", v1.Source)
	}

	// Check second vulnerability with no CVSS metrics
	v2 := vulns[1]
	if v2.CVEID != "CVE-2023-5678" {
		t.Errorf("expected CVE-2023-5678, got %s", v2.CVEID)
	}
	if v2.Description != "English description" {
		t.Errorf("expected English description (even if not first), got %s", v2.Description)
	}
	if v2.Severity != "UNKNOWN" {
		t.Errorf("expected UNKNOWN severity (no metrics), got %s", v2.Severity)
	}
	// M46 B2: a metrics-less CVE stays un-scored (nil), not 0.0.
	if v2.CVSSScore != nil {
		t.Errorf("expected nil CVSSScore (no metrics), got %v", *v2.CVSSScore)
	}
}

func TestConvertToVulnerabilities_EmptyEntries(t *testing.T) {
	svc := &NVDService{}
	vulns := svc.convertToVulnerabilities([]NVDVulnEntry{})

	if len(vulns) != 0 {
		t.Errorf("expected empty or nil slice, got %d items", len(vulns))
	}
}

func TestConvertToVulnerabilities_NoEnglishDescription(t *testing.T) {
	svc := &NVDService{}

	entries := []NVDVulnEntry{
		{
			CVE: NVDCVE{
				ID:        "CVE-2023-0001",
				Published: "2023-01-01T00:00:00.000",
				Descriptions: []NVDDesc{
					{Lang: "ja", Value: "日本語のみ"},
					{Lang: "fr", Value: "French only"},
				},
				Metrics: NVDMetrics{},
			},
		},
	}

	vulns := svc.convertToVulnerabilities(entries)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	// When no English description exists, Description should be empty
	if vulns[0].Description != "" {
		t.Errorf("expected empty description when no English found, got %s", vulns[0].Description)
	}
}

// HTTP Mock Tests

func TestNVDService_HTTPMock_SuccessfulSearch(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "GET" {
			t.Errorf("expected GET method, got %s", r.Method)
		}

		// Check for API key header (optional)
		apiKey := r.Header.Get("apiKey")
		if apiKey != "" && apiKey != "test-api-key" {
			t.Errorf("unexpected API key: %s", apiKey)
		}

		// Return mock response
		response := NVDResponse{
			ResultsPerPage: nvdIntPtr(1),
			StartIndex:     nvdIntPtr(0),
			TotalResults:   nvdIntPtr(1),
			Vulnerabilities: nvdEntriesPtr([]NVDVulnEntry{
				{
					CVE: NVDCVE{
						ID:        "CVE-2023-9999",
						Published: "2023-05-15T12:00:00.000",
						Descriptions: []NVDDesc{
							{Lang: "en", Value: "Test vulnerability in lodash"},
						},
						Metrics: NVDMetrics{
							CvssMetricV31: []CvssMetric{
								{CvssData: CvssData{BaseScore: 7.5, BaseSeverity: "HIGH"}},
							},
						},
					},
				},
			}),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// M40 Wave B: the base URL is now injectable, so searchByKeyword can be
	// driven end-to-end against an httptest server (recon flagged this as the
	// gap at nvd_test.go:320-322).
	svc := NewNVDService(nil, nil, "test-api-key", server.URL, false)
	vulns, err := svc.searchByKeyword(context.Background(), "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("searchByKeyword returned error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].CVEID != "CVE-2023-9999" {
		t.Errorf("expected CVE-2023-9999, got %s", vulns[0].CVEID)
	}
	if vulns[0].CVSSScore == nil || *vulns[0].CVSSScore != 7.5 {
		t.Errorf("expected CVSS 7.5, got %v", vulns[0].CVSSScore)
	}
	if vulns[0].Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", vulns[0].Severity)
	}
	if vulns[0].Source != "NVD" {
		t.Errorf("expected source NVD, got %s", vulns[0].Source)
	}
}

// TestNVDService_SearchByCVEID_HTTPMock drives SearchByCVEID against an
// injected httptest base URL (M40 Wave B).
func TestNVDService_SearchByCVEID_HTTPMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cveId"); got != "CVE-2021-44228" {
			t.Errorf("expected cveId query CVE-2021-44228, got %q", got)
		}
		response := NVDResponse{
			ResultsPerPage: nvdIntPtr(1),
			StartIndex:     nvdIntPtr(0),
			TotalResults:   nvdIntPtr(1),
			Vulnerabilities: nvdEntriesPtr([]NVDVulnEntry{
				{
					CVE: NVDCVE{
						ID:        "CVE-2021-44228",
						Published: "2021-12-10T10:15:00Z",
						Descriptions: []NVDDesc{
							{Lang: "en", Value: "Log4Shell"},
						},
						Metrics: NVDMetrics{
							CvssMetricV31: []CvssMetric{
								{CvssData: CvssData{BaseScore: 10.0, BaseSeverity: "CRITICAL"}},
							},
						},
					},
				},
			}),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	svc := NewNVDService(nil, nil, "", server.URL, false)
	vuln, err := svc.SearchByCVEID(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("SearchByCVEID returned error: %v", err)
	}
	if vuln == nil {
		t.Fatal("expected a vulnerability, got nil")
	}
	if vuln.CVEID != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %s", vuln.CVEID)
	}
	if vuln.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", vuln.Severity)
	}
}

// TestNVDService_Offline_NoHTTP asserts offline mode short-circuits every
// fetch entry point to an empty result with no error and no network hit
// (M40 Wave B air-gapped degrade mode).
func TestNVDService_Offline_NoHTTP(t *testing.T) {
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	svc := NewNVDService(nil, nil, "", server.URL, true)

	vulns, err := svc.searchByKeyword(context.Background(), "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("offline searchByKeyword should not error, got %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("offline searchByKeyword should return empty, got %d", len(vulns))
	}

	vuln, err := svc.SearchByCVEID(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("offline SearchByCVEID should not error, got %v", err)
	}
	if vuln != nil {
		t.Errorf("offline SearchByCVEID should return nil, got %v", vuln)
	}

	if hit {
		t.Error("offline mode must not make any HTTP request")
	}
}

// TestNVDService_DefaultBaseURL asserts an empty baseURL falls back to the
// nvdAPIBase const (M40 Wave B).
func TestNVDService_DefaultBaseURL(t *testing.T) {
	svc := NewNVDService(nil, nil, "", "", false)
	if svc.baseURL != nvdAPIBase {
		t.Errorf("expected default baseURL %q, got %q", nvdAPIBase, svc.baseURL)
	}
}

// The five tests below used to stand up an httptest server and then assert
// NOTHING — each ended in a comment like "the actual test would need the
// searchByKeyword to be callable with a custom URL" (Codex M54 R8, Low). That
// was true when they were written; NVDService.baseURL has been configurable
// since M40 Wave B, so the reason expired and the placeholders stayed green no
// matter what the error handling did. The invalid-JSON one is the test that
// should have caught the R8 trailing-content defect and could not.
//
// They now drive the real lookup. Each asserts an ERROR, because the failure
// mode this product cannot afford is a bad response being read as "this
// component has no vulnerabilities".

func TestNVDService_HTTPMock_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message": "Rate limit exceeded"}`))
	}))
	defer server.Close()

	svc := NewNVDService(nil, nil, "", server.URL, false)
	if _, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0"); err == nil {
		t.Error("a 429 from NVD produced no error; the component would be counted as " +
			"successfully checked with zero findings")
	}
}

func TestNVDService_HTTPMock_InvalidJSON(t *testing.T) {
	cases := map[string]string{
		"malformed":         `{invalid json`,
		"trailing document": `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}{"a":1}`,
		"trailing garbage":  `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]} nope`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			svc := NewNVDService(nil, nil, "", server.URL, false)
			if _, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0"); err == nil {
				t.Errorf("body %q produced no error; a valid envelope followed by anything at "+
					"all would be accepted as an authoritative empty result", body)
			}
		})
	}
}

func TestNVDService_HTTPMock_Timeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(release)
		server.Close()
	}()

	svc := NewNVDService(nil, nil, "", server.URL, false)
	svc.httpClient = &http.Client{Timeout: 20 * time.Millisecond}
	if _, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0"); err == nil {
		t.Error("a timed-out NVD request produced no error")
	}
}

func TestNVDService_HTTPMock_EmptyResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A complete envelope reporting zero matches: the one shape that IS a
		// legitimate "this component has no CVEs" and must NOT error.
		response := NVDResponse{
			ResultsPerPage:  nvdIntPtr(0),
			StartIndex:      nvdIntPtr(0),
			TotalResults:    nvdIntPtr(0),
			Vulnerabilities: nvdEntriesPtr([]NVDVulnEntry{}),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer server.Close()

	svc := NewNVDService(nil, nil, "", server.URL, false)
	vulns, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0")
	if err != nil {
		t.Fatalf("a well-formed zero-result response must not error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("got %d vulnerabilities, want 0", len(vulns))
	}
}

func TestNVDService_HTTPMock_NetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Close the connection without sending anything.
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	}))
	defer server.Close()

	svc := NewNVDService(nil, nil, "", server.URL, false)
	if _, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0"); err == nil {
		t.Error("a dropped connection produced no error")
	}
}

func TestNewNVDService(t *testing.T) {
	svc := NewNVDService(nil, nil, "test-key", "", false)

	if svc == nil {
		t.Fatal("NewNVDService returned nil")
	}
	if svc.apiKey != "test-key" {
		t.Errorf("expected apiKey 'test-key', got '%s'", svc.apiKey)
	}
	if svc.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if svc.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", svc.httpClient.Timeout)
	}
}

func TestNewNVDService_EmptyAPIKey(t *testing.T) {
	svc := NewNVDService(nil, nil, "", "", false)

	if svc == nil {
		t.Fatal("NewNVDService returned nil")
	}
	if svc.apiKey != "" {
		t.Errorf("expected empty apiKey, got '%s'", svc.apiKey)
	}
}

// Test NVD API response structures
func TestNVDCVE_FullParsing(t *testing.T) {
	jsonData := `{
		"id": "CVE-2021-44228",
		"published": "2021-12-10T10:15:00.000",
		"lastModified": "2023-11-07T03:38:00.000",
		"descriptions": [
			{
				"lang": "en",
				"value": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints."
			}
		],
		"metrics": {
			"cvssMetricV31": [
				{
					"cvssData": {
						"baseScore": 10.0,
						"baseSeverity": "CRITICAL"
					}
				}
			],
			"cvssMetricV2": [
				{
					"cvssData": {
						"baseScore": 9.3
					}
				}
			]
		}
	}`

	var cve NVDCVE
	if err := json.Unmarshal([]byte(jsonData), &cve); err != nil {
		t.Fatalf("failed to unmarshal CVE: %v", err)
	}

	if cve.ID != "CVE-2021-44228" {
		t.Errorf("expected CVE ID CVE-2021-44228, got %s", cve.ID)
	}
	if cve.Published != "2021-12-10T10:15:00.000" {
		t.Errorf("unexpected published date: %s", cve.Published)
	}
	if len(cve.Metrics.CvssMetricV31) != 1 {
		t.Errorf("expected 1 CVSS V3.1 metric, got %d", len(cve.Metrics.CvssMetricV31))
	}
	if cve.Metrics.CvssMetricV31[0].CvssData.BaseScore != 10.0 {
		t.Errorf("expected CVSS score 10.0, got %f", cve.Metrics.CvssMetricV31[0].CvssData.BaseScore)
	}
}

func TestNVDMetrics_Empty(t *testing.T) {
	jsonData := `{}`

	var metrics NVDMetrics
	if err := json.Unmarshal([]byte(jsonData), &metrics); err != nil {
		t.Fatalf("failed to unmarshal empty metrics: %v", err)
	}

	if len(metrics.CvssMetricV31) != 0 {
		t.Errorf("expected empty CvssMetricV31, got %d items", len(metrics.CvssMetricV31))
	}
	if len(metrics.CvssMetricV30) != 0 {
		t.Errorf("expected empty CvssMetricV30, got %d items", len(metrics.CvssMetricV30))
	}
	if len(metrics.CvssMetricV2) != 0 {
		t.Errorf("expected empty CvssMetricV2, got %d items", len(metrics.CvssMetricV2))
	}
}

// Test for published date parsing in convertToVulnerabilities
func TestConvertToVulnerabilities_DateParsing(t *testing.T) {
	svc := &NVDService{}

	// The NVD code uses time.RFC3339 format which requires timezone
	entries := []NVDVulnEntry{
		{
			CVE: NVDCVE{
				ID:           "CVE-2023-0001",
				Published:    "2023-06-15T14:30:00Z", // RFC3339 format with Z timezone
				LastModified: "2023-07-20T10:00:00Z",
				Descriptions: []NVDDesc{
					{Lang: "en", Value: "Test"},
				},
				Metrics: NVDMetrics{},
			},
		},
	}

	vulns := svc.convertToVulnerabilities(entries)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	// The published date should be parsed correctly
	expected := time.Date(2023, 6, 15, 14, 30, 0, 0, time.UTC)
	if !vulns[0].PublishedAt.Equal(expected) {
		t.Errorf("expected PublishedAt %v, got %v", expected, vulns[0].PublishedAt)
	}
}

// TestConvertToVulnerabilities_NonRFC3339Date pins the zoneless timestamp NVD
// actually sends.
//
// M54 (Codex R4, Medium) INVERTED this test. It used to assert
// `PublishedAt == nil` for "2023-06-15T14:30:00.000", and its own comment said
// why: "NVD API actually returns dates like ... which doesn't match RFC3339,
// so PublishedAt remains zero". So the format the production API sends was
// known, and the test pinned the parser's failure to read it as if that were
// the intended behaviour. The consequence was not cosmetic — EVERY
// vulnerability this scanner created stored published_at = NULL, and the field
// was absent from every API response built from a scan.
//
// A test that encodes a defect as a contract is worse than no test: it makes
// the defect look deliberate and turns the fix into a red build. The
// assertion is now what a caller needs to be true.
func TestConvertToVulnerabilities_NonRFC3339Date(t *testing.T) {
	svc := &NVDService{}

	entries := []NVDVulnEntry{
		{
			CVE: NVDCVE{
				ID:        "CVE-2023-0001",
				Published: "2023-06-15T14:30:00.000", // exactly what NVD sends
				Descriptions: []NVDDesc{
					{Lang: "en", Value: "Test"},
				},
				Metrics: NVDMetrics{},
			},
		},
	}

	vulns := svc.convertToVulnerabilities(entries)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	if vulns[0].PublishedAt == nil {
		t.Fatal("PublishedAt is nil for the timestamp shape the NVD API actually sends. " +
			"RFC3339 requires an offset and NVD does not send one, so parsing with RFC3339 " +
			"alone drops every real publication date.")
	}
	// The zoneless form is read as UTC, which is what the NVD API documents.
	want := time.Date(2023, 6, 15, 14, 30, 0, 0, time.UTC)
	if !vulns[0].PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", *vulns[0].PublishedAt, want)
	}
}

func TestConvertToVulnerabilities_InvalidDate(t *testing.T) {
	svc := &NVDService{}

	entries := []NVDVulnEntry{
		{
			CVE: NVDCVE{
				ID:        "CVE-2023-0001",
				Published: "invalid-date",
				Descriptions: []NVDDesc{
					{Lang: "en", Value: "Test"},
				},
				Metrics: NVDMetrics{},
			},
		},
	}

	vulns := svc.convertToVulnerabilities(entries)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	// With an invalid date, PublishedAt stays nil (M46 B2: absent
	// timestamps are nil, not a zero time.Time).
	if vulns[0].PublishedAt != nil {
		t.Errorf("expected nil PublishedAt for invalid date, got %v", *vulns[0].PublishedAt)
	}
}

func TestNVDService_ScanComponents_RequiresRepositories(t *testing.T) {
	// This test documents that ScanComponents requires non-nil repositories
	// In production, this would use mock repositories
	//
	// Note: ScanComponents will panic if called with nil repositories
	// This is expected behavior - the service must be properly initialized

	svc := NewNVDService(nil, nil, "test-key", "", false)
	if svc.vulnRepo != nil {
		t.Error("expected nil vulnRepo when initialized with nil")
	}
	if svc.compRepo != nil {
		t.Error("expected nil compRepo when initialized with nil")
	}
	// We don't call ScanComponents here as it would panic with nil repos
	// Integration tests should use proper mock repositories
}

// Benchmark tests
func BenchmarkExtractCvss(b *testing.B) {
	metrics := NVDMetrics{
		CvssMetricV31: []CvssMetric{
			{CvssData: CvssData{BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
		},
		CvssMetricV30: []CvssMetric{
			{CvssData: CvssData{BaseScore: 7.5, BaseSeverity: "HIGH"}},
		},
		CvssMetricV2: []CvssMetric{
			{CvssData: CvssData{BaseScore: 5.0}},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractCvss(metrics)
	}
}

func BenchmarkScoreToCvss2Severity(b *testing.B) {
	scores := []float64{10.0, 7.5, 5.0, 3.0, 0.0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, score := range scores {
			scoreToCvss2Severity(score)
		}
	}
}

func BenchmarkConvertToVulnerabilities(b *testing.B) {
	svc := &NVDService{}
	entries := make([]NVDVulnEntry, 100)
	for i := 0; i < 100; i++ {
		entries[i] = NVDVulnEntry{
			CVE: NVDCVE{
				ID:        "CVE-2023-" + string(rune(i)),
				Published: "2023-01-01T00:00:00.000",
				Descriptions: []NVDDesc{
					{Lang: "en", Value: "Test vulnerability"},
				},
				Metrics: NVDMetrics{
					CvssMetricV31: []CvssMetric{
						{CvssData: CvssData{BaseScore: 7.5, BaseSeverity: "HIGH"}},
					},
				},
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		svc.convertToVulnerabilities(entries)
	}
}

// nvdIntPtr is the addressable-literal helper for NVDResponse.ResultsPerPage,
// which is a pointer so that an ABSENT envelope field is distinguishable from
// a present zero (M54, Codex R4 Critical).
func nvdIntPtr(v int) *int { return &v }

// TestM54NVDResponse_EnvelopeAbsenceIsNotZeroResults pins the distinction the
// pointer field exists for (Codex M54 R4, Critical): a 200 response whose body
// is not an NVD envelope must be an ERROR, not "this component has no CVEs".
//
// It matters because NVDService.baseURL is operator-overridable for air-gapped
// mirrors, so a proxy or mirror answering 200 with `null` / `{}` is reachable
// in the field — and before this, the scan counted that component as processed
// and reported completed with zero findings.
func TestM54NVDResponse_EnvelopeAbsenceIsNotZeroResults(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"null body", `null`, true},
		{"empty object", `{}`, true},
		{"envelope present, genuinely zero results", `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`, false},
		{"envelope present with results", `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Errorf("write body: %v", err)
				}
			}))
			defer srv.Close()

			svc := NewNVDService(nil, nil, "", srv.URL, false)
			_, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0")
			if tc.wantErr && err == nil {
				t.Errorf("body %s produced no error — an empty body is indistinguishable from "+
					"'no CVEs found', which the scan reports as a completed, clean result", tc.body)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("body %s: unexpected error %v", tc.body, err)
			}
		})
	}
}

// TestM54ParseNVDTimestamp_AcceptsTheFormatNVDActuallySends pins the
// zoneless shape (Codex M54 R4, Medium). time.RFC3339 alone rejected every
// real NVD `published` value, so published_at was stored NULL for every
// vulnerability this scanner created.
func TestM54ParseNVDTimestamp_AcceptsTheFormatNVDActuallySends(t *testing.T) {
	cases := []struct {
		in   string
		want string // RFC3339 rendering, or "" for nil
	}{
		{"2024-03-29T17:15:21.150", "2024-03-29T17:15:21Z"}, // what NVD really sends
		{"2024-03-29T17:15:21", "2024-03-29T17:15:21Z"},
		{"2024-03-29T17:15:21.150Z", "2024-03-29T17:15:21Z"}, // offset honoured, not reinterpreted
		{"2024-03-29T17:15:21+09:00", "2024-03-29T08:15:21Z"},
		{"", ""},
		{"not a timestamp", ""},
	}
	for _, tc := range cases {
		got := parseNVDTimestamp(tc.in)
		if tc.want == "" {
			if got != nil {
				t.Errorf("parseNVDTimestamp(%q) = %v, want nil", tc.in, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("parseNVDTimestamp(%q) = nil, want %s — NVD does not send an offset, so "+
				"RFC3339 alone drops every real publication date", tc.in, tc.want)
			continue
		}
		if g := got.UTC().Format(time.RFC3339); g != tc.want {
			t.Errorf("parseNVDTimestamp(%q) = %s, want %s", tc.in, g, tc.want)
		}
	}
}

// nvdEntriesPtr is the addressable-literal helper for
// NVDResponse.Vulnerabilities, which is a pointer to slice so that an ABSENT
// array is distinguishable from a present empty one (M54, Codex R5 Critical).
func nvdEntriesPtr(v []NVDVulnEntry) *[]NVDVulnEntry { return &v }

// TestM54ExtractCvss_PrefersPrimaryOverSecondary pins the severity-selection
// rule (Codex M54 R5, Critical).
//
// NVD attaches several CVSS assessments to one CVE — its own "Primary" plus
// any "Secondary" ones from CNAs and third parties — and does NOT order them
// with Primary first. extractCvss used to take element zero, so whichever
// organisation happened to be listed first decided the severity this product
// reports. The live example Codex cited demotes an NVD Primary 9.8/CRITICAL to
// a Secondary 6.3/MEDIUM, which is enough for `--fail-on critical` to exit 0
// on a scan whose only finding is that CVE.
func TestM54ExtractCvss_PrefersPrimaryOverSecondary(t *testing.T) {
	metrics := NVDMetrics{
		CvssMetricV31: []CvssMetric{
			// Secondary first, exactly as NVD can order them.
			{Type: "Secondary", Source: "vuldb@vuldb.com",
				CvssData: CvssData{BaseScore: 6.3, BaseSeverity: "MEDIUM"}},
			{Type: "Primary", Source: "nvd@nist.gov",
				CvssData: CvssData{BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
		},
	}
	score, severity := extractCvss(metrics)
	if score == nil {
		t.Fatal("no score extracted")
	}
	if *score != 9.8 || severity != "CRITICAL" {
		t.Errorf("extractCvss = (%v, %q), want (9.8, \"CRITICAL\") — the Primary assessment is "+
			"NVD's own and must win regardless of array position", *score, severity)
	}
}

// TestM54ExtractCvss_FallsBackToFirstWhenNoPrimary keeps the previous
// behaviour for the ordinary case where NVD published no Primary assessment:
// nothing privileges one Secondary over another, so the first is used.
func TestM54ExtractCvss_FallsBackToFirstWhenNoPrimary(t *testing.T) {
	metrics := NVDMetrics{
		CvssMetricV31: []CvssMetric{
			{Type: "Secondary", CvssData: CvssData{BaseScore: 6.3, BaseSeverity: "MEDIUM"}},
			{Type: "Secondary", CvssData: CvssData{BaseScore: 4.0, BaseSeverity: "MEDIUM"}},
		},
	}
	score, severity := extractCvss(metrics)
	if score == nil || *score != 6.3 || severity != "MEDIUM" {
		t.Errorf("extractCvss = (%v, %q), want (6.3, \"MEDIUM\")", score, severity)
	}
}

// TestM54ExtractCvss_V40OnlyIsNotUnknown pins the CVSS v4 gap (Codex M54 R5,
// High). A CVE that NVD scores only with v4 matched no modelled field, so it
// was stored with a nil score and severity "UNKNOWN" — invisible to
// `--fail-on high`.
func TestM54ExtractCvss_V40OnlyIsNotUnknown(t *testing.T) {
	metrics := NVDMetrics{
		CvssMetricV40: []CvssMetric{
			{Type: "Primary", CvssData: CvssData{BaseScore: 7.0, BaseSeverity: "HIGH"}},
		},
	}
	score, severity := extractCvss(metrics)
	if score == nil {
		t.Fatal("a v4-only CVE produced no score; it would be stored as UNKNOWN and " +
			"`--fail-on high` could not see it")
	}
	if *score != 7.0 || severity != "HIGH" {
		t.Errorf("extractCvss = (%v, %q), want (7.0, \"HIGH\")", *score, severity)
	}
}

// TestM54ExtractCvss_V31StillOutranksV40 pins the deliberately conservative
// ordering: adding v4 must not re-grade any CVE that already has a v3 score.
// Whether v4 should outrank v3 is a product decision, not part of this fix.
func TestM54ExtractCvss_V31StillOutranksV40(t *testing.T) {
	metrics := NVDMetrics{
		CvssMetricV31: []CvssMetric{
			{Type: "Primary", CvssData: CvssData{BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
		},
		CvssMetricV40: []CvssMetric{
			{Type: "Primary", CvssData: CvssData{BaseScore: 7.0, BaseSeverity: "HIGH"}},
		},
	}
	score, severity := extractCvss(metrics)
	if score == nil || *score != 9.8 || severity != "CRITICAL" {
		t.Errorf("extractCvss = (%v, %q), want the v3.1 score (9.8, \"CRITICAL\")", score, severity)
	}
}

// TestM54NVDResponse_ValidateChecksTheWholeEnvelope pins what validate really
// rejects. The R4 cut checked only resultsPerPage while its comment claimed it
// rejected any non-envelope body — a comment stronger than the code, which is
// the defect class this repo treats as first-class (Codex M54 R5, Critical).
func TestM54NVDResponse_ValidateChecksTheWholeEnvelope(t *testing.T) {
	// Every case below that is meant to exercise a LATER check carries
	// startIndex:0 (Codex M54 R10, Low). When R8 made startIndex required, the
	// cases written before it started failing at that earlier check instead of
	// the one they were named for — so removing the page-length check or the
	// cve.id validation would have left them green. A test that passes for the
	// wrong reason pins nothing.
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"null", `null`, true},
		{"empty object", `{}`, true},
		{"resultsPerPage only, no array", `{"resultsPerPage":0}`, true},
		{"claims results but carries none", `{"resultsPerPage":1,"startIndex":0,"totalResults":1}`, true},
		{"claims results, empty array", `{"resultsPerPage":0,"startIndex":0,"totalResults":5,"vulnerabilities":[]}`, true},
		// Both of these passed the R5 cut, whose name already claimed it
		// checked "the whole envelope" — the test's coverage was weaker than
		// its own title (Codex M54 R6, Critical).
		{"totalResults absent entirely", `{"resultsPerPage":0,"vulnerabilities":[]}`, true},
		// The scanner never asks for a later page, so being handed one means
		// the first page is missing and nothing here can tell (Codex M54 R8,
		// Critical).
		{"startIndex absent", `{"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}`, true},
		{"a later page, internally consistent", `{"resultsPerPage":1,"startIndex":20,"totalResults":40,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`, true},
		{"page shorter than it declares", `{"resultsPerPage":2,"startIndex":0,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`, true},
		// An entry with no usable cve.id passed every earlier cut (Codex M54
		// R7, Critical). It became a row with CVEID "", which VARCHAR NOT NULL
		// accepts, so components were linked to an unidentifiable finding and
		// the scan still completed.
		{"entry with no cve wrapper", `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{}]}`, true},
		{"entry with empty cve.id", `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":""}}]}`, true},
		{"entry with malformed cve.id", `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"not-a-cve"}}]}`, true},
		{"one good entry, one malformed", `{"resultsPerPage":2,"startIndex":0,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}},{"cve":{"id":""}}]}`, true},
		{"genuine no-matches answer", `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`, false},
		{"normal answer", `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`, false},
		// A truncated RESULT SET is well-formed: the page is internally honest
		// about carrying 1 of 500. validate does NOT close the pagination gap
		// documented on searchByKeyword and must not be read as if it did.
		{"first page of a larger result set is accepted", `{"resultsPerPage":1,"startIndex":0,"totalResults":500,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r NVDResponse
			if err := json.Unmarshal([]byte(tc.body), &r); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			err := r.validate()
			if tc.wantErr && err == nil {
				t.Errorf("validate() accepted %s; an unusable body must not read as "+
					"'this component has no CVEs'", tc.body)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validate() rejected %s: %v", tc.body, err)
			}
		})
	}
}

// TestM54SearchByCVEID_RefusesAnAnswerAboutADifferentCVE pins the point-lookup
// identity check (Codex M54 R7, High).
//
// The request names one cveId, so the answer must be that CVE. Until M54 the
// first entry was returned unchecked, so a mirror — NVDService.baseURL is
// operator-overridable for air-gapped deployments — could answer a request for
// a CRITICAL CVE with a LOW one and have it cached and served under the
// requested identity.
func TestM54SearchByCVEID_RefusesAnAnswerAboutADifferentCVE(t *testing.T) {
	cases := []struct {
		name      string
		asked     string
		answered  string
		wantErr   bool
		wantFound bool
	}{
		{"honest answer", "CVE-2021-44228", "CVE-2021-44228", false, true},
		{"case difference is not a mismatch", "cve-2021-44228", "CVE-2021-44228", false, true},
		{"substituted CVE", "CVE-2021-44228", "CVE-2000-0001", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				body := `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"` +
					tc.answered + `","descriptions":[{"lang":"en","value":"x"}]}}]}`
				if _, err := w.Write([]byte(body)); err != nil {
					t.Errorf("write: %v", err)
				}
			}))
			defer srv.Close()

			svc := NewNVDService(nil, nil, "", srv.URL, false)
			got, err := svc.SearchByCVEID(context.Background(), tc.asked)
			if tc.wantErr {
				if err == nil {
					t.Errorf("asked for %s, NVD answered with %s, and the lookup returned no "+
						"error — the wrong CVE would be cached and served under the requested id",
						tc.asked, tc.answered)
				}
				if got != nil {
					t.Errorf("a rejected answer must not be returned; got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantFound && got == nil {
				t.Error("expected the requested CVE to be returned")
			}
		})
	}
}

// m54TruncatedBody is an io.Reader that yields data and then reports a broken
// transfer rather than a clean EOF — a server that declared a longer body and
// closed the connection.
type m54TruncatedBody struct {
	data []byte
	i    int
}

func (t *m54TruncatedBody) Read(p []byte) (int, error) {
	if t.i >= len(t.data) {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, t.data[t.i:])
	t.i += n
	return n, nil
}

// TestM54DecodeNVDResponse_RejectsATruncatedTransfer pins the difference
// between "the body ended" and "the connection broke" (Codex M54 R9,
// Critical).
//
// The R8 cut used dec.More(), which returns a bool and collapses its
// lookahead's error into false. A transfer cut short immediately after a
// complete empty-result envelope therefore reported "nothing follows" and was
// accepted as an authoritative zero-finding answer.
func TestM54DecodeNVDResponse_RejectsATruncatedTransfer(t *testing.T) {
	envelope := `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`

	if _, err := decodeNVDResponse(&m54TruncatedBody{data: []byte(envelope)}); err == nil {
		t.Error("a truncated transfer produced no error; a complete-looking empty envelope " +
			"followed by a broken connection would be read as 'this component has no CVEs'")
	}

	// The same bytes over a clean reader must still be accepted.
	if _, err := decodeNVDResponse(strings.NewReader(envelope)); err != nil {
		t.Errorf("a clean, well-formed zero-result body must be accepted: %v", err)
	}
}
