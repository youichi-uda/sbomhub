package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestEPSSService_FetchScores_InjectedURL proves that s.baseURL is actually
// used to build the request URL: we stand up an httptest server returning a
// canned FIRST EPSS API response and assert the scores are parsed from it.
func TestEPSSService_FetchScores_InjectedURL(t *testing.T) {
	const body = `{
		"status": "OK",
		"status-code": 200,
		"version": "1.0",
		"total": 2,
		"data": [
			{"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99998", "date": "2024-01-15"},
			{"cve": "CVE-2021-45046", "epss": "0.12345", "percentile": "0.54321", "date": "2024-01-15"}
		]
	}`

	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	// vulnRepo is not needed for fetchEPSSScores / GetScore paths.
	svc := NewEPSSService(nil, server.URL, false)

	scores, err := svc.fetchEPSSScores(context.Background(), []string{"CVE-2021-44228", "CVE-2021-45046"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	if !hit {
		t.Fatal("expected the injected server URL to be hit, but it was not")
	}
	if len(scores) != 2 {
		t.Fatalf("expected 2 parsed scores, got %d", len(scores))
	}

	got, ok := scores["CVE-2021-44228"]
	if !ok {
		t.Fatalf("expected score for CVE-2021-44228 to be present")
	}
	if got.Score != 0.97565 {
		t.Errorf("Score = %v, want 0.97565", got.Score)
	}
	if got.Percentile != 0.99998 {
		t.Errorf("Percentile = %v, want 0.99998", got.Percentile)
	}

	// GetScore is the exported real-time lookup and must go through baseURL too.
	single, err := svc.GetScore(context.Background(), "CVE-2021-45046")
	if err != nil {
		t.Fatalf("GetScore returned error: %v", err)
	}
	if single == nil {
		t.Fatal("GetScore returned nil for a present CVE")
	}
	if single.Score != 0.12345 {
		t.Errorf("GetScore Score = %v, want 0.12345", single.Score)
	}
}

// TestEPSSService_FiltersMalformedBeforeFetch proves the M42 Wave 1 boundary
// guard: a malformed CVE in a batch is DROPPED before the external URL is built,
// so it never reaches the FIRST EPSS API, while the valid IDs still go through
// as a comma-separated batch. The httptest handler inspects the actual query it
// received and fails the test if the malformed token leaked through.
func TestEPSSService_FiltersMalformedBeforeFetch(t *testing.T) {
	const body = `{"status":"OK","status-code":200,"version":"1.0","total":0,"data":[]}`

	var gotRawQuery, gotCVEParam string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		gotCVEParam = r.URL.Query().Get("cve")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	// One valid ID, one hostile/malformed token, one more valid ID.
	batch := []string{"CVE-2021-44228", "not a cve! OR 1=1", "CVE-2021-45046"}
	if _, err := svc.fetchEPSSScores(context.Background(), batch); err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}

	// The malformed token must be entirely absent from the outbound request.
	if strings.Contains(gotRawQuery, "OR") || strings.Contains(gotRawQuery, "1=1") ||
		strings.Contains(gotCVEParam, "OR") || strings.Contains(gotCVEParam, "not") {
		t.Fatalf("malformed CVE leaked into the EPSS request: rawQuery=%q cve=%q", gotRawQuery, gotCVEParam)
	}

	// The two valid IDs must survive as a literal comma-separated batch (the
	// comma is a legitimate separator EPSS expects, not %2C-encoded).
	if gotCVEParam != "CVE-2021-44228,CVE-2021-45046" {
		t.Errorf("cve param = %q, want %q (comma-separated batch preserved)", gotCVEParam, "CVE-2021-44228,CVE-2021-45046")
	}
	if gotRawQuery != "cve=CVE-2021-44228,CVE-2021-45046" {
		t.Errorf("raw query = %q, want %q", gotRawQuery, "cve=CVE-2021-44228,CVE-2021-45046")
	}
}

// TestEPSSService_AllMalformed_NoFetch proves that a batch containing only
// malformed IDs never makes an HTTP call at all (the server handler fails the
// test if reached) and returns an empty, error-free result.
func TestEPSSService_AllMalformed_NoFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no HTTP call must be made when every CVE in the batch is malformed; got %q", r.URL.RawQuery)
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	scores, err := svc.fetchEPSSScores(context.Background(), []string{"bogus", "CVE-xxxx", "'; DROP TABLE"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected empty scores for an all-malformed batch, got %d", len(scores))
	}
}

// TestEPSSService_GetScore_MalformedRejectedNoFetch proves the single real-time
// lookup validates its input first and returns validation.ErrInvalidCVEID
// WITHOUT any external call (the handler maps that to 400).
func TestEPSSService_GetScore_MalformedRejectedNoFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("GetScore must not make an HTTP call for a malformed CVE; got %q", r.URL.RawQuery)
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	_, err := svc.GetScore(context.Background(), "definitely-not-a-cve")
	if err == nil {
		t.Fatal("GetScore(malformed) returned nil error, want validation error")
	}
}

// TestEPSSService_EscapeMechanism documents the defence-in-depth encoder used
// when building the cve param. Validated CVE IDs contain only [A-Z0-9-] (which
// QueryEscape leaves untouched, so real batches are unchanged), but the encoder
// still percent-encodes anything dangerous — this pins that contract.
func TestEPSSService_EscapeMechanism(t *testing.T) {
	// A valid CVE is passed through verbatim.
	if got := url.QueryEscape("CVE-2021-44228"); got != "CVE-2021-44228" {
		t.Errorf("QueryEscape(valid CVE) = %q, want it unchanged", got)
	}
	// A hostile value with a space + ampersand is neutralised (no raw
	// separators survive to break out of the cve param).
	got := url.QueryEscape("CVE-2021-4 &x")
	if strings.ContainsAny(got, " &") {
		t.Errorf("QueryEscape(hostile) = %q, want no raw space/ampersand", got)
	}
}

// TestEPSSService_Offline asserts that offline mode short-circuits BEFORE any
// HTTP call is made. The server handler fails the test if it is ever reached.
func TestEPSSService_Offline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("offline mode must not make HTTP calls")
	}))
	defer server.Close()

	// nil vulnRepo is safe: the offline guard returns before the repo is touched.
	svc := NewEPSSService(nil, server.URL, true)

	// SyncScores must return nil without hitting the network or the repo.
	if err := svc.SyncScores(context.Background()); err != nil {
		t.Errorf("SyncScores in offline mode returned error: %v", err)
	}

	// GetScore must return (nil, nil) in offline mode.
	data, err := svc.GetScore(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Errorf("GetScore in offline mode returned error: %v", err)
	}
	if data != nil {
		t.Errorf("GetScore in offline mode returned data %+v, want nil", data)
	}
}
