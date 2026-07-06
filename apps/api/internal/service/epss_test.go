package service

import (
	"context"
	"net/http"
	"net/http/httptest"
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
