package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGHSAClient_GetByGHSAID(t *testing.T) {
	want := GHSAAdvisory{
		GHSAID:      "GHSA-9763-4f94-gfch",
		CVEID:       "CVE-2024-24786",
		Summary:     "protojson.Unmarshal infinite loop",
		Description: "Stuff",
		Severity:    "high",
		Identifiers: []GHSAIdentifier{
			{Type: "GHSA", Value: "GHSA-9763-4f94-gfch"},
			{Type: "CVE", Value: "CVE-2024-24786"},
		},
		Vulnerabilities: []GHSAVulnerability{
			{
				Package:                GHSAPackage{Ecosystem: "go", Name: "google.golang.org/protobuf"},
				VulnerableVersionRange: "< 1.33.0",
				FirstPatchedVersion:    "1.33.0",
				VulnerableFunctions:    []string{"encoding/protojson.Unmarshal"},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q want GET", r.Method)
		}
		if r.URL.Path != "/advisories/GHSA-9763-4f94-gfch" {
			t.Errorf("path = %q want /advisories/GHSA-9763-4f94-gfch", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept = %q want application/vnd.github+json", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != ghsaAPIVersion {
			t.Errorf("X-GitHub-Api-Version = %q want %q", got, ghsaAPIVersion)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q want Bearer test-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := NewGHSAClient("test-token").WithBaseURL(srv.URL)
	got, err := c.GetByGHSAID(context.Background(), "GHSA-9763-4f94-gfch")
	if err != nil {
		t.Fatalf("GetByGHSAID: %v", err)
	}
	if got == nil {
		t.Fatal("got nil advisory")
	}
	if got.GHSAID != want.GHSAID || got.CVEID != want.CVEID {
		t.Errorf("got = %+v\nwant ids = %s / %s", got, want.GHSAID, want.CVEID)
	}
	if len(got.Vulnerabilities) != 1 || got.Vulnerabilities[0].FirstPatchedVersion != "1.33.0" {
		t.Errorf("Vulnerabilities not round-tripped: %+v", got.Vulnerabilities)
	}
}

func TestGHSAClient_GetByGHSAID_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	c := NewGHSAClient("").WithBaseURL(srv.URL)
	got, err := c.GetByGHSAID(context.Background(), "GHSA-missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil on 404, got %+v", got)
	}
}

func TestGHSAClient_GetByCVEID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve_id") != "CVE-2024-24786" {
			t.Errorf("cve_id = %q want CVE-2024-24786", r.URL.Query().Get("cve_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ghsa_id":"GHSA-9763-4f94-gfch","cve_id":"CVE-2024-24786","summary":"x"}]`))
	}))
	defer srv.Close()

	c := NewGHSAClient("").WithBaseURL(srv.URL)
	got, err := c.GetByCVEID(context.Background(), "CVE-2024-24786")
	if err != nil {
		t.Fatalf("GetByCVEID: %v", err)
	}
	if len(got) != 1 || got[0].GHSAID != "GHSA-9763-4f94-gfch" {
		t.Errorf("got = %+v", got)
	}
}

func TestGHSAClient_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer srv.Close()

	c := NewGHSAClient("").WithBaseURL(srv.URL)
	_, err := c.GetByGHSAID(context.Background(), "GHSA-x")
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected rate-limited error, got %v", err)
	}
}

func TestGHSAClient_EmptyID(t *testing.T) {
	c := NewGHSAClient("")
	if _, err := c.GetByGHSAID(context.Background(), ""); err == nil {
		t.Error("expected error on empty GHSA id")
	}
	if _, err := c.GetByCVEID(context.Background(), ""); err == nil {
		t.Error("expected error on empty CVE id")
	}
	if _, err := c.ListByEcosystem(context.Background(), "", 10); err == nil {
		t.Error("expected error on empty ecosystem")
	}
}
