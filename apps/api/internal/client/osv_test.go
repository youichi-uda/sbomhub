package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewOSVClient_DefaultBaseURL(t *testing.T) {
	c := NewOSVClient()
	if c.baseURL != DefaultOSVBaseURL {
		t.Errorf("expected default baseURL %q, got %q", DefaultOSVBaseURL, c.baseURL)
	}
	if c.offline {
		t.Error("expected offline false by default")
	}
}

func TestOSVClient_WithBaseURL_TrimsTrailingSlash(t *testing.T) {
	c := NewOSVClient().WithBaseURL("https://mirror.example/v1/")
	if c.baseURL != "https://mirror.example/v1" {
		t.Errorf("expected trailing slash trimmed, got %q", c.baseURL)
	}
	// Empty value must not clobber the existing base.
	c.WithBaseURL("")
	if c.baseURL != "https://mirror.example/v1" {
		t.Errorf("empty WithBaseURL should be a no-op, got %q", c.baseURL)
	}
}

func TestOSVClient_GetVulnerability_HTTPMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/vulns/CVE-2023-1234") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "CVE-2023-1234",
			"summary": "Test vuln in libfoo",
			"affected": [
				{
					"package": {"name": "libfoo", "ecosystem": "npm"},
					"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
					"versions": ["1.0.0", "1.1.0"]
				}
			]
		}`))
	}))
	defer server.Close()

	c := NewOSVClient().WithBaseURL(server.URL)
	vuln, err := c.GetVulnerability(context.Background(), "CVE-2023-1234")
	if err != nil {
		t.Fatalf("GetVulnerability returned error: %v", err)
	}
	if vuln == nil {
		t.Fatal("expected a vulnerability, got nil")
	}
	if vuln.ID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", vuln.ID)
	}

	// Exercise the shared remediation extractor to prove the parse is usable.
	rem := c.GetRemediation(vuln, "libfoo", "npm")
	if rem == nil || rem.FixedVersion != "1.2.3" {
		t.Errorf("expected fixed version 1.2.3, got %+v", rem)
	}
}

// TestOSVClient_Offline_NoHTTP asserts offline mode short-circuits
// GetVulnerability to nil with no network hit (M40 Wave B).
func TestOSVClient_Offline_NoHTTP(t *testing.T) {
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOSVClient().WithBaseURL(server.URL).WithOffline(true)
	vuln, err := c.GetVulnerability(context.Background(), "CVE-2023-1234")
	if err != nil {
		t.Fatalf("offline GetVulnerability should not error, got %v", err)
	}
	if vuln != nil {
		t.Errorf("offline GetVulnerability should return nil, got %v", vuln)
	}
	if hit {
		t.Error("offline mode must not make any HTTP request")
	}
}
