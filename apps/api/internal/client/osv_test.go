package client

import (
	"context"
	"errors"
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

// TestOSVClient_GetVulnerability_OversizedBodyError pins the M43 Phase D R2
// finding 2 response-size bound: a body larger than 5MB
// (maxOSVResponseBytes) is rejected as a decode error instead of being
// buffered/parsed without limit — a hostile or misconfigured OSV endpoint
// cannot balloon scheduler memory.
func TestOSVClient_GetVulnerability_OversizedBodyError(t *testing.T) {
	// Valid JSON whose total size is just over 5MB: the limit must trip on
	// SIZE, not on JSON validity.
	huge := `{"id":"CVE-2025-1","summary":"` + strings.Repeat("a", 5<<20) + `"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(huge))
	}))
	defer server.Close()

	c := NewOSVClient().WithBaseURL(server.URL)
	vuln, err := c.GetVulnerability(context.Background(), "CVE-2025-1")
	if err == nil {
		id := "<nil>"
		if vuln != nil {
			id = vuln.ID
		}
		t.Fatalf("expected an error for a >5MB body, got vuln id=%q", id)
	}
	if vuln != nil {
		t.Errorf("expected nil vuln on oversized body, got id=%q", vuln.ID)
	}
}

// TestOSVClient_GetVulnerability_404ReturnsErrNotFound pins the M45 Wave 1 C1
// typed-404 contract: a wire 404 surfaces as (nil, ErrOSVNotFound), matchable
// with errors.Is, so callers can distinguish a definitive negative from a
// transient fetch failure.
func TestOSVClient_GetVulnerability_404ReturnsErrNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := NewOSVClient().WithBaseURL(server.URL)
	vuln, err := c.GetVulnerability(context.Background(), "CVE-2025-0404")
	if !errors.Is(err, ErrOSVNotFound) {
		t.Fatalf("GetVulnerability on 404 err = %v, want errors.Is(ErrOSVNotFound)", err)
	}
	if vuln != nil {
		t.Errorf("GetVulnerability on 404 vuln = %+v, want nil", vuln)
	}
}

// TestOSVClient_GetVulnerability_5xxIsNotErrNotFound guards the sentinel's
// discrimination: a transient 5xx must NOT match ErrOSVNotFound, so the
// scheduler keeps treating it as a retryable failure (no tombstone) rather
// than a definitive negative.
func TestOSVClient_GetVulnerability_5xxIsNotErrNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOSVClient().WithBaseURL(server.URL)
	_, err := c.GetVulnerability(context.Background(), "CVE-2025-0500")
	if err == nil {
		t.Fatal("GetVulnerability on 500 err = nil, want a non-nil error")
	}
	if errors.Is(err, ErrOSVNotFound) {
		t.Errorf("GetVulnerability on 500 matched ErrOSVNotFound, want a distinct transient error (err=%v)", err)
	}
}

// TestRecordLinked pins the M45 Wave 1 C2 linkage authority moved from the
// scheduler to the client package: a body vouches for a lookup when its own ID
// is the requested id OR its aliases name the CVE; an unrelated body is
// unlinked.
func TestRecordLinked(t *testing.T) {
	tests := []struct {
		name        string
		vuln        *OSVVulnerability
		requestedID string
		cveID       string
		want        bool
	}{
		{
			name:        "self-identifying id matches requestedID",
			vuln:        &OSVVulnerability{ID: "CVE-2025-1", Aliases: nil},
			requestedID: "CVE-2025-1",
			cveID:       "CVE-2025-1",
			want:        true,
		},
		{
			name:        "aliases name the CVE (alias home)",
			vuln:        &OSVVulnerability{ID: "GHSA-xxxx-yyyy-zzzz", Aliases: []string{"CVE-2025-1"}},
			requestedID: "GHSA-xxxx-yyyy-zzzz",
			cveID:       "CVE-2025-1",
			want:        true,
		},
		{
			name:        "alias match wins even when id differs from requestedID",
			vuln:        &OSVVulnerability{ID: "GO-2025-0001", Aliases: []string{" CVE-2025-1 "}},
			requestedID: "GO-2025-9999",
			cveID:       "CVE-2025-1",
			want:        true,
		},
		{
			name:        "unrelated body: id mismatch and no alias",
			vuln:        &OSVVulnerability{ID: "GO-2025-0002", Aliases: []string{"CVE-2099-9"}},
			requestedID: "CVE-2025-1",
			cveID:       "CVE-2025-1",
			want:        false,
		},
		{
			name:        "nil body is unlinked",
			vuln:        nil,
			requestedID: "CVE-2025-1",
			cveID:       "CVE-2025-1",
			want:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RecordLinked(tt.vuln, tt.requestedID, tt.cveID); got != tt.want {
				t.Errorf("RecordLinked(%+v, %q, %q) = %v, want %v", tt.vuln, tt.requestedID, tt.cveID, got, tt.want)
			}
		})
	}
}

// TestOSVClient_IsOffline pins the M43 Phase D R4 accessor the scheduler's
// offline-drift guard keys on: it must track WithOffline exactly (false by
// default, flips both ways) without touching any fetch behaviour.
func TestOSVClient_IsOffline(t *testing.T) {
	c := NewOSVClient()
	if c.IsOffline() {
		t.Error("IsOffline() = true on a fresh client, want false")
	}
	if !c.WithOffline(true).IsOffline() {
		t.Error("IsOffline() = false after WithOffline(true), want true")
	}
	if c.WithOffline(false).IsOffline() {
		t.Error("IsOffline() = true after WithOffline(false), want false")
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
