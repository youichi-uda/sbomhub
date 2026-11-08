package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// GET /api/v1/search/cve falls back to NVD when the CVE is not in the local
// catalogue. When NVD refused that lookup (rate limit) or failed, the route
// answered 500 "failed to search" — a server fault for what is an upstream
// condition the caller can act on. Driven end to end here: real handler ->
// real SearchService -> real NVDService -> a fake NVD over HTTP.

type localMissRepo struct{}

func (localMissRepo) SearchByCVE(context.Context, string) (*model.CVESearchResult, error) {
	return nil, nil
}

func (localMissRepo) SearchByComponent(context.Context, string, string) (*model.ComponentSearchResult, error) {
	return nil, nil
}

func driveCVESearchAgainstNVD(t *testing.T, nvd http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	srv := httptest.NewServer(nvd)
	t.Cleanup(srv.Close)
	h := NewSearchHandler(service.NewSearchServiceWithNVD(localMissRepo{},
		service.NewNVDService(nil, nil, "", srv.URL, false)))
	c, rec := newSearchCtx("/api/v1/search/cve?q=CVE-2024-1234")
	if err := h.SearchByCVE(c); err != nil {
		t.Fatalf("SearchByCVE returned error: %v", err)
	}
	return rec
}

func TestSearchCVE_NVDRateLimited_Is503WithRetryAfter(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		retryAfter string
		wantRetry  string
	}{
		// NVD documents 403 for requests over the public rate limit; 429 is
		// what a proxy or a future NVD answers. Both mean "not now".
		{"403 without Retry-After", http.StatusForbidden, "", "30"},
		{"429 with Retry-After seconds", http.StatusTooManyRequests, "17", "17"},
		{"429 with absurd Retry-After is clamped", http.StatusTooManyRequests, "999999", "3600"},
		{"503 with Retry-After", http.StatusServiceUnavailable, "5", "5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := driveCVESearchAgainstNVD(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("upstream says SECRET-UPSTREAM-BODY"))
			})
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, body = %s; want 503", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Retry-After"); got != tc.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", got, tc.wantRetry)
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["code"] != "nvd_unavailable" {
				t.Fatalf("body = %v", body)
			}
			if strings.Contains(rec.Body.String(), "SECRET-UPSTREAM-BODY") {
				t.Fatalf("upstream body leaked: %s", rec.Body.String())
			}
		})
	}
}

func TestSearchCVE_NVDFailure_Is502(t *testing.T) {
	rec := driveCVESearchAgainstNVD(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("SECRET-UPSTREAM-BODY"))
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s; want 502", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "" {
		t.Fatalf("unexpected Retry-After on 502")
	}
	if strings.Contains(rec.Body.String(), "SECRET-UPSTREAM-BODY") {
		t.Fatalf("upstream body leaked: %s", rec.Body.String())
	}
}

func TestSearchCVE_NVDUnreachable_Is502(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // connection refused from now on
	h := NewSearchHandler(service.NewSearchServiceWithNVD(localMissRepo{},
		service.NewNVDService(nil, nil, "", url, false)))
	c, rec := newSearchCtx("/api/v1/search/cve?q=CVE-2024-1234")
	if err := h.SearchByCVE(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s; want 502", rec.Code, rec.Body.String())
	}
}
