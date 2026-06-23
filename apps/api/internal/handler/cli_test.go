package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// TestCLIUpload_AdvertisesDeprecationHeaders verifies Trust Rescue 9.3.1 (#9):
// the legacy POST /api/v1/cli/upload route MUST advertise RFC 8594 (Sunset) +
// RFC 5988 (Link rel=successor-version) so SDK consumers see the upcoming
// removal on every response. We hit the unauthenticated error path on purpose
// — the headers are part of the deprecation contract and must be present
// regardless of whether the request body / tenant context is valid.
func TestCLIUpload_AdvertisesDeprecationHeaders(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/upload", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// nil CLIService — Upload returns 401 before ever touching it because
	// no tenant context is set on the request. That path still runs the
	// header writes at the top of the handler, which is what we want to
	// pin down.
	h := &CLIHandler{cliService: nil}

	if err := h.Upload(c); err != nil {
		t.Fatalf("Upload returned unexpected error: %v", err)
	}

	if got := rec.Header().Get("Deprecation"); got != "true" {
		t.Errorf("Deprecation header = %q, want %q", got, "true")
	}
	if got := rec.Header().Get("Sunset"); got == "" {
		t.Error("Sunset header is missing")
	} else if !strings.Contains(got, "2026") {
		t.Errorf("Sunset header = %q, expected to contain the 2026 sunset date", got)
	}
	link := rec.Header().Get("Link")
	if link == "" {
		t.Fatal("Link header is missing")
	}
	if !strings.Contains(link, "/api/v1/projects/{id}/sbom") {
		t.Errorf("Link header = %q, expected to point at canonical /api/v1/projects/{id}/sbom", link)
	}
	if !strings.Contains(link, `rel="successor-version"`) {
		t.Errorf("Link header = %q, expected rel=\"successor-version\"", link)
	}
}

// TestCLIUpload_DeprecationHeadersOnErrorBody verifies that the Sunset signal
// is delivered even on 4xx responses — clients should not have to coerce a
// successful upload to discover the deprecation. RFC 8594 §3 explicitly
// permits Sunset on any response.
func TestCLIUpload_DeprecationHeadersOnErrorBody(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/upload", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := &CLIHandler{cliService: nil}
	_ = h.Upload(c)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected non-200 (missing tenant context), got %d", rec.Code)
	}
	if rec.Header().Get("Deprecation") != "true" {
		t.Error("Deprecation: true must be present on the error response, not only on 200")
	}
}
