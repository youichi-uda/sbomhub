package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
)

// stubImpactService drives ImpactHandler down its error / success paths without
// a database. It satisfies the handler's impactService interface.
type stubImpactService struct {
	impact *model.CVEImpact
	err    error
}

func (s stubImpactService) GetCVEImpact(_ context.Context, _ uuid.UUID, _ string) (*model.CVEImpact, error) {
	return s.impact, s.err
}

// newImpactCtx builds an echo context for GET /vulnerabilities/:cve_id/impact
// with a tenant already in context, so the handler proceeds past the auth guard.
func newImpactCtx(t *testing.T, cveID string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/"+cveID+"/impact", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("cve_id")
	c.SetParamValues(cveID)
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	return c, rec
}

// TestGetCVEImpact_ErrorDoesNotLeakInternal pins F396: when the service returns
// an error carrying internal detail (SQL driver text, scan error, connection
// string), the handler must answer 500 with a stable generic message and never
// echo the underlying error string to the caller.
func TestGetCVEImpact_ErrorDoesNotLeakInternal(t *testing.T) {
	// A realistic leaky error: exactly the shape the F394 mutation produced
	// ("converting NULL to string is unsupported"), plus a fake DSN/host to make
	// any leak unmistakable.
	leaky := errors.New(`resolve vulnerability meta for CVE-2021-1: sql: Scan error on column index 1, name "severity": converting NULL to string is unsupported; host=10.0.0.5 user="sbomhub_app" password=hunter2`)
	h := NewImpactHandler(stubImpactService{err: leaky})

	c, rec := newImpactCtx(t, "CVE-2021-0001")
	if err := h.GetCVEImpact(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	body := rec.Body.String()
	for _, leak := range []string{
		"Scan error", "converting NULL", "10.0.0.5", "sbomhub_app", "password", "hunter2",
		"resolve vulnerability meta", "sql:",
	} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks internal detail %q: %s", leak, body)
		}
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v (body=%s)", err, body)
	}
	if resp["error"] != "failed to get vulnerability impact" {
		t.Errorf("error message = %q, want stable generic \"failed to get vulnerability impact\"", resp["error"])
	}
}

// TestGetCVEImpact_UnknownCVEIs404 keeps the nil-impact -> 404 contract intact
// (an unknown CVE is distinct from a 500), so the F396 error-hardening does not
// swallow the not-found path.
func TestGetCVEImpact_UnknownCVEIs404(t *testing.T) {
	h := NewImpactHandler(stubImpactService{impact: nil, err: nil})

	c, rec := newImpactCtx(t, "CVE-9999-0001")
	if err := h.GetCVEImpact(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for unknown CVE", rec.Code)
	}
}

// TestGetCVEImpact_MissingTenantIs401 documents the auth guard: no tenant in
// context -> 401, never reaching the service.
func TestGetCVEImpact_MissingTenantIs401(t *testing.T) {
	h := NewImpactHandler(stubImpactService{})

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2021-1/impact", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("cve_id")
	c.SetParamValues("CVE-2021-1")
	// Deliberately do not set ContextKeyTenantID.

	if err := h.GetCVEImpact(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without tenant context", rec.Code)
	}
}
