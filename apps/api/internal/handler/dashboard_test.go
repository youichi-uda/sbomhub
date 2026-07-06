package handler

import (
	"context"
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

// ----------------------------------------------------------------------------
// Handler-level fake for the dashboard handler (F396). The handler is wired
// against the dashboardServiceAPI interface (see dashboard.go) so these
// tests never touch a real DB. The DB-error case asserts the handler
// returns 500 WITHOUT echoing the raw error string — pre-fix code returned
// 500 with err.Error() verbatim, so the leak assertion fails on pre-fix.
// ----------------------------------------------------------------------------

type fakeDashboardService struct {
	summary *model.DashboardSummary
	err     error

	// GetTopRisks capture/canned response (F449 / M39).
	topRisks       []model.TopRisk
	topRisksErr    error
	gotSortBy      string // records the sortBy the handler forwarded
	getTopRisksHit bool
}

func (f *fakeDashboardService) GetSummary(_ context.Context, _ uuid.UUID) (*model.DashboardSummary, error) {
	return f.summary, f.err
}

func (f *fakeDashboardService) GetTopRisks(_ context.Context, _ uuid.UUID, sortBy string) ([]model.TopRisk, error) {
	f.getTopRisksHit = true
	f.gotSortBy = sortBy
	return f.topRisks, f.topRisksErr
}

func newDashboardCtx(tenantID uuid.UUID, withTenant bool) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if withTenant {
		c.Set(middleware.ContextKeyTenantID, tenantID)
	}
	return c, rec
}

// GetSummary: a DB / unknown error must map to 500 with a generic body,
// never the raw error. (pre-fix: 500 + err.Error() — the leak assertion is
// what fails on pre-fix code.)
func TestDashboardHandler_GetSummary_DBError_Returns500_NoLeak(t *testing.T) {
	const marker = "SECRET_DB_INTERNALS_dsn=postgres://u:p@h/db"
	h := NewDashboardHandler(&fakeDashboardService{err: errors.New("pq: relation missing " + marker)})

	c, rec := newDashboardCtx(uuid.New(), true)
	if err := h.GetSummary(c); err != nil {
		t.Fatalf("GetSummary returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DB error status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), marker) {
		t.Errorf("500 body leaked raw DB error: %s", rec.Body.String())
	}
}

// GetSummary: missing tenant context → 401 (unchanged behaviour).
func TestDashboardHandler_GetSummary_NoTenant_Returns401(t *testing.T) {
	h := NewDashboardHandler(&fakeDashboardService{summary: &model.DashboardSummary{}})

	c, rec := newDashboardCtx(uuid.Nil, false)
	if err := h.GetSummary(c); err != nil {
		t.Fatalf("GetSummary returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-tenant status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// GetSummary: happy path returns 200 with the canned summary.
func TestDashboardHandler_GetSummary_HappyPath_Returns200(t *testing.T) {
	h := NewDashboardHandler(&fakeDashboardService{summary: &model.DashboardSummary{}})

	c, rec := newDashboardCtx(uuid.New(), true)
	if err := h.GetSummary(c); err != nil {
		t.Fatalf("GetSummary returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("happy-path status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// GetTopRisks (F449 / M39): GET /api/v1/dashboard/top-risks?sort=epss|cvss.
// Default sort is "epss" (the widget is labelled "By EPSS"); unknown values
// are rejected with 400 (mirrors the sbom.go list handler posture).
// ----------------------------------------------------------------------------

func newTopRisksCtx(tenantID uuid.UUID, withTenant bool, rawQuery string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	target := "/api/v1/dashboard/top-risks"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if withTenant {
		c.Set(middleware.ContextKeyTenantID, tenantID)
	}
	return c, rec
}

// An unknown ?sort value is rejected with 400 and the service is never called.
func TestDashboardHandler_GetTopRisks_BadSort_Returns400(t *testing.T) {
	f := &fakeDashboardService{topRisks: []model.TopRisk{}}
	h := NewDashboardHandler(f)

	c, rec := newTopRisksCtx(uuid.New(), true, "sort=bad")
	if err := h.GetTopRisks(c); err != nil {
		t.Fatalf("GetTopRisks returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad-sort status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if f.getTopRisksHit {
		t.Errorf("service GetTopRisks was called on a rejected sort value")
	}
	if !strings.Contains(rec.Body.String(), "invalid sort") {
		t.Errorf("bad-sort body = %s, want it to mention \"invalid sort\"", rec.Body.String())
	}
}

// A missing ?sort defaults to "epss" (the label-matching default; DIFFERS from
// M38's /vulnerabilities cvss default).
func TestDashboardHandler_GetTopRisks_MissingSort_DefaultsToEPSS(t *testing.T) {
	f := &fakeDashboardService{topRisks: []model.TopRisk{}}
	h := NewDashboardHandler(f)

	c, rec := newTopRisksCtx(uuid.New(), true, "")
	if err := h.GetTopRisks(c); err != nil {
		t.Fatalf("GetTopRisks returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("missing-sort status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !f.getTopRisksHit {
		t.Fatalf("service GetTopRisks was not called")
	}
	if f.gotSortBy != "epss" {
		t.Errorf("default sortBy = %q, want \"epss\"", f.gotSortBy)
	}
}

// ?sort=cvss is forwarded to the service verbatim.
func TestDashboardHandler_GetTopRisks_CVSS_Passes(t *testing.T) {
	f := &fakeDashboardService{topRisks: []model.TopRisk{}}
	h := NewDashboardHandler(f)

	c, rec := newTopRisksCtx(uuid.New(), true, "sort=cvss")
	if err := h.GetTopRisks(c); err != nil {
		t.Fatalf("GetTopRisks returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("sort=cvss status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if f.gotSortBy != "cvss" {
		t.Errorf("forwarded sortBy = %q, want \"cvss\"", f.gotSortBy)
	}
}

// ?sort=epss is forwarded to the service verbatim.
func TestDashboardHandler_GetTopRisks_EPSS_Passes(t *testing.T) {
	f := &fakeDashboardService{topRisks: []model.TopRisk{}}
	h := NewDashboardHandler(f)

	c, rec := newTopRisksCtx(uuid.New(), true, "sort=epss")
	if err := h.GetTopRisks(c); err != nil {
		t.Fatalf("GetTopRisks returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("sort=epss status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if f.gotSortBy != "epss" {
		t.Errorf("forwarded sortBy = %q, want \"epss\"", f.gotSortBy)
	}
}

// Missing tenant context → 401 (parallel to GetSummary).
func TestDashboardHandler_GetTopRisks_NoTenant_Returns401(t *testing.T) {
	h := NewDashboardHandler(&fakeDashboardService{topRisks: []model.TopRisk{}})

	c, rec := newTopRisksCtx(uuid.Nil, false, "sort=epss")
	if err := h.GetTopRisks(c); err != nil {
		t.Fatalf("GetTopRisks returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-tenant status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// A DB / unknown error maps to 500 with a generic body — never the raw error.
func TestDashboardHandler_GetTopRisks_DBError_Returns500_NoLeak(t *testing.T) {
	const marker = "SECRET_DB_INTERNALS_dsn=postgres://u:p@h/db"
	f := &fakeDashboardService{topRisksErr: errors.New("pq: relation missing " + marker)}
	h := NewDashboardHandler(f)

	c, rec := newTopRisksCtx(uuid.New(), true, "sort=epss")
	if err := h.GetTopRisks(c); err != nil {
		t.Fatalf("GetTopRisks returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DB error status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), marker) {
		t.Errorf("500 body leaked raw DB error: %s", rec.Body.String())
	}
}
