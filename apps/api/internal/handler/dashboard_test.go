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
}

func (f *fakeDashboardService) GetSummary(_ context.Context, _ uuid.UUID) (*model.DashboardSummary, error) {
	return f.summary, f.err
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
