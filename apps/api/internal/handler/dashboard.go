package handler

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
)

// dashboardServiceAPI is the subset of *service.DashboardService the
// handler uses. Declared as an interface so dashboard_test.go can
// substitute a fake without a real DB. The concrete
// *service.DashboardService satisfies it, so the cmd/server/main.go wiring
// is unchanged.
type dashboardServiceAPI interface {
	GetSummary(ctx context.Context, tenantID uuid.UUID) (*model.DashboardSummary, error)
	GetTopRisks(ctx context.Context, tenantID uuid.UUID, sortBy string) ([]model.TopRisk, error)
}

type DashboardHandler struct {
	dashboardService dashboardServiceAPI
}

func NewDashboardHandler(ds dashboardServiceAPI) *DashboardHandler {
	return &DashboardHandler{dashboardService: ds}
}

func (h *DashboardHandler) GetSummary(c echo.Context) error {
	// Get tenant ID from auth context for proper tenant isolation
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	summary, err := h.dashboardService.GetSummary(c.Request().Context(), tenantID)
	if err != nil {
		// DB / unknown fault: log the detail server-side, return a generic
		// message (F396 — never leak err.Error() to the client).
		slog.Warn("dashboard: get summary failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load dashboard summary"})
	}
	return c.JSON(http.StatusOK, summary)
}

// GetTopRisks serves GET /api/v1/dashboard/top-risks?sort=epss|cvss (F449 /
// M39): the dedicated endpoint that backs the dashboard's CVSS⇄EPSS toggle for
// the Top Risks widget. It returns the same []model.TopRisk shape as
// summary.top_risks so the web can swap the widget's data source without a
// summary re-fetch.
//
// `?sort` defaults to "epss" — the widget is labelled "By EPSS", so EPSS is the
// behaviour-preserving default here (this DIFFERS from M38's /vulnerabilities
// list, which defaults to cvss). Unknown values are rejected with 400 rather
// than silently falling back, mirroring the sbom.go list handler's posture.
func (h *DashboardHandler) GetTopRisks(c echo.Context) error {
	// Get tenant ID from auth context for proper tenant isolation.
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	sortBy := "epss"
	if v := c.QueryParam("sort"); v != "" {
		if v != "cvss" && v != "epss" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid sort"})
		}
		sortBy = v
	}

	risks, err := h.dashboardService.GetTopRisks(c.Request().Context(), tenantID, sortBy)
	if err != nil {
		// DB / unknown fault: log server-side, return a generic message
		// (F396 — never leak err.Error() to the client).
		slog.Warn("dashboard: get top risks failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load top risks"})
	}
	return c.JSON(http.StatusOK, risks)
}
