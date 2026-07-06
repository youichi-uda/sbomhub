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
