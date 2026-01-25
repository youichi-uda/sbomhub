package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

type DashboardHandler struct {
	dashboardService *service.DashboardService
}

func NewDashboardHandler(ds *service.DashboardService) *DashboardHandler {
	return &DashboardHandler{dashboardService: ds}
}

func (h *DashboardHandler) GetSummary(c echo.Context) error {
	summary, err := h.dashboardService.GetSummary(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, summary)
}
