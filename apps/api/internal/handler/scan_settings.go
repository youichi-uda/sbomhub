package handler

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ScanSettingsHandler handles scan settings API endpoints
type ScanSettingsHandler struct {
	scanService *service.ScanSettingsService
}

// NewScanSettingsHandler creates a new scan settings handler
func NewScanSettingsHandler(ss *service.ScanSettingsService) *ScanSettingsHandler {
	return &ScanSettingsHandler{scanService: ss}
}

// Get returns scan settings for the current tenant
// GET /api/v1/settings/scan
func (h *ScanSettingsHandler) Get(c echo.Context) error {
	ctx := c.Request().Context()
	tenantCtx := middleware.NewTenantContext(c)
	if tenantCtx == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "unauthorized",
		})
	}

	settings, err := h.scanService.Get(ctx, tenantCtx.TenantID())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, settings)
}

// Update updates scan settings
// PUT /api/v1/settings/scan
func (h *ScanSettingsHandler) Update(c echo.Context) error {
	ctx := c.Request().Context()
	tenantCtx := middleware.NewTenantContext(c)
	if tenantCtx == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "unauthorized",
		})
	}

	// Check admin permission
	if !tenantCtx.CanAdmin() {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "admin permission required",
		})
	}

	var input service.UpdateScanSettingsInput
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
	}

	settings, err := h.scanService.Update(ctx, tenantCtx.TenantID(), input)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, settings)
}

// GetLogs returns scan execution logs
// GET /api/v1/settings/scan/logs
func (h *ScanSettingsHandler) GetLogs(c echo.Context) error {
	ctx := c.Request().Context()
	tenantCtx := middleware.NewTenantContext(c)
	if tenantCtx == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "unauthorized",
		})
	}

	limit := 20
	if l := c.QueryParam("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	logs, err := h.scanService.GetLogs(ctx, tenantCtx.TenantID(), limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	if logs == nil {
		logs = []service.ScanLog{}
	}

	return c.JSON(http.StatusOK, logs)
}
