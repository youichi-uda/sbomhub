package handler

import (
	"errors"
	"log/slog"
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
		slog.Warn("scan_settings: get failed", "tenant_id", tenantCtx.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get scan settings",
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
		// Mixed-400 split (mirrors SbomHandler.Upload / F443): invalid
		// schedule type/hour/day are caller-fixable validation feedback
		// (marked with service.ErrValidation → 400 with the helpful
		// message); the %w-wrapped DB errors from the load/upsert path are
		// internal → 500 generic, raw error logged server-side only. The
		// pre-fix path blanket-400'd every failure AND echoed the raw
		// driver string.
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
		}
		slog.Warn("scan_settings: update failed", "tenant_id", tenantCtx.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to update scan settings",
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
		slog.Warn("scan_settings: get logs failed", "tenant_id", tenantCtx.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get scan logs",
		})
	}

	if logs == nil {
		logs = []service.ScanLog{}
	}

	return c.JSON(http.StatusOK, logs)
}
