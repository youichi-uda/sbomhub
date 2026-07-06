package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/service"
)

// AnalyticsHandler handles analytics related requests
type AnalyticsHandler struct {
	analyticsService *service.AnalyticsService
}

// NewAnalyticsHandler creates a new AnalyticsHandler
func NewAnalyticsHandler(as *service.AnalyticsService) *AnalyticsHandler {
	return &AnalyticsHandler{analyticsService: as}
}

// GetSummary returns the complete analytics summary
// GET /api/v1/analytics/summary
func (h *AnalyticsHandler) GetSummary(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	days := 30
	if daysStr := c.QueryParam("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	summary, err := h.analyticsService.GetSummary(c.Request().Context(), tenantID, days)
	if err != nil {
		slog.Warn("analytics: get summary failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load analytics summary"})
	}

	return c.JSON(http.StatusOK, summary)
}

// GetMTTR returns Mean Time To Remediate data
// GET /api/v1/analytics/mttr
func (h *AnalyticsHandler) GetMTTR(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	days := 30
	if daysStr := c.QueryParam("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	mttr, err := h.analyticsService.GetMTTR(c.Request().Context(), tenantID, days)
	if err != nil {
		slog.Warn("analytics: get mttr failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load MTTR analytics"})
	}

	return c.JSON(http.StatusOK, mttr)
}

// GetVulnerabilityTrend returns vulnerability trend data
// GET /api/v1/analytics/vulnerability-trend
func (h *AnalyticsHandler) GetVulnerabilityTrend(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	days := 30
	if daysStr := c.QueryParam("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	trend, err := h.analyticsService.GetVulnerabilityTrend(c.Request().Context(), tenantID, days)
	if err != nil {
		slog.Warn("analytics: get vulnerability trend failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load vulnerability trend"})
	}

	return c.JSON(http.StatusOK, trend)
}

// GetSLOAchievement returns SLO achievement data
// GET /api/v1/analytics/slo-achievement
func (h *AnalyticsHandler) GetSLOAchievement(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	days := 30
	if daysStr := c.QueryParam("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	slo, err := h.analyticsService.GetSLOAchievement(c.Request().Context(), tenantID, days)
	if err != nil {
		slog.Warn("analytics: get slo achievement failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load SLO achievement"})
	}

	return c.JSON(http.StatusOK, slo)
}

// GetComplianceTrend returns compliance score trend
// GET /api/v1/analytics/compliance-trend
func (h *AnalyticsHandler) GetComplianceTrend(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	days := 30
	if daysStr := c.QueryParam("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	trend, err := h.analyticsService.GetComplianceTrend(c.Request().Context(), tenantID, days)
	if err != nil {
		slog.Warn("analytics: get compliance trend failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load compliance trend"})
	}

	return c.JSON(http.StatusOK, trend)
}

// GetSLOTargets returns SLO targets
// GET /api/v1/analytics/slo-targets
func (h *AnalyticsHandler) GetSLOTargets(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	targets, err := h.analyticsService.GetSLOTargets(c.Request().Context(), tenantID)
	if err != nil {
		slog.Warn("analytics: get slo targets failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load SLO targets"})
	}

	return c.JSON(http.StatusOK, targets)
}

// UpdateSLOTarget updates an SLO target
// PUT /api/v1/analytics/slo-targets
func (h *AnalyticsHandler) UpdateSLOTarget(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Check admin permission
	if !tc.CanAdmin() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "admin permission required"})
	}

	var input struct {
		Severity    string `json:"severity"`
		TargetHours int    `json:"target_hours"`
	}
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	err := h.analyticsService.UpdateSLOTarget(c.Request().Context(), tenantID, input.Severity, input.TargetHours)
	if err != nil {
		// F443: only echo the raw service error for caller-fixable validation
		// failures (bad severity / non-positive hours → 400). The repository
		// (DB) error is now %w-wrapped internal — log it and return a generic
		// body instead of leaking the SQL/driver string at a blanket 400.
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		slog.Warn("analytics: update slo target failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update SLO target"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "updated"})
}
