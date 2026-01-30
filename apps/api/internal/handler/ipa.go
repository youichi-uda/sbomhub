package handler

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

// IPAHandler handles IPA integration API requests
type IPAHandler struct {
	ipaService *service.IPAService
}

// NewIPAHandler creates a new IPAHandler
func NewIPAHandler(ipaService *service.IPAService) *IPAHandler {
	return &IPAHandler{
		ipaService: ipaService,
	}
}

// ListAnnouncements handles GET /api/v1/ipa/announcements
func (h *IPAHandler) ListAnnouncements(c echo.Context) error {
	ctx := c.Request().Context()

	// Parse query parameters
	category := c.QueryParam("category")
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))

	if limit <= 0 {
		limit = 20
	}

	result, err := h.ipaService.ListAnnouncements(ctx, category, limit, offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to list announcements")
	}

	return c.JSON(http.StatusOK, result)
}

// GetAnnouncementsByCVE handles GET /api/v1/vulnerabilities/:cve_id/ipa
func (h *IPAHandler) GetAnnouncementsByCVE(c echo.Context) error {
	ctx := c.Request().Context()
	cveID := c.Param("cve_id")

	if cveID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "CVE ID is required")
	}

	announcements, err := h.ipaService.GetAnnouncementsByCVE(ctx, cveID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get IPA announcements")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"announcements": announcements,
		"cve_id":        cveID,
	})
}

// GetSyncSettings handles GET /api/v1/settings/ipa
func (h *IPAHandler) GetSyncSettings(c echo.Context) error {
	ctx := c.Request().Context()

	tenantID, ok := c.Get("tenant_id").(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Tenant ID not found")
	}

	settings, err := h.ipaService.GetSyncSettings(ctx, tenantID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get sync settings")
	}

	return c.JSON(http.StatusOK, settings)
}

// UpdateSyncSettingsRequest represents the request body for updating sync settings
type UpdateSyncSettingsRequest struct {
	Enabled        bool     `json:"enabled"`
	NotifyOnNew    bool     `json:"notify_on_new"`
	NotifySeverity []string `json:"notify_severity"`
}

// UpdateSyncSettings handles PUT /api/v1/settings/ipa
func (h *IPAHandler) UpdateSyncSettings(c echo.Context) error {
	ctx := c.Request().Context()

	tenantID, ok := c.Get("tenant_id").(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Tenant ID not found")
	}

	var req UpdateSyncSettingsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	input := service.UpdateSyncSettingsInput{
		Enabled:        req.Enabled,
		NotifyOnNew:    req.NotifyOnNew,
		NotifySeverity: req.NotifySeverity,
	}

	settings, err := h.ipaService.UpdateSyncSettings(ctx, tenantID, input)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update sync settings")
	}

	return c.JSON(http.StatusOK, settings)
}

// SyncAnnouncements handles POST /api/v1/ipa/sync
func (h *IPAHandler) SyncAnnouncements(c echo.Context) error {
	ctx := c.Request().Context()

	tenantID, ok := c.Get("tenant_id").(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Tenant ID not found")
	}

	result, err := h.ipaService.SyncForTenant(ctx, tenantID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to sync announcements")
	}

	return c.JSON(http.StatusOK, result)
}
