package handler

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

// KEVHandler handles KEV integration API requests
type KEVHandler struct {
	kevService *service.KEVService
}

// NewKEVHandler creates a new KEVHandler
func NewKEVHandler(kevService *service.KEVService) *KEVHandler {
	return &KEVHandler{
		kevService: kevService,
	}
}

// SyncCatalog handles POST /api/v1/kev/sync
func (h *KEVHandler) SyncCatalog(c echo.Context) error {
	ctx := c.Request().Context()

	result, err := h.kevService.SyncCatalog(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to sync KEV catalog: "+err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":         "KEV catalog sync completed",
		"new_entries":     result.NewEntries,
		"updated_entries": result.UpdatedEntries,
		"total_processed": result.TotalProcessed,
		"catalog_version": result.CatalogVersion,
	})
}

// ListCatalog handles GET /api/v1/kev/catalog
func (h *KEVHandler) ListCatalog(c echo.Context) error {
	ctx := c.Request().Context()

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))

	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	entries, total, err := h.kevService.GetCatalog(ctx, limit, offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to list KEV catalog")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetByCVE handles GET /api/v1/kev/:cve_id
func (h *KEVHandler) GetByCVE(c echo.Context) error {
	ctx := c.Request().Context()
	cveID := c.Param("cve_id")

	if cveID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "CVE ID is required")
	}

	entry, err := h.kevService.GetByCVE(ctx, cveID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get KEV entry")
	}

	if entry == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"in_kev": false,
			"cve_id": cveID,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"in_kev": true,
		"cve_id": cveID,
		"entry":  entry,
	})
}

// GetStats handles GET /api/v1/kev/stats
func (h *KEVHandler) GetStats(c echo.Context) error {
	ctx := c.Request().Context()

	stats, err := h.kevService.GetStats(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get KEV stats")
	}

	return c.JSON(http.StatusOK, stats)
}

// GetProjectKEVVulnerabilities handles GET /api/v1/projects/:id/kev
func (h *KEVHandler) GetProjectKEVVulnerabilities(c echo.Context) error {
	ctx := c.Request().Context()

	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid project ID")
	}

	vulnerabilities, err := h.kevService.GetKEVVulnerabilities(ctx, projectID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get KEV vulnerabilities")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"vulnerabilities": vulnerabilities,
		"count":           len(vulnerabilities),
		"project_id":      projectID,
	})
}

// GetSyncSettings handles GET /api/v1/kev/settings
func (h *KEVHandler) GetSyncSettings(c echo.Context) error {
	ctx := c.Request().Context()

	settings, err := h.kevService.GetSyncSettings(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get KEV sync settings")
	}

	return c.JSON(http.StatusOK, settings)
}

// GetLatestSync handles GET /api/v1/kev/sync/latest
func (h *KEVHandler) GetLatestSync(c echo.Context) error {
	ctx := c.Request().Context()

	log, err := h.kevService.GetLatestSyncLog(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get latest sync log")
	}

	if log == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "No sync has been performed yet",
		})
	}

	return c.JSON(http.StatusOK, log)
}

// CheckCVE handles GET /api/v1/vulnerabilities/:cve_id/kev
func (h *KEVHandler) CheckCVE(c echo.Context) error {
	ctx := c.Request().Context()
	cveID := c.Param("cve_id")

	if cveID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "CVE ID is required")
	}

	inKEV, err := h.kevService.CheckCVEInKEV(ctx, cveID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check CVE in KEV")
	}

	response := map[string]interface{}{
		"cve_id": cveID,
		"in_kev": inKEV,
	}

	if inKEV {
		entry, _ := h.kevService.GetByCVE(ctx, cveID)
		if entry != nil {
			response["date_added"] = entry.DateAdded
			response["due_date"] = entry.DueDate
			response["known_ransomware_use"] = entry.KnownRansomwareUse
			response["vendor_project"] = entry.VendorProject
			response["product"] = entry.Product
			response["required_action"] = entry.RequiredAction
		}
	}

	return c.JSON(http.StatusOK, response)
}
