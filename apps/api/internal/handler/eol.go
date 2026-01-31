package handler

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

// EOLHandler handles EOL integration API requests
type EOLHandler struct {
	eolService *service.EOLService
}

// NewEOLHandler creates a new EOLHandler
func NewEOLHandler(eolService *service.EOLService) *EOLHandler {
	return &EOLHandler{
		eolService: eolService,
	}
}

// SyncCatalog handles POST /api/v1/eol/sync
func (h *EOLHandler) SyncCatalog(c echo.Context) error {
	ctx := c.Request().Context()

	result, err := h.eolService.SyncCatalog(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to sync EOL catalog: "+err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":            "EOL catalog sync completed",
		"products_synced":    result.ProductsSynced,
		"cycles_synced":      result.CyclesSynced,
		"components_updated": result.ComponentsUpdated,
	})
}

// ListProducts handles GET /api/v1/eol/products
func (h *EOLHandler) ListProducts(c echo.Context) error {
	ctx := c.Request().Context()

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))

	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	products, total, err := h.eolService.GetProducts(ctx, limit, offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to list EOL products")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"products": products,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

// GetProduct handles GET /api/v1/eol/products/:name
func (h *EOLHandler) GetProduct(c echo.Context) error {
	ctx := c.Request().Context()
	name := c.Param("name")

	if name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Product name is required")
	}

	product, cycles, err := h.eolService.GetProductByName(ctx, name)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get EOL product")
	}

	if product == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Product not found")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"product": product,
		"cycles":  cycles,
	})
}

// GetStats handles GET /api/v1/eol/stats
func (h *EOLHandler) GetStats(c echo.Context) error {
	ctx := c.Request().Context()

	stats, err := h.eolService.GetStats(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get EOL stats")
	}

	return c.JSON(http.StatusOK, stats)
}

// GetProjectEOLSummary handles GET /api/v1/projects/:id/eol-summary
func (h *EOLHandler) GetProjectEOLSummary(c echo.Context) error {
	ctx := c.Request().Context()

	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid project ID")
	}

	summary, err := h.eolService.GetEOLSummary(ctx, projectID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get EOL summary")
	}

	return c.JSON(http.StatusOK, summary)
}

// UpdateProjectComponentsEOL handles POST /api/v1/projects/:id/eol-check
func (h *EOLHandler) UpdateProjectComponentsEOL(c echo.Context) error {
	ctx := c.Request().Context()

	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid project ID")
	}

	updated, err := h.eolService.UpdateProjectComponentsEOL(ctx, projectID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update component EOL status")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":            "EOL check completed",
		"components_updated": updated,
		"project_id":         projectID,
	})
}

// GetSyncSettings handles GET /api/v1/eol/settings
func (h *EOLHandler) GetSyncSettings(c echo.Context) error {
	ctx := c.Request().Context()

	settings, err := h.eolService.GetSyncSettings(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get EOL sync settings")
	}

	return c.JSON(http.StatusOK, settings)
}

// GetLatestSync handles GET /api/v1/eol/sync/latest
func (h *EOLHandler) GetLatestSync(c echo.Context) error {
	ctx := c.Request().Context()

	log, err := h.eolService.GetLatestSyncLog(ctx)
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

// CheckComponentEOL handles GET /api/v1/eol/check
func (h *EOLHandler) CheckComponentEOL(c echo.Context) error {
	ctx := c.Request().Context()

	name := c.QueryParam("name")
	version := c.QueryParam("version")
	purl := c.QueryParam("purl")

	if name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Component name is required")
	}

	info, err := h.eolService.MatchComponentToEOL(ctx, name, version, purl)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check component EOL status")
	}

	return c.JSON(http.StatusOK, info)
}
