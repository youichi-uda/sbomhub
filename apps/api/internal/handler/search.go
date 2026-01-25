package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

type SearchHandler struct {
	searchService *service.SearchService
}

func NewSearchHandler(ss *service.SearchService) *SearchHandler {
	return &SearchHandler{searchService: ss}
}

// SearchByCVE handles CVE search requests
func (h *SearchHandler) SearchByCVE(c echo.Context) error {
	cveID := c.QueryParam("q")
	if cveID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "query parameter 'q' is required"})
	}

	result, err := h.searchService.SearchByCVE(c.Request().Context(), cveID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

// SearchByComponent handles component search requests
func (h *SearchHandler) SearchByComponent(c echo.Context) error {
	name := c.QueryParam("name")
	if name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "query parameter 'name' is required"})
	}

	version := c.QueryParam("version")

	result, err := h.searchService.SearchByComponent(c.Request().Context(), name, version)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}
