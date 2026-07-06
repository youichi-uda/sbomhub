package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// searchServiceAPI is the subset of *service.SearchService the handler
// uses. Declared as an interface so search_test.go can substitute a fake
// that returns canned results / sentinel errors without a real DB or NVD
// client. The concrete *service.SearchService satisfies it, so the
// cmd/server/main.go wiring is unchanged.
type searchServiceAPI interface {
	SearchByCVE(ctx context.Context, cveID string) (*model.CVESearchResult, error)
	SearchByComponent(ctx context.Context, name string, versionConstraint string) (*model.ComponentSearchResult, error)
}

type SearchHandler struct {
	searchService searchServiceAPI
}

func NewSearchHandler(ss searchServiceAPI) *SearchHandler {
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
		// Map the service's sentinel errors to the right status. Never
		// return err.Error() to the client: the DB / unknown branch would
		// leak raw internals (F396).
		switch {
		case errors.Is(err, service.ErrInvalidCVEID):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid CVE ID format"})
		case errors.Is(err, service.ErrCVENotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "CVE not found"})
		default:
			slog.Warn("search: cve search failed", "cve_id", cveID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to search"})
		}
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
		// DB / unknown fault: log the detail server-side, return a generic
		// message (F396 — never leak err.Error() to the client).
		slog.Warn("search: component search failed", "name", name, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to search"})
	}

	return c.JSON(http.StatusOK, result)
}
