package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

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
		var upstream *service.NVDUpstreamError
		// Map the service's sentinel errors to the right status. Never
		// return err.Error() to the client: the DB / unknown branch would
		// leak raw internals (F396).
		switch {
		case errors.Is(err, service.ErrInvalidCVEID):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid CVE ID format"})
		case errors.Is(err, service.ErrCVENotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "CVE not found"})
		case errors.As(err, &upstream):
			return respondNVDUpstream(c, cveID, upstream)
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

// respondNVDUpstream answers a CVE search whose NVD fallback did not get a
// usable answer. The CVE was not in the local catalogue, so the API could not
// answer — but the fault is upstream, not ours, and the caller can act on it:
//
//   - NVD said "not now" (rate limit: 403/429, or 503): 503 Service
//     Unavailable with Retry-After. 503 rather than 429 because the CALLER did
//     not exceed any limit of this API — SBOMHub's own upstream throttled it,
//     which is what RFC 9110 §15.6.4 + §10.2.3 (503 + Retry-After) describe.
//     The same status the API already uses when a dependency is temporarily
//     unavailable (AI disabled, public-link rate limiter without Redis).
//   - any other upstream failure (other status, unreachable, undecodable
//     answer): 502 Bad Gateway, as for the billing provider (billing.go).
//
// The body carries a stable `code` (`nvd_unavailable` / `nvd_upstream_error`)
// and never the upstream response (nor does the log line).
func respondNVDUpstream(c echo.Context, cveID string, upstream *service.NVDUpstreamError) error {
	slog.Warn("search: nvd fallback failed", "cve_id", cveID,
		"status", upstream.Status, "temporary", upstream.Temporary, "error", upstream)
	if upstream.Temporary {
		secs := int(upstream.RetryAfter / time.Second)
		if secs < 1 {
			secs = 1
		}
		c.Response().Header().Set("Retry-After", strconv.Itoa(secs))
		return c.JSON(http.StatusServiceUnavailable, map[string]any{
			"error":               "CVE is not in the local catalogue and NVD is not accepting lookups right now (rate limited); retry later",
			"code":                "nvd_unavailable",
			"retry_after_seconds": secs,
		})
	}
	return c.JSON(http.StatusBadGateway, map[string]string{
		"error": "CVE is not in the local catalogue and the NVD lookup failed",
		"code":  "nvd_upstream_error",
	})
}
