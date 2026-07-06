package handler

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/validation"
)

// RemediationHandler handles remediation API endpoints
type RemediationHandler struct {
	remediationService *service.RemediationService
}

// NewRemediationHandler creates a new remediation handler
func NewRemediationHandler(rs *service.RemediationService) *RemediationHandler {
	return &RemediationHandler{remediationService: rs}
}

// GetRemediation returns remediation guidance for a vulnerability
// GET /api/v1/vulnerabilities/:id/remediation
func (h *RemediationHandler) GetRemediation(c echo.Context) error {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid vulnerability ID",
		})
	}

	ctx := c.Request().Context()
	remediation, err := h.remediationService.GetRemediation(ctx, id)
	if err != nil {
		// F44x: GetRemediation wraps the repository lookup failure as
		// "vulnerability not found: %w" — echoing err.Error() leaked the raw
		// driver error. The service collapses genuine not-found and backend
		// faults into the same error, so without a service seam they cannot be
		// distinguished here: return a stable 404 message and keep the raw
		// detail in the server log only.
		slog.Warn("remediation: lookup failed", "vulnerability_id", id, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "vulnerability not found",
		})
	}

	return c.JSON(http.StatusOK, remediation)
}

// GetRemediationByCVE returns remediation guidance by CVE ID
// GET /api/v1/remediation/:cve_id
type RemediationByCVERequest struct {
	ComponentName    string `query:"component_name"`
	ComponentVersion string `query:"component_version"`
}

func (h *RemediationHandler) GetRemediationByCVE(c echo.Context) error {
	cveID := c.Param("cve_id")
	if cveID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "CVE ID is required",
		})
	}
	// M42: reject a malformed CVE ID before it can reach the external OSV
	// request URL (this endpoint feeds the OSV /vulns/<id> path). Use the
	// normalized ID downstream.
	normalizedCVE, verr := validation.ValidateCVEID(cveID)
	if verr != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid CVE ID format",
		})
	}
	cveID = normalizedCVE

	var req RemediationByCVERequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request",
		})
	}

	ctx := c.Request().Context()
	remediation, err := h.remediationService.GetRemediationByCVE(ctx, cveID, req.ComponentName, req.ComponentVersion)
	if err != nil {
		// F44x: GetRemediationByCVE wraps the OSV client failure as
		// "failed to fetch from OSV: %w" — echoing err.Error() leaked the raw
		// upstream/HTTP error. A genuine not-found and an OSV backend failure
		// are indistinguishable here without a service seam, so return a stable
		// message and keep the raw detail in the server log only.
		slog.Warn("remediation: OSV lookup failed", "cve_id", cveID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "remediation not available",
		})
	}

	return c.JSON(http.StatusOK, remediation)
}
