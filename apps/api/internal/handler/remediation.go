package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
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
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": err.Error(),
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

	var req RemediationByCVERequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request",
		})
	}

	ctx := c.Request().Context()
	remediation, err := h.remediationService.GetRemediationByCVE(ctx, cveID, req.ComponentName, req.ComponentVersion)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, remediation)
}
