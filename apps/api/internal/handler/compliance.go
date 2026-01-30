package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

type ComplianceHandler struct {
	complianceService *service.ComplianceService
}

func NewComplianceHandler(cs *service.ComplianceService) *ComplianceHandler {
	return &ComplianceHandler{complianceService: cs}
}

// getTenantID extracts tenant ID from context (set by middleware)
func getTenantID(c echo.Context) uuid.UUID {
	if tenantID, ok := c.Get("tenant_id").(uuid.UUID); ok {
		return tenantID
	}
	// Fallback for development/testing
	return uuid.Nil
}

// getUserID extracts user ID from context (set by middleware)
func getUserID(c echo.Context) string {
	if userID, ok := c.Get("user_id").(string); ok {
		return userID
	}
	return "system"
}

// Check performs compliance check for a project
func (h *ComplianceHandler) Check(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	result, err := h.complianceService.CheckCompliance(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

// ExportReport exports compliance report
func (h *ComplianceHandler) ExportReport(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	format := c.QueryParam("format")
	if format == "" {
		format = "json"
	}

	result, err := h.complianceService.CheckCompliance(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	switch format {
	case "json":
		return c.JSON(http.StatusOK, result)
	case "pdf":
		data, err := h.complianceService.GenerateCompliancePDF(c.Request().Context(), projectID, result)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		filename := fmt.Sprintf("compliance-report-%s-%s.txt", projectID.String()[:8], time.Now().Format("20060102"))
		c.Response().Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		c.Response().Header().Set("Content-Length", strconv.Itoa(len(data)))
		return c.Blob(http.StatusOK, "text/plain", data)
	case "xlsx":
		data, err := h.complianceService.GenerateComplianceExcel(c.Request().Context(), projectID, result)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		filename := fmt.Sprintf("compliance-report-%s-%s.csv", projectID.String()[:8], time.Now().Format("20060102"))
		c.Response().Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		c.Response().Header().Set("Content-Length", strconv.Itoa(len(data)))
		return c.Blob(http.StatusOK, "text/csv", data)
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported format"})
	}
}

// ============================================================================
// METI Checklist (18 items) Handlers
// ============================================================================

// GetChecklist returns the full METI checklist with auto-verification and manual responses
// GET /api/v1/projects/:id/checklist
func (h *ComplianceHandler) GetChecklist(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	tenantID := getTenantID(c)
	result, err := h.complianceService.GetChecklist(c.Request().Context(), tenantID, projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

// UpdateChecklistResponse updates a manual checklist response
// PUT /api/v1/projects/:id/checklist/:checkId
func (h *ComplianceHandler) UpdateChecklistResponse(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	checkID := c.Param("checkId")
	if checkID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "check_id is required"})
	}

	var req struct {
		Response bool    `json:"response"`
		Note     *string `json:"note,omitempty"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	tenantID := getTenantID(c)
	userID := getUserID(c)

	err = h.complianceService.UpdateChecklistResponse(c.Request().Context(), tenantID, projectID, checkID, req.Response, req.Note, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// DeleteChecklistResponse removes a manual checklist response
// DELETE /api/v1/projects/:id/checklist/:checkId
func (h *ComplianceHandler) DeleteChecklistResponse(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	checkID := c.Param("checkId")
	if checkID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "check_id is required"})
	}

	err = h.complianceService.DeleteChecklistResponse(c.Request().Context(), projectID, checkID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}

// ============================================================================
// Visualization Framework Handlers
// ============================================================================

// GetVisualizationSettings returns visualization settings for a project
// GET /api/v1/projects/:id/visualization
func (h *ComplianceHandler) GetVisualizationSettings(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	result, err := h.complianceService.GetVisualizationSettings(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

// UpdateVisualizationSettings updates visualization settings for a project
// PUT /api/v1/projects/:id/visualization
func (h *ComplianceHandler) UpdateVisualizationSettings(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	var input model.VisualizationSettingsInput
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	tenantID := getTenantID(c)
	settings, err := h.complianceService.UpdateVisualizationSettings(c.Request().Context(), tenantID, projectID, &input)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, settings)
}

// DeleteVisualizationSettings removes visualization settings for a project
// DELETE /api/v1/projects/:id/visualization
func (h *ComplianceHandler) DeleteVisualizationSettings(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	err = h.complianceService.DeleteVisualizationSettings(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}
