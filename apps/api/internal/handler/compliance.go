package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
		slog.Warn("compliance: compliance check failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to check compliance"})
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
		slog.Warn("compliance: export report compliance check failed", "project_id", projectID, "format", format, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to export compliance report"})
	}

	switch format {
	case "json":
		return c.JSON(http.StatusOK, result)
	case "pdf":
		data, err := h.complianceService.GenerateCompliancePDF(c.Request().Context(), projectID, result)
		if err != nil {
			slog.Warn("compliance: export report pdf generation failed", "project_id", projectID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate compliance report"})
		}
		filename := fmt.Sprintf("compliance-report-%s-%s.pdf", projectID.String()[:8], time.Now().Format("20060102"))
		c.Response().Header().Set("Content-Type", "application/pdf")
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		c.Response().Header().Set("Content-Length", strconv.Itoa(len(data)))
		return c.Blob(http.StatusOK, "application/pdf", data)
	case "xlsx":
		data, err := h.complianceService.GenerateComplianceExcel(c.Request().Context(), projectID, result)
		if err != nil {
			slog.Warn("compliance: export report xlsx generation failed", "project_id", projectID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate compliance report"})
		}
		filename := fmt.Sprintf("compliance-report-%s-%s.xlsx", projectID.String()[:8], time.Now().Format("20060102"))
		c.Response().Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		c.Response().Header().Set("Content-Length", strconv.Itoa(len(data)))
		return c.Blob(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", data)
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
		slog.Warn("compliance: get checklist failed", "tenant_id", tenantID, "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load checklist"})
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
		// M47 W1: a project that is not this tenant's answers 404 — the
		// same answer as an unknown project id.
		if errors.Is(err, service.ErrComplianceProjectNotInTenant) {
			slog.Warn("compliance: update checklist rejected, project not in tenant",
				"tenant_id", tenantID, "project_id", projectID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
		}
		slog.Warn("compliance: update checklist response failed", "tenant_id", tenantID, "project_id", projectID, "check_id", checkID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update checklist response"})
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

	// tenantID from middleware -- F73 cross-tenant guard.
	tenantID := getTenantID(c)
	err = h.complianceService.DeleteChecklistResponse(c.Request().Context(), tenantID, projectID, checkID)
	if err != nil {
		// M47 W1: see UpdateChecklistResponse.
		if errors.Is(err, service.ErrComplianceProjectNotInTenant) {
			slog.Warn("compliance: delete checklist rejected, project not in tenant",
				"tenant_id", tenantID, "project_id", projectID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
		}
		// M47 W2: the repository now reports a 0-row DELETE (wrapped
		// sql.ErrNoRows) instead of discarding it. Project ownership was
		// already adjudicated above, so this can only mean "no such
		// response" — 404, not the 204 the pre-fix code returned for a
		// delete that removed nothing.
		if errors.Is(err, sql.ErrNoRows) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "checklist response not found"})
		}
		slog.Warn("compliance: delete checklist response failed", "tenant_id", tenantID, "project_id", projectID, "check_id", checkID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete checklist response"})
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

	// tenantID from middleware -- F73 cross-tenant guard.
	tenantID := getTenantID(c)
	result, err := h.complianceService.GetVisualizationSettings(c.Request().Context(), tenantID, projectID)
	if err != nil {
		slog.Warn("compliance: get visualization settings failed", "tenant_id", tenantID, "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load visualization settings"})
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
		// M47 W1: see UpdateChecklistResponse.
		if errors.Is(err, service.ErrComplianceProjectNotInTenant) {
			slog.Warn("compliance: update visualization rejected, project not in tenant",
				"tenant_id", tenantID, "project_id", projectID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
		}
		slog.Warn("compliance: update visualization settings failed", "tenant_id", tenantID, "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update visualization settings"})
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

	// tenantID from middleware -- F73 cross-tenant guard.
	tenantID := getTenantID(c)
	err = h.complianceService.DeleteVisualizationSettings(c.Request().Context(), tenantID, projectID)
	if err != nil {
		// M47 W1: see UpdateChecklistResponse.
		if errors.Is(err, service.ErrComplianceProjectNotInTenant) {
			slog.Warn("compliance: delete visualization rejected, project not in tenant",
				"tenant_id", tenantID, "project_id", projectID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
		}
		// M47 W2: see DeleteChecklistResponse — a 0-row DELETE means this
		// project has no settings row, which is a 404 rather than a 204
		// reporting a deletion that did not happen.
		if errors.Is(err, sql.ErrNoRows) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "visualization settings not found"})
		}
		slog.Warn("compliance: delete visualization settings failed", "tenant_id", tenantID, "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete visualization settings"})
	}

	return c.NoContent(http.StatusNoContent)
}
