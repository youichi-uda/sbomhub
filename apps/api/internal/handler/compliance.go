package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

type ComplianceHandler struct {
	complianceService *service.ComplianceService
}

func NewComplianceHandler(cs *service.ComplianceService) *ComplianceHandler {
	return &ComplianceHandler{complianceService: cs}
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
	case "pdf", "xlsx":
		// For now, just return JSON with a note
		// TODO: Implement PDF/Excel export
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "PDF/Excel export not yet implemented",
			"data":    result,
		})
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported format"})
	}
}
