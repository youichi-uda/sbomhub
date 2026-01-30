package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

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
