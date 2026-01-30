package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ReportHandler handles report related requests
type ReportHandler struct {
	reportService *service.ReportService
}

// NewReportHandler creates a new ReportHandler
func NewReportHandler(rs *service.ReportService) *ReportHandler {
	return &ReportHandler{reportService: rs}
}

// GetSettings returns report settings
// GET /api/v1/reports/settings
func (h *ReportHandler) GetSettings(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	reportType := c.QueryParam("type")
	if reportType == "" {
		// Return all settings
		settings, err := h.reportService.GetAllSettings(c.Request().Context(), tenantID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, settings)
	}

	settings, err := h.reportService.GetSettings(c.Request().Context(), tenantID, reportType)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, settings)
}

// UpdateSettings updates report settings
// PUT /api/v1/reports/settings
func (h *ReportHandler) UpdateSettings(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Check admin permission
	if !tc.CanAdmin() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "admin permission required"})
	}

	var input model.CreateReportSettingsInput
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Validate report type
	validTypes := map[string]bool{
		model.ReportTypeExecutive:  true,
		model.ReportTypeTechnical:  true,
		model.ReportTypeCompliance: true,
	}
	if !validTypes[input.ReportType] {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid report type"})
	}

	settings, err := h.reportService.UpdateSettings(c.Request().Context(), tenantID, input)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, settings)
}

// Generate generates a report manually
// POST /api/v1/reports/generate
func (h *ReportHandler) Generate(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()
	userID := tc.UserID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var input model.GenerateReportInput
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Validate report type
	validTypes := map[string]bool{
		model.ReportTypeExecutive:  true,
		model.ReportTypeTechnical:  true,
		model.ReportTypeCompliance: true,
	}
	if !validTypes[input.ReportType] {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid report type"})
	}

	// Validate format
	validFormats := map[string]bool{
		model.ReportFormatPDF:  true,
		model.ReportFormatXLSX: true,
	}
	if !validFormats[input.Format] {
		input.Format = model.ReportFormatPDF
	}

	report, err := h.reportService.GenerateReport(c.Request().Context(), tenantID, userID, input)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusAccepted, report)
}

// List returns generated reports
// GET /api/v1/reports
func (h *ReportHandler) List(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	page := 1
	if p, err := strconv.Atoi(c.QueryParam("page")); err == nil && p > 0 {
		page = p
	}

	limit := 20
	if l, err := strconv.Atoi(c.QueryParam("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	reports, total, err := h.reportService.ListReports(c.Request().Context(), tenantID, page, limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	totalPages := total / limit
	if total%limit > 0 {
		totalPages++
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"reports":     reports,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	})
}

// Get returns a specific report
// GET /api/v1/reports/:id
func (h *ReportHandler) Get(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	reportID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid report id"})
	}

	report, err := h.reportService.GetReport(c.Request().Context(), tenantID, reportID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "report not found"})
	}

	return c.JSON(http.StatusOK, report)
}

// Download downloads a report file
// GET /api/v1/reports/:id/download
func (h *ReportHandler) Download(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	reportID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid report id"})
	}

	data, filename, err := h.reportService.GetReportFile(c.Request().Context(), tenantID, reportID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	// Determine content type
	contentType := "application/octet-stream"
	if len(filename) > 4 {
		ext := filename[len(filename)-4:]
		switch ext {
		case ".pdf":
			contentType = "application/pdf"
		case "xlsx":
			contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		}
	}

	c.Response().Header().Set("Content-Type", contentType)
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Response().Header().Set("Content-Length", strconv.Itoa(len(data)))

	return c.Blob(http.StatusOK, contentType, data)
}
