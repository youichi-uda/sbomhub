package handler

import (
	"fmt"
	"log/slog"
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
			slog.Warn("report: get all settings failed", "tenant_id", tenantID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load report settings"})
		}
		return c.JSON(http.StatusOK, settings)
	}

	settings, err := h.reportService.GetSettings(c.Request().Context(), tenantID, reportType)
	if err != nil {
		slog.Warn("report: get settings failed", "tenant_id", tenantID, "report_type", reportType, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load report settings"})
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
		slog.Warn("report: update settings failed", "tenant_id", tenantID, "report_type", input.ReportType, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update report settings"})
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

	// Set locale from Accept-Language header if not specified in request
	if input.Locale == "" {
		acceptLang := c.Request().Header.Get("Accept-Language")
		if len(acceptLang) >= 2 && acceptLang[:2] == "en" {
			input.Locale = "en"
		} else {
			input.Locale = "ja" // Default to Japanese
		}
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

	report, launcher, err := h.reportService.GenerateReport(c.Request().Context(), tenantID, userID, input)
	if err != nil {
		slog.Warn("report: generate failed", "tenant_id", tenantID, "report_type", input.ReportType, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate report"})
	}

	// F208 / M14-1: publish the newly-minted report UUID so the audit
	// middleware records audit_logs.resource_id = report.ID. POST
	// /reports/generate has no UUID path param so without this Set the
	// audit row would drop to NULL and break the forensic join
	// audit_logs ⨝ reports for every report.generated row.
	if report != nil {
		middleware.SetAuditResourceID(c, report.ID)
	}

	// Defer the async PDF/XLSX build until the request's tenant tx commits.
	// generateReportAsync opens its own tenant tx to issue the terminal
	// UpdateReport, but it raced the parent CreateReport INSERT on fast
	// generators — leaving the report stuck at "generating" forever (codex-r6
	// P1). RegisterPostCommit is a no-op (logged) outside TenantTx and is
	// nil-safe, so non-tenant call sites and error paths above degrade
	// gracefully.
	middleware.RegisterPostCommit(c, launcher)

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
		slog.Warn("report: list failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list reports"})
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
		slog.Warn("report: get report file failed", "tenant_id", tenantID, "report_id", reportID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "report not found"})
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
