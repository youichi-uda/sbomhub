package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// ReportService handles report operations
type ReportService struct {
	reportRepo    *repository.ReportRepository
	dashboardRepo *repository.DashboardRepository
	analyticsRepo *repository.AnalyticsRepository
	tenantRepo    *repository.TenantRepository
	reportDir     string
}

// NewReportService creates a new ReportService
func NewReportService(
	reportRepo *repository.ReportRepository,
	dashboardRepo *repository.DashboardRepository,
	analyticsRepo *repository.AnalyticsRepository,
	tenantRepo *repository.TenantRepository,
	reportDir string,
) *ReportService {
	// Ensure report directory exists
	os.MkdirAll(reportDir, 0755)

	return &ReportService{
		reportRepo:    reportRepo,
		dashboardRepo: dashboardRepo,
		analyticsRepo: analyticsRepo,
		tenantRepo:    tenantRepo,
		reportDir:     reportDir,
	}
}

// GetSettings returns report settings for a tenant
func (s *ReportService) GetSettings(ctx context.Context, tenantID uuid.UUID, reportType string) (*model.ReportSettings, error) {
	settings, err := s.reportRepo.GetSettings(ctx, tenantID, reportType)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	// Return default settings if none exist
	if settings == nil {
		return &model.ReportSettings{
			ID:              uuid.New(),
			TenantID:        tenantID,
			ReportType:      reportType,
			Enabled:         false,
			ScheduleType:    model.ScheduleTypeMonthly,
			ScheduleDay:     1,
			ScheduleHour:    9,
			Format:          model.ReportFormatPDF,
			EmailEnabled:    false,
			EmailRecipients: []string{},
			IncludeSections: []string{"summary", "vulnerabilities", "compliance"},
		}, nil
	}

	return settings, nil
}

// GetAllSettings returns all report settings for a tenant
func (s *ReportService) GetAllSettings(ctx context.Context, tenantID uuid.UUID) ([]model.ReportSettings, error) {
	settings, err := s.reportRepo.GetAllSettings(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	// Add default settings for missing report types
	existingTypes := make(map[string]bool)
	for _, s := range settings {
		existingTypes[s.ReportType] = true
	}

	reportTypes := []string{model.ReportTypeExecutive, model.ReportTypeTechnical, model.ReportTypeCompliance}
	for _, rt := range reportTypes {
		if !existingTypes[rt] {
			settings = append(settings, model.ReportSettings{
				ID:              uuid.New(),
				TenantID:        tenantID,
				ReportType:      rt,
				Enabled:         false,
				ScheduleType:    model.ScheduleTypeMonthly,
				ScheduleDay:     1,
				ScheduleHour:    9,
				Format:          model.ReportFormatPDF,
				EmailEnabled:    false,
				EmailRecipients: []string{},
				IncludeSections: []string{"summary", "vulnerabilities", "compliance"},
			})
		}
	}

	return settings, nil
}

// UpdateSettings updates report settings
func (s *ReportService) UpdateSettings(ctx context.Context, tenantID uuid.UUID, input model.CreateReportSettingsInput) (*model.ReportSettings, error) {
	// Validate input
	if input.ScheduleDay < 1 {
		input.ScheduleDay = 1
	}
	if input.ScheduleType == model.ScheduleTypeWeekly && input.ScheduleDay > 7 {
		input.ScheduleDay = 7
	}
	if input.ScheduleType == model.ScheduleTypeMonthly && input.ScheduleDay > 28 {
		input.ScheduleDay = 28
	}
	if input.ScheduleHour < 0 || input.ScheduleHour > 23 {
		input.ScheduleHour = 9
	}

	settings := &model.ReportSettings{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Enabled:         input.Enabled,
		ReportType:      input.ReportType,
		ScheduleType:    input.ScheduleType,
		ScheduleDay:     input.ScheduleDay,
		ScheduleHour:    input.ScheduleHour,
		Format:          input.Format,
		EmailEnabled:    input.EmailEnabled,
		EmailRecipients: input.EmailRecipients,
		IncludeSections: input.IncludeSections,
	}

	if err := s.reportRepo.UpsertSettings(ctx, settings); err != nil {
		return nil, fmt.Errorf("failed to update settings: %w", err)
	}

	return settings, nil
}

// GenerateReport generates a report manually
func (s *ReportService) GenerateReport(ctx context.Context, tenantID, userID uuid.UUID, input model.GenerateReportInput) (*model.GeneratedReport, error) {
	// Create report record
	report := &model.GeneratedReport{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ReportType:  input.ReportType,
		Format:      input.Format,
		Title:       fmt.Sprintf("%s Report - %s", getReportTypeLabel(input.ReportType), time.Now().Format("2006-01-02")),
		PeriodStart: input.PeriodStart,
		PeriodEnd:   input.PeriodEnd,
		Status:      model.ReportStatusGenerating,
		GeneratedBy: &userID,
	}

	// Set default period if not specified
	if report.PeriodEnd.IsZero() {
		report.PeriodEnd = time.Now()
	}
	if report.PeriodStart.IsZero() {
		report.PeriodStart = report.PeriodEnd.AddDate(0, -1, 0) // Default to last month
	}

	if err := s.reportRepo.CreateReport(ctx, report); err != nil {
		return nil, fmt.Errorf("failed to create report record: %w", err)
	}

	// Generate report asynchronously
	go s.generateReportAsync(context.Background(), tenantID, report)

	return report, nil
}

// generateReportAsync generates the report file asynchronously
func (s *ReportService) generateReportAsync(ctx context.Context, tenantID uuid.UUID, report *model.GeneratedReport) {
	startTime := time.Now()

	// Panic recovery to ensure status is updated even if something goes wrong
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in report generation",
				"report_id", report.ID,
				"tenant_id", tenantID,
				"panic", r,
				"duration_ms", time.Since(startTime).Milliseconds(),
			)
			report.Status = model.ReportStatusFailed
			report.ErrorMessage = fmt.Sprintf("Internal error: %v", r)
			s.reportRepo.UpdateReport(ctx, report)
		}
	}()

	slog.Info("starting report generation",
		"report_id", report.ID,
		"tenant_id", tenantID,
		"report_type", report.ReportType,
		"format", report.Format,
	)

	// Set tenant context for RLS
	if s.tenantRepo != nil {
		s.tenantRepo.SetCurrentTenant(ctx, tenantID)
	}

	// Gather report data
	data, err := s.gatherReportData(ctx, tenantID, report.PeriodStart, report.PeriodEnd)
	if err != nil {
		slog.Error("failed to gather report data",
			"report_id", report.ID,
			"error", err,
		)
		report.Status = model.ReportStatusFailed
		report.ErrorMessage = fmt.Sprintf("Failed to gather data: %v", err)
		s.reportRepo.UpdateReport(ctx, report)
		return
	}

	// Generate file
	var fileData []byte
	switch report.Format {
	case model.ReportFormatPDF:
		fileData, err = s.generatePDF(data)
	case model.ReportFormatXLSX:
		fileData, err = s.generateExcel(data)
	default:
		err = fmt.Errorf("unsupported format: %s", report.Format)
	}

	if err != nil {
		slog.Error("failed to generate report file",
			"report_id", report.ID,
			"format", report.Format,
			"error", err,
		)
		report.Status = model.ReportStatusFailed
		report.ErrorMessage = fmt.Sprintf("Failed to generate file: %v", err)
		s.reportRepo.UpdateReport(ctx, report)
		return
	}

	// Generate filename for reference
	filename := fmt.Sprintf("%s_%s_%s.%s",
		report.ReportType,
		tenantID.String()[:8],
		time.Now().Format("20060102_150405"),
		report.Format,
	)

	// Update report record - store content in database
	now := time.Now()
	report.FilePath = filename // Store filename for reference
	report.FileSize = len(fileData)
	report.FileContent = fileData // Store content in DB
	report.Status = model.ReportStatusCompleted
	report.CompletedAt = &now

	if err := s.reportRepo.UpdateReport(ctx, report); err != nil {
		slog.Error("failed to update report record",
			"report_id", report.ID,
			"error", err,
		)
		return
	}

	slog.Info("report generation completed",
		"report_id", report.ID,
		"file_size", report.FileSize,
		"duration_ms", time.Since(startTime).Milliseconds(),
	)
}

// gatherReportData collects all data needed for the report
func (s *ReportService) gatherReportData(ctx context.Context, tenantID uuid.UUID, start, end time.Time) (*model.ExecutiveReportData, error) {
	data := &model.ExecutiveReportData{
		PeriodStart: start,
		PeriodEnd:   end,
		GeneratedAt: time.Now(),
	}

	// Get dashboard data
	if s.dashboardRepo != nil {
		// Get total projects
		if totalProjects, err := s.dashboardRepo.GetTotalProjects(ctx); err == nil {
			data.Summary.TotalProjects = totalProjects
		}

		// Get total components
		if totalComponents, err := s.dashboardRepo.GetTotalComponents(ctx); err == nil {
			data.Summary.TotalComponents = totalComponents
		}

		// Get vulnerability counts
		if vulnCounts, err := s.dashboardRepo.GetVulnerabilityCounts(ctx); err == nil {
			data.Summary.TotalVulnerabilities = vulnCounts.Critical + vulnCounts.High +
				vulnCounts.Medium + vulnCounts.Low

			data.VulnerabilityData.BySeverity = map[string]int{
				"CRITICAL": vulnCounts.Critical,
				"HIGH":     vulnCounts.High,
				"MEDIUM":   vulnCounts.Medium,
				"LOW":      vulnCounts.Low,
			}
		}

		// Get project scores
		if projectScores, err := s.dashboardRepo.GetProjectScores(ctx); err == nil {
			data.ProjectScores = projectScores
		}

		// Get top risks
		if topRisks, err := s.dashboardRepo.GetTopRisks(ctx, 10); err == nil {
			data.TopRisks = topRisks
		}

		// Get trend data
		if trend, err := s.dashboardRepo.GetTrend(ctx, 30); err == nil {
			for _, t := range trend {
				data.VulnerabilityData.TrendData = append(data.VulnerabilityData.TrendData, model.TrendPoint{
					Date:     t.Date,
					Critical: t.Critical,
					High:     t.High,
					Medium:   t.Medium,
					Low:      t.Low,
				})
			}
		}
	}

	// Get analytics data
	if s.analyticsRepo != nil {
		stats, err := s.analyticsRepo.GetQuickStats(ctx, tenantID)
		if err == nil && stats != nil {
			data.Summary.ResolvedInPeriod = stats.ResolvedLast30Days
			data.Summary.AverageMTTRHours = stats.AverageMTTRHours
			data.Summary.SLOAchievementPct = stats.OverallSLOAchievementPct
			data.Summary.ComplianceScore = stats.CurrentComplianceScore
			data.Summary.ComplianceMaxScore = stats.ComplianceMaxScore
		}
	}

	return data, nil
}

// generatePDF generates a PDF report (simplified implementation)
func (s *ReportService) generatePDF(data *model.ExecutiveReportData) ([]byte, error) {
	// This is a simplified implementation. In production, use maroto or similar library.
	// For now, generate a text-based report as placeholder
	content := fmt.Sprintf(`
SBOMHUB EXECUTIVE REPORT
========================

Period: %s to %s
Generated: %s

SUMMARY
-------
Total Projects: %d
Total Components: %d
Total Vulnerabilities: %d

Resolved in Period: %d
Average MTTR: %.1f hours
SLO Achievement: %.1f%%

VULNERABILITY BREAKDOWN
----------------------
Critical: %d
High: %d
Medium: %d
Low: %d

COMPLIANCE
----------
Score: %d / %d

`,
		data.PeriodStart.Format("2006-01-02"),
		data.PeriodEnd.Format("2006-01-02"),
		data.GeneratedAt.Format("2006-01-02 15:04:05"),
		data.Summary.TotalProjects,
		data.Summary.TotalComponents,
		data.Summary.TotalVulnerabilities,
		data.Summary.ResolvedInPeriod,
		data.Summary.AverageMTTRHours,
		data.Summary.SLOAchievementPct,
		data.VulnerabilityData.BySeverity["CRITICAL"],
		data.VulnerabilityData.BySeverity["HIGH"],
		data.VulnerabilityData.BySeverity["MEDIUM"],
		data.VulnerabilityData.BySeverity["LOW"],
		data.Summary.ComplianceScore,
		data.Summary.ComplianceMaxScore,
	)

	return []byte(content), nil
}

// generateExcel generates an Excel report (simplified implementation)
func (s *ReportService) generateExcel(data *model.ExecutiveReportData) ([]byte, error) {
	// This is a simplified implementation. In production, use excelize library.
	// For now, generate CSV as placeholder
	content := fmt.Sprintf(`Metric,Value
Period Start,%s
Period End,%s
Total Projects,%d
Total Components,%d
Total Vulnerabilities,%d
Critical,%d
High,%d
Medium,%d
Low,%d
Resolved in Period,%d
Average MTTR (hours),%.1f
SLO Achievement (%%),%.1f
Compliance Score,%d/%d
`,
		data.PeriodStart.Format("2006-01-02"),
		data.PeriodEnd.Format("2006-01-02"),
		data.Summary.TotalProjects,
		data.Summary.TotalComponents,
		data.Summary.TotalVulnerabilities,
		data.VulnerabilityData.BySeverity["CRITICAL"],
		data.VulnerabilityData.BySeverity["HIGH"],
		data.VulnerabilityData.BySeverity["MEDIUM"],
		data.VulnerabilityData.BySeverity["LOW"],
		data.Summary.ResolvedInPeriod,
		data.Summary.AverageMTTRHours,
		data.Summary.SLOAchievementPct,
		data.Summary.ComplianceScore, data.Summary.ComplianceMaxScore,
	)

	return []byte(content), nil
}

// GetReport returns a generated report by ID
func (s *ReportService) GetReport(ctx context.Context, tenantID, reportID uuid.UUID) (*model.GeneratedReport, error) {
	return s.reportRepo.GetReport(ctx, tenantID, reportID)
}

// ListReports returns generated reports for a tenant
func (s *ReportService) ListReports(ctx context.Context, tenantID uuid.UUID, page, limit int) ([]model.GeneratedReport, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	return s.reportRepo.ListReports(ctx, tenantID, limit, offset)
}

// GetReportFile returns the file content for a report
func (s *ReportService) GetReportFile(ctx context.Context, tenantID, reportID uuid.UUID) ([]byte, string, error) {
	report, err := s.reportRepo.GetReportWithContent(ctx, tenantID, reportID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get report: %w", err)
	}

	if report.Status != model.ReportStatusCompleted && report.Status != model.ReportStatusEmailed {
		return nil, "", fmt.Errorf("report is not ready: status=%s", report.Status)
	}

	// Return content from database
	if len(report.FileContent) > 0 {
		filename := filepath.Base(report.FilePath)
		return report.FileContent, filename, nil
	}

	// Fallback to file system for old reports
	data, err := os.ReadFile(report.FilePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read file: %w", err)
	}

	filename := filepath.Base(report.FilePath)
	return data, filename, nil
}

func getReportTypeLabel(reportType string) string {
	switch reportType {
	case model.ReportTypeExecutive:
		return "Executive"
	case model.ReportTypeTechnical:
		return "Technical"
	case model.ReportTypeCompliance:
		return "Compliance"
	default:
		return "Report"
	}
}
