package service

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/core/entity"
	"github.com/johnfercher/maroto/v2/pkg/props"
	"github.com/sbomhub/sbomhub/internal/assets"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/xuri/excelize/v2"
)

// ReportService handles report operations
type ReportService struct {
	reportRepo        *repository.ReportRepository
	dashboardRepo     *repository.DashboardRepository
	analyticsRepo     *repository.AnalyticsRepository
	tenantRepo        *repository.TenantRepository
	checklistRepo     *repository.ChecklistRepository
	visualizationRepo *repository.VisualizationRepository
	reportDir         string
}

// NewReportService creates a new ReportService
func NewReportService(
	reportRepo *repository.ReportRepository,
	dashboardRepo *repository.DashboardRepository,
	analyticsRepo *repository.AnalyticsRepository,
	tenantRepo *repository.TenantRepository,
	checklistRepo *repository.ChecklistRepository,
	visualizationRepo *repository.VisualizationRepository,
	reportDir string,
) *ReportService {
	// Ensure report directory exists
	os.MkdirAll(reportDir, 0755)

	return &ReportService{
		reportRepo:        reportRepo,
		dashboardRepo:     dashboardRepo,
		analyticsRepo:     analyticsRepo,
		tenantRepo:        tenantRepo,
		checklistRepo:     checklistRepo,
		visualizationRepo: visualizationRepo,
		reportDir:         reportDir,
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
	// Default locale to Japanese if not specified
	locale := input.Locale
	if locale == "" {
		locale = "ja"
	}

	// Create report record
	report := &model.GeneratedReport{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ReportType:  input.ReportType,
		Format:      input.Format,
		Title:       fmt.Sprintf("%s - %s", getReportTypeLabel(input.ReportType), time.Now().Format("2006-01-02")),
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
	go s.generateReportAsync(context.Background(), tenantID, report, locale)

	return report, nil
}

// generateReportAsync generates the report file asynchronously
func (s *ReportService) generateReportAsync(ctx context.Context, tenantID uuid.UUID, report *model.GeneratedReport, locale string) {
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
		fileData, err = s.generatePDF(data, report.ReportType, locale)
	case model.ReportFormatXLSX:
		fileData, err = s.generateExcel(data, report.ReportType, locale)
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

	// Get checklist data (aggregate across all projects)
	if s.checklistRepo != nil {
		checklistData := s.gatherChecklistData(ctx, tenantID)
		if checklistData != nil {
			data.ChecklistData = checklistData
		}
	}

	// Get visualization data (use first project's settings as representative)
	if s.visualizationRepo != nil {
		vizData := s.gatherVisualizationData(ctx, tenantID)
		if vizData != nil {
			data.VisualizationData = vizData
		}
	}

	return data, nil
}

// gatherChecklistData collects checklist data for the report
func (s *ReportService) gatherChecklistData(ctx context.Context, tenantID uuid.UUID) *model.ChecklistReportData {
	// Get all checklist items definition
	allItems := model.GetAllChecklistItems()
	phaseLabels := model.GetChecklistPhaseLabels()

	// Group items by phase
	phaseItems := make(map[model.ChecklistPhase][]model.ChecklistItem)
	for _, item := range allItems {
		phaseItems[item.Phase] = append(phaseItems[item.Phase], item)
	}

	data := &model.ChecklistReportData{
		Score:    0,
		MaxScore: len(allItems),
	}

	phases := []model.ChecklistPhase{model.PhaseSetup, model.PhaseCreation, model.PhaseOperation}
	for _, phase := range phases {
		items := phaseItems[phase]
		phaseLabel := phaseLabels[phase]

		phaseData := model.ChecklistPhaseReportData{
			Phase:    string(phase),
			LabelJa:  phaseLabel.LabelJa,
			MaxScore: len(items),
		}

		for _, item := range items {
			// For report, just include the item definition
			// In a real implementation, you'd aggregate responses across projects
			itemData := model.ChecklistItemReportData{
				ID:         item.ID,
				LabelJa:    item.LabelJa,
				AutoVerify: item.AutoVerify,
				Passed:     item.AutoVerify, // Auto-verified items are considered passed for now
			}
			if item.AutoVerify {
				phaseData.Score++
				data.Score++
			}
			phaseData.Items = append(phaseData.Items, itemData)
		}

		data.Phases = append(data.Phases, phaseData)
	}

	return data
}

// gatherVisualizationData collects visualization settings for the report
func (s *ReportService) gatherVisualizationData(ctx context.Context, tenantID uuid.UUID) *model.VisualizationReportData {
	// Return default visualization settings for reports
	// In a real implementation, you'd get this from project settings
	return &model.VisualizationReportData{
		SBOMAuthorScope:  "supplier",
		DependencyScope:  "direct",
		GenerationMethod: "auto",
		DataFormat:       "cyclonedx",
		UtilizationScope: []string{"vulnerability", "license"},
		UtilizationActor: "development",
	}
}

// generatePDF generates a PDF report using maroto
func (s *ReportService) generatePDF(data *model.ExecutiveReportData, reportType string, locale string) ([]byte, error) {
	// Get translations
	t := GetTranslations(locale)

	// Load Japanese font from embedded assets (IPA Gothic)
	fontBytes, err := assets.Fonts.ReadFile("fonts/IPAGothic.ttf")
	if err != nil {
		return nil, fmt.Errorf("failed to load font: %w", err)
	}

	cfg := config.NewBuilder().
		WithPageNumber().
		WithLeftMargin(15).
		WithTopMargin(15).
		WithRightMargin(15).
		WithCustomFonts([]*entity.CustomFont{
			{
				Family: "IPAGothic",
				Style:  fontstyle.Normal,
				Bytes:  fontBytes,
			},
			{
				Family: "IPAGothic",
				Style:  fontstyle.Bold,
				Bytes:  fontBytes, // IPA Gothic doesn't have bold variant, use same font
			},
		}).
		WithDefaultFont(&props.Font{Family: "IPAGothic"}).
		Build()

	m := maroto.New(cfg)

	// Title based on report type
	title := s.getReportTitleI18n(reportType, t)
	m.AddRows(s.buildPDFTitle(title))
	m.AddRows(s.buildPDFSubtitle(fmt.Sprintf("%s: %s - %s",
		t.Period,
		data.PeriodStart.Format("2006-01-02"),
		data.PeriodEnd.Format("2006-01-02"))))
	m.AddRows(s.buildPDFSubtitle(fmt.Sprintf("%s: %s",
		t.GeneratedAt,
		data.GeneratedAt.Format("2006-01-02 15:04"))))

	// Generate content based on report type
	switch reportType {
	case model.ReportTypeExecutive:
		s.buildExecutivePDFContent(m, data, t)
	case model.ReportTypeTechnical:
		s.buildTechnicalPDFContent(m, data, t)
	case model.ReportTypeCompliance:
		s.buildCompliancePDFContent(m, data, t)
	default:
		s.buildExecutivePDFContent(m, data, t) // fallback to executive
	}

	// Generate PDF
	doc, err := m.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return doc.GetBytes(), nil
}

// getReportTitle returns the title for a report type (deprecated, use getReportTitleI18n)
func (s *ReportService) getReportTitle(reportType string) string {
	return s.getReportTitleI18n(reportType, GetTranslations("ja"))
}

// getReportTitleI18n returns the localized title for a report type
func (s *ReportService) getReportTitleI18n(reportType string, t *ReportTranslations) string {
	switch reportType {
	case model.ReportTypeExecutive:
		return t.TitleExecutive
	case model.ReportTypeTechnical:
		return t.TitleTechnical
	case model.ReportTypeCompliance:
		return t.TitleCompliance
	default:
		return t.TitleDefault
	}
}

// buildExecutivePDFContent builds content for executive report (summary focused)
func (s *ReportService) buildExecutivePDFContent(m core.Maroto, data *model.ExecutiveReportData, t *ReportTranslations) {
	// Summary Section
	m.AddRows(s.buildPDFSectionHeader(t.Summary))
	m.AddRows(s.buildPDFKeyValue(t.Projects, fmt.Sprintf("%d", data.Summary.TotalProjects)))
	m.AddRows(s.buildPDFKeyValue(t.Components, fmt.Sprintf("%d", data.Summary.TotalComponents)))
	m.AddRows(s.buildPDFKeyValue(t.TotalVulnerabilities, fmt.Sprintf("%d", data.Summary.TotalVulnerabilities)))
	m.AddRows(s.buildPDFKeyValue(t.ResolvedInPeriod, fmt.Sprintf("%d", data.Summary.ResolvedInPeriod)))
	m.AddRows(s.buildPDFKeyValue(t.AverageMTTR, fmt.Sprintf("%.1f %s", data.Summary.AverageMTTRHours, t.Hours)))
	m.AddRows(s.buildPDFKeyValue(t.SLOAchievement, fmt.Sprintf("%.1f%%", data.Summary.SLOAchievementPct)))

	// Vulnerability Summary
	m.AddRows(s.buildPDFSectionHeader(t.VulnerabilityBreakdown))
	m.AddRows(s.buildPDFKeyValue(t.Critical, fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["CRITICAL"])))
	m.AddRows(s.buildPDFKeyValue(t.High, fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["HIGH"])))
	m.AddRows(s.buildPDFKeyValue(t.Medium, fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["MEDIUM"])))
	m.AddRows(s.buildPDFKeyValue(t.Low, fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["LOW"])))

	// Compliance Score
	m.AddRows(s.buildPDFSectionHeader(t.Compliance))
	m.AddRows(s.buildPDFKeyValue(t.Score, fmt.Sprintf("%d / %d",
		data.Summary.ComplianceScore, data.Summary.ComplianceMaxScore)))

	// Top Risks (limited)
	if len(data.TopRisks) > 0 {
		m.AddRows(s.buildPDFSectionHeader(t.TopRisks))
		for i, risk := range data.TopRisks {
			if i >= 5 {
				break
			}
			m.AddRows(s.buildPDFKeyValue(
				fmt.Sprintf("%d. %s", i+1, risk.CVEID),
				fmt.Sprintf("%s - CVSS: %.1f", risk.ProjectName, risk.CVSSScore),
			))
		}
	}
}

// buildTechnicalPDFContent builds content for technical report (detailed vulnerability info)
func (s *ReportService) buildTechnicalPDFContent(m core.Maroto, data *model.ExecutiveReportData, t *ReportTranslations) {
	// Summary Section
	m.AddRows(s.buildPDFSectionHeader(t.Summary))
	m.AddRows(s.buildPDFKeyValue(t.Projects, fmt.Sprintf("%d", data.Summary.TotalProjects)))
	m.AddRows(s.buildPDFKeyValue(t.Components, fmt.Sprintf("%d", data.Summary.TotalComponents)))
	m.AddRows(s.buildPDFKeyValue(t.TotalVulnerabilities, fmt.Sprintf("%d", data.Summary.TotalVulnerabilities)))

	// Detailed Vulnerability Breakdown
	m.AddRows(s.buildPDFSectionHeader(t.VulnerabilityDetailed))
	m.AddRows(s.buildPDFKeyValue(t.CriticalCount, fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["CRITICAL"])))
	m.AddRows(s.buildPDFKeyValue(t.HighCount, fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["HIGH"])))
	m.AddRows(s.buildPDFKeyValue(t.MediumCount, fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["MEDIUM"])))
	m.AddRows(s.buildPDFKeyValue(t.LowCount, fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["LOW"])))

	// Metrics
	m.AddRows(s.buildPDFSectionHeader(t.SecurityMetrics))
	m.AddRows(s.buildPDFKeyValue(t.ResolvedInPeriod, fmt.Sprintf("%d", data.Summary.ResolvedInPeriod)))
	m.AddRows(s.buildPDFKeyValue(t.AverageMTTR, fmt.Sprintf("%.1f %s", data.Summary.AverageMTTRHours, t.Hours)))
	m.AddRows(s.buildPDFKeyValue(t.SLOAchievement, fmt.Sprintf("%.1f%%", data.Summary.SLOAchievementPct)))

	// Extended Top Risks (more details)
	if len(data.TopRisks) > 0 {
		m.AddRows(s.buildPDFSectionHeader(t.TopRisksDetailed))
		for i, risk := range data.TopRisks {
			if i >= 10 {
				break
			}
			m.AddRows(s.buildPDFKeyValue(
				fmt.Sprintf("%d. %s", i+1, risk.CVEID),
				fmt.Sprintf("CVSS: %.1f, EPSS: %.2f%%", risk.CVSSScore, risk.EPSSScore*100),
			))
			m.AddRows(s.buildPDFKeyValue(
				fmt.Sprintf("   %s", t.Project),
				risk.ProjectName,
			))
			m.AddRows(s.buildPDFKeyValue(
				fmt.Sprintf("   %s", t.Component),
				risk.ComponentName,
			))
		}
	}

	// Trend Data Summary
	if len(data.VulnerabilityData.TrendData) > 0 {
		m.AddRows(s.buildPDFSectionHeader(t.VulnerabilityTrend))
		count := len(data.VulnerabilityData.TrendData)
		start := 0
		if count > 7 {
			start = count - 7
		}
		for i := start; i < count; i++ {
			trend := data.VulnerabilityData.TrendData[i]
			total := trend.Critical + trend.High + trend.Medium + trend.Low
			m.AddRows(s.buildPDFKeyValue(
				trend.Date.Format("2006-01-02"),
				fmt.Sprintf("%s: %d (C:%d H:%d M:%d L:%d)",
					t.Total, total, trend.Critical, trend.High, trend.Medium, trend.Low),
			))
		}
	}
}

// buildCompliancePDFContent builds content for compliance report (checklist & framework)
func (s *ReportService) buildCompliancePDFContent(m core.Maroto, data *model.ExecutiveReportData, t *ReportTranslations) {
	// Compliance Score Summary
	m.AddRows(s.buildPDFSectionHeader(t.ComplianceScore))
	m.AddRows(s.buildPDFKeyValue(t.Score, fmt.Sprintf("%d / %d",
		data.Summary.ComplianceScore, data.Summary.ComplianceMaxScore)))
	if data.Summary.ComplianceMaxScore > 0 {
		pct := float64(data.Summary.ComplianceScore) / float64(data.Summary.ComplianceMaxScore) * 100
		m.AddRows(s.buildPDFKeyValue(t.AchievementRate, fmt.Sprintf("%.1f%%", pct)))
	}

	// METI Checklist Section (detailed)
	if data.ChecklistData != nil {
		m.AddRows(s.buildPDFSectionHeader(t.METIChecklist))
		checklistPct := 0.0
		if data.ChecklistData.MaxScore > 0 {
			checklistPct = float64(data.ChecklistData.Score) / float64(data.ChecklistData.MaxScore) * 100
		}
		m.AddRows(s.buildPDFKeyValue(t.TotalProgress, fmt.Sprintf("%d / %d (%.0f%%)",
			data.ChecklistData.Score, data.ChecklistData.MaxScore, checklistPct)))

		// Phase details
		for _, phase := range data.ChecklistData.Phases {
			phasePct := 0.0
			if phase.MaxScore > 0 {
				phasePct = float64(phase.Score) / float64(phase.MaxScore) * 100
			}
			m.AddRows(s.buildPDFKeyValue(
				phase.LabelJa, // Keep phase labels in Japanese (from checklist definition)
				fmt.Sprintf("%d / %d (%.0f%%)", phase.Score, phase.MaxScore, phasePct),
			))

			// Individual items
			for _, item := range phase.Items {
				status := t.NotCompleted
				if item.Passed {
					status = t.Completed
				}
				autoMark := ""
				if item.AutoVerify {
					autoMark = fmt.Sprintf(" [%s]", t.Auto)
				}
				m.AddRows(s.buildPDFKeyValue(
					fmt.Sprintf("  - %s%s", item.LabelJa, autoMark),
					status,
				))
			}
		}
	}

	// Visualization Framework Section (detailed)
	if data.VisualizationData != nil {
		m.AddRows(s.buildPDFSectionHeader(t.VisualizationFramework))
		vizOptions := model.GetVisualizationOptions()

		// (a) SBOM Author
		authorLabel := s.getVisualizationOptionLabel(vizOptions.SBOMAuthorScope, data.VisualizationData.SBOMAuthorScope)
		m.AddRows(s.buildPDFKeyValue(t.VizSBOMAuthor, authorLabel))

		// (b) Dependencies
		depLabel := s.getVisualizationOptionLabel(vizOptions.DependencyScope, data.VisualizationData.DependencyScope)
		m.AddRows(s.buildPDFKeyValue(t.VizDependency, depLabel))

		// (c) Generation Method
		genLabel := s.getVisualizationOptionLabel(vizOptions.GenerationMethod, data.VisualizationData.GenerationMethod)
		m.AddRows(s.buildPDFKeyValue(t.VizGeneration, genLabel))

		// (d) Data Format
		formatLabel := s.getVisualizationOptionLabel(vizOptions.DataFormat, data.VisualizationData.DataFormat)
		m.AddRows(s.buildPDFKeyValue(t.VizDataFormat, formatLabel))

		// (f) Utilization Actor
		actorLabel := s.getVisualizationOptionLabel(vizOptions.UtilizationActor, data.VisualizationData.UtilizationActor)
		m.AddRows(s.buildPDFKeyValue(t.VizUtilization, actorLabel))
	}

	// Basic vulnerability summary for context
	m.AddRows(s.buildPDFSectionHeader(t.VulnerabilitySummary))
	m.AddRows(s.buildPDFKeyValue(t.TotalVulnerabilities, fmt.Sprintf("%d", data.Summary.TotalVulnerabilities)))
	m.AddRows(s.buildPDFKeyValue(t.CriticalHigh, fmt.Sprintf("%d / %d",
		data.VulnerabilityData.BySeverity["CRITICAL"],
		data.VulnerabilityData.BySeverity["HIGH"])))
}

// getVisualizationOptionLabel returns the Japanese label for a visualization option value
func (s *ReportService) getVisualizationOptionLabel(options []model.VisualizationOption, value string) string {
	for _, opt := range options {
		if opt.Value == value {
			return opt.LabelJa
		}
	}
	return value
}

// PDF helper functions
func (s *ReportService) buildPDFTitle(title string) core.Row {
	return row.New(16).Add(
		col.New(12).Add(
			text.New(title, props.Text{
				Size:   20,
				Style:  fontstyle.Bold,
				Align:  align.Center,
				Family: "IPAGothic",
			}),
		),
	)
}

func (s *ReportService) buildPDFSubtitle(subtitle string) core.Row {
	return row.New(8).Add(
		col.New(12).Add(
			text.New(subtitle, props.Text{
				Size:   10,
				Align:  align.Center,
				Color:  &props.Color{Red: 100, Green: 100, Blue: 100},
				Family: "IPAGothic",
			}),
		),
	)
}

func (s *ReportService) buildPDFSectionHeader(header string) core.Row {
	return row.New(14).Add(
		col.New(12).Add(
			text.New(header, props.Text{
				Size:   14,
				Style:  fontstyle.Bold,
				Top:    6,
				Family: "IPAGothic",
			}),
		),
	)
}

func (s *ReportService) buildPDFKeyValue(key, value string) core.Row {
	return row.New(8).Add(
		col.New(6).Add(
			text.New(key, props.Text{
				Size:   10,
				Family: "IPAGothic",
			}),
		),
		col.New(6).Add(
			text.New(value, props.Text{
				Size:   10,
				Align:  align.Right,
				Family: "IPAGothic",
			}),
		),
	)
}

// generateExcel generates an Excel report using excelize
func (s *ReportService) generateExcel(data *model.ExecutiveReportData, reportType string, locale string) ([]byte, error) {
	// Get translations
	t := GetTranslations(locale)

	f := excelize.NewFile()
	defer f.Close()

	// Create Summary sheet with title based on report type
	sheetName := t.SheetSummary
	f.SetSheetName("Sheet1", sheetName)

	// Set column widths
	f.SetColWidth(sheetName, "A", "A", 25)
	f.SetColWidth(sheetName, "B", "B", 30)

	// Header style
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 14, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#4472C4"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	// Title based on report type
	title := s.getReportTitleI18n(reportType, t)
	f.MergeCell(sheetName, "A1", "B1")
	f.SetCellValue(sheetName, "A1", title)
	f.SetCellStyle(sheetName, "A1", "B1", headerStyle)
	f.SetRowHeight(sheetName, 1, 30)

	// Period info
	f.SetCellValue(sheetName, "A2", t.Period)
	f.SetCellValue(sheetName, "B2", fmt.Sprintf("%s - %s",
		data.PeriodStart.Format("2006-01-02"),
		data.PeriodEnd.Format("2006-01-02")))
	f.SetCellValue(sheetName, "A3", t.GeneratedAt)
	f.SetCellValue(sheetName, "B3", data.GeneratedAt.Format("2006-01-02 15:04"))

	// Summary data
	row := 5
	summaryData := [][]interface{}{
		{t.Projects, data.Summary.TotalProjects},
		{t.Components, data.Summary.TotalComponents},
		{t.TotalVulnerabilities, data.Summary.TotalVulnerabilities},
		{t.ResolvedInPeriod, data.Summary.ResolvedInPeriod},
		{fmt.Sprintf("%s (%s)", t.AverageMTTR, t.Hours), fmt.Sprintf("%.1f", data.Summary.AverageMTTRHours)},
		{fmt.Sprintf("%s (%%)", t.SLOAchievement), fmt.Sprintf("%.1f", data.Summary.SLOAchievementPct)},
		{t.ComplianceScore, fmt.Sprintf("%d / %d", data.Summary.ComplianceScore, data.Summary.ComplianceMaxScore)},
	}

	for _, d := range summaryData {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), d[0])
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), d[1])
		row++
	}

	// Vulnerability breakdown
	row += 2
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), t.VulnerabilityBreakdown)
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), headerStyle)
	row++

	vulnData := [][]interface{}{
		{t.Critical, data.VulnerabilityData.BySeverity["CRITICAL"]},
		{t.High, data.VulnerabilityData.BySeverity["HIGH"]},
		{t.Medium, data.VulnerabilityData.BySeverity["MEDIUM"]},
		{t.Low, data.VulnerabilityData.BySeverity["LOW"]},
	}

	for _, d := range vulnData {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), d[0])
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), d[1])
		row++
	}

	// Create Top Risks sheet for Executive and Technical reports
	if len(data.TopRisks) > 0 && (reportType == model.ReportTypeExecutive || reportType == model.ReportTypeTechnical) {
		riskSheet := t.SheetTopRisks
		f.NewSheet(riskSheet)
		f.SetColWidth(riskSheet, "A", "A", 20)
		f.SetColWidth(riskSheet, "B", "B", 25)
		f.SetColWidth(riskSheet, "C", "C", 15)
		f.SetColWidth(riskSheet, "D", "D", 12)
		f.SetColWidth(riskSheet, "E", "E", 12)

		// Headers
		f.SetCellValue(riskSheet, "A1", t.CVEID)
		f.SetCellValue(riskSheet, "B1", t.Project)
		f.SetCellValue(riskSheet, "C1", t.Component)
		f.SetCellValue(riskSheet, "D1", t.CVSS)
		f.SetCellValue(riskSheet, "E1", t.EPSS)

		for i, risk := range data.TopRisks {
			row := i + 2
			f.SetCellValue(riskSheet, fmt.Sprintf("A%d", row), risk.CVEID)
			f.SetCellValue(riskSheet, fmt.Sprintf("B%d", row), risk.ProjectName)
			f.SetCellValue(riskSheet, fmt.Sprintf("C%d", row), risk.ComponentName)
			f.SetCellValue(riskSheet, fmt.Sprintf("D%d", row), risk.CVSSScore)
			f.SetCellValue(riskSheet, fmt.Sprintf("E%d", row), fmt.Sprintf("%.2f%%", risk.EPSSScore*100))
		}
	}

	// Create Trend sheet for Technical reports only
	if len(data.VulnerabilityData.TrendData) > 0 && reportType == model.ReportTypeTechnical {
		trendSheet := t.SheetTrend
		f.NewSheet(trendSheet)
		f.SetColWidth(trendSheet, "A", "A", 15)
		f.SetColWidth(trendSheet, "B", "E", 12)

		// Headers
		f.SetCellValue(trendSheet, "A1", t.Date)
		f.SetCellValue(trendSheet, "B1", t.Critical)
		f.SetCellValue(trendSheet, "C1", t.High)
		f.SetCellValue(trendSheet, "D1", t.Medium)
		f.SetCellValue(trendSheet, "E1", t.Low)

		for i, trend := range data.VulnerabilityData.TrendData {
			row := i + 2
			f.SetCellValue(trendSheet, fmt.Sprintf("A%d", row), trend.Date)
			f.SetCellValue(trendSheet, fmt.Sprintf("B%d", row), trend.Critical)
			f.SetCellValue(trendSheet, fmt.Sprintf("C%d", row), trend.High)
			f.SetCellValue(trendSheet, fmt.Sprintf("D%d", row), trend.Medium)
			f.SetCellValue(trendSheet, fmt.Sprintf("E%d", row), trend.Low)
		}
	}

	// Create METI Checklist sheet for Compliance reports only
	if data.ChecklistData != nil && reportType == model.ReportTypeCompliance {
		checklistSheet := t.SheetChecklist
		f.NewSheet(checklistSheet)
		f.SetColWidth(checklistSheet, "A", "A", 15)
		f.SetColWidth(checklistSheet, "B", "B", 40)
		f.SetColWidth(checklistSheet, "C", "C", 12)
		f.SetColWidth(checklistSheet, "D", "D", 12)
		f.SetColWidth(checklistSheet, "E", "E", 30)

		// Title
		f.MergeCell(checklistSheet, "A1", "E1")
		f.SetCellValue(checklistSheet, "A1", t.METIChecklist)
		f.SetCellStyle(checklistSheet, "A1", "E1", headerStyle)
		f.SetRowHeight(checklistSheet, 1, 25)

		// Summary
		checklistPct := 0.0
		if data.ChecklistData.MaxScore > 0 {
			checklistPct = float64(data.ChecklistData.Score) / float64(data.ChecklistData.MaxScore) * 100
		}
		f.SetCellValue(checklistSheet, "A2", t.TotalProgress)
		f.SetCellValue(checklistSheet, "B2", fmt.Sprintf("%d / %d (%.0f%%)",
			data.ChecklistData.Score, data.ChecklistData.MaxScore, checklistPct))

		// Headers
		row := 4
		f.SetCellValue(checklistSheet, fmt.Sprintf("A%d", row), t.Phase)
		f.SetCellValue(checklistSheet, fmt.Sprintf("B%d", row), t.Item)
		f.SetCellValue(checklistSheet, fmt.Sprintf("C%d", row), t.AutoVerify)
		f.SetCellValue(checklistSheet, fmt.Sprintf("D%d", row), t.Status)
		f.SetCellValue(checklistSheet, fmt.Sprintf("E%d", row), t.Notes)
		row++

		// Checklist items by phase
		for _, phase := range data.ChecklistData.Phases {
			for i, item := range phase.Items {
				f.SetCellValue(checklistSheet, fmt.Sprintf("A%d", row), func() string {
					if i == 0 {
						return phase.LabelJa
					}
					return ""
				}())
				f.SetCellValue(checklistSheet, fmt.Sprintf("B%d", row), item.LabelJa)
				f.SetCellValue(checklistSheet, fmt.Sprintf("C%d", row), func() string {
					if item.AutoVerify {
						return "○"
					}
					return "-"
				}())
				f.SetCellValue(checklistSheet, fmt.Sprintf("D%d", row), func() string {
					if item.Passed {
						return t.Completed
					}
					return t.NotCompleted
				}())
				f.SetCellValue(checklistSheet, fmt.Sprintf("E%d", row), item.Note)
				row++
			}
		}
	}

	// Create Visualization Framework sheet for Compliance reports only
	if data.VisualizationData != nil && reportType == model.ReportTypeCompliance {
		vizSheet := t.SheetVisualization
		f.NewSheet(vizSheet)
		f.SetColWidth(vizSheet, "A", "A", 25)
		f.SetColWidth(vizSheet, "B", "B", 35)
		f.SetColWidth(vizSheet, "C", "C", 35)

		// Title
		f.MergeCell(vizSheet, "A1", "C1")
		f.SetCellValue(vizSheet, "A1", t.VisualizationFramework)
		f.SetCellStyle(vizSheet, "A1", "C1", headerStyle)
		f.SetRowHeight(vizSheet, 1, 25)

		// Headers
		f.SetCellValue(vizSheet, "A3", t.Perspective)
		f.SetCellValue(vizSheet, "B3", t.Setting)
		f.SetCellValue(vizSheet, "C3", t.Description)

		vizOptions := model.GetVisualizationOptions()

		// (a) SBOM Author
		row := 4
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizSBOMAuthor)
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.SBOMAuthorScope, data.VisualizationData.SBOMAuthorScope))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizSBOMAuthorDesc)
		row++

		// (b) Dependencies
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizDependency)
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.DependencyScope, data.VisualizationData.DependencyScope))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizDependencyDesc)
		row++

		// (c) Generation Method
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizGeneration)
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.GenerationMethod, data.VisualizationData.GenerationMethod))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizGenerationDesc)
		row++

		// (d) Data Format
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizDataFormat)
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.DataFormat, data.VisualizationData.DataFormat))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizDataFormatDesc)
		row++

		// (e) Utilization Scope - skip for now as it's complex
		row++

		// (f) Utilization Actor
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizUtilization)
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.UtilizationActor, data.VisualizationData.UtilizationActor))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizUtilizationDesc)
	}

	// Write to buffer
	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		return nil, fmt.Errorf("failed to write Excel: %w", err)
	}

	return buf.Bytes(), nil
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
