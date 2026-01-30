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
func (s *ReportService) generatePDF(data *model.ExecutiveReportData) ([]byte, error) {
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

	// Title
	m.AddRows(s.buildPDFTitle("SBOMHub セキュリティレポート"))
	m.AddRows(s.buildPDFSubtitle(fmt.Sprintf("期間: %s 〜 %s",
		data.PeriodStart.Format("2006-01-02"),
		data.PeriodEnd.Format("2006-01-02"))))
	m.AddRows(s.buildPDFSubtitle(fmt.Sprintf("生成日時: %s",
		data.GeneratedAt.Format("2006-01-02 15:04"))))

	// Summary Section
	m.AddRows(s.buildPDFSectionHeader("サマリー"))
	m.AddRows(s.buildPDFKeyValue("プロジェクト数", fmt.Sprintf("%d", data.Summary.TotalProjects)))
	m.AddRows(s.buildPDFKeyValue("コンポーネント数", fmt.Sprintf("%d", data.Summary.TotalComponents)))
	m.AddRows(s.buildPDFKeyValue("脆弱性総数", fmt.Sprintf("%d", data.Summary.TotalVulnerabilities)))
	m.AddRows(s.buildPDFKeyValue("期間内解決数", fmt.Sprintf("%d", data.Summary.ResolvedInPeriod)))
	m.AddRows(s.buildPDFKeyValue("平均MTTR", fmt.Sprintf("%.1f時間", data.Summary.AverageMTTRHours)))
	m.AddRows(s.buildPDFKeyValue("SLO達成率", fmt.Sprintf("%.1f%%", data.Summary.SLOAchievementPct)))

	// Vulnerability Section
	m.AddRows(s.buildPDFSectionHeader("脆弱性内訳"))
	m.AddRows(s.buildPDFKeyValue("Critical", fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["CRITICAL"])))
	m.AddRows(s.buildPDFKeyValue("High", fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["HIGH"])))
	m.AddRows(s.buildPDFKeyValue("Medium", fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["MEDIUM"])))
	m.AddRows(s.buildPDFKeyValue("Low", fmt.Sprintf("%d", data.VulnerabilityData.BySeverity["LOW"])))

	// Compliance Section
	m.AddRows(s.buildPDFSectionHeader("コンプライアンス"))
	m.AddRows(s.buildPDFKeyValue("スコア", fmt.Sprintf("%d / %d",
		data.Summary.ComplianceScore, data.Summary.ComplianceMaxScore)))

	// Top Risks Section
	if len(data.TopRisks) > 0 {
		m.AddRows(s.buildPDFSectionHeader("TOP リスク"))
		for i, risk := range data.TopRisks {
			if i >= 5 {
				break
			}
			m.AddRows(s.buildPDFKeyValue(
				fmt.Sprintf("%d. %s", i+1, risk.CVEID),
				fmt.Sprintf("%s - CVSS: %.1f, EPSS: %.2f%%",
					risk.ProjectName, risk.CVSSScore, risk.EPSSScore*100),
			))
		}
	}

	// METI Checklist Section
	if data.ChecklistData != nil {
		m.AddRows(s.buildPDFSectionHeader("経産省ガイドライン チェックリスト"))
		checklistPct := 0.0
		if data.ChecklistData.MaxScore > 0 {
			checklistPct = float64(data.ChecklistData.Score) / float64(data.ChecklistData.MaxScore) * 100
		}
		m.AddRows(s.buildPDFKeyValue("進捗", fmt.Sprintf("%d / %d (%.0f%%)",
			data.ChecklistData.Score, data.ChecklistData.MaxScore, checklistPct)))

		for _, phase := range data.ChecklistData.Phases {
			phasePct := 0.0
			if phase.MaxScore > 0 {
				phasePct = float64(phase.Score) / float64(phase.MaxScore) * 100
			}
			m.AddRows(s.buildPDFKeyValue(
				fmt.Sprintf("  %s", phase.LabelJa),
				fmt.Sprintf("%d / %d (%.0f%%)", phase.Score, phase.MaxScore, phasePct),
			))
		}
	}

	// Visualization Framework Section
	if data.VisualizationData != nil {
		m.AddRows(s.buildPDFSectionHeader("SBOM可視化フレームワーク"))
		vizOptions := model.GetVisualizationOptions()

		// (a) SBOM作成主体
		authorLabel := s.getVisualizationOptionLabel(vizOptions.SBOMAuthorScope, data.VisualizationData.SBOMAuthorScope)
		m.AddRows(s.buildPDFKeyValue("SBOM作成主体", authorLabel))

		// (b) 依存関係
		depLabel := s.getVisualizationOptionLabel(vizOptions.DependencyScope, data.VisualizationData.DependencyScope)
		m.AddRows(s.buildPDFKeyValue("依存関係", depLabel))

		// (c) 生成手段
		genLabel := s.getVisualizationOptionLabel(vizOptions.GenerationMethod, data.VisualizationData.GenerationMethod)
		m.AddRows(s.buildPDFKeyValue("生成手段", genLabel))

		// (d) データ様式
		formatLabel := s.getVisualizationOptionLabel(vizOptions.DataFormat, data.VisualizationData.DataFormat)
		m.AddRows(s.buildPDFKeyValue("データ様式", formatLabel))

		// (f) 活用主体
		actorLabel := s.getVisualizationOptionLabel(vizOptions.UtilizationActor, data.VisualizationData.UtilizationActor)
		m.AddRows(s.buildPDFKeyValue("活用主体", actorLabel))
	}

	// Generate PDF
	doc, err := m.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return doc.GetBytes(), nil
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
func (s *ReportService) generateExcel(data *model.ExecutiveReportData) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	// Create Summary sheet
	sheetName := "サマリー"
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

	// Title
	f.MergeCell(sheetName, "A1", "B1")
	f.SetCellValue(sheetName, "A1", "SBOMHub セキュリティレポート")
	f.SetCellStyle(sheetName, "A1", "B1", headerStyle)
	f.SetRowHeight(sheetName, 1, 30)

	// Period info
	f.SetCellValue(sheetName, "A2", "期間")
	f.SetCellValue(sheetName, "B2", fmt.Sprintf("%s 〜 %s",
		data.PeriodStart.Format("2006-01-02"),
		data.PeriodEnd.Format("2006-01-02")))
	f.SetCellValue(sheetName, "A3", "生成日時")
	f.SetCellValue(sheetName, "B3", data.GeneratedAt.Format("2006-01-02 15:04"))

	// Summary data
	row := 5
	summaryData := [][]interface{}{
		{"プロジェクト数", data.Summary.TotalProjects},
		{"コンポーネント数", data.Summary.TotalComponents},
		{"脆弱性総数", data.Summary.TotalVulnerabilities},
		{"期間内解決数", data.Summary.ResolvedInPeriod},
		{"平均MTTR (時間)", fmt.Sprintf("%.1f", data.Summary.AverageMTTRHours)},
		{"SLO達成率 (%)", fmt.Sprintf("%.1f", data.Summary.SLOAchievementPct)},
		{"コンプライアンススコア", fmt.Sprintf("%d / %d", data.Summary.ComplianceScore, data.Summary.ComplianceMaxScore)},
	}

	for _, d := range summaryData {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), d[0])
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), d[1])
		row++
	}

	// Vulnerability breakdown
	row += 2
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "脆弱性内訳")
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), headerStyle)
	row++

	vulnData := [][]interface{}{
		{"Critical", data.VulnerabilityData.BySeverity["CRITICAL"]},
		{"High", data.VulnerabilityData.BySeverity["HIGH"]},
		{"Medium", data.VulnerabilityData.BySeverity["MEDIUM"]},
		{"Low", data.VulnerabilityData.BySeverity["LOW"]},
	}

	for _, d := range vulnData {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), d[0])
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), d[1])
		row++
	}

	// Create Top Risks sheet if data exists
	if len(data.TopRisks) > 0 {
		riskSheet := "TOPリスク"
		f.NewSheet(riskSheet)
		f.SetColWidth(riskSheet, "A", "A", 20)
		f.SetColWidth(riskSheet, "B", "B", 25)
		f.SetColWidth(riskSheet, "C", "C", 15)
		f.SetColWidth(riskSheet, "D", "D", 12)
		f.SetColWidth(riskSheet, "E", "E", 12)

		// Headers
		f.SetCellValue(riskSheet, "A1", "CVE ID")
		f.SetCellValue(riskSheet, "B1", "プロジェクト")
		f.SetCellValue(riskSheet, "C1", "コンポーネント")
		f.SetCellValue(riskSheet, "D1", "CVSS")
		f.SetCellValue(riskSheet, "E1", "EPSS")

		for i, risk := range data.TopRisks {
			row := i + 2
			f.SetCellValue(riskSheet, fmt.Sprintf("A%d", row), risk.CVEID)
			f.SetCellValue(riskSheet, fmt.Sprintf("B%d", row), risk.ProjectName)
			f.SetCellValue(riskSheet, fmt.Sprintf("C%d", row), risk.ComponentName)
			f.SetCellValue(riskSheet, fmt.Sprintf("D%d", row), risk.CVSSScore)
			f.SetCellValue(riskSheet, fmt.Sprintf("E%d", row), fmt.Sprintf("%.2f%%", risk.EPSSScore*100))
		}
	}

	// Create Trend sheet if data exists
	if len(data.VulnerabilityData.TrendData) > 0 {
		trendSheet := "トレンド"
		f.NewSheet(trendSheet)
		f.SetColWidth(trendSheet, "A", "A", 15)
		f.SetColWidth(trendSheet, "B", "E", 12)

		// Headers
		f.SetCellValue(trendSheet, "A1", "日付")
		f.SetCellValue(trendSheet, "B1", "Critical")
		f.SetCellValue(trendSheet, "C1", "High")
		f.SetCellValue(trendSheet, "D1", "Medium")
		f.SetCellValue(trendSheet, "E1", "Low")

		for i, trend := range data.VulnerabilityData.TrendData {
			row := i + 2
			f.SetCellValue(trendSheet, fmt.Sprintf("A%d", row), trend.Date)
			f.SetCellValue(trendSheet, fmt.Sprintf("B%d", row), trend.Critical)
			f.SetCellValue(trendSheet, fmt.Sprintf("C%d", row), trend.High)
			f.SetCellValue(trendSheet, fmt.Sprintf("D%d", row), trend.Medium)
			f.SetCellValue(trendSheet, fmt.Sprintf("E%d", row), trend.Low)
		}
	}

	// Create METI Checklist sheet if data exists
	if data.ChecklistData != nil {
		checklistSheet := "チェックリスト"
		f.NewSheet(checklistSheet)
		f.SetColWidth(checklistSheet, "A", "A", 15)
		f.SetColWidth(checklistSheet, "B", "B", 40)
		f.SetColWidth(checklistSheet, "C", "C", 12)
		f.SetColWidth(checklistSheet, "D", "D", 12)
		f.SetColWidth(checklistSheet, "E", "E", 30)

		// Title
		f.MergeCell(checklistSheet, "A1", "E1")
		f.SetCellValue(checklistSheet, "A1", "経産省SBOMガイドライン チェックリスト")
		f.SetCellStyle(checklistSheet, "A1", "E1", headerStyle)
		f.SetRowHeight(checklistSheet, 1, 25)

		// Summary
		checklistPct := 0.0
		if data.ChecklistData.MaxScore > 0 {
			checklistPct = float64(data.ChecklistData.Score) / float64(data.ChecklistData.MaxScore) * 100
		}
		f.SetCellValue(checklistSheet, "A2", "進捗")
		f.SetCellValue(checklistSheet, "B2", fmt.Sprintf("%d / %d (%.0f%%)",
			data.ChecklistData.Score, data.ChecklistData.MaxScore, checklistPct))

		// Headers
		row := 4
		f.SetCellValue(checklistSheet, fmt.Sprintf("A%d", row), "フェーズ")
		f.SetCellValue(checklistSheet, fmt.Sprintf("B%d", row), "項目")
		f.SetCellValue(checklistSheet, fmt.Sprintf("C%d", row), "自動検証")
		f.SetCellValue(checklistSheet, fmt.Sprintf("D%d", row), "状態")
		f.SetCellValue(checklistSheet, fmt.Sprintf("E%d", row), "備考")
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
						return "完了"
					}
					return "未完了"
				}())
				f.SetCellValue(checklistSheet, fmt.Sprintf("E%d", row), item.Note)
				row++
			}
		}
	}

	// Create Visualization Framework sheet if data exists
	if data.VisualizationData != nil {
		vizSheet := "可視化フレームワーク"
		f.NewSheet(vizSheet)
		f.SetColWidth(vizSheet, "A", "A", 25)
		f.SetColWidth(vizSheet, "B", "B", 35)
		f.SetColWidth(vizSheet, "C", "C", 35)

		// Title
		f.MergeCell(vizSheet, "A1", "C1")
		f.SetCellValue(vizSheet, "A1", "SBOM可視化フレームワーク設定")
		f.SetCellStyle(vizSheet, "A1", "C1", headerStyle)
		f.SetRowHeight(vizSheet, 1, 25)

		// Headers
		f.SetCellValue(vizSheet, "A3", "観点")
		f.SetCellValue(vizSheet, "B3", "設定値")
		f.SetCellValue(vizSheet, "C3", "説明")

		vizOptions := model.GetVisualizationOptions()

		// (a) SBOM作成主体
		row := 4
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), "(a) SBOM作成主体 (Who)")
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.SBOMAuthorScope, data.VisualizationData.SBOMAuthorScope))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), "SBOMを作成する主体")
		row++

		// (b) 依存関係
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), "(b) 依存関係 (What, Where)")
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.DependencyScope, data.VisualizationData.DependencyScope))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), "SBOMに含める依存関係の範囲")
		row++

		// (c) 生成手段
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), "(c) 生成手段 (How)")
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.GenerationMethod, data.VisualizationData.GenerationMethod))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), "SBOMの生成方法")
		row++

		// (d) データ様式
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), "(d) データ様式 (What)")
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.DataFormat, data.VisualizationData.DataFormat))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), "SBOMのデータ形式")
		row++

		// (e) 活用範囲
		scopeLabels := []string{}
		for _, scope := range data.VisualizationData.UtilizationScope {
			scopeLabels = append(scopeLabels,
				s.getVisualizationOptionLabel(vizOptions.UtilizationScope, scope))
		}
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), "(e) 活用範囲 (Why)")
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row), fmt.Sprintf("%v", scopeLabels))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), "SBOMの活用目的")
		row++

		// (f) 活用主体
		f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), "(f) 活用主体 (Who)")
		f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.UtilizationActor, data.VisualizationData.UtilizationActor))
		f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), "SBOMを活用する主体")
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
