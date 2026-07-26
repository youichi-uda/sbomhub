package service

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/sbomhub/sbomhub/internal/database"
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
	// db is the raw *sql.DB handle used by background goroutines (notably
	// generateReportAsync) to open their own tenant-scoped transactions via
	// database.WithTxFunc. Request-driven paths do NOT use this field — they
	// inherit the middleware-opened tx through ctx.
	//
	// Why this exists (codex-r5 P2):
	//   GenerateReport persists a "generating" row inside the caller's tenant
	//   tx, then hands back a launcher that the caller invokes after commit
	//   to spawn generateReportAsync (codex-r6 P1). By the time the goroutine
	//   wakes up the parent tx has long committed, so the ctx it inherits
	//   carries no tenant_id GUC. Without opening a new tenant tx here,
	//   repository.q(ctx) degrades to a raw pool connection,
	//   `app.current_tenant_id` is unset, the RLS UPDATE on generated_reports
	//   silently matches 0 rows, and the report sticks at "generating"
	//   forever with no file content saved.
	db        *sql.DB
	reportDir string
}

// NewReportService creates a new ReportService.
//
// Note: this constructor does NOT take *sql.DB to keep the signature
// (and therefore the cmd/server/main.go wiring, which is a settled
// "DO NOT touch" file in the codex review queue) stable. The db handle
// needed by generateReportAsync is injected later via SetDB — in
// practice from NewReportGenerationJob[Full] during scheduler init,
// which runs before HTTP serving starts. See SetDB for details.
func NewReportService(
	reportRepo *repository.ReportRepository,
	dashboardRepo *repository.DashboardRepository,
	analyticsRepo *repository.AnalyticsRepository,
	tenantRepo *repository.TenantRepository,
	checklistRepo *repository.ChecklistRepository,
	visualizationRepo *repository.VisualizationRepository,
	reportDir string,
) *ReportService {
	// Ensure report directory exists. The constructor deliberately cannot
	// return an error (its signature is settled — see doc comment above), so
	// a mkdir failure is logged loudly instead of silently discarded
	// (errcheck, M46 Track C-3a). Report bytes are persisted in the DB
	// (GeneratedReport.FileContent); the directory only backs the legacy
	// filesystem fallback in GetReportFile, so failing to create it must not
	// prevent service construction.
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		slog.Error("failed to create report directory", "dir", reportDir, "error", err)
	}

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

// SetDB attaches the raw *sql.DB handle used by background goroutines to open
// their own tenant-scoped transactions (see ReportService.db doc comment for
// the full why).
//
// This is called from scheduler.NewReportGenerationJob[Full] so that both the
// HTTP-driven path (handler -> GenerateReport -> generateReportAsync) and the
// scheduler-driven path see the same db wiring. Calling it more than once is
// idempotent — the last db wins. Calling it with a nil db is a no-op so we
// never accidentally tear down a previously-attached handle.
func (s *ReportService) SetDB(db *sql.DB) {
	if db == nil {
		return
	}
	s.db = db
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

// GenerateReport persists the initial `generating` report row inside the
// caller's tenant transaction and returns a launcher closure that starts the
// background PDF/XLSX build. The launcher MUST be invoked AFTER the caller's
// transaction commits — typically via middleware.RegisterPostCommit on the
// HTTP path, or right after runWithTenantTx returns on the scheduler path.
//
// codex-r6 P1: previously this method spawned generateReportAsync inline with
// `go ...` before returning. The goroutine opens its own tenant tx to issue
// the terminal UpdateReport (codex-r5 P2), but it raced the caller's tx
// commit on fast generators: if UpdateReport landed before the CreateReport
// INSERT became visible to other transactions, UPDATE matched 0 rows.
// ReportRepository.UpdateReport does not check rows affected, so the failure
// was silent — the report stuck at "generating" with the UI showing
// "generating now..." forever. Deferring the launch until the parent tx has
// committed makes the INSERT visible before the launcher's UpdateReport
// looks for it.
//
// A non-nil launcher is returned together with a non-nil report on success.
// On error both report and launcher are nil so the caller does not have to
// nil-check the launcher before invoking it (RegisterPostCommit is itself
// nil-safe, but the scheduler path calls launcher() directly).
func (s *ReportService) GenerateReport(ctx context.Context, tenantID, userID uuid.UUID, input model.GenerateReportInput) (*model.GeneratedReport, func(), error) {
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
		return nil, nil, fmt.Errorf("failed to create report record: %w", err)
	}

	// tenantID/report/locale are captured explicitly so the launcher (and
	// the goroutine it spawns) do not depend on the caller's request ctx —
	// that ctx carries the parent tx, which will commit and release its
	// connection before the goroutine runs. The goroutine opens its own
	// tenant-scoped tx via runWithTenantTx for the terminal UpdateReport.
	launcher := func() {
		go s.generateReportAsync(tenantID, report, locale)
	}

	return report, launcher, nil
}

// generateReportAsync generates the report file asynchronously.
//
// This runs on a goroutine spawned by GenerateReport. The caller's tenant
// transaction has already committed by the time we wake up, so we MUST open
// our own tenant-scoped transaction to do anything against RLS-bound tables
// — both the data-gathering reads (projects / dashboard / analytics views
// joined on tenant_id) and the terminal UpdateReport.
//
// codex-r5 P2: previously this function used context.Background() and relied
// on the now-noop tenantRepo.SetCurrentTenant call. Because
// `set_config(..., is_local=true)` only takes effect inside a transaction,
// the GUC was never actually set on the pool connection serving UpdateReport,
// and RLS WITH CHECK rejected every UPDATE — leaving the report stuck at
// "generating" with no file content saved.
func (s *ReportService) generateReportAsync(tenantID uuid.UUID, report *model.GeneratedReport, locale string) {
	startTime := time.Now()
	ctx := context.Background()

	// Panic recovery: even on panic we still try to record "failed". The
	// generation tx (if any) has already been rolled back and re-raised by
	// WithTxFunc by the time we land here, so the status-update goes in its
	// own fresh tenant tx via markReportFailed.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in report generation",
				"report_id", report.ID,
				"tenant_id", tenantID,
				"panic", r,
				"duration_ms", time.Since(startTime).Milliseconds(),
			)
			// F445: the panic value is logged above; GeneratedReport.ErrorMessage
			// is returned to clients, so persist a generic message only.
			s.markReportFailed(ctx, tenantID, report, "report generation failed")
		}
	}()

	slog.Info("starting report generation",
		"report_id", report.ID,
		"tenant_id", tenantID,
		"report_type", report.ReportType,
		"format", report.Format,
	)

	err := s.runWithTenantTx(ctx, tenantID, func(txCtx context.Context) error {
		return s.runReportGeneration(txCtx, tenantID, report, locale)
	})
	if err != nil {
		slog.Error("report generation failed",
			"report_id", report.ID,
			"tenant_id", tenantID,
			"error", err,
			"duration_ms", time.Since(startTime).Milliseconds(),
		)
		// Generation tx rolled back. Record the failure in its own fresh
		// tenant tx so the row reflects "failed" instead of staying
		// "generating" forever. F445: the raw err is logged above;
		// GeneratedReport.ErrorMessage is returned to clients, so persist a
		// generic message only.
		s.markReportFailed(ctx, tenantID, report, "report generation failed")
		return
	}

	slog.Info("report generation completed",
		"report_id", report.ID,
		"file_size", report.FileSize,
		"duration_ms", time.Since(startTime).Milliseconds(),
	)
}

// runReportGeneration is the body of generateReportAsync that runs inside a
// tenant-scoped tx (txCtx carries it). It gathers data, renders the file, and
// writes the terminal UpdateReport — all three need RLS context to see /
// update the right tenant's rows.
//
// Returning an error here causes WithTxFunc to roll back; the caller
// (generateReportAsync) will then open a separate tenant tx via
// markReportFailed to persist the "failed" status.
//
// Trade-off (acknowledged in the codex-r5 task): the tx is held for the full
// duration of file IO + PDF/XLSX rendering, which can be several seconds.
// This mirrors the existing ScanService background scan pattern (R1-1b) and
// is acceptable for current report volumes.
//
// TODO(perf): revisit if parallel report generation ever ramps up to the
// point of saturating the connection pool. Verified 2026-07-02 (M24-3
// F350): the tx still spans gatherReportData + PDF/XLSX rendering + the
// terminal UpdateReport, so each in-flight generation pins one pooled
// connection for the full render duration.
func (s *ReportService) runReportGeneration(txCtx context.Context, tenantID uuid.UUID, report *model.GeneratedReport, locale string) error {
	// Gather report data (RLS-bound reads via repos that pick up the tx
	// through database.Querier). gatherReportData never fails by design —
	// see its doc comment — so there is no error branch here (unparam,
	// M46 Track C-3a).
	data := s.gatherReportData(txCtx, tenantID, report.PeriodStart, report.PeriodEnd)

	// Generate file
	var fileData []byte
	var err error
	switch report.Format {
	case model.ReportFormatPDF:
		fileData, err = s.generatePDF(data, report.ReportType, locale)
	case model.ReportFormatXLSX:
		fileData, err = s.generateExcel(data, report.ReportType, locale)
	default:
		err = fmt.Errorf("unsupported format: %s", report.Format)
	}
	if err != nil {
		return fmt.Errorf("generate report file: %w", err)
	}

	// Generate filename for reference
	filename := fmt.Sprintf("%s_%s_%s.%s",
		report.ReportType,
		tenantID.String()[:8],
		time.Now().Format("20060102_150405"),
		report.Format,
	)

	// Stamp success fields and write the terminal UPDATE inside the same
	// tenant tx so RLS WITH CHECK passes and the row flips from "generating"
	// to "completed" atomically with the content bytes.
	now := time.Now()
	report.FilePath = filename
	report.FileSize = len(fileData)
	report.FileContent = fileData
	report.Status = model.ReportStatusCompleted
	report.CompletedAt = &now

	if err := s.reportRepo.UpdateReport(txCtx, report); err != nil {
		return fmt.Errorf("update report record: %w", err)
	}
	return nil
}

// markReportFailed records a generation failure (panic or error path) by
// running UpdateReport inside its own fresh tenant tx. This is a second-best
// effort — if it also fails we log loudly but cannot do more without
// risking infinite recursion.
func (s *ReportService) markReportFailed(ctx context.Context, tenantID uuid.UUID, report *model.GeneratedReport, errMsg string) {
	report.Status = model.ReportStatusFailed
	report.ErrorMessage = errMsg
	if updErr := s.runWithTenantTx(ctx, tenantID, func(txCtx context.Context) error {
		return s.reportRepo.UpdateReport(txCtx, report)
	}); updErr != nil {
		slog.Error("failed to mark report as failed",
			"report_id", report.ID,
			"tenant_id", tenantID,
			"original_error", errMsg,
			"update_error", updErr,
		)
	}
}

// runWithTenantTx opens a fresh transaction on s.db, pins
// `app.current_tenant_id` to tenantID for the duration of that tx, and runs
// fn with a ctx that carries the tx via database.WithTx. This mirrors
// scheduler.runWithTenantTx — the two could be unified later, but keeping a
// private copy here keeps the codex-r5 fix scope-local and the
// scheduler.runWithTenantTx untouched (it is referenced from multiple
// "DO NOT touch" files).
//
// `is_local=true` scopes the GUC to the transaction only, so once the tx
// commits or rolls back the pooled connection returns to the pool with no
// tenant residue.
func (s *ReportService) runWithTenantTx(ctx context.Context, tenantID uuid.UUID, fn func(txCtx context.Context) error) error {
	if s.db == nil {
		return fmt.Errorf("report service: db handle is nil; cannot open tenant-scoped tx")
	}
	return database.WithTxFunc(ctx, s.db, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(
			txCtx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); err != nil {
			return fmt.Errorf("set tenant context for %s: %w", tenantID, err)
		}
		return fn(txCtx)
	})
}

// gatherReportData collects all data needed for the report.
//
// It is deliberately infallible (M46 Track C-3a, unparam): per the M41 (F461)
// design below, every failing section read is logged at WARN and leaves its
// section empty rather than failing the whole report, so the previous
// `(*model.ExecutiveReportData, error)` signature returned a literally
// always-nil error and the caller's error branch was dead code. Removing the
// return changes NO behavior — failures were already folded into
// warn-and-degrade before this cleanup. If a hard-fail semantic is ever
// wanted (e.g. "no report is better than a zero-filled report"), reintroduce
// the error return and make each section read propagate instead of degrade —
// do not bolt error handling onto this signature piecemeal.
func (s *ReportService) gatherReportData(ctx context.Context, tenantID uuid.UUID, start, end time.Time) *model.ExecutiveReportData {
	data := &model.ExecutiveReportData{
		PeriodStart: start,
		PeriodEnd:   end,
		GeneratedAt: time.Now(),
	}

	// Get dashboard data.
	//
	// M41 (F460): these MUST use the tenant-scoped *ByTenant variants. The
	// non-tenant GetTotal*/GetVulnerabilityCounts/GetProjectScores/GetTopRisks/
	// GetTrend methods were always-error deprecated stubs, so the old
	// `err == nil { assign }` guards silently never fired and every report
	// shipped with Summary counts = 0, an empty severity breakdown and no Top
	// Risks / Project Scores / Trend. tenantID is already set on the RLS GUC by
	// runWithTenantTx, so the *ByTenant queries see exactly this tenant's rows.
	//
	// M41 (F461): each read now logs at WARN on a non-nil error (the silent
	// swallow is precisely why the empty-report bug hid for so long). We still
	// degrade gracefully — a single failing section leaves its data empty
	// rather than failing the whole report — but a real DB error now produces a
	// visible signal instead of a silently-empty section.
	if s.dashboardRepo != nil {
		// Get total projects
		if totalProjects, err := s.dashboardRepo.GetTotalProjectsByTenant(ctx, tenantID); err == nil {
			data.Summary.TotalProjects = totalProjects
		} else {
			slog.Warn("report: total projects unavailable", "tenant_id", tenantID, "error", err)
		}

		// Get total components
		if totalComponents, err := s.dashboardRepo.GetTotalComponentsByTenant(ctx, tenantID); err == nil {
			data.Summary.TotalComponents = totalComponents
		} else {
			slog.Warn("report: total components unavailable", "tenant_id", tenantID, "error", err)
		}

		// Get vulnerability counts
		if vulnCounts, err := s.dashboardRepo.GetVulnerabilityCountsByTenant(ctx, tenantID); err == nil {
			data.Summary.TotalVulnerabilities = vulnCounts.Critical + vulnCounts.High +
				vulnCounts.Medium + vulnCounts.Low

			data.VulnerabilityData.BySeverity = map[string]int{
				"CRITICAL": vulnCounts.Critical,
				"HIGH":     vulnCounts.High,
				"MEDIUM":   vulnCounts.Medium,
				"LOW":      vulnCounts.Low,
			}
		} else {
			slog.Warn("report: vulnerability counts unavailable", "tenant_id", tenantID, "error", err)
		}

		// Get project scores
		if projectScores, err := s.dashboardRepo.GetProjectScoresByTenant(ctx, tenantID); err == nil {
			data.ProjectScores = projectScores
		} else {
			slog.Warn("report: project scores unavailable", "tenant_id", tenantID, "error", err)
		}

		// Get top risks
		if topRisks, err := s.dashboardRepo.GetTopRisksByTenant(ctx, tenantID, 10, "epss"); err == nil {
			data.TopRisks = topRisks
		} else {
			slog.Warn("report: top risks unavailable", "tenant_id", tenantID, "error", err)
		}

		// Get trend data
		if trend, err := s.dashboardRepo.GetTrendByTenant(ctx, tenantID, 30); err == nil {
			for _, t := range trend {
				data.VulnerabilityData.TrendData = append(data.VulnerabilityData.TrendData, model.TrendPoint{
					Date:     t.Date,
					Critical: t.Critical,
					High:     t.High,
					Medium:   t.Medium,
					Low:      t.Low,
				})
			}
		} else {
			slog.Warn("report: vulnerability trend unavailable", "tenant_id", tenantID, "error", err)
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
		vizData := s.gatherVisualizationData()
		if vizData != nil {
			data.VisualizationData = vizData
		}
	}

	return data
}

// gatherChecklistData collects checklist data for the report
func (s *ReportService) gatherChecklistData(ctx context.Context, tenantID uuid.UUID) *model.ChecklistReportData {
	// Get all checklist items definition
	allItems := model.GetAllChecklistItems()
	phaseLabels := model.GetChecklistPhaseLabels()

	// Get all responses from the tenant
	responses, err := s.checklistRepo.ListByTenant(ctx, tenantID)
	if err != nil {
		// Log error at ERROR level since DB query failure is significant
		// Continue with empty responses to allow partial report generation
		slog.Error("failed to get checklist responses for report - using defaults",
			"tenant_id", tenantID,
			"error", err,
			"impact", "checklist section will show all items as not passed")
		responses = nil
	}

	// Build a map of check_id -> passed status (true if any project marked it as passed)
	// This aggregates across all projects - an item is considered passed if at least one project has it passed
	passedItems := make(map[string]bool)
	notesMap := make(map[string]string)
	for _, resp := range responses {
		if resp.Response {
			passedItems[resp.CheckID] = true
		}
		// Keep the most recent note for each check item
		// ListByTenant returns results ordered by check_id, updated_at DESC
		// so the first non-empty note we encounter for each check_id is the most recent
		if _, exists := notesMap[resp.CheckID]; !exists {
			if resp.Note != nil && *resp.Note != "" {
				notesMap[resp.CheckID] = *resp.Note
			}
		}
	}

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
			// Determine if passed: auto-verified items are always passed, otherwise check actual responses
			passed := item.AutoVerify || passedItems[item.ID]

			itemData := model.ChecklistItemReportData{
				ID:         item.ID,
				LabelJa:    item.LabelJa,
				AutoVerify: item.AutoVerify,
				Passed:     passed,
				Note:       notesMap[item.ID],
			}
			if passed {
				phaseData.Score++
				data.Score++
			}
			phaseData.Items = append(phaseData.Items, itemData)
		}

		data.Phases = append(data.Phases, phaseData)
	}

	return data
}

// gatherVisualizationData collects visualization settings for the report.
//
// This is still a static-defaults stub: it does not read anything from
// visualizationRepo (the caller only gates on the repo being non-nil), so it
// takes no ctx/tenantID (unparam, M46 Track C-3a). When per-project
// visualization settings are actually wired up, reintroduce
// (ctx, tenantID) together with the repo read.
func (s *ReportService) gatherVisualizationData() *model.VisualizationReportData {
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

// getUtilizationScopeLabels returns a comma-separated string of labels for selected utilization scopes
func (s *ReportService) getUtilizationScopeLabels(options []model.VisualizationOption, values []string) string {
	if len(values) == 0 {
		return "-"
	}
	optionMap := make(map[string]string)
	for _, opt := range options {
		optionMap[opt.Value] = opt.LabelJa
	}
	var labels []string
	for _, v := range values {
		if label, ok := optionMap[v]; ok {
			labels = append(labels, label)
		} else {
			labels = append(labels, v)
		}
	}
	return strings.Join(labels, ", ")
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

// generateExcel generates an Excel report using excelize.
//
// M46 Track C-3a: every excelize write below is routed through the shared
// first-error collector (reportErrs, defined next to GenerateComplianceExcel
// which established the pattern in Track C-1). Before this, ~97 error returns
// were silently discarded, so a failed cell/sheet/style write still yielded a
// "successful" — but incomplete — workbook. The collector keeps the FIRST
// failure and generateExcel checks it once before serialization, propagating
// the error to runReportGeneration, which flips the report row to "failed".
func (s *ReportService) generateExcel(data *model.ExecutiveReportData, reportType string, locale string) ([]byte, error) {
	// Get translations
	t := GetTranslations(locale)

	f := excelize.NewFile()
	defer f.Close()

	ec := &reportErrs{}

	// Create Summary sheet with title based on report type
	sheetName := t.SheetSummary
	ec.collect(f.SetSheetName("Sheet1", sheetName))

	// Set column widths
	ec.collect(f.SetColWidth(sheetName, "A", "A", 25))
	ec.collect(f.SetColWidth(sheetName, "B", "B", 30))

	// Header style
	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 14, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#4472C4"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})
	ec.collect(err)

	// Title based on report type
	title := s.getReportTitleI18n(reportType, t)
	ec.collect(f.MergeCell(sheetName, "A1", "B1"))
	ec.collect(f.SetCellValue(sheetName, "A1", title))
	ec.collect(f.SetCellStyle(sheetName, "A1", "B1", headerStyle))
	ec.collect(f.SetRowHeight(sheetName, 1, 30))

	// Period info
	ec.collect(f.SetCellValue(sheetName, "A2", t.Period))
	ec.collect(f.SetCellValue(sheetName, "B2", fmt.Sprintf("%s - %s",
		data.PeriodStart.Format("2006-01-02"),
		data.PeriodEnd.Format("2006-01-02"))))
	ec.collect(f.SetCellValue(sheetName, "A3", t.GeneratedAt))
	ec.collect(f.SetCellValue(sheetName, "B3", data.GeneratedAt.Format("2006-01-02 15:04")))

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
		ec.collect(f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), d[0]))
		ec.collect(f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), d[1]))
		row++
	}

	// Vulnerability breakdown
	row += 2
	ec.collect(f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), t.VulnerabilityBreakdown))
	ec.collect(f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), headerStyle))
	row++

	vulnData := [][]interface{}{
		{t.Critical, data.VulnerabilityData.BySeverity["CRITICAL"]},
		{t.High, data.VulnerabilityData.BySeverity["HIGH"]},
		{t.Medium, data.VulnerabilityData.BySeverity["MEDIUM"]},
		{t.Low, data.VulnerabilityData.BySeverity["LOW"]},
	}

	for _, d := range vulnData {
		ec.collect(f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), d[0]))
		ec.collect(f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), d[1]))
		row++
	}

	// Create Top Risks sheet for Executive and Technical reports
	if len(data.TopRisks) > 0 && (reportType == model.ReportTypeExecutive || reportType == model.ReportTypeTechnical) {
		riskSheet := t.SheetTopRisks
		_, err = f.NewSheet(riskSheet)
		ec.collect(err)
		ec.collect(f.SetColWidth(riskSheet, "A", "A", 20))
		ec.collect(f.SetColWidth(riskSheet, "B", "B", 25))
		ec.collect(f.SetColWidth(riskSheet, "C", "C", 15))
		ec.collect(f.SetColWidth(riskSheet, "D", "D", 12))
		ec.collect(f.SetColWidth(riskSheet, "E", "E", 12))

		// Headers
		ec.collect(f.SetCellValue(riskSheet, "A1", t.CVEID))
		ec.collect(f.SetCellValue(riskSheet, "B1", t.Project))
		ec.collect(f.SetCellValue(riskSheet, "C1", t.Component))
		ec.collect(f.SetCellValue(riskSheet, "D1", t.CVSS))
		ec.collect(f.SetCellValue(riskSheet, "E1", t.EPSS))

		for i, risk := range data.TopRisks {
			row := i + 2
			ec.collect(f.SetCellValue(riskSheet, fmt.Sprintf("A%d", row), risk.CVEID))
			ec.collect(f.SetCellValue(riskSheet, fmt.Sprintf("B%d", row), risk.ProjectName))
			ec.collect(f.SetCellValue(riskSheet, fmt.Sprintf("C%d", row), risk.ComponentName))
			ec.collect(f.SetCellValue(riskSheet, fmt.Sprintf("D%d", row), risk.CVSSScore))
			ec.collect(f.SetCellValue(riskSheet, fmt.Sprintf("E%d", row), fmt.Sprintf("%.2f%%", risk.EPSSScore*100)))
		}
	}

	// Create Trend sheet for Technical reports only
	if len(data.VulnerabilityData.TrendData) > 0 && reportType == model.ReportTypeTechnical {
		trendSheet := t.SheetTrend
		_, err = f.NewSheet(trendSheet)
		ec.collect(err)
		ec.collect(f.SetColWidth(trendSheet, "A", "A", 15))
		ec.collect(f.SetColWidth(trendSheet, "B", "E", 12))

		// Headers
		ec.collect(f.SetCellValue(trendSheet, "A1", t.Date))
		ec.collect(f.SetCellValue(trendSheet, "B1", t.Critical))
		ec.collect(f.SetCellValue(trendSheet, "C1", t.High))
		ec.collect(f.SetCellValue(trendSheet, "D1", t.Medium))
		ec.collect(f.SetCellValue(trendSheet, "E1", t.Low))

		for i, trend := range data.VulnerabilityData.TrendData {
			row := i + 2
			ec.collect(f.SetCellValue(trendSheet, fmt.Sprintf("A%d", row), trend.Date))
			ec.collect(f.SetCellValue(trendSheet, fmt.Sprintf("B%d", row), trend.Critical))
			ec.collect(f.SetCellValue(trendSheet, fmt.Sprintf("C%d", row), trend.High))
			ec.collect(f.SetCellValue(trendSheet, fmt.Sprintf("D%d", row), trend.Medium))
			ec.collect(f.SetCellValue(trendSheet, fmt.Sprintf("E%d", row), trend.Low))
		}
	}

	// Create METI Checklist sheet for Compliance reports only
	if data.ChecklistData != nil && reportType == model.ReportTypeCompliance {
		checklistSheet := t.SheetChecklist
		_, err = f.NewSheet(checklistSheet)
		ec.collect(err)
		ec.collect(f.SetColWidth(checklistSheet, "A", "A", 15))
		ec.collect(f.SetColWidth(checklistSheet, "B", "B", 40))
		ec.collect(f.SetColWidth(checklistSheet, "C", "C", 12))
		ec.collect(f.SetColWidth(checklistSheet, "D", "D", 12))
		ec.collect(f.SetColWidth(checklistSheet, "E", "E", 30))

		// Title
		ec.collect(f.MergeCell(checklistSheet, "A1", "E1"))
		ec.collect(f.SetCellValue(checklistSheet, "A1", t.METIChecklist))
		ec.collect(f.SetCellStyle(checklistSheet, "A1", "E1", headerStyle))
		ec.collect(f.SetRowHeight(checklistSheet, 1, 25))

		// Summary
		checklistPct := 0.0
		if data.ChecklistData.MaxScore > 0 {
			checklistPct = float64(data.ChecklistData.Score) / float64(data.ChecklistData.MaxScore) * 100
		}
		ec.collect(f.SetCellValue(checklistSheet, "A2", t.TotalProgress))
		ec.collect(f.SetCellValue(checklistSheet, "B2", fmt.Sprintf("%d / %d (%.0f%%)",
			data.ChecklistData.Score, data.ChecklistData.MaxScore, checklistPct)))

		// Headers
		row := 4
		ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("A%d", row), t.Phase))
		ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("B%d", row), t.Item))
		ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("C%d", row), t.AutoVerify))
		ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("D%d", row), t.Status))
		ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("E%d", row), t.Notes))
		row++

		// Checklist items by phase
		for _, phase := range data.ChecklistData.Phases {
			for i, item := range phase.Items {
				ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("A%d", row), func() string {
					if i == 0 {
						return phase.LabelJa
					}
					return ""
				}()))
				ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("B%d", row), item.LabelJa))
				ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("C%d", row), func() string {
					if item.AutoVerify {
						return "○"
					}
					return "-"
				}()))
				ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("D%d", row), func() string {
					if item.Passed {
						return t.Completed
					}
					return t.NotCompleted
				}()))
				ec.collect(f.SetCellValue(checklistSheet, fmt.Sprintf("E%d", row), item.Note))
				row++
			}
		}
	}

	// Create Visualization Framework sheet for Compliance reports only
	if data.VisualizationData != nil && reportType == model.ReportTypeCompliance {
		vizSheet := t.SheetVisualization
		_, err = f.NewSheet(vizSheet)
		ec.collect(err)
		ec.collect(f.SetColWidth(vizSheet, "A", "A", 25))
		ec.collect(f.SetColWidth(vizSheet, "B", "B", 35))
		ec.collect(f.SetColWidth(vizSheet, "C", "C", 35))

		// Title
		ec.collect(f.MergeCell(vizSheet, "A1", "C1"))
		ec.collect(f.SetCellValue(vizSheet, "A1", t.VisualizationFramework))
		ec.collect(f.SetCellStyle(vizSheet, "A1", "C1", headerStyle))
		ec.collect(f.SetRowHeight(vizSheet, 1, 25))

		// Headers
		ec.collect(f.SetCellValue(vizSheet, "A3", t.Perspective))
		ec.collect(f.SetCellValue(vizSheet, "B3", t.Setting))
		ec.collect(f.SetCellValue(vizSheet, "C3", t.Description))

		vizOptions := model.GetVisualizationOptions()

		// (a) SBOM Author
		row := 4
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizSBOMAuthor))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.SBOMAuthorScope, data.VisualizationData.SBOMAuthorScope)))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizSBOMAuthorDesc))
		row++

		// (b) Dependencies
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizDependency))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.DependencyScope, data.VisualizationData.DependencyScope)))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizDependencyDesc))
		row++

		// (c) Generation Method
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizGeneration))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.GenerationMethod, data.VisualizationData.GenerationMethod)))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizGenerationDesc))
		row++

		// (d) Data Format
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizDataFormat))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.DataFormat, data.VisualizationData.DataFormat)))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizDataFormatDesc))
		row++

		// (e) Utilization Scope
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizUtilizationScope))
		scopeLabels := s.getUtilizationScopeLabels(vizOptions.UtilizationScope, data.VisualizationData.UtilizationScope)
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row), scopeLabels))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizUtilizationScopeDesc))
		row++

		// (f) Utilization Actor
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("A%d", row), t.VizUtilization))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("B%d", row),
			s.getVisualizationOptionLabel(vizOptions.UtilizationActor, data.VisualizationData.UtilizationActor)))
		ec.collect(f.SetCellValue(vizSheet, fmt.Sprintf("C%d", row), t.VizUtilizationDesc))
	}

	// A corrupt workbook must not be reported as success — fail before
	// serializing if any cell/sheet/style write above failed (same contract
	// as GenerateComplianceExcel, M46 Track C).
	if ec.err != nil {
		return nil, fmt.Errorf("failed to build Excel report: %w", ec.err)
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
