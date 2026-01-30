package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ReportGenerationJob handles periodic report generation
type ReportGenerationJob struct {
	reportService *service.ReportService
	reportRepo    *repository.ReportRepository
	tenantRepo    *repository.TenantRepository
	interval      time.Duration
	logger        *slog.Logger
}

// NewReportGenerationJob creates a new report generation job
func NewReportGenerationJob(
	reportService *service.ReportService,
	reportRepo *repository.ReportRepository,
	tenantRepo *repository.TenantRepository,
	interval time.Duration,
) *ReportGenerationJob {
	return &ReportGenerationJob{
		reportService: reportService,
		reportRepo:    reportRepo,
		tenantRepo:    tenantRepo,
		interval:      interval,
		logger:        slog.Default().With("job", "report_generation"),
	}
}

// Start starts the report generation job
func (j *ReportGenerationJob) Start(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Check immediately on start
	j.run(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Info("Report generation job stopped")
			return
		case <-ticker.C:
			j.run(ctx)
		}
	}
}

// run executes a single check cycle
func (j *ReportGenerationJob) run(ctx context.Context) {
	now := time.Now()
	j.logger.Debug("Checking scheduled reports", "time", now.Format("15:04"))

	// Get all enabled report settings
	settings, err := j.reportRepo.GetEnabledSettings(ctx)
	if err != nil {
		j.logger.Error("Failed to get enabled settings", "error", err)
		return
	}

	if len(settings) == 0 {
		j.logger.Debug("No enabled report schedules found")
		return
	}

	j.logger.Debug("Found enabled report settings", "count", len(settings))

	for _, setting := range settings {
		if j.shouldGenerate(&setting, now) {
			j.logger.Info("Triggering scheduled report generation",
				"tenant_id", setting.TenantID,
				"report_type", setting.ReportType,
				"format", setting.Format,
			)
			go j.generateReport(ctx, &setting)
		}
	}
}

// shouldGenerate checks if a report should be generated based on schedule
func (j *ReportGenerationJob) shouldGenerate(setting *model.ReportSettings, now time.Time) bool {
	// Check hour (allow 5 minute window)
	if now.Hour() != setting.ScheduleHour || now.Minute() >= 5 {
		return false
	}

	switch setting.ScheduleType {
	case model.ScheduleTypeWeekly:
		// ScheduleDay: 0=Sunday, 1=Monday, ..., 6=Saturday
		return int(now.Weekday()) == setting.ScheduleDay

	case model.ScheduleTypeMonthly:
		// ScheduleDay: 1-28
		return now.Day() == setting.ScheduleDay

	default:
		return false
	}
}

// generateReport generates a report for a tenant
func (j *ReportGenerationJob) generateReport(ctx context.Context, setting *model.ReportSettings) {
	startTime := time.Now()

	// Calculate period based on schedule type
	periodEnd := time.Now()
	var periodStart time.Time

	switch setting.ScheduleType {
	case model.ScheduleTypeWeekly:
		periodStart = periodEnd.AddDate(0, 0, -7)
	case model.ScheduleTypeMonthly:
		periodStart = periodEnd.AddDate(0, -1, 0)
	default:
		periodStart = periodEnd.AddDate(0, -1, 0)
	}

	input := model.GenerateReportInput{
		ReportType:  setting.ReportType,
		Format:      setting.Format,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}

	// Use system user ID for scheduled reports
	systemUserID := uuid.Nil

	report, err := j.reportService.GenerateReport(ctx, setting.TenantID, systemUserID, input)
	if err != nil {
		j.logger.Error("Failed to generate scheduled report",
			"tenant_id", setting.TenantID,
			"report_type", setting.ReportType,
			"error", err,
			"duration_ms", time.Since(startTime).Milliseconds(),
		)
		return
	}

	j.logger.Info("Scheduled report generation initiated",
		"tenant_id", setting.TenantID,
		"report_id", report.ID,
		"report_type", setting.ReportType,
		"format", setting.Format,
		"duration_ms", time.Since(startTime).Milliseconds(),
	)

	// Note: Email sending would be handled here if implemented
	// For now, the report is generated and stored in the database
}

// ReportGenerationResult contains the result of a generation cycle
type ReportGenerationResult struct {
	Checked   int
	Generated int
	Failed    int
}

// RunOnce runs a single check and returns results
func (j *ReportGenerationJob) RunOnce(ctx context.Context) (*ReportGenerationResult, error) {
	now := time.Now()
	result := &ReportGenerationResult{}

	settings, err := j.reportRepo.GetEnabledSettings(ctx)
	if err != nil {
		return nil, err
	}

	result.Checked = len(settings)

	for _, setting := range settings {
		if j.shouldGenerate(&setting, now) {
			j.generateReport(ctx, &setting)
			result.Generated++
		}
	}

	return result, nil
}
