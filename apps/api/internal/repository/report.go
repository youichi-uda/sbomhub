package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ReportRepository handles report data access
type ReportRepository struct {
	db *sql.DB
}

// NewReportRepository creates a new ReportRepository
func NewReportRepository(db *sql.DB) *ReportRepository {
	return &ReportRepository{db: db}
}

// GetSettings returns report settings for a tenant and report type
func (r *ReportRepository) GetSettings(ctx context.Context, tenantID uuid.UUID, reportType string) (*model.ReportSettings, error) {
	query := `
		SELECT id, tenant_id, enabled, report_type, schedule_type, schedule_day, schedule_hour,
			format, email_enabled, email_recipients, include_sections, created_at, updated_at
		FROM report_settings
		WHERE tenant_id = $1 AND report_type = $2
	`

	var s model.ReportSettings
	err := r.db.QueryRowContext(ctx, query, tenantID, reportType).Scan(
		&s.ID, &s.TenantID, &s.Enabled, &s.ReportType, &s.ScheduleType, &s.ScheduleDay, &s.ScheduleHour,
		&s.Format, &s.EmailEnabled, pq.Array(&s.EmailRecipients), pq.Array(&s.IncludeSections),
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// GetAllSettings returns all report settings for a tenant
func (r *ReportRepository) GetAllSettings(ctx context.Context, tenantID uuid.UUID) ([]model.ReportSettings, error) {
	query := `
		SELECT id, tenant_id, enabled, report_type, schedule_type, schedule_day, schedule_hour,
			format, email_enabled, email_recipients, include_sections, created_at, updated_at
		FROM report_settings
		WHERE tenant_id = $1
		ORDER BY report_type
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []model.ReportSettings
	for rows.Next() {
		var s model.ReportSettings
		if err := rows.Scan(
			&s.ID, &s.TenantID, &s.Enabled, &s.ReportType, &s.ScheduleType, &s.ScheduleDay, &s.ScheduleHour,
			&s.Format, &s.EmailEnabled, pq.Array(&s.EmailRecipients), pq.Array(&s.IncludeSections),
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		settings = append(settings, s)
	}

	return settings, nil
}

// UpsertSettings creates or updates report settings
func (r *ReportRepository) UpsertSettings(ctx context.Context, s *model.ReportSettings) error {
	query := `
		INSERT INTO report_settings (
			id, tenant_id, enabled, report_type, schedule_type, schedule_day, schedule_hour,
			format, email_enabled, email_recipients, include_sections, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
		ON CONFLICT (tenant_id, report_type)
		DO UPDATE SET
			enabled = $3, schedule_type = $5, schedule_day = $6, schedule_hour = $7,
			format = $8, email_enabled = $9, email_recipients = $10, include_sections = $11,
			updated_at = NOW()
	`

	_, err := r.db.ExecContext(ctx, query,
		s.ID, s.TenantID, s.Enabled, s.ReportType, s.ScheduleType, s.ScheduleDay, s.ScheduleHour,
		s.Format, s.EmailEnabled, pq.Array(s.EmailRecipients), pq.Array(s.IncludeSections),
	)
	return err
}

// GetEnabledSettings returns all enabled report settings for scheduled generation
func (r *ReportRepository) GetEnabledSettings(ctx context.Context) ([]model.ReportSettings, error) {
	query := `
		SELECT id, tenant_id, enabled, report_type, schedule_type, schedule_day, schedule_hour,
			format, email_enabled, email_recipients, include_sections, created_at, updated_at
		FROM report_settings
		WHERE enabled = true
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []model.ReportSettings
	for rows.Next() {
		var s model.ReportSettings
		if err := rows.Scan(
			&s.ID, &s.TenantID, &s.Enabled, &s.ReportType, &s.ScheduleType, &s.ScheduleDay, &s.ScheduleHour,
			&s.Format, &s.EmailEnabled, pq.Array(&s.EmailRecipients), pq.Array(&s.IncludeSections),
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		settings = append(settings, s)
	}

	return settings, nil
}

// CreateReport creates a new generated report record
func (r *ReportRepository) CreateReport(ctx context.Context, report *model.GeneratedReport) error {
	query := `
		INSERT INTO generated_reports (
			id, tenant_id, settings_id, report_type, format, title, period_start, period_end,
			file_path, file_size, status, generated_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
	`

	_, err := r.db.ExecContext(ctx, query,
		report.ID, report.TenantID, report.SettingsID, report.ReportType, report.Format,
		report.Title, report.PeriodStart, report.PeriodEnd,
		report.FilePath, report.FileSize, report.Status, report.GeneratedBy,
	)
	return err
}

// UpdateReport updates a generated report
func (r *ReportRepository) UpdateReport(ctx context.Context, report *model.GeneratedReport) error {
	query := `
		UPDATE generated_reports SET
			file_path = $2, file_size = $3, file_content = $4, status = $5, error_message = $6,
			email_sent_at = $7, email_recipients = $8, completed_at = $9
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		report.ID, report.FilePath, report.FileSize, report.FileContent, report.Status, report.ErrorMessage,
		report.EmailSentAt, pq.Array(report.EmailRecipients), report.CompletedAt,
	)
	return err
}

// GetReportWithContent returns a generated report with file content by ID
func (r *ReportRepository) GetReportWithContent(ctx context.Context, tenantID, reportID uuid.UUID) (*model.GeneratedReport, error) {
	query := `
		SELECT id, tenant_id, settings_id, report_type, format, title, period_start, period_end,
			file_path, file_size, file_content, status, error_message, generated_by, email_sent_at,
			email_recipients, created_at, completed_at
		FROM generated_reports
		WHERE id = $1 AND tenant_id = $2
	`

	var report model.GeneratedReport
	var emailRecipients []string
	err := r.db.QueryRowContext(ctx, query, reportID, tenantID).Scan(
		&report.ID, &report.TenantID, &report.SettingsID, &report.ReportType, &report.Format,
		&report.Title, &report.PeriodStart, &report.PeriodEnd,
		&report.FilePath, &report.FileSize, &report.FileContent, &report.Status, &report.ErrorMessage,
		&report.GeneratedBy, &report.EmailSentAt, pq.Array(&emailRecipients),
		&report.CreatedAt, &report.CompletedAt,
	)
	if err != nil {
		return nil, err
	}
	report.EmailRecipients = emailRecipients

	return &report, nil
}

// GetReport returns a generated report by ID
func (r *ReportRepository) GetReport(ctx context.Context, tenantID, reportID uuid.UUID) (*model.GeneratedReport, error) {
	query := `
		SELECT id, tenant_id, settings_id, report_type, format, title, period_start, period_end,
			file_path, file_size, status, error_message, generated_by, email_sent_at,
			email_recipients, created_at, completed_at
		FROM generated_reports
		WHERE id = $1 AND tenant_id = $2
	`

	var report model.GeneratedReport
	var emailRecipients []string
	err := r.db.QueryRowContext(ctx, query, reportID, tenantID).Scan(
		&report.ID, &report.TenantID, &report.SettingsID, &report.ReportType, &report.Format,
		&report.Title, &report.PeriodStart, &report.PeriodEnd,
		&report.FilePath, &report.FileSize, &report.Status, &report.ErrorMessage,
		&report.GeneratedBy, &report.EmailSentAt, pq.Array(&emailRecipients),
		&report.CreatedAt, &report.CompletedAt,
	)
	if err != nil {
		return nil, err
	}
	report.EmailRecipients = emailRecipients

	return &report, nil
}

// ListReports returns generated reports for a tenant
func (r *ReportRepository) ListReports(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]model.GeneratedReport, int, error) {
	// Get total count
	countQuery := `SELECT COUNT(*) FROM generated_reports WHERE tenant_id = $1`
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
		SELECT id, tenant_id, settings_id, report_type, format, title, period_start, period_end,
			file_path, file_size, status, error_message, generated_by, email_sent_at,
			email_recipients, created_at, completed_at
		FROM generated_reports
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var reports []model.GeneratedReport
	for rows.Next() {
		var report model.GeneratedReport
		var emailRecipients []string
		if err := rows.Scan(
			&report.ID, &report.TenantID, &report.SettingsID, &report.ReportType, &report.Format,
			&report.Title, &report.PeriodStart, &report.PeriodEnd,
			&report.FilePath, &report.FileSize, &report.Status, &report.ErrorMessage,
			&report.GeneratedBy, &report.EmailSentAt, pq.Array(&emailRecipients),
			&report.CreatedAt, &report.CompletedAt,
		); err != nil {
			return nil, 0, err
		}
		report.EmailRecipients = emailRecipients
		reports = append(reports, report)
	}

	return reports, total, nil
}

// DeleteOldReports deletes reports older than the specified time
func (r *ReportRepository) DeleteOldReports(ctx context.Context, tenantID uuid.UUID, before time.Time) (int64, error) {
	query := `DELETE FROM generated_reports WHERE tenant_id = $1 AND created_at < $2`
	result, err := r.db.ExecContext(ctx, query, tenantID, before)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
