package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ErrGeneratedReportNotFound is returned by UpdateReport when the statement
// matched no `generated_reports` row for the report's tenant.
//
// M47 W2: wraps sql.ErrNoRows (see ErrTenantUserNotFound in
// repository/user.go for the rationale).
var ErrGeneratedReportNotFound = fmt.Errorf("generated_reports: no row matched for this tenant: %w", sql.ErrNoRows)

// ReportRepository handles report data access
type ReportRepository struct {
	db *sql.DB
}

// NewReportRepository creates a new ReportRepository
func NewReportRepository(db *sql.DB) *ReportRepository {
	return &ReportRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
// report_settings and generated_reports both have RLS enabled (migration 013),
// so listing/upserting these from a non-tx pool connection silently returns no
// rows for sbomhub_app (codex-r1 Finding 2). The scheduler path
// (GetEnabledSettings) keeps falling back to r.db because it runs outside any
// request and intentionally needs the cross-tenant view.
func (r *ReportRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
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
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID, reportType).Scan(
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

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return settings, nil
}

// UpsertSettings creates or updates report settings
//
// M47 W2 classification: BENIGN — `ON CONFLICT ... DO UPDATE` with no
// WHERE guard always affects exactly one row, so there is no 0-row
// outcome for the caller to adjudicate.
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

	_, err := r.q(ctx).ExecContext(ctx, query,
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

	rows, err := r.q(ctx).QueryContext(ctx, query)
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
	if err := rows.Err(); err != nil {
		return nil, err
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

	_, err := r.q(ctx).ExecContext(ctx, query,
		report.ID, report.TenantID, report.SettingsID, report.ReportType, report.Format,
		report.Title, report.PeriodStart, report.PeriodEnd,
		report.FilePath, report.FileSize, report.Status, report.GeneratedBy,
	)
	return err
}

// UpdateReport writes the terminal state of a generated report, restricted
// to the tenant that owns the supplied struct.
//
// M47 W2: this is the one site in the sweep whose consequence was already
// written down in prose before it was fixed — service/report.go says the
// terminal UPDATE could match 0 rows and that "ReportRepository.UpdateReport
// does not check rows affected, so the failure was silent — the report
// stuck at 'generating' with the UI showing 'generating now...' forever".
// 0 rows now returns ErrGeneratedReportNotFound, which the generation and
// email paths already surface (they wrap and log any error). The
// `AND tenant_id = $10` belt is added at the same time so migration 023's
// FORCE RLS is not the only thing scoping the write; report.TenantID is
// set by the service from the session tenant, never from a request body.
func (r *ReportRepository) UpdateReport(ctx context.Context, report *model.GeneratedReport) error {
	query := `
		UPDATE generated_reports SET
			file_path = $2, file_size = $3, file_content = $4, status = $5, error_message = $6,
			email_sent_at = $7, email_recipients = $8, completed_at = $9
		WHERE id = $1 AND tenant_id = $10
	`

	res, err := r.q(ctx).ExecContext(ctx, query,
		report.ID, report.FilePath, report.FileSize, report.FileContent, report.Status, report.ErrorMessage,
		report.EmailSentAt, pq.Array(report.EmailRecipients), report.CompletedAt, report.TenantID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update generated_reports (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update report %s for tenant %s: %w", report.ID, report.TenantID, ErrGeneratedReportNotFound)
	}
	return nil
}

// GetReportWithContent returns a generated report with file content by ID
func (r *ReportRepository) GetReportWithContent(ctx context.Context, tenantID, reportID uuid.UUID) (*model.GeneratedReport, error) {
	query := `
		SELECT id, tenant_id, settings_id, report_type, format, title, period_start, period_end,
			COALESCE(file_path, ''), file_size, file_content, status, COALESCE(error_message, ''), generated_by, email_sent_at,
			email_recipients, created_at, completed_at
		FROM generated_reports
		WHERE id = $1 AND tenant_id = $2
	`

	var report model.GeneratedReport
	var emailRecipients []string
	err := r.q(ctx).QueryRowContext(ctx, query, reportID, tenantID).Scan(
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
			COALESCE(file_path, ''), file_size, status, COALESCE(error_message, ''), generated_by, email_sent_at,
			email_recipients, created_at, completed_at
		FROM generated_reports
		WHERE id = $1 AND tenant_id = $2
	`

	var report model.GeneratedReport
	var emailRecipients []string
	err := r.q(ctx).QueryRowContext(ctx, query, reportID, tenantID).Scan(
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
	if err := r.q(ctx).QueryRowContext(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
		SELECT id, tenant_id, settings_id, report_type, format, title, period_start, period_end,
			COALESCE(file_path, ''), file_size, status, COALESCE(error_message, ''), generated_by, email_sent_at,
			email_recipients, created_at, completed_at
		FROM generated_reports
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, limit, offset)
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
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return reports, total, nil
}

// DeleteOldReports deletes reports older than the specified time
func (r *ReportRepository) DeleteOldReports(ctx context.Context, tenantID uuid.UUID, before time.Time) (int64, error) {
	query := `DELETE FROM generated_reports WHERE tenant_id = $1 AND created_at < $2`
	result, err := r.q(ctx).ExecContext(ctx, query, tenantID, before)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
