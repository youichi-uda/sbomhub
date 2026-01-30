package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// AnalyticsRepository handles analytics data access
type AnalyticsRepository struct {
	db *sql.DB
}

// NewAnalyticsRepository creates a new AnalyticsRepository
func NewAnalyticsRepository(db *sql.DB) *AnalyticsRepository {
	return &AnalyticsRepository{db: db}
}

// GetMTTR calculates Mean Time To Remediate by severity
func (r *AnalyticsRepository) GetMTTR(ctx context.Context, tenantID uuid.UUID, start, end time.Time) ([]model.MTTRResult, error) {
	query := `
		WITH mttr_data AS (
			SELECT
				severity,
				EXTRACT(EPOCH FROM (resolved_at - detected_at)) / 3600 as hours
			FROM vulnerability_resolution_events
			WHERE tenant_id = $1
				AND resolved_at IS NOT NULL
				AND resolved_at >= $2
				AND resolved_at <= $3
		),
		slo AS (
			SELECT severity, target_hours
			FROM slo_targets
			WHERE tenant_id = $1 OR tenant_id IS NULL
			ORDER BY tenant_id NULLS LAST
		)
		SELECT
			m.severity,
			COALESCE(AVG(m.hours), 0) as mttr_hours,
			COUNT(*) as count,
			COALESCE(s.target_hours, 168) as target_hours
		FROM mttr_data m
		LEFT JOIN slo s ON m.severity = s.severity
		GROUP BY m.severity, s.target_hours
		ORDER BY
			CASE m.severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH' THEN 2
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 4
				ELSE 5
			END
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.MTTRResult
	for rows.Next() {
		var m model.MTTRResult
		if err := rows.Scan(&m.Severity, &m.MTTRHours, &m.Count, &m.TargetHours); err != nil {
			return nil, err
		}
		m.OnTarget = m.MTTRHours <= float64(m.TargetHours)
		results = append(results, m)
	}

	return results, nil
}

// GetVulnerabilityTrend returns daily vulnerability counts
func (r *AnalyticsRepository) GetVulnerabilityTrend(ctx context.Context, tenantID uuid.UUID, days int) ([]model.VulnerabilityTrendPoint, error) {
	// First try to get from snapshots
	query := `
		SELECT
			snapshot_date::text as date,
			critical_count,
			high_count,
			medium_count,
			low_count,
			total_count,
			resolved_count
		FROM vulnerability_snapshots
		WHERE tenant_id = $1
			AND snapshot_date >= CURRENT_DATE - $2::int
		ORDER BY snapshot_date ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.VulnerabilityTrendPoint
	for rows.Next() {
		var p model.VulnerabilityTrendPoint
		if err := rows.Scan(&p.Date, &p.Critical, &p.High, &p.Medium, &p.Low, &p.Total, &p.Resolved); err != nil {
			return nil, err
		}
		results = append(results, p)
	}

	// If no snapshots, calculate from current data
	if len(results) == 0 {
		return r.calculateVulnerabilityTrend(ctx, tenantID, days)
	}

	return results, nil
}

// calculateVulnerabilityTrend calculates trend from vulnerability data
func (r *AnalyticsRepository) calculateVulnerabilityTrend(ctx context.Context, tenantID uuid.UUID, days int) ([]model.VulnerabilityTrendPoint, error) {
	query := `
		WITH date_series AS (
			SELECT generate_series(
				CURRENT_DATE - $2::int,
				CURRENT_DATE,
				'1 day'::interval
			)::date as date
		),
		daily_counts AS (
			SELECT
				DATE(vre.detected_at) as date,
				COUNT(CASE WHEN vre.severity = 'CRITICAL' THEN 1 END) as critical,
				COUNT(CASE WHEN vre.severity = 'HIGH' THEN 1 END) as high,
				COUNT(CASE WHEN vre.severity = 'MEDIUM' THEN 1 END) as medium,
				COUNT(CASE WHEN vre.severity = 'LOW' THEN 1 END) as low
			FROM vulnerability_resolution_events vre
			WHERE vre.tenant_id = $1
				AND vre.detected_at >= CURRENT_DATE - $2::int
			GROUP BY DATE(vre.detected_at)
		),
		daily_resolved AS (
			SELECT
				DATE(resolved_at) as date,
				COUNT(*) as resolved
			FROM vulnerability_resolution_events
			WHERE tenant_id = $1
				AND resolved_at >= CURRENT_DATE - $2::int
				AND resolved_at IS NOT NULL
			GROUP BY DATE(resolved_at)
		)
		SELECT
			ds.date::text,
			COALESCE(dc.critical, 0) as critical,
			COALESCE(dc.high, 0) as high,
			COALESCE(dc.medium, 0) as medium,
			COALESCE(dc.low, 0) as low,
			COALESCE(dc.critical, 0) + COALESCE(dc.high, 0) + COALESCE(dc.medium, 0) + COALESCE(dc.low, 0) as total,
			COALESCE(dr.resolved, 0) as resolved
		FROM date_series ds
		LEFT JOIN daily_counts dc ON ds.date = dc.date
		LEFT JOIN daily_resolved dr ON ds.date = dr.date
		ORDER BY ds.date ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.VulnerabilityTrendPoint
	for rows.Next() {
		var p model.VulnerabilityTrendPoint
		if err := rows.Scan(&p.Date, &p.Critical, &p.High, &p.Medium, &p.Low, &p.Total, &p.Resolved); err != nil {
			return nil, err
		}
		results = append(results, p)
	}

	return results, nil
}

// GetSLOAchievement returns SLO achievement statistics
func (r *AnalyticsRepository) GetSLOAchievement(ctx context.Context, tenantID uuid.UUID, start, end time.Time) ([]model.SLOAchievement, error) {
	query := `
		WITH slo AS (
			SELECT DISTINCT ON (severity) severity, target_hours
			FROM slo_targets
			WHERE tenant_id = $1 OR tenant_id IS NULL
			ORDER BY severity, tenant_id NULLS LAST
		),
		resolved AS (
			SELECT
				vre.severity,
				COUNT(*) as total_count,
				COUNT(CASE
					WHEN EXTRACT(EPOCH FROM (vre.resolved_at - vre.detected_at)) / 3600 <= s.target_hours
					THEN 1
				END) as on_target_count,
				AVG(EXTRACT(EPOCH FROM (vre.resolved_at - vre.detected_at)) / 3600) as avg_mttr
			FROM vulnerability_resolution_events vre
			JOIN slo s ON vre.severity = s.severity
			WHERE vre.tenant_id = $1
				AND vre.resolved_at IS NOT NULL
				AND vre.resolved_at >= $2
				AND vre.resolved_at <= $3
			GROUP BY vre.severity
		)
		SELECT
			s.severity,
			COALESCE(r.total_count, 0) as total_count,
			COALESCE(r.on_target_count, 0) as on_target_count,
			CASE
				WHEN COALESCE(r.total_count, 0) = 0 THEN 100.0
				ELSE (COALESCE(r.on_target_count, 0)::float / r.total_count) * 100
			END as achievement_pct,
			s.target_hours,
			COALESCE(r.avg_mttr, 0) as avg_mttr
		FROM slo s
		LEFT JOIN resolved r ON s.severity = r.severity
		ORDER BY
			CASE s.severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH' THEN 2
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 4
				ELSE 5
			END
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.SLOAchievement
	for rows.Next() {
		var s model.SLOAchievement
		if err := rows.Scan(&s.Severity, &s.TotalCount, &s.OnTargetCount, &s.AchievementPct, &s.TargetHours, &s.AverageMTTR); err != nil {
			return nil, err
		}
		results = append(results, s)
	}

	return results, nil
}

// GetComplianceTrend returns compliance score history
func (r *AnalyticsRepository) GetComplianceTrend(ctx context.Context, tenantID uuid.UUID, days int) ([]model.ComplianceTrendPoint, error) {
	query := `
		SELECT
			snapshot_date::text as date,
			overall_score as score,
			max_score,
			(overall_score::float / NULLIF(max_score, 0)) * 100 as percentage,
			sbom_generation_score,
			vulnerability_management_score,
			license_management_score
		FROM compliance_snapshots
		WHERE tenant_id = $1
			AND project_id IS NULL
			AND snapshot_date >= CURRENT_DATE - $2::int
		ORDER BY snapshot_date ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.ComplianceTrendPoint
	for rows.Next() {
		var p model.ComplianceTrendPoint
		if err := rows.Scan(&p.Date, &p.Score, &p.MaxScore, &p.Percentage, &p.SBOMScore, &p.VulnerabilityScore, &p.LicenseScore); err != nil {
			return nil, err
		}
		results = append(results, p)
	}

	return results, nil
}

// GetQuickStats returns summary statistics
func (r *AnalyticsRepository) GetQuickStats(ctx context.Context, tenantID uuid.UUID) (*model.AnalyticsQuickStats, error) {
	stats := &model.AnalyticsQuickStats{}

	// Get open vulnerabilities count
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM vulnerability_resolution_events
		WHERE tenant_id = $1 AND resolved_at IS NULL
	`, tenantID).Scan(&stats.TotalOpenVulnerabilities)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get resolved in last 30 days
	err = r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM vulnerability_resolution_events
		WHERE tenant_id = $1
			AND resolved_at IS NOT NULL
			AND resolved_at >= CURRENT_DATE - 30
	`, tenantID).Scan(&stats.ResolvedLast30Days)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get average MTTR
	err = r.db.QueryRowContext(ctx, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - detected_at)) / 3600), 0)
		FROM vulnerability_resolution_events
		WHERE tenant_id = $1
			AND resolved_at IS NOT NULL
			AND resolved_at >= CURRENT_DATE - 30
	`, tenantID).Scan(&stats.AverageMTTRHours)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get latest compliance score
	err = r.db.QueryRowContext(ctx, `
		SELECT overall_score, max_score
		FROM compliance_snapshots
		WHERE tenant_id = $1 AND project_id IS NULL
		ORDER BY snapshot_date DESC
		LIMIT 1
	`, tenantID).Scan(&stats.CurrentComplianceScore, &stats.ComplianceMaxScore)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	return stats, nil
}

// GetSLOTargets returns SLO targets for a tenant
func (r *AnalyticsRepository) GetSLOTargets(ctx context.Context, tenantID uuid.UUID) ([]model.SLOTarget, error) {
	query := `
		SELECT DISTINCT ON (severity)
			id, tenant_id, severity, target_hours, created_at, updated_at
		FROM slo_targets
		WHERE tenant_id = $1 OR tenant_id IS NULL
		ORDER BY severity, tenant_id NULLS LAST
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []model.SLOTarget
	for rows.Next() {
		var t model.SLOTarget
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Severity, &t.TargetHours, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}

	return targets, nil
}

// UpsertSLOTarget creates or updates an SLO target
func (r *AnalyticsRepository) UpsertSLOTarget(ctx context.Context, tenantID uuid.UUID, severity string, targetHours int) error {
	query := `
		INSERT INTO slo_targets (id, tenant_id, severity, target_hours, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (tenant_id, severity)
		DO UPDATE SET target_hours = $4, updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query, uuid.New(), tenantID, severity, targetHours)
	return err
}

// CreateVulnerabilitySnapshot stores a daily snapshot
func (r *AnalyticsRepository) CreateVulnerabilitySnapshot(ctx context.Context, snapshot *model.VulnerabilitySnapshot) error {
	query := `
		INSERT INTO vulnerability_snapshots (
			id, tenant_id, snapshot_date, critical_count, high_count, medium_count, low_count,
			total_count, resolved_count, mttr_hours, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		ON CONFLICT (tenant_id, snapshot_date)
		DO UPDATE SET
			critical_count = $4, high_count = $5, medium_count = $6, low_count = $7,
			total_count = $8, resolved_count = $9, mttr_hours = $10
	`
	_, err := r.db.ExecContext(ctx, query,
		snapshot.ID, snapshot.TenantID, snapshot.SnapshotDate,
		snapshot.CriticalCount, snapshot.HighCount, snapshot.MediumCount, snapshot.LowCount,
		snapshot.TotalCount, snapshot.ResolvedCount, snapshot.MTTRHours,
	)
	return err
}

// CreateComplianceSnapshot stores a daily compliance snapshot
func (r *AnalyticsRepository) CreateComplianceSnapshot(ctx context.Context, snapshot *model.ComplianceSnapshot) error {
	query := `
		INSERT INTO compliance_snapshots (
			id, tenant_id, project_id, snapshot_date, overall_score, max_score,
			sbom_generation_score, vulnerability_management_score, license_management_score, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (tenant_id, project_id, snapshot_date)
		DO UPDATE SET
			overall_score = $5, max_score = $6,
			sbom_generation_score = $7, vulnerability_management_score = $8, license_management_score = $9
	`
	_, err := r.db.ExecContext(ctx, query,
		snapshot.ID, snapshot.TenantID, snapshot.ProjectID, snapshot.SnapshotDate,
		snapshot.OverallScore, snapshot.MaxScore,
		snapshot.SBOMGenerationScore, snapshot.VulnerabilityManagementScore, snapshot.LicenseManagementScore,
	)
	return err
}

// RecordVulnerabilityResolution records a vulnerability resolution event
func (r *AnalyticsRepository) RecordVulnerabilityResolution(ctx context.Context, event *model.VulnerabilityResolutionEvent) error {
	query := `
		INSERT INTO vulnerability_resolution_events (
			id, tenant_id, vulnerability_id, project_id, cve_id, severity,
			detected_at, resolved_at, resolution_type, resolution_notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
			resolved_at = $8,
			resolution_type = $9,
			resolution_notes = $10,
			updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		event.ID, event.TenantID, event.VulnerabilityID, event.ProjectID,
		event.CVEID, event.Severity, event.DetectedAt, event.ResolvedAt,
		event.ResolutionType, event.ResolutionNotes,
	)
	return err
}
