package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
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

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
// compliance_snapshots / slo_targets / vulnerability_snapshots /
// vulnerability_resolution_events all have RLS via migration 012, so analytics
// endpoints must run inside the per-request tx that TenantTx opens, or every
// chart silently flatlines (codex-r1 Finding 2).
func (r *AnalyticsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
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
		-- M49: DISTINCT ON (severity) — this CTE used to return BOTH the
		-- tenant's override and the global (tenant_id IS NULL) default for the
		-- same severity, and the bare ORDER BY did nothing to collapse them.
		-- The LEFT JOIN below then fanned every resolved row out across both
		-- rows, so a tenant that had customised even one SLO target saw that
		-- severity listed TWICE in the MTTR panel and every COUNT(*) for it
		-- doubled. GetSLOAchievement already had the DISTINCT ON; this is the
		-- same de-duplication, with the same "tenant row wins over the global
		-- default" ordering. (Found by the M49 report-period test, which read
		-- back 2 resolutions from a 1-event fixture.)
		slo AS (
			SELECT DISTINCT ON (severity) severity, target_hours
			FROM slo_targets
			WHERE tenant_id = $1 OR tenant_id IS NULL
			ORDER BY severity, tenant_id NULLS LAST
		)
		SELECT
			m.severity,
			-- M49: NOT COALESCE'd to 0. AVG over an all-NULL / empty group is
			-- SQL NULL = "nothing measured", and MTTR is a metric where LOW IS
			-- GOOD: a 0 here is the BEST possible value and makes the
			-- on-target verdict below unconditionally true. Scans into
			-- sql.NullFloat64 → *float64 (nil = not measured).
			AVG(m.hours) as mttr_hours,
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

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.MTTRResult
	for rows.Next() {
		var m model.MTTRResult
		var mttrHours sql.NullFloat64
		if err := rows.Scan(&m.Severity, &mttrHours, &m.Count, &m.TargetHours); err != nil {
			return nil, err
		}
		// M49: the on-target verdict is DERIVED, so it can only exist where
		// the measurement does. Pre-fix `m.MTTRHours <= float64(...)` was
		// evaluated on the 0 sentinel, so a severity with no remediation at
		// all was flagged on-target (0 <= every target) and rendered with a
		// green check. nil now means "no verdict".
		if mttrHours.Valid {
			hours := mttrHours.Float64
			m.MTTRHours = &hours
			onTarget := hours <= float64(m.TargetHours)
			m.OnTarget = &onTarget
		}
		results = append(results, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, days)
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
	// Checked BEFORE the empty-slice fallback: a mid-iteration failure must
	// surface as an error, not silently reroute to the fallback calculation.
	if err := rows.Err(); err != nil {
		return nil, err
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

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, days)
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
	if err := rows.Err(); err != nil {
		return nil, err
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
			-- total_count / on_target_count keep COALESCE(..., 0): these are
			-- COUNTs over the LEFT JOIN's NULL side, and "0 vulnerabilities
			-- of this severity were resolved in the window" is a TRUE count,
			-- not a stand-in for a missing measurement.
			COALESCE(r.total_count, 0) as total_count,
			COALESCE(r.on_target_count, 0) as on_target_count,
			-- M49 (supersedes M46 wave 3's belt-and-braces COALESCE): the
			-- zero-resolved arm now yields SQL NULL instead of a literal
			-- 100.0. A ratio over an empty denominator is not 100% — it is
			-- undefined, and answering "100% SLO achievement" for a severity
			-- nobody has ever remediated is the same 0-sentinel species as
			-- the MTTR below, just pointing at the other end of the scale.
			-- Scans into sql.NullFloat64 → *float64 (nil = not measured).
			CASE
				WHEN COALESCE(r.total_count, 0) = 0 THEN NULL
				ELSE (COALESCE(r.on_target_count, 0)::float / r.total_count) * 100
			END as achievement_pct,
			s.target_hours,
			-- M49: NOT COALESCE'd to 0 — see GetMTTR. On the NULL side of the
			-- LEFT JOIN (severity with no resolved rows) avg_mttr is SQL NULL
			-- and must stay NULL, not become a 0-hour remediation.
			r.avg_mttr as avg_mttr
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

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.SLOAchievement
	for rows.Next() {
		var s model.SLOAchievement
		var achievementPct, avgMTTR sql.NullFloat64
		if err := rows.Scan(&s.Severity, &s.TotalCount, &s.OnTargetCount, &achievementPct, &s.TargetHours, &avgMTTR); err != nil {
			return nil, err
		}
		if achievementPct.Valid {
			pct := achievementPct.Float64
			s.AchievementPct = &pct
		}
		if avgMTTR.Valid {
			mttr := avgMTTR.Float64
			s.AverageMTTR = &mttr
		}
		results = append(results, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
			-- M49 (supersedes M46 wave 3's COALESCE): max_score = 0 (no
			-- checklist configured yet) makes NULLIF return NULL and the whole
			-- ratio NULL — a real snapshot shape, not an FP. The old
			-- COALESCE(..., 0) then reported an unassessed tenant as "0%
			-- compliant", a measurement it never made. The NULL now flows into
			-- the *float64 ComplianceTrendPoint.Percentage (nil = not
			-- measured), matching the headline tile.
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

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.ComplianceTrendPoint
	for rows.Next() {
		var p model.ComplianceTrendPoint
		var percentage sql.NullFloat64
		if err := rows.Scan(&p.Date, &p.Score, &p.MaxScore, &percentage, &p.SBOMScore, &p.VulnerabilityScore, &p.LicenseScore); err != nil {
			return nil, err
		}
		if percentage.Valid {
			pct := percentage.Float64
			p.Percentage = &pct
		}
		results = append(results, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// GetQuickStats returns summary statistics
func (r *AnalyticsRepository) GetQuickStats(ctx context.Context, tenantID uuid.UUID) (*model.AnalyticsQuickStats, error) {
	stats := &model.AnalyticsQuickStats{}

	// Get open vulnerabilities count
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM vulnerability_resolution_events
		WHERE tenant_id = $1 AND resolved_at IS NULL
	`, tenantID).Scan(&stats.TotalOpenVulnerabilities)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get resolved in last 30 days
	err = r.q(ctx).QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM vulnerability_resolution_events
		WHERE tenant_id = $1
			AND resolved_at IS NOT NULL
			AND resolved_at >= CURRENT_DATE - 30
	`, tenantID).Scan(&stats.ResolvedLast30Days)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get average MTTR.
	//
	// M49: NOT COALESCE'd to 0. This single value drives the dashboard's
	// "average MTTR" headline tile and the executive report's summary line;
	// with no resolution in the last 30 days the AVG is SQL NULL, and the
	// old 0 told an operator (and an auditor reading the PDF) that this
	// tenant remediates instantly.
	var avgMTTRHours sql.NullFloat64
	err = r.q(ctx).QueryRowContext(ctx, `
		SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - detected_at)) / 3600)
		FROM vulnerability_resolution_events
		WHERE tenant_id = $1
			AND resolved_at IS NOT NULL
			AND resolved_at >= CURRENT_DATE - 30
	`, tenantID).Scan(&avgMTTRHours)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if avgMTTRHours.Valid {
		hours := avgMTTRHours.Float64
		stats.AverageMTTRHours = &hours
	}

	// Get latest compliance score
	err = r.q(ctx).QueryRowContext(ctx, `
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

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

// UpsertSLOTarget creates or updates an SLO target
//
// M47 W2 classification: BENIGN — `ON CONFLICT ... DO UPDATE` with no
// WHERE guard always affects exactly one row, so there is no 0-row
// outcome for the caller to adjudicate.
func (r *AnalyticsRepository) UpsertSLOTarget(ctx context.Context, tenantID uuid.UUID, severity string, targetHours int) error {
	query := `
		INSERT INTO slo_targets (id, tenant_id, severity, target_hours, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (tenant_id, severity)
		DO UPDATE SET target_hours = $4, updated_at = NOW()
	`
	_, err := r.q(ctx).ExecContext(ctx, query, uuid.New(), tenantID, severity, targetHours)
	return err
}

// CreateVulnerabilitySnapshot stores a daily snapshot
//
// M47 W2 classification: BENIGN — `ON CONFLICT ... DO UPDATE` with no
// WHERE guard always affects exactly one row, so there is no 0-row
// outcome for the caller to adjudicate.
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
	_, err := r.q(ctx).ExecContext(ctx, query,
		snapshot.ID, snapshot.TenantID, snapshot.SnapshotDate,
		snapshot.CriticalCount, snapshot.HighCount, snapshot.MediumCount, snapshot.LowCount,
		snapshot.TotalCount, snapshot.ResolvedCount, snapshot.MTTRHours,
	)
	return err
}

// CreateComplianceSnapshot stores a daily compliance snapshot
//
// M47 W2 classification: BENIGN — `ON CONFLICT ... DO UPDATE` with no
// WHERE guard always affects exactly one row, so there is no 0-row
// outcome for the caller to adjudicate.
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
	_, err := r.q(ctx).ExecContext(ctx, query,
		snapshot.ID, snapshot.TenantID, snapshot.ProjectID, snapshot.SnapshotDate,
		snapshot.OverallScore, snapshot.MaxScore,
		snapshot.SBOMGenerationScore, snapshot.VulnerabilityManagementScore, snapshot.LicenseManagementScore,
	)
	return err
}

// RecordVulnerabilityResolution records a vulnerability resolution event
//
// M47 W2 classification: BENIGN — `ON CONFLICT ... DO UPDATE` with no
// WHERE guard always affects exactly one row, so there is no 0-row
// outcome for the caller to adjudicate.
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
	_, err := r.q(ctx).ExecContext(ctx, query,
		event.ID, event.TenantID, event.VulnerabilityID, event.ProjectID,
		event.CVEID, event.Severity, event.DetectedAt, event.ResolvedAt,
		event.ResolutionType, event.ResolutionNotes,
	)
	return err
}
