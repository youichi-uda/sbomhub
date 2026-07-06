package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type DashboardRepository struct {
	db *sql.DB
}

func NewDashboardRepository(db *sql.DB) *DashboardRepository {
	return &DashboardRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
// Required so dashboard aggregations join projects/sboms/components under the
// tenant GUC set by TenantTx (codex-r1 Finding 2).
func (r *DashboardRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// GetTotalProjectsByTenant returns the total number of projects for a tenant
func (r *DashboardRepository) GetTotalProjectsByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.q(ctx).QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE tenant_id = $1`, tenantID).Scan(&count)
	return count, err
}

// GetTotalComponentsByTenant returns the total number of components for a tenant's projects
func (r *DashboardRepository) GetTotalComponentsByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	query := `
		SELECT COUNT(*) FROM components c
		INNER JOIN sboms s ON c.sbom_id = s.id
		INNER JOIN projects p ON s.project_id = p.id
		WHERE p.tenant_id = $1
	`
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID).Scan(&count)
	return count, err
}

// GetVulnerabilityCountsByTenant returns vulnerability counts for a tenant's projects
func (r *DashboardRepository) GetVulnerabilityCountsByTenant(ctx context.Context, tenantID uuid.UUID) (model.VulnerabilityCounts, error) {
	query := `
		SELECT
			COALESCE(SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) as critical,
			COALESCE(SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END), 0) as high,
			COALESCE(SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) as medium,
			COALESCE(SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END), 0) as low
		FROM vulnerabilities v
		INNER JOIN component_vulnerabilities cv ON v.id = cv.vulnerability_id
		INNER JOIN components c ON cv.component_id = c.id
		INNER JOIN sboms s ON c.sbom_id = s.id
		INNER JOIN projects p ON s.project_id = p.id
		WHERE p.tenant_id = $1
	`
	var counts model.VulnerabilityCounts
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID).Scan(
		&counts.Critical,
		&counts.High,
		&counts.Medium,
		&counts.Low,
	)
	return counts, err
}

// topRisksOrderBy returns the ORDER BY clause for the OUTER wrapper of the Top
// Risks query (F449 / M39). It mirrors component.go's vulnListOrderBy: only one
// of two fixed clauses is ever chosen, so sortBy is never interpolated into SQL
// and an out-of-band value degrades safely to cvss (the handler already rejects
// unknown values with 400). sortBy=="epss" orders by exploitation probability
// (migration 055's epss_score) descending with `NULLS LAST` so un-scored rows
// tail the list rather than floating above scored CRITICAL/HIGH rows (Postgres
// defaults DESC to NULLS FIRST); cvss_score is the tiebreaker. Any other value
// keeps the historical CVSS-descending order with cve_id as a stable tiebreaker.
//
// These clauses reference the OUTER wrapper's aliased columns (epss_score,
// cvss_score, cve_id from the DISTINCT ON subquery), NOT v.-prefixed columns.
// The INNER `DISTINCT ON (v.cve_id) ... ORDER BY v.cve_id, v.cvss_score DESC`
// stays unchanged (Postgres requires DISTINCT ON's leading ORDER BY to be the
// distinct expression). EPSS is a per-CVE global attribute (055 column comment),
// so the deduped row carries the correct epss_score and switching only the outer
// order is well-defined; LIMIT applies after the outer order, yielding the true
// top-N by the selected axis.
func topRisksOrderBy(sortBy string) string {
	// cve_id is the final unique tiebreaker so the LIMIT-N cutoff is
	// deterministic for rows tied on the sort key(s) (F451). cvss_score is
	// nullable on the vulnerabilities table, so NULLS LAST keeps un-scored
	// CVEs from floating to the top of the CVSS tiebreak.
	if sortBy == "epss" {
		return "ORDER BY epss_score DESC NULLS LAST, cvss_score DESC NULLS LAST, cve_id"
	}
	return "ORDER BY cvss_score DESC NULLS LAST, cve_id"
}

// GetTopRisksByTenant returns the top vulnerabilities for a tenant's projects,
// ordered by sortBy ("epss" or, for any other value, cvss — see topRisksOrderBy).
func (r *DashboardRepository) GetTopRisksByTenant(ctx context.Context, tenantID uuid.UUID, limit int, sortBy string) ([]model.TopRisk, error) {
	// M36-A / F432: epss_score is now in the canonical migration chain
	// (055_vulnerabilities_epss), so this reads the real column instead of the
	// old 0::numeric sentinel. COALESCE(v.epss_score, 0) keeps it NULL-safe: the
	// column stays NULL until the scheduled epss_sync (M36-B) populates it, and
	// scanning a SQL NULL into the bare float64 TopRisk.EPSSScore would error.
	// An un-synced row therefore still reads 0, exactly as before.
	query := `
		SELECT DISTINCT ON (v.cve_id)
			v.cve_id,
			COALESCE(v.epss_score, 0) as epss_score,
			v.cvss_score,
			v.severity,
			p.id as project_id,
			p.name as project_name,
			c.name as component_name,
			c.version as component_version
		FROM vulnerabilities v
		INNER JOIN component_vulnerabilities cv ON v.id = cv.vulnerability_id
		INNER JOIN components c ON cv.component_id = c.id
		INNER JOIN sboms s ON c.sbom_id = s.id
		INNER JOIN projects p ON s.project_id = p.id
		WHERE p.tenant_id = $1
		ORDER BY v.cve_id, v.cvss_score DESC
	`

	// Wrap with ordering and limit. Only the OUTER order switches on sortBy;
	// the INNER DISTINCT ON keeps its required per-CVE dedup order (see
	// topRisksOrderBy).
	query = `
		SELECT * FROM (` + query + `) sub
		` + topRisksOrderBy(sortBy) + `
		LIMIT $2
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var risks []model.TopRisk
	for rows.Next() {
		var risk model.TopRisk
		if err := rows.Scan(
			&risk.CVEID,
			&risk.EPSSScore,
			&risk.CVSSScore,
			&risk.Severity,
			&risk.ProjectID,
			&risk.ProjectName,
			&risk.ComponentName,
			&risk.ComponentVersion,
		); err != nil {
			return nil, err
		}
		risks = append(risks, risk)
	}

	if risks == nil {
		risks = []model.TopRisk{}
	}
	return risks, rows.Err()
}

// GetProjectScoresByTenant returns project risk scores for a tenant
func (r *DashboardRepository) GetProjectScoresByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.ProjectScore, error) {
	query := `
		SELECT
			p.id,
			p.name,
			COALESCE(SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) as critical,
			COALESCE(SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END), 0) as high,
			COALESCE(SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) as medium,
			COALESCE(SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END), 0) as low
		FROM projects p
		LEFT JOIN sboms s ON p.id = s.project_id
		LEFT JOIN components c ON s.id = c.sbom_id
		LEFT JOIN component_vulnerabilities cv ON c.id = cv.component_id
		LEFT JOIN vulnerabilities v ON cv.vulnerability_id = v.id
		WHERE p.tenant_id = $1
		GROUP BY p.id, p.name
		ORDER BY
			COALESCE(SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) DESC,
			COALESCE(SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END), 0) DESC
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scores []model.ProjectScore
	for rows.Next() {
		var score model.ProjectScore
		if err := rows.Scan(
			&score.ProjectID,
			&score.ProjectName,
			&score.Critical,
			&score.High,
			&score.Medium,
			&score.Low,
		); err != nil {
			return nil, err
		}
		// Calculate risk score (weighted)
		score.RiskScore = calculateRiskScore(score.Critical, score.High, score.Medium, score.Low)
		score.Severity = determineSeverity(score.Critical, score.High, score.Medium, score.Low)
		scores = append(scores, score)
	}

	if scores == nil {
		scores = []model.ProjectScore{}
	}
	return scores, rows.Err()
}

// GetTrendByTenant returns vulnerability trend data for a tenant
func (r *DashboardRepository) GetTrendByTenant(ctx context.Context, tenantID uuid.UUID, days int) ([]model.TrendPoint, error) {
	query := `
		WITH date_series AS (
			SELECT generate_series(
				CURRENT_DATE - INTERVAL '1 day' * $1,
				CURRENT_DATE,
				INTERVAL '1 day'
			)::date as date
		),
		daily_vulns AS (
			SELECT
				cv.detected_at::date as date,
				v.severity,
				COUNT(*) as count
			FROM component_vulnerabilities cv
			INNER JOIN vulnerabilities v ON cv.vulnerability_id = v.id
			INNER JOIN components c ON cv.component_id = c.id
			INNER JOIN sboms s ON c.sbom_id = s.id
			INNER JOIN projects p ON s.project_id = p.id
			WHERE cv.detected_at >= CURRENT_DATE - INTERVAL '1 day' * $1
			  AND p.tenant_id = $2
			GROUP BY cv.detected_at::date, v.severity
		)
		SELECT
			ds.date,
			COALESCE(SUM(CASE WHEN dv.severity = 'CRITICAL' THEN dv.count ELSE 0 END), 0) as critical,
			COALESCE(SUM(CASE WHEN dv.severity = 'HIGH' THEN dv.count ELSE 0 END), 0) as high,
			COALESCE(SUM(CASE WHEN dv.severity = 'MEDIUM' THEN dv.count ELSE 0 END), 0) as medium,
			COALESCE(SUM(CASE WHEN dv.severity = 'LOW' THEN dv.count ELSE 0 END), 0) as low
		FROM date_series ds
		LEFT JOIN daily_vulns dv ON ds.date = dv.date
		GROUP BY ds.date
		ORDER BY ds.date
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, days, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trend []model.TrendPoint
	for rows.Next() {
		var point model.TrendPoint
		if err := rows.Scan(
			&point.Date,
			&point.Critical,
			&point.High,
			&point.Medium,
			&point.Low,
		); err != nil {
			return nil, err
		}
		trend = append(trend, point)
	}

	if trend == nil {
		trend = []model.TrendPoint{}
	}
	return trend, rows.Err()
}

func calculateRiskScore(critical, high, medium, low int) int {
	// Weighted scoring: Critical=40, High=20, Medium=5, Low=1
	score := critical*40 + high*20 + medium*5 + low
	if score > 100 {
		score = 100
	}
	return score
}

func determineSeverity(critical, high, medium, low int) string {
	if critical > 0 {
		return "critical"
	}
	if high > 0 {
		return "high"
	}
	if medium > 0 {
		return "medium"
	}
	if low > 0 {
		return "low"
	}
	return "none"
}

// GetProjectVulnerabilityCounts gets vulnerability counts for a specific project
func (r *DashboardRepository) GetProjectVulnerabilityCounts(ctx context.Context, projectID uuid.UUID) (model.VulnerabilityCounts, error) {
	query := `
		SELECT
			COALESCE(SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) as critical,
			COALESCE(SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END), 0) as high,
			COALESCE(SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) as medium,
			COALESCE(SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END), 0) as low
		FROM vulnerabilities v
		INNER JOIN component_vulnerabilities cv ON v.id = cv.vulnerability_id
		INNER JOIN components c ON cv.component_id = c.id
		INNER JOIN sboms s ON c.sbom_id = s.id
		WHERE s.project_id = $1
	`
	var counts model.VulnerabilityCounts
	err := r.q(ctx).QueryRowContext(ctx, query, projectID).Scan(
		&counts.Critical,
		&counts.High,
		&counts.Medium,
		&counts.Low,
	)
	return counts, err
}
