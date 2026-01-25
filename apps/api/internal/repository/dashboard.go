package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type DashboardRepository struct {
	db *sql.DB
}

func NewDashboardRepository(db *sql.DB) *DashboardRepository {
	return &DashboardRepository{db: db}
}

func (r *DashboardRepository) GetTotalProjects(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects`).Scan(&count)
	return count, err
}

func (r *DashboardRepository) GetTotalComponents(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM components`).Scan(&count)
	return count, err
}

func (r *DashboardRepository) GetVulnerabilityCounts(ctx context.Context) (model.VulnerabilityCounts, error) {
	query := `
		SELECT
			COALESCE(SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) as critical,
			COALESCE(SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END), 0) as high,
			COALESCE(SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) as medium,
			COALESCE(SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END), 0) as low
		FROM vulnerabilities v
		INNER JOIN component_vulnerabilities cv ON v.id = cv.vulnerability_id
	`
	var counts model.VulnerabilityCounts
	err := r.db.QueryRowContext(ctx, query).Scan(
		&counts.Critical,
		&counts.High,
		&counts.Medium,
		&counts.Low,
	)
	return counts, err
}

func (r *DashboardRepository) GetTopRisks(ctx context.Context, limit int) ([]model.TopRisk, error) {
	// Note: If epss_score column doesn't exist, this will still work with 0 values
	// Run 006_epss.sql migration to enable EPSS scores
	query := `
		SELECT DISTINCT ON (v.cve_id)
			v.cve_id,
			0::numeric as epss_score,
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
		ORDER BY v.cve_id, v.cvss_score DESC
	`

	// Wrap with ordering and limit
	query = `
		SELECT * FROM (` + query + `) sub
		ORDER BY cvss_score DESC
		LIMIT $1
	`

	rows, err := r.db.QueryContext(ctx, query, limit)
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

func (r *DashboardRepository) GetProjectScores(ctx context.Context) ([]model.ProjectScore, error) {
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
		GROUP BY p.id, p.name
		ORDER BY
			COALESCE(SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) DESC,
			COALESCE(SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END), 0) DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
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

func (r *DashboardRepository) GetTrend(ctx context.Context, days int) ([]model.TrendPoint, error) {
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
			WHERE cv.detected_at >= CURRENT_DATE - INTERVAL '1 day' * $1
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

	rows, err := r.db.QueryContext(ctx, query, days)
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
	err := r.db.QueryRowContext(ctx, query, projectID).Scan(
		&counts.Critical,
		&counts.High,
		&counts.Medium,
		&counts.Low,
	)
	return counts, err
}
