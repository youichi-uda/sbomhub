package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// SSVCRepository handles SSVC data access
type SSVCRepository struct {
	db *sql.DB
}

// NewSSVCRepository creates a new SSVCRepository
func NewSSVCRepository(db *sql.DB) *SSVCRepository {
	return &SSVCRepository{db: db}
}

// GetProjectDefaults gets SSVC defaults for a project
func (r *SSVCRepository) GetProjectDefaults(ctx context.Context, projectID uuid.UUID) (*model.SSVCProjectDefaults, error) {
	query := `
		SELECT id, project_id, tenant_id, mission_prevalence, safety_impact,
			system_exposure, auto_assess_enabled, auto_assess_exploitation,
			auto_assess_automatable, created_at, updated_at
		FROM ssvc_project_defaults
		WHERE project_id = $1
	`

	var d model.SSVCProjectDefaults
	err := r.db.QueryRowContext(ctx, query, projectID).Scan(
		&d.ID, &d.ProjectID, &d.TenantID, &d.MissionPrevalence, &d.SafetyImpact,
		&d.SystemExposure, &d.AutoAssessEnabled, &d.AutoAssessExploitation,
		&d.AutoAssessAutomatable, &d.CreatedAt, &d.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &d, nil
}

// UpsertProjectDefaults creates or updates project defaults
func (r *SSVCRepository) UpsertProjectDefaults(ctx context.Context, d *model.SSVCProjectDefaults) error {
	query := `
		INSERT INTO ssvc_project_defaults (
			id, project_id, tenant_id, mission_prevalence, safety_impact,
			system_exposure, auto_assess_enabled, auto_assess_exploitation,
			auto_assess_automatable, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (project_id)
		DO UPDATE SET
			mission_prevalence = $4, safety_impact = $5, system_exposure = $6,
			auto_assess_enabled = $7, auto_assess_exploitation = $8,
			auto_assess_automatable = $9, updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		d.ID, d.ProjectID, d.TenantID, d.MissionPrevalence, d.SafetyImpact,
		d.SystemExposure, d.AutoAssessEnabled, d.AutoAssessExploitation,
		d.AutoAssessAutomatable,
	)
	return err
}

// GetAssessment gets an assessment by project and vulnerability
func (r *SSVCRepository) GetAssessment(ctx context.Context, projectID, vulnerabilityID uuid.UUID) (*model.SSVCAssessment, error) {
	query := `
		SELECT id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
			decision, exploitation_auto, automatable_auto, assessed_by, assessed_at,
			notes, created_at, updated_at
		FROM ssvc_assessments
		WHERE project_id = $1 AND vulnerability_id = $2
	`

	var a model.SSVCAssessment
	err := r.db.QueryRowContext(ctx, query, projectID, vulnerabilityID).Scan(
		&a.ID, &a.ProjectID, &a.TenantID, &a.VulnerabilityID, &a.CVEID,
		&a.Exploitation, &a.Automatable, &a.TechnicalImpact, &a.MissionPrevalence, &a.SafetyImpact,
		&a.Decision, &a.ExploitationAuto, &a.AutomatableAuto, &a.AssessedBy, &a.AssessedAt,
		&a.Notes, &a.CreatedAt, &a.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &a, nil
}

// GetAssessmentByCVE gets an assessment by project and CVE ID
func (r *SSVCRepository) GetAssessmentByCVE(ctx context.Context, projectID uuid.UUID, cveID string) (*model.SSVCAssessment, error) {
	query := `
		SELECT id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
			decision, exploitation_auto, automatable_auto, assessed_by, assessed_at,
			notes, created_at, updated_at
		FROM ssvc_assessments
		WHERE project_id = $1 AND cve_id = $2
	`

	var a model.SSVCAssessment
	err := r.db.QueryRowContext(ctx, query, projectID, cveID).Scan(
		&a.ID, &a.ProjectID, &a.TenantID, &a.VulnerabilityID, &a.CVEID,
		&a.Exploitation, &a.Automatable, &a.TechnicalImpact, &a.MissionPrevalence, &a.SafetyImpact,
		&a.Decision, &a.ExploitationAuto, &a.AutomatableAuto, &a.AssessedBy, &a.AssessedAt,
		&a.Notes, &a.CreatedAt, &a.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &a, nil
}

// CreateAssessment creates a new assessment
func (r *SSVCRepository) CreateAssessment(ctx context.Context, a *model.SSVCAssessment) error {
	query := `
		INSERT INTO ssvc_assessments (
			id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
			decision, exploitation_auto, automatable_auto, assessed_by, assessed_at,
			notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
	`
	_, err := r.db.ExecContext(ctx, query,
		a.ID, a.ProjectID, a.TenantID, a.VulnerabilityID, a.CVEID,
		a.Exploitation, a.Automatable, a.TechnicalImpact, a.MissionPrevalence, a.SafetyImpact,
		a.Decision, a.ExploitationAuto, a.AutomatableAuto, a.AssessedBy, a.AssessedAt,
		a.Notes,
	)
	return err
}

// UpdateAssessment updates an existing assessment
func (r *SSVCRepository) UpdateAssessment(ctx context.Context, a *model.SSVCAssessment) error {
	query := `
		UPDATE ssvc_assessments SET
			exploitation = $1, automatable = $2, technical_impact = $3,
			mission_prevalence = $4, safety_impact = $5, decision = $6,
			exploitation_auto = $7, automatable_auto = $8, assessed_by = $9,
			assessed_at = $10, notes = $11, updated_at = NOW()
		WHERE id = $12
	`
	_, err := r.db.ExecContext(ctx, query,
		a.Exploitation, a.Automatable, a.TechnicalImpact,
		a.MissionPrevalence, a.SafetyImpact, a.Decision,
		a.ExploitationAuto, a.AutomatableAuto, a.AssessedBy,
		a.AssessedAt, a.Notes, a.ID,
	)
	return err
}

// CreateAssessmentHistory creates a history entry
func (r *SSVCRepository) CreateAssessmentHistory(ctx context.Context, h *model.SSVCAssessmentHistory) error {
	query := `
		INSERT INTO ssvc_assessment_history (
			id, assessment_id,
			prev_exploitation, prev_automatable, prev_technical_impact,
			prev_mission_prevalence, prev_safety_impact, prev_decision,
			new_exploitation, new_automatable, new_technical_impact,
			new_mission_prevalence, new_safety_impact, new_decision,
			changed_by, changed_at, change_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := r.db.ExecContext(ctx, query,
		h.ID, h.AssessmentID,
		h.PrevExploitation, h.PrevAutomatable, h.PrevTechnicalImpact,
		h.PrevMissionPrevalence, h.PrevSafetyImpact, h.PrevDecision,
		h.NewExploitation, h.NewAutomatable, h.NewTechnicalImpact,
		h.NewMissionPrevalence, h.NewSafetyImpact, h.NewDecision,
		h.ChangedBy, h.ChangedAt, h.ChangeReason,
	)
	return err
}

// ListAssessments lists assessments for a project
func (r *SSVCRepository) ListAssessments(ctx context.Context, projectID uuid.UUID, decision *model.SSVCDecision, limit, offset int) ([]model.SSVCAssessmentWithVuln, int, error) {
	// Count query
	countQuery := `SELECT COUNT(*) FROM ssvc_assessments WHERE project_id = $1`
	countArgs := []interface{}{projectID}
	if decision != nil {
		countQuery += ` AND decision = $2`
		countArgs = append(countArgs, *decision)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// List query with vulnerability details
	query := `
		SELECT a.id, a.project_id, a.tenant_id, a.vulnerability_id, a.cve_id,
			a.exploitation, a.automatable, a.technical_impact, a.mission_prevalence, a.safety_impact,
			a.decision, a.exploitation_auto, a.automatable_auto, a.assessed_by, a.assessed_at,
			a.notes, a.created_at, a.updated_at,
			v.severity, v.cvss_score, v.in_kev, v.epss_score
		FROM ssvc_assessments a
		JOIN vulnerabilities v ON v.id = a.vulnerability_id
		WHERE a.project_id = $1
	`
	args := []interface{}{projectID}
	argIndex := 2

	if decision != nil {
		query += fmt.Sprintf(` AND a.decision = $%d`, argIndex)
		args = append(args, *decision)
		argIndex++
	}

	query += fmt.Sprintf(` ORDER BY
		CASE a.decision
			WHEN 'immediate' THEN 1
			WHEN 'out_of_cycle' THEN 2
			WHEN 'scheduled' THEN 3
			ELSE 4
		END,
		a.assessed_at DESC
		LIMIT $%d OFFSET $%d`, argIndex, argIndex+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assessments []model.SSVCAssessmentWithVuln
	for rows.Next() {
		var a model.SSVCAssessmentWithVuln
		if err := rows.Scan(
			&a.ID, &a.ProjectID, &a.TenantID, &a.VulnerabilityID, &a.CVEID,
			&a.Exploitation, &a.Automatable, &a.TechnicalImpact, &a.MissionPrevalence, &a.SafetyImpact,
			&a.Decision, &a.ExploitationAuto, &a.AutomatableAuto, &a.AssessedBy, &a.AssessedAt,
			&a.Notes, &a.CreatedAt, &a.UpdatedAt,
			&a.VulnerabilitySeverity, &a.VulnerabilityCVSSScore, &a.VulnerabilityInKEV, &a.VulnerabilityEPSSScore,
		); err != nil {
			return nil, 0, err
		}
		assessments = append(assessments, a)
	}

	return assessments, total, nil
}

// GetSummary gets assessment summary for a project
func (r *SSVCRepository) GetSummary(ctx context.Context, projectID uuid.UUID) (*model.SSVCSummary, error) {
	// Get assessment counts by decision
	query := `
		SELECT
			COUNT(*) FILTER (WHERE decision = 'immediate') as immediate,
			COUNT(*) FILTER (WHERE decision = 'out_of_cycle') as out_of_cycle,
			COUNT(*) FILTER (WHERE decision = 'scheduled') as scheduled,
			COUNT(*) FILTER (WHERE decision = 'defer') as defer,
			COUNT(*) as total
		FROM ssvc_assessments
		WHERE project_id = $1
	`

	var summary model.SSVCSummary
	summary.ProjectID = projectID

	err := r.db.QueryRowContext(ctx, query, projectID).Scan(
		&summary.Immediate, &summary.OutOfCycle, &summary.Scheduled,
		&summary.Defer, &summary.TotalAssessed,
	)
	if err != nil {
		return nil, err
	}

	// Get count of unassessed vulnerabilities
	unassessedQuery := `
		SELECT COUNT(DISTINCT cv.vulnerability_id)
		FROM component_vulnerabilities cv
		JOIN components c ON c.id = cv.component_id
		JOIN sboms s ON s.id = c.sbom_id
		WHERE s.project_id = $1
		AND NOT EXISTS (
			SELECT 1 FROM ssvc_assessments sa
			WHERE sa.project_id = $1 AND sa.vulnerability_id = cv.vulnerability_id
		)
	`
	if err := r.db.QueryRowContext(ctx, unassessedQuery, projectID).Scan(&summary.Unassessed); err != nil {
		// Ignore error, default to 0
		summary.Unassessed = 0
	}

	return &summary, nil
}

// DeleteAssessment deletes an assessment
func (r *SSVCRepository) DeleteAssessment(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM ssvc_assessments WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// UpdateVulnerabilitySSVCDecision updates the SSVC decision on the vulnerability record
func (r *SSVCRepository) UpdateVulnerabilitySSVCDecision(ctx context.Context, vulnerabilityID uuid.UUID, decision model.SSVCDecision) error {
	query := `UPDATE vulnerabilities SET ssvc_decision = $1, updated_at = NOW() WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, decision, vulnerabilityID)
	return err
}

// GetAssessmentHistory gets history for an assessment
func (r *SSVCRepository) GetAssessmentHistory(ctx context.Context, assessmentID uuid.UUID) ([]model.SSVCAssessmentHistory, error) {
	query := `
		SELECT id, assessment_id,
			prev_exploitation, prev_automatable, prev_technical_impact,
			prev_mission_prevalence, prev_safety_impact, prev_decision,
			new_exploitation, new_automatable, new_technical_impact,
			new_mission_prevalence, new_safety_impact, new_decision,
			changed_by, changed_at, change_reason
		FROM ssvc_assessment_history
		WHERE assessment_id = $1
		ORDER BY changed_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []model.SSVCAssessmentHistory
	for rows.Next() {
		var h model.SSVCAssessmentHistory
		if err := rows.Scan(
			&h.ID, &h.AssessmentID,
			&h.PrevExploitation, &h.PrevAutomatable, &h.PrevTechnicalImpact,
			&h.PrevMissionPrevalence, &h.PrevSafetyImpact, &h.PrevDecision,
			&h.NewExploitation, &h.NewAutomatable, &h.NewTechnicalImpact,
			&h.NewMissionPrevalence, &h.NewSafetyImpact, &h.NewDecision,
			&h.ChangedBy, &h.ChangedAt, &h.ChangeReason,
		); err != nil {
			return nil, err
		}
		history = append(history, h)
	}

	return history, nil
}

// GetImmediateAssessments gets all assessments with immediate decision for a tenant
func (r *SSVCRepository) GetImmediateAssessments(ctx context.Context) ([]model.SSVCAssessmentWithVuln, error) {
	query := `
		SELECT a.id, a.project_id, a.tenant_id, a.vulnerability_id, a.cve_id,
			a.exploitation, a.automatable, a.technical_impact, a.mission_prevalence, a.safety_impact,
			a.decision, a.exploitation_auto, a.automatable_auto, a.assessed_by, a.assessed_at,
			a.notes, a.created_at, a.updated_at,
			v.severity, v.cvss_score, v.in_kev, v.epss_score
		FROM ssvc_assessments a
		JOIN vulnerabilities v ON v.id = a.vulnerability_id
		WHERE a.decision = 'immediate'
		ORDER BY a.assessed_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assessments []model.SSVCAssessmentWithVuln
	for rows.Next() {
		var a model.SSVCAssessmentWithVuln
		if err := rows.Scan(
			&a.ID, &a.ProjectID, &a.TenantID, &a.VulnerabilityID, &a.CVEID,
			&a.Exploitation, &a.Automatable, &a.TechnicalImpact, &a.MissionPrevalence, &a.SafetyImpact,
			&a.Decision, &a.ExploitationAuto, &a.AutomatableAuto, &a.AssessedBy, &a.AssessedAt,
			&a.Notes, &a.CreatedAt, &a.UpdatedAt,
			&a.VulnerabilitySeverity, &a.VulnerabilityCVSSScore, &a.VulnerabilityInKEV, &a.VulnerabilityEPSSScore,
		); err != nil {
			return nil, err
		}
		assessments = append(assessments, a)
	}

	return assessments, nil
}
