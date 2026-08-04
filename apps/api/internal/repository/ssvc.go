package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// M47 W2 — sentinel for the 0-row mutation contract on this repository.
// Wraps sql.ErrNoRows; see ErrTenantUserNotFound (repository/user.go)
// for why.
var (
	// ErrSSVCAssessmentNotFound is returned by UpdateAssessment when the
	// statement matched no `ssvc_assessments` row for the caller's
	// (tenant, project).
	ErrSSVCAssessmentNotFound = fmt.Errorf("ssvc_assessments: no row matched for this tenant/project: %w", sql.ErrNoRows)
)

// M47 W4 removed ErrVulnerabilityRowNotFound alongside
// UpdateVulnerabilitySSVCDecision, its only producer.

// SSVCRepository handles SSVC data access
type SSVCRepository struct {
	db *sql.DB
}

// NewSSVCRepository creates a new SSVCRepository
func NewSSVCRepository(db *sql.DB) *SSVCRepository {
	return &SSVCRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
// ssvc_assessments and ssvc_project_defaults both have RLS (migration 021),
// and the per-component scoring queries join sboms/components which also have
// FORCE RLS, so handler calls outside the tenant tx silently return no rows
// (codex-r1 Finding 2).
func (r *SSVCRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
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
	err := r.q(ctx).QueryRowContext(ctx, query, projectID).Scan(
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
//
// M47 W2 classification: BENIGN — `ON CONFLICT ... DO UPDATE` with no
// WHERE guard always affects exactly one row, so there is no 0-row
// outcome for the caller to adjudicate.
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
	_, err := r.q(ctx).ExecContext(ctx, query,
		d.ID, d.ProjectID, d.TenantID, d.MissionPrevalence, d.SafetyImpact,
		d.SystemExposure, d.AutoAssessEnabled, d.AutoAssessExploitation,
		d.AutoAssessAutomatable,
	)
	return err
}

// GetAssessment gets an assessment by project and vulnerability.
//
// M46 W2: notes is DDL-nullable TEXT (021) and NULL rows are the NORM —
// 14/14 dev-DB assessments carry NULL notes (measured 2026-07-26), so a
// bare scan into the NULL-intolerant model string aborted every
// assessment read. COALESCE to ” per the wave-1 contract (” means absent).
func (r *SSVCRepository) GetAssessment(ctx context.Context, projectID, vulnerabilityID uuid.UUID) (*model.SSVCAssessment, error) {
	query := `
		SELECT id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
			decision, exploitation_auto, automatable_auto, assessed_by, assessed_at,
			COALESCE(notes, ''), created_at, updated_at
		FROM ssvc_assessments
		WHERE project_id = $1 AND vulnerability_id = $2
	`

	var a model.SSVCAssessment
	err := r.q(ctx).QueryRowContext(ctx, query, projectID, vulnerabilityID).Scan(
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

// GetAssessmentByCVE gets an assessment by project and CVE ID.
// M46 W2: notes COALESCE'd (see GetAssessment).
func (r *SSVCRepository) GetAssessmentByCVE(ctx context.Context, projectID uuid.UUID, cveID string) (*model.SSVCAssessment, error) {
	query := `
		SELECT id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
			decision, exploitation_auto, automatable_auto, assessed_by, assessed_at,
			COALESCE(notes, ''), created_at, updated_at
		FROM ssvc_assessments
		WHERE project_id = $1 AND cve_id = $2
	`

	var a model.SSVCAssessment
	err := r.q(ctx).QueryRowContext(ctx, query, projectID, cveID).Scan(
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
	_, err := r.q(ctx).ExecContext(ctx, query,
		a.ID, a.ProjectID, a.TenantID, a.VulnerabilityID, a.CVEID,
		a.Exploitation, a.Automatable, a.TechnicalImpact, a.MissionPrevalence, a.SafetyImpact,
		a.Decision, a.ExploitationAuto, a.AutomatableAuto, a.AssessedBy, a.AssessedAt,
		a.Notes,
	)
	return err
}

// UpdateAssessment updates an existing assessment.
//
// M46 Codex final round (Medium #1, second route): cve_id is part of the SET
// list. Both service entry points derive the CVE server-side from the
// vulnerability id (SSVCService.AssessVulnerability /
// AutoAssessVulnerability -> GetCVEIDByIDInProject), so any call that
// actually reaches this UPDATE re-stamps the authoritative value and REPAIRS
// a cve_id a pre-fix caller mispaired via ?cve_id=. Leaving the column out of
// the UPDATE — the pre-fix shape — meant a spoofed pairing survived every
// subsequent legitimate assessment of that vulnerability.
//
// The repair is NOT universal, and the limit is deliberate: auto-assess
// returns an existing MANUAL assessment (both *_auto flags false) untouched
// rather than overwriting a human's judgement, so it never reaches this
// statement and never repairs such a row. A mispaired manual assessment is
// repaired by the manual route — the same route that could have created the
// mispairing — and by nothing else.
// vulnerability_id itself is deliberately NOT updatable here: it is the
// identity half of the (project_id, vulnerability_id) key the caller looked
// the row up by.
//
// M47 W2: the statement was `WHERE id = $13` with its result discarded —
// the only tenant guard was migration 042's FORCE RLS, and when that guard
// fired the UPDATE matched 0 rows and returned nil, so a refused write was
// reported as a saved assessment (and the service then went on to stamp
// the denormalised vulnerabilities.ssvc_decision from it). The statement
// now carries the same explicit `AND tenant_id AND project_id` belt its
// sibling DeleteAssessment already had — the asymmetry between the two was
// the finding — and 0 rows returns ErrSSVCAssessmentNotFound.
// a.TenantID / a.ProjectID are set by both service entry points from the
// session tenant and the route's project id, never from a request body.
func (r *SSVCRepository) UpdateAssessment(ctx context.Context, a *model.SSVCAssessment) error {
	query := `
		UPDATE ssvc_assessments SET
			cve_id = $1,
			exploitation = $2, automatable = $3, technical_impact = $4,
			mission_prevalence = $5, safety_impact = $6, decision = $7,
			exploitation_auto = $8, automatable_auto = $9, assessed_by = $10,
			assessed_at = $11, notes = $12, updated_at = NOW()
		WHERE id = $13 AND tenant_id = $14 AND project_id = $15
	`
	res, err := r.q(ctx).ExecContext(ctx, query,
		a.CVEID,
		a.Exploitation, a.Automatable, a.TechnicalImpact,
		a.MissionPrevalence, a.SafetyImpact, a.Decision,
		a.ExploitationAuto, a.AutomatableAuto, a.AssessedBy,
		a.AssessedAt, a.Notes, a.ID, a.TenantID, a.ProjectID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update ssvc_assessments (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update assessment %s for tenant %s / project %s: %w",
			a.ID, a.TenantID, a.ProjectID, ErrSSVCAssessmentNotFound)
	}
	return nil
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
	_, err := r.q(ctx).ExecContext(ctx, query,
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
	if err := r.q(ctx).QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// List query with vulnerability details.
	//
	// M46 W2: a.notes / v.severity COALESCE'd (nullable, ” means absent);
	// v.cvss_score scans into the model's *float64
	// (SSVCAssessmentWithVuln.VulnerabilityCVSSScore) — same column and
	// same no-0.0-sentinel contract as wave 1's model.Vulnerability
	// (f97c7fa): an un-scored CRITICAL must not render as CVSS 0.0.
	query := `
		SELECT a.id, a.project_id, a.tenant_id, a.vulnerability_id, a.cve_id,
			a.exploitation, a.automatable, a.technical_impact, a.mission_prevalence, a.safety_impact,
			a.decision, a.exploitation_auto, a.automatable_auto, a.assessed_by, a.assessed_at,
			COALESCE(a.notes, ''), a.created_at, a.updated_at,
			COALESCE(v.severity, ''), v.cvss_score, v.in_kev, v.epss_score
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

	rows, err := r.q(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	assessments := []model.SSVCAssessmentWithVuln{}
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
	if err := rows.Err(); err != nil {
		return nil, 0, err
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

	err := r.q(ctx).QueryRowContext(ctx, query, projectID).Scan(
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
	if err := r.q(ctx).QueryRowContext(ctx, unassessedQuery, projectID).Scan(&summary.Unassessed); err != nil {
		// Ignore error, default to 0
		summary.Unassessed = 0
	}

	return &summary, nil
}

// DeleteAssessment deletes one assessment, scoped to the caller's (tenant,
// project), and reports whether a row was actually removed.
//
// M46 Codex final round (Medium #1, route sweep): the pre-fix statement was a
// bare `DELETE FROM ssvc_assessments WHERE id = $1` whose result was
// discarded. ssvc_assessments carries FORCE RLS so cross-TENANT deletion was
// blocked, but nothing scoped the delete to the :id project the route names,
// and no application-layer tenant predicate backed the policy up — the same
// belt-and-braces the sibling meti_assessments.ClearOverride already uses
// (`WHERE tenant_id = $1 AND project_id = $2`). The discarded result is the
// other half: without it the handler returned 204 for a row it never touched.
func (r *SSVCRepository) DeleteAssessment(ctx context.Context, projectID, tenantID, id uuid.UUID) (bool, error) {
	query := `DELETE FROM ssvc_assessments WHERE id = $1 AND project_id = $2 AND tenant_id = $3`
	res, err := r.q(ctx).ExecContext(ctx, query, id, projectID, tenantID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// M47 W4 removed UpdateVulnerabilitySSVCDecision. It ran
// `UPDATE vulnerabilities SET ssvc_decision = $1, updated_at = NOW()
// WHERE id = $2` — a per-(tenant, project) decision written to the shared,
// tenant-less CVE catalogue, so the last tenant to assess a CVE overwrote
// every other tenant's decision on that row. Nothing read the column (no Go
// reader, no SELECT, no model field, no TS consumer), so the write was
// pure cross-tenant clobber with no consumer to serve. Migration 062 drops
// the column and its index. The authoritative record is the
// ssvc_assessments row — see the SSVCService doc comment.

// AssessmentInProject reports whether `id` names an ssvc_assessments row of
// the caller's (tenant, project). It is the M50 follow-up the
// GetAssessmentHistory comment below asked for: the scoped existence check
// that lets the service tell "no such assessment, or not yours" (one
// sentinel, 404) apart from "yours, and it has never changed" (200 []).
//
// It follows the route-level ownership contract documented at the head of
// scope_checks.go — explicit tenant_id / project_id predicates as the belt,
// ssvc_assessments' FORCE RLS as the braces, and (false, nil) for "absent",
// "invisible" and "someone else's" alike so the caller has ONE sentinel to
// collapse into a 404. Like GetCVEIDByIDInProject (vulnerability.go) and
// ComponentBelongsToProject (vex.go) it lives beside its caller rather than
// in scope_checks.go; that file holds the M47 W1 batch, not every predicate.
//
// Callers MUST run this inside the request's TenantTx, or the RLS half
// degrades to "0 rows" — which this reports as not-in-scope (fail closed).
//
// Shape note: SELECT EXISTS always returns exactly one row, so a false answer
// is a real "no" and never a swallowed error — unlike a QueryRow + ErrNoRows
// dance, where a scan failure and an absent row have to be told apart at
// every call site.
func (r *SSVCRepository) AssessmentInProject(ctx context.Context, projectID, tenantID, id uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || projectID == uuid.Nil || id == uuid.Nil {
		return false, nil
	}
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM ssvc_assessments
			WHERE id = $1 AND project_id = $2 AND tenant_id = $3
		)`
	var exists bool
	if err := r.q(ctx).QueryRowContext(ctx, query, id, projectID, tenantID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// GetAssessmentHistory gets history for an assessment that belongs to the
// caller's (tenant, project).
//
// M46 W2: change_reason is nullable TEXT (021) — COALESCE to ” (” means
// absent). The prev_* columns already scan into pointer types.
//
// M46 Codex final round (route sweep, round 2): ssvc_assessment_history has
// no tenant_id or project_id of its own — it hangs off assessment_id — and
// the pre-fix statement filtered on that alone. The route's :id project
// segment was therefore decorative here exactly as it was on
// DeleteAssessment: a caller could read any assessment's decision-change
// history through any of its projects' URLs. The parent row is now joined and
// constrained, which also makes the read tenant-safe through
// ssvc_assessments' FORCE RLS (belt) on top of the explicit predicate
// (braces).
//
// M50: that wave left an out-of-scope id reading as an EMPTY history and
// noted the cost — the route could not tell "no such assessment" apart from
// "this assessment has never changed" — as a follow-up. This is the
// follow-up. The statement below is UNCHANGED: it still returns rows only for
// an in-scope assessment, and an empty slice for everything else. What
// changed is upstream — SSVCService.GetAssessmentHistory now calls
// AssessmentInProject FIRST and returns ErrSSVCAssessmentNotInProject (404)
// when it is false, so the empty slice this method returns now means only
// "in scope, no recorded changes". Keeping the scoping predicate here as well
// is deliberate belt-and-braces: the existence check is an authorization
// gate, not this read's only tenancy guard.
func (r *SSVCRepository) GetAssessmentHistory(ctx context.Context, projectID, tenantID, assessmentID uuid.UUID) ([]model.SSVCAssessmentHistory, error) {
	query := `
		SELECT h.id, h.assessment_id,
			h.prev_exploitation, h.prev_automatable, h.prev_technical_impact,
			h.prev_mission_prevalence, h.prev_safety_impact, h.prev_decision,
			h.new_exploitation, h.new_automatable, h.new_technical_impact,
			h.new_mission_prevalence, h.new_safety_impact, h.new_decision,
			h.changed_by, h.changed_at, COALESCE(h.change_reason, '')
		FROM ssvc_assessment_history h
		JOIN ssvc_assessments a ON a.id = h.assessment_id
		WHERE h.assessment_id = $1 AND a.project_id = $2 AND a.tenant_id = $3
		ORDER BY h.changed_at DESC
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, assessmentID, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	history := []model.SSVCAssessmentHistory{}
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return history, nil
}

// GetImmediateAssessments gets all assessments with immediate decision for a tenant.
// M46 W2: a.notes / v.severity COALESCE'd, v.cvss_score scans into the
// model's *float64 (see ListAssessments).
func (r *SSVCRepository) GetImmediateAssessments(ctx context.Context) ([]model.SSVCAssessmentWithVuln, error) {
	query := `
		SELECT a.id, a.project_id, a.tenant_id, a.vulnerability_id, a.cve_id,
			a.exploitation, a.automatable, a.technical_impact, a.mission_prevalence, a.safety_impact,
			a.decision, a.exploitation_auto, a.automatable_auto, a.assessed_by, a.assessed_at,
			COALESCE(a.notes, ''), a.created_at, a.updated_at,
			COALESCE(v.severity, ''), v.cvss_score, v.in_kev, v.epss_score
		FROM ssvc_assessments a
		JOIN vulnerabilities v ON v.id = a.vulnerability_id
		WHERE a.decision = 'immediate'
		ORDER BY a.assessed_at DESC
	`

	rows, err := r.q(ctx).QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	assessments := []model.SSVCAssessmentWithVuln{}
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return assessments, nil
}
