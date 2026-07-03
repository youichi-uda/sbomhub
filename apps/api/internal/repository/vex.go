package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type VEXRepository struct {
	db *sql.DB
}

func NewVEXRepository(db *sql.DB) *VEXRepository {
	return &VEXRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
func (r *VEXRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Create inserts a new vex_statements row.
//
// tenant_id is required because vex_statements is FORCE ROW LEVEL SECURITY
// (migration 023) with `WITH CHECK (tenant_id = current_setting(
// 'app.current_tenant_id')::UUID)`. The application runtime role
// (sbomhub_app) is NOBYPASSRLS, so a missing or wrong tenant_id is rejected
// at INSERT time. Callers must populate v.TenantID before calling Create;
// VEXService resolves it from the parent project via
// LookupProjectTenantID below.
func (r *VEXRepository) Create(ctx context.Context, v *model.VEXStatement) error {
	query := `
		INSERT INTO vex_statements (id, tenant_id, project_id, vulnerability_id, component_id, status, justification, action_statement, impact_statement, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		v.ID, v.TenantID, v.ProjectID, v.VulnerabilityID, v.ComponentID,
		v.Status, v.Justification, v.ActionStatement, v.ImpactStatement,
		v.CreatedBy, v.CreatedAt, v.UpdatedAt,
	)
	return err
}

// LookupProjectTenantID returns the tenant_id of the project that owns
// projectID. It mirrors SbomRepository.LookupProjectTenantID and exists so
// VEXService can populate VEXStatement.TenantID before insert without
// growing its constructor surface (which would force a cmd/server/main.go
// change owned by a different wave).
func (r *VEXRepository) LookupProjectTenantID(ctx context.Context, projectID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := r.q(ctx).QueryRowContext(ctx, `SELECT tenant_id FROM projects WHERE id = $1`, projectID).Scan(&tenantID)
	return tenantID, err
}

// ComponentBelongsToProject reports whether componentID is a component of a
// SBOM owned by projectID (M26-D / F379 write defence, issue #131).
//
// A vex_statement carries both project_id and (optionally) component_id, but
// there is no DB constraint tying the two together (migration 045 deliberately
// leaves components without a project_id — ownership is transitive through
// sboms). So nothing at the schema level stops a statement in project A from
// referencing a component that actually lives in project B of the SAME tenant.
// The cross-project VEX suggestion feature attributes a suggestion's
// provenance to vs.project_id, so such a mis-linked component_id would make a
// suggestion claim "project A decided this" while the matched purl really came
// from project B's component — a provenance integrity break. This guard lets
// VEXService.CreateStatement reject that at write time.
//
// Tenant-scoped: components / sboms are FORCE RLS, so a caller inside a
// TenantTx only ever sees its own tenant's rows; the join additionally binds
// the component to the project via its sbom. Returns false (no error) when the
// component does not exist, is not visible, or belongs to another project.
func (r *VEXRepository) ComponentBelongsToProject(ctx context.Context, componentID, projectID uuid.UUID) (bool, error) {
	var exists bool
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM components c
			JOIN sboms s ON s.id = c.sbom_id
			WHERE c.id = $1 AND s.project_id = $2
		)`, componentID, projectID).Scan(&exists)
	return exists, err
}

// GetStatementForTenant returns the vex_statement with id, scoped to
// tenantID (M27-A / F381, issue #132). It is the tenant-scoped source
// resolver the apply flow uses: FORCE RLS already makes a foreign tenant's
// rows invisible when called inside a TenantTx (authoritative boundary),
// and the explicit `tenant_id = $2` predicate is the defence-in-depth belt
// that becomes load-bearing only if RLS is ever disabled — the same
// belt-and-braces shape as ListCrossProjectVEXCandidates. Unlike GetByID
// (which does not select or filter tenant_id), this selects tenant_id and
// pins it so a cross-tenant source_statement_id supplied by a client is
// rejected here rather than silently trusted. Returns (nil, nil) when the
// statement does not exist or is not visible to the tenant.
func (r *VEXRepository) GetStatementForTenant(ctx context.Context, tenantID, id uuid.UUID) (*model.VEXStatement, error) {
	query := `
		SELECT id, tenant_id, project_id, vulnerability_id, component_id, status, justification, action_statement, impact_statement, created_by, created_at, updated_at
		FROM vex_statements
		WHERE id = $1 AND tenant_id = $2
	`
	var v model.VEXStatement
	err := r.q(ctx).QueryRowContext(ctx, query, id, tenantID).Scan(
		&v.ID, &v.TenantID, &v.ProjectID, &v.VulnerabilityID, &v.ComponentID,
		&v.Status, &v.Justification, &v.ActionStatement, &v.ImpactStatement,
		&v.CreatedBy, &v.CreatedAt, &v.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// GetComponentPurlInProject returns the purl of componentID when it belongs
// to a SBOM owned by projectID (M27-A / F381, issue #132). It mirrors the
// ComponentBelongsToProject join but also returns the coordinate, so the
// apply flow can re-verify the M26 purl match without a second round-trip.
// found is false (no error) when the component does not exist, is not
// visible under RLS, or belongs to another project — the same
// project-level tightening WITHIN the tenant that F379 applies to reads.
// The returned purl is COALESCEd to "" so a coordinate-less component never
// scans as NULL.
func (r *VEXRepository) GetComponentPurlInProject(ctx context.Context, componentID, projectID uuid.UUID) (string, bool, error) {
	var purl string
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT COALESCE(c.purl, '')
		FROM components c
		JOIN sboms s ON s.id = c.sbom_id
		WHERE c.id = $1 AND s.project_id = $2`, componentID, projectID).Scan(&purl)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return purl, true, nil
}

// CreateProvenance inserts a vex_statement_provenance row (M27-A / F381,
// issue #132). The row must carry the same tenant_id as the target
// statement so the FORCE RLS WITH CHECK on vex_statement_provenance
// (migration 052) is satisfied — the caller (VEXService.ApplySuggestion)
// populates TenantID from the freshly-created target statement, which
// CreateStatement resolved from the target project inside the same tx.
func (r *VEXRepository) CreateProvenance(ctx context.Context, p *model.VEXStatementProvenance) error {
	query := `
		INSERT INTO vex_statement_provenance
			(id, tenant_id, target_statement_id, source_statement_id, source_project_id, applied_by, applied_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		p.ID, p.TenantID, p.TargetStatementID, p.SourceStatementID, p.SourceProjectID, p.AppliedBy, p.AppliedAt,
	)
	return err
}

func (r *VEXRepository) Update(ctx context.Context, v *model.VEXStatement) error {
	query := `
		UPDATE vex_statements
		SET status = $1, justification = $2, action_statement = $3, impact_statement = $4, updated_at = $5
		WHERE id = $6
	`
	result, err := r.q(ctx).ExecContext(ctx, query,
		v.Status, v.Justification, v.ActionStatement, v.ImpactStatement, v.UpdatedAt, v.ID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("vex statement not found")
	}
	return nil
}

func (r *VEXRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.VEXStatement, error) {
	query := `
		SELECT id, project_id, vulnerability_id, component_id, status, justification, action_statement, impact_statement, created_by, created_at, updated_at
		FROM vex_statements
		WHERE id = $1
	`
	var v model.VEXStatement
	err := r.q(ctx).QueryRowContext(ctx, query, id).Scan(
		&v.ID, &v.ProjectID, &v.VulnerabilityID, &v.ComponentID,
		&v.Status, &v.Justification, &v.ActionStatement, &v.ImpactStatement,
		&v.CreatedBy, &v.CreatedAt, &v.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (r *VEXRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.VEXStatementWithDetails, error) {
	query := `
		SELECT
			vs.id, vs.project_id, vs.vulnerability_id, vs.component_id,
			vs.status, vs.justification, vs.action_statement, vs.impact_statement,
			vs.created_by, vs.created_at, vs.updated_at,
			v.cve_id, v.severity,
			c.name, c.version
		FROM vex_statements vs
		JOIN vulnerabilities v ON v.id = vs.vulnerability_id
		LEFT JOIN components c ON c.id = vs.component_id
		WHERE vs.project_id = $1
		ORDER BY vs.updated_at DESC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statements []model.VEXStatementWithDetails
	for rows.Next() {
		var s model.VEXStatementWithDetails
		if err := rows.Scan(
			&s.ID, &s.ProjectID, &s.VulnerabilityID, &s.ComponentID,
			&s.Status, &s.Justification, &s.ActionStatement, &s.ImpactStatement,
			&s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
			&s.VulnerabilityCVEID, &s.VulnerabilitySeverity,
			&s.ComponentName, &s.ComponentVersion,
		); err != nil {
			return nil, err
		}
		statements = append(statements, s)
	}
	return statements, nil
}

func (r *VEXRepository) ListByVulnerability(ctx context.Context, vulnerabilityID uuid.UUID) ([]model.VEXStatement, error) {
	query := `
		SELECT id, project_id, vulnerability_id, component_id, status, justification, action_statement, impact_statement, created_by, created_at, updated_at
		FROM vex_statements
		WHERE vulnerability_id = $1
		ORDER BY updated_at DESC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statements []model.VEXStatement
	for rows.Next() {
		var v model.VEXStatement
		if err := rows.Scan(
			&v.ID, &v.ProjectID, &v.VulnerabilityID, &v.ComponentID,
			&v.Status, &v.Justification, &v.ActionStatement, &v.ImpactStatement,
			&v.CreatedBy, &v.CreatedAt, &v.UpdatedAt,
		); err != nil {
			return nil, err
		}
		statements = append(statements, v)
	}
	return statements, nil
}

func (r *VEXRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM vex_statements WHERE id = $1`
	result, err := r.q(ctx).ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("vex statement not found")
	}
	return nil
}

// GetByProjectAndVulnerability finds a VEX statement for a specific project/vulnerability combination
func (r *VEXRepository) GetByProjectAndVulnerability(ctx context.Context, projectID, vulnerabilityID uuid.UUID, componentID *uuid.UUID) (*model.VEXStatement, error) {
	var query string
	var args []interface{}

	if componentID == nil {
		query = `
			SELECT id, project_id, vulnerability_id, component_id, status, justification, action_statement, impact_statement, created_by, created_at, updated_at
			FROM vex_statements
			WHERE project_id = $1 AND vulnerability_id = $2 AND component_id IS NULL
		`
		args = []interface{}{projectID, vulnerabilityID}
	} else {
		query = `
			SELECT id, project_id, vulnerability_id, component_id, status, justification, action_statement, impact_statement, created_by, created_at, updated_at
			FROM vex_statements
			WHERE project_id = $1 AND vulnerability_id = $2 AND component_id = $3
		`
		args = []interface{}{projectID, vulnerabilityID, componentID}
	}

	var v model.VEXStatement
	err := r.q(ctx).QueryRowContext(ctx, query, args...).Scan(
		&v.ID, &v.ProjectID, &v.VulnerabilityID, &v.ComponentID,
		&v.Status, &v.Justification, &v.ActionStatement, &v.ImpactStatement,
		&v.CreatedBy, &v.CreatedAt, &v.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}
