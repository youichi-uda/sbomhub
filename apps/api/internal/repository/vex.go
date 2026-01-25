package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type VEXRepository struct {
	db *sql.DB
}

func NewVEXRepository(db *sql.DB) *VEXRepository {
	return &VEXRepository{db: db}
}

func (r *VEXRepository) Create(ctx context.Context, v *model.VEXStatement) error {
	query := `
		INSERT INTO vex_statements (id, project_id, vulnerability_id, component_id, status, justification, action_statement, impact_statement, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := r.db.ExecContext(ctx, query,
		v.ID, v.ProjectID, v.VulnerabilityID, v.ComponentID,
		v.Status, v.Justification, v.ActionStatement, v.ImpactStatement,
		v.CreatedBy, v.CreatedAt, v.UpdatedAt,
	)
	return err
}

func (r *VEXRepository) Update(ctx context.Context, v *model.VEXStatement) error {
	query := `
		UPDATE vex_statements
		SET status = $1, justification = $2, action_statement = $3, impact_statement = $4, updated_at = $5
		WHERE id = $6
	`
	result, err := r.db.ExecContext(ctx, query,
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
	err := r.db.QueryRowContext(ctx, query, id).Scan(
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
	rows, err := r.db.QueryContext(ctx, query, projectID)
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
	rows, err := r.db.QueryContext(ctx, query, vulnerabilityID)
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
	result, err := r.db.ExecContext(ctx, query, id)
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
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
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
