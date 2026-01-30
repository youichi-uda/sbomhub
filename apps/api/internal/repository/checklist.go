package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type ChecklistRepository struct {
	db *sql.DB
}

func NewChecklistRepository(db *sql.DB) *ChecklistRepository {
	return &ChecklistRepository{db: db}
}

// ListByProject returns all checklist responses for a project
func (r *ChecklistRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.ChecklistResponse, error) {
	query := `
		SELECT id, tenant_id, project_id, check_id, response, note, updated_by, updated_at
		FROM compliance_checklist_responses
		WHERE project_id = $1
		ORDER BY check_id
	`
	rows, err := r.db.QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var responses []model.ChecklistResponse
	for rows.Next() {
		var resp model.ChecklistResponse
		var note sql.NullString
		if err := rows.Scan(
			&resp.ID, &resp.TenantID, &resp.ProjectID, &resp.CheckID,
			&resp.Response, &note, &resp.UpdatedBy, &resp.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if note.Valid {
			resp.Note = &note.String
		}
		responses = append(responses, resp)
	}
	return responses, rows.Err()
}

// GetByCheckID returns a specific checklist response
func (r *ChecklistRepository) GetByCheckID(ctx context.Context, projectID uuid.UUID, checkID string) (*model.ChecklistResponse, error) {
	query := `
		SELECT id, tenant_id, project_id, check_id, response, note, updated_by, updated_at
		FROM compliance_checklist_responses
		WHERE project_id = $1 AND check_id = $2
	`
	var resp model.ChecklistResponse
	var note sql.NullString
	err := r.db.QueryRowContext(ctx, query, projectID, checkID).Scan(
		&resp.ID, &resp.TenantID, &resp.ProjectID, &resp.CheckID,
		&resp.Response, &note, &resp.UpdatedBy, &resp.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if note.Valid {
		resp.Note = &note.String
	}
	return &resp, nil
}

// Upsert creates or updates a checklist response
func (r *ChecklistRepository) Upsert(ctx context.Context, resp *model.ChecklistResponse) error {
	query := `
		INSERT INTO compliance_checklist_responses (id, tenant_id, project_id, check_id, response, note, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (project_id, check_id)
		DO UPDATE SET response = $5, note = $6, updated_by = $7, updated_at = $8
	`
	_, err := r.db.ExecContext(ctx, query,
		resp.ID, resp.TenantID, resp.ProjectID, resp.CheckID,
		resp.Response, resp.Note, resp.UpdatedBy, resp.UpdatedAt,
	)
	return err
}

// Delete removes a checklist response
func (r *ChecklistRepository) Delete(ctx context.Context, projectID uuid.UUID, checkID string) error {
	query := `DELETE FROM compliance_checklist_responses WHERE project_id = $1 AND check_id = $2`
	_, err := r.db.ExecContext(ctx, query, projectID, checkID)
	return err
}

// DeleteByProject removes all checklist responses for a project
func (r *ChecklistRepository) DeleteByProject(ctx context.Context, projectID uuid.UUID) error {
	query := `DELETE FROM compliance_checklist_responses WHERE project_id = $1`
	_, err := r.db.ExecContext(ctx, query, projectID)
	return err
}

// BulkUpsert creates or updates multiple checklist responses
func (r *ChecklistRepository) BulkUpsert(ctx context.Context, responses []model.ChecklistResponse) error {
	if len(responses) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO compliance_checklist_responses (id, tenant_id, project_id, check_id, response, note, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (project_id, check_id)
		DO UPDATE SET response = $5, note = $6, updated_by = $7, updated_at = $8
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now()
	for _, resp := range responses {
		if resp.ID == uuid.Nil {
			resp.ID = uuid.New()
		}
		resp.UpdatedAt = now
		_, err := stmt.ExecContext(ctx,
			resp.ID, resp.TenantID, resp.ProjectID, resp.CheckID,
			resp.Response, resp.Note, resp.UpdatedBy, resp.UpdatedAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
