package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ChecklistRepository persists per-project METI checklist responses
// (manual yes/no answers for items that cannot be auto-verified).
//
// M4 Codex review round 13 / F73: every method takes tenantID as the
// first scoping argument and includes `AND tenant_id = $N` in the
// WHERE / DO UPDATE WHERE clause. This is the defense-in-depth twin of
// migration 040 (RLS ENABLE + FORCE on compliance_checklist_responses):
// even if the request middleware ever forgets to set
// app.current_tenant_id (so RLS would silently allow zero rows), the
// repository will at least refuse to operate cross-tenant by mistake
// because every method requires the caller to supply tenantID and the
// SQL filters by it. The two layers are independent and either alone
// is sufficient; we ship both so a regression in one is caught by the
// other.
type ChecklistRepository struct {
	db *sql.DB
}

func NewChecklistRepository(db *sql.DB) *ChecklistRepository {
	return &ChecklistRepository{db: db}
}

// ListByProject returns all checklist responses for a project, scoped
// to the caller's tenant. tenantID MUST come from the authenticated
// session (NOT from request path / body) -- F73 regression class.
func (r *ChecklistRepository) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.ChecklistResponse, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("ChecklistRepository.ListByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("ChecklistRepository.ListByProject: project_id is required")
	}
	query := `
		SELECT id, tenant_id, project_id, check_id, response, note, updated_by, updated_at
		FROM compliance_checklist_responses
		WHERE tenant_id = $1 AND project_id = $2
		ORDER BY check_id
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, projectID)
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

// ListByTenant returns all checklist responses for a tenant (aggregated across all projects)
// Results are ordered by check_id and updated_at DESC so the most recent note for each item comes first
func (r *ChecklistRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.ChecklistResponse, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("ChecklistRepository.ListByTenant: tenant_id is required")
	}
	query := `
		SELECT id, tenant_id, project_id, check_id, response, note, updated_by, updated_at
		FROM compliance_checklist_responses
		WHERE tenant_id = $1
		ORDER BY check_id, updated_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID)
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

// GetByCheckID returns a specific checklist response, scoped to the
// caller's tenant. F73 regression class.
func (r *ChecklistRepository) GetByCheckID(ctx context.Context, tenantID, projectID uuid.UUID, checkID string) (*model.ChecklistResponse, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("ChecklistRepository.GetByCheckID: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("ChecklistRepository.GetByCheckID: project_id is required")
	}
	query := `
		SELECT id, tenant_id, project_id, check_id, response, note, updated_by, updated_at
		FROM compliance_checklist_responses
		WHERE tenant_id = $1 AND project_id = $2 AND check_id = $3
	`
	var resp model.ChecklistResponse
	var note sql.NullString
	err := r.db.QueryRowContext(ctx, query, tenantID, projectID, checkID).Scan(
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

// Upsert creates or updates a checklist response.
//
// resp.TenantID is the WRITE intent; the ON CONFLICT DO UPDATE arm
// carries an explicit `WHERE compliance_checklist_responses.tenant_id =
// EXCLUDED.tenant_id` guard so a tenant-A session that happens to land
// on a tenant-B (project_id, check_id) row cannot overwrite it. The
// migration 040 RLS WITH CHECK clause is the primary defense; this
// app-layer guard is the F73 defense-in-depth twin -- it also makes
// the failure mode "0 rows affected" rather than "RLS error" when the
// caller passes a tenantID that disagrees with app.current_tenant_id.
func (r *ChecklistRepository) Upsert(ctx context.Context, resp *model.ChecklistResponse) error {
	if resp == nil {
		return fmt.Errorf("ChecklistRepository.Upsert: response is required")
	}
	if resp.TenantID == uuid.Nil {
		return fmt.Errorf("ChecklistRepository.Upsert: tenant_id is required")
	}
	if resp.ProjectID == uuid.Nil {
		return fmt.Errorf("ChecklistRepository.Upsert: project_id is required")
	}
	query := `
		INSERT INTO compliance_checklist_responses (id, tenant_id, project_id, check_id, response, note, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (project_id, check_id)
		DO UPDATE SET response = EXCLUDED.response,
		              note = EXCLUDED.note,
		              updated_by = EXCLUDED.updated_by,
		              updated_at = EXCLUDED.updated_at
		WHERE compliance_checklist_responses.tenant_id = EXCLUDED.tenant_id
	`
	_, err := r.db.ExecContext(ctx, query,
		resp.ID, resp.TenantID, resp.ProjectID, resp.CheckID,
		resp.Response, resp.Note, resp.UpdatedBy, resp.UpdatedAt,
	)
	return err
}

// Delete removes a checklist response, scoped to the caller's tenant.
// F73 regression class: a tenant-A session must not be able to delete
// a tenant-B row by guessing the (project_id, check_id) pair.
func (r *ChecklistRepository) Delete(ctx context.Context, tenantID, projectID uuid.UUID, checkID string) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("ChecklistRepository.Delete: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return fmt.Errorf("ChecklistRepository.Delete: project_id is required")
	}
	query := `DELETE FROM compliance_checklist_responses WHERE tenant_id = $1 AND project_id = $2 AND check_id = $3`
	_, err := r.db.ExecContext(ctx, query, tenantID, projectID, checkID)
	return err
}

// DeleteByProject removes all checklist responses for a project,
// scoped to the caller's tenant. F73 regression class.
func (r *ChecklistRepository) DeleteByProject(ctx context.Context, tenantID, projectID uuid.UUID) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("ChecklistRepository.DeleteByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return fmt.Errorf("ChecklistRepository.DeleteByProject: project_id is required")
	}
	query := `DELETE FROM compliance_checklist_responses WHERE tenant_id = $1 AND project_id = $2`
	_, err := r.db.ExecContext(ctx, query, tenantID, projectID)
	return err
}

// BulkUpsert creates or updates multiple checklist responses.
//
// Each response's TenantID must be non-nil. The ON CONFLICT DO UPDATE
// WHERE clause mirrors Upsert -- it refuses to overwrite a row that
// belongs to a different tenant. F73 regression class.
func (r *ChecklistRepository) BulkUpsert(ctx context.Context, responses []model.ChecklistResponse) error {
	if len(responses) == 0 {
		return nil
	}
	for i := range responses {
		if responses[i].TenantID == uuid.Nil {
			return fmt.Errorf("ChecklistRepository.BulkUpsert: tenant_id is required (idx %d)", i)
		}
		if responses[i].ProjectID == uuid.Nil {
			return fmt.Errorf("ChecklistRepository.BulkUpsert: project_id is required (idx %d)", i)
		}
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
		DO UPDATE SET response = EXCLUDED.response,
		              note = EXCLUDED.note,
		              updated_by = EXCLUDED.updated_by,
		              updated_at = EXCLUDED.updated_at
		WHERE compliance_checklist_responses.tenant_id = EXCLUDED.tenant_id
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
