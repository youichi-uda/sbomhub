package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type SbomRepository struct {
	db *sql.DB
}

func NewSbomRepository(db *sql.DB) *SbomRepository {
	return &SbomRepository{db: db}
}

// Create inserts a new sbom row.
//
// tenant_id is required because:
//   - the column is NOT NULL since migration 027, and
//   - the FORCE ROW LEVEL SECURITY policy on `sboms` enforces
//     `WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::UUID)`
//     so a NULL or wrong tenant_id is rejected at INSERT time regardless of
//     the column constraint.
//
// Callers must populate s.TenantID before calling Create. SbomService /
// CLIService resolve it from the parent project (see
// LookupProjectTenantID below).
func (r *SbomRepository) Create(ctx context.Context, s *model.Sbom) error {
	query := `INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.ExecContext(ctx, query, s.ID, s.TenantID, s.ProjectID, s.Format, s.Version, s.RawData, s.CreatedAt)
	return err
}

// LookupProjectTenantID returns the tenant_id of the project that owns
// projectID. It exists so that the SbomService (which does not hold a
// reference to ProjectRepository) can populate sbom.TenantID before insert
// without growing its constructor surface, which would force changes in
// cmd/server/main.go owned by a different wave.
func (r *SbomRepository) LookupProjectTenantID(ctx context.Context, projectID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := r.db.QueryRowContext(ctx, `SELECT tenant_id FROM projects WHERE id = $1`, projectID).Scan(&tenantID)
	return tenantID, err
}

func (r *SbomRepository) GetLatest(ctx context.Context, projectID uuid.UUID) (*model.Sbom, error) {
	query := `SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = $1 ORDER BY created_at DESC LIMIT 1`
	var s model.Sbom
	err := r.db.QueryRowContext(ctx, query, projectID).Scan(&s.ID, &s.ProjectID, &s.Format, &s.Version, &s.RawData, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SbomRepository) GetByID(ctx context.Context, sbomID uuid.UUID) (*model.Sbom, error) {
	query := `SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE id = $1`
	var s model.Sbom
	err := r.db.QueryRowContext(ctx, query, sbomID).Scan(&s.ID, &s.ProjectID, &s.Format, &s.Version, &s.RawData, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SbomRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.Sbom, error) {
	query := `SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = $1 ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sboms []model.Sbom
	for rows.Next() {
		var s model.Sbom
		if err := rows.Scan(&s.ID, &s.ProjectID, &s.Format, &s.Version, &s.RawData, &s.CreatedAt); err != nil {
			return nil, err
		}
		sboms = append(sboms, s)
	}
	return sboms, nil
}
