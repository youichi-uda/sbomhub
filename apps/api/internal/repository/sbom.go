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

func (r *SbomRepository) Create(ctx context.Context, s *model.Sbom) error {
	query := `INSERT INTO sboms (id, project_id, format, version, raw_data, created_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.db.ExecContext(ctx, query, s.ID, s.ProjectID, s.Format, s.Version, s.RawData, s.CreatedAt)
	return err
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
