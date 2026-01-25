package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type ProjectRepository struct {
	db *sql.DB
}

func NewProjectRepository(db *sql.DB) *ProjectRepository {
	return &ProjectRepository{db: db}
}

func (r *ProjectRepository) Create(ctx context.Context, p *model.Project) error {
	query := `INSERT INTO projects (id, name, description, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.ExecContext(ctx, query, p.ID, p.Name, p.Description, p.CreatedAt, p.UpdatedAt)
	return err
}

func (r *ProjectRepository) List(ctx context.Context) ([]model.Project, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM projects ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []model.Project
	for rows.Next() {
		var p model.Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, nil
}

func (r *ProjectRepository) Get(ctx context.Context, id uuid.UUID) (*model.Project, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM projects WHERE id = $1`
	var p model.Project
	err := r.db.QueryRowContext(ctx, query, id).Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *ProjectRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM projects WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}
