package repository

import (
	"context"
	"database/sql"
)

type StatsRepository struct {
	db *sql.DB
}

func NewStatsRepository(db *sql.DB) *StatsRepository {
	return &StatsRepository{db: db}
}

func (r *StatsRepository) CountProjects(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM projects").Scan(&count)
	return count, err
}

func (r *StatsRepository) CountComponents(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM components").Scan(&count)
	return count, err
}

func (r *StatsRepository) CountVulnerabilities(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT vulnerability_id) FROM component_vulnerabilities").Scan(&count)
	return count, err
}
