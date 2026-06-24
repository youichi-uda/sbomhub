package repository

import (
	"context"
	"database/sql"

	"github.com/sbomhub/sbomhub/internal/database"
)

type StatsRepository struct {
	db *sql.DB
}

func NewStatsRepository(db *sql.DB) *StatsRepository {
	return &StatsRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
// Without this, the COUNT(*) queries below run on a pool connection that does
// not carry the tenant GUC set by TenantTx middleware, so RLS-enforced
// projects/components rows are invisible and the dashboard returns all zeros
// (codex-r1 Finding 2).
func (r *StatsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

func (r *StatsRepository) CountProjects(ctx context.Context) (int, error) {
	var count int
	err := r.q(ctx).QueryRowContext(ctx, "SELECT COUNT(*) FROM projects").Scan(&count)
	return count, err
}

func (r *StatsRepository) CountComponents(ctx context.Context) (int, error) {
	var count int
	err := r.q(ctx).QueryRowContext(ctx, "SELECT COUNT(*) FROM components").Scan(&count)
	return count, err
}

func (r *StatsRepository) CountVulnerabilities(ctx context.Context) (int, error) {
	var count int
	err := r.q(ctx).QueryRowContext(ctx, "SELECT COUNT(DISTINCT vulnerability_id) FROM component_vulnerabilities").Scan(&count)
	return count, err
}
