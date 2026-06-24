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

// CountVulnerabilities returns the count of distinct vulnerabilities that
// affect components visible to the current tenant.
//
// `component_vulnerabilities` is a global join table with no `tenant_id`
// column and no RLS policy attached (Codex R15 P2 finding). Querying it
// directly — as the original implementation did — returned the cluster-wide
// distinct count, so /api/v1/stats leaked the existence and rough count of
// other tenants' vulnerable components into every tenant's dashboard.
//
// The fix is to project the join through `components`, which carries
// `tenant_id` and is protected by FORCE ROW LEVEL SECURITY (migrations
// 007_multitenancy + 023_rls_security_hardening). When this query runs
// inside a TenantTx (see `q(ctx)` above) the inner JOIN against
// `components` is automatically filtered to the current
// `app.current_tenant_id`, so the COUNT only sees vulnerability links
// owned by this tenant. Background callers without a TenantTx (none today)
// fall back to the pool connection, where FORCE RLS still rejects rows
// because no GUC is bound; the count is 0 rather than leaking.
//
// SELECT DISTINCT is preserved so a vulnerability that affects multiple
// components of the same tenant is counted once, matching the previous
// semantics.
func (r *StatsRepository) CountVulnerabilities(ctx context.Context) (int, error) {
	var count int
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT cv.vulnerability_id)
		FROM component_vulnerabilities cv
		JOIN components c ON c.id = cv.component_id
	`).Scan(&count)
	return count, err
}
