package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ErrTenantNotFound is returned by Update / UpdatePlan / Delete when the
// statement matched no `tenants` row.
//
// M47 W2: `tenants` has no RLS (migration 007 deliberately protects only
// the per-tenant resource tables), so `WHERE id = $N` is the only guard
// these three writes have — and all three discarded their result, so a
// plan change or deletion aimed at a non-existent / already-deleted tenant
// returned nil and was reported as done. UpdatePlan is the write the M46
// cross-tenant escalation actually landed on, which is why the whole
// `tenants` group is brought under one contract here rather than just the
// method that happened to be exploited.
//
// Wraps sql.ErrNoRows for the reason documented on ErrTenantUserNotFound
// (repository/user.go): existing sql.ErrNoRows handler branches keep
// working, named errors.Is stays available.
var ErrTenantNotFound = fmt.Errorf("tenants: no row matched: %w", sql.ErrNoRows)

type TenantRepository struct {
	db *sql.DB
}

func NewTenantRepository(db *sql.DB) *TenantRepository {
	return &TenantRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
// The `tenants` table itself has no RLS, so this is purely about keeping
// reads/writes on the same pinned connection as the rest of the request.
//
// Note: Create() below opens its own BeginTx because it must seed both
// `tenants` and `scan_settings` atomically; it is only invoked from
// pre-request paths (Auth middleware bootstrap, Clerk webhook handler)
// where no request-scoped tx is open yet. Migration 048 (F185) brought
// `scan_settings` under FORCE ROW LEVEL SECURITY with WITH CHECK bound to
// `current_setting('app.current_tenant_id', true)::UUID`, so the same
// transaction must bind that GUC before the scan_settings INSERT —
// otherwise the WITH CHECK predicate evaluates against NULL, the INSERT
// is rejected, the tx rolls back, and the `tenants` INSERT is lost too.
// See F187 (M13 Phase D round 3) for the full failure trail; the integration
// test in `tenant_rls_test.go` pins the fix.
func (r *TenantRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

func (r *TenantRepository) Create(ctx context.Context, t *model.Tenant) error {
	// Use transaction to ensure both tenant and scan_settings are created atomically
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// After a successful Commit this Rollback returns sql.ErrTxDone by
	// design; anything else is a real cleanup failure worth logging
	// (middleware/tx.go / repository/checklist.go precedent).
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && rbErr != sql.ErrTxDone {
			slog.Warn("tenant create: tx rollback failed", "error", rbErr)
		}
	}()

	// Create tenant
	query := `
		INSERT INTO tenants (id, clerk_org_id, name, slug, plan, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = tx.ExecContext(ctx, query,
		t.ID, t.ClerkOrgID, t.Name, t.Slug, t.Plan, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		return err
	}

	// F187 (M13 Phase D round 3): bind `app.current_tenant_id` for the rest
	// of this transaction so the scan_settings INSERT below passes the FORCE
	// RLS WITH CHECK predicate introduced by migration 048 (F185). The `true`
	// second argument makes set_config tx-scoped (SET LOCAL semantics) so the
	// GUC does NOT leak across pooled connection re-use after Commit. Without
	// this, GetOrCreateDefault / GetOrCreateByClerkOrgID — every entry path
	// into tenant bootstrap (Auth middleware, Clerk webhook) — fails with
	// `pq: new row violates row-level security policy for table "scan_settings"`
	// and the tenant row never lands. The TenantRepository.SetCurrentTenant
	// helper does the same thing for request-scoped txns; we re-issue it
	// directly here because that helper routes through r.q(ctx) and would
	// not see our local tx.
	if _, err = tx.ExecContext(ctx,
		`SELECT set_config('app.current_tenant_id', $1, true)`, t.ID.String()); err != nil {
		return err
	}

	// Auto-create scan_settings with defaults (enabled by default)
	scanSettingsQuery := `
		INSERT INTO scan_settings (id, tenant_id, enabled, schedule_type, schedule_hour,
		                           notify_critical, notify_high, next_scan_at)
		VALUES (uuid_generate_v4(), $1, true, 'daily', 6, true, true, NOW())
	`
	_, err = tx.ExecContext(ctx, scanSettingsQuery, t.ID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (r *TenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	query := `
		SELECT id, clerk_org_id, name, slug, plan, created_at, updated_at
		FROM tenants WHERE id = $1
	`
	var t model.Tenant
	err := r.q(ctx).QueryRowContext(ctx, query, id).Scan(
		&t.ID, &t.ClerkOrgID, &t.Name, &t.Slug, &t.Plan, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TenantRepository) GetByClerkOrgID(ctx context.Context, clerkOrgID string) (*model.Tenant, error) {
	query := `
		SELECT id, clerk_org_id, name, slug, plan, created_at, updated_at
		FROM tenants WHERE clerk_org_id = $1
	`
	var t model.Tenant
	err := r.q(ctx).QueryRowContext(ctx, query, clerkOrgID).Scan(
		&t.ID, &t.ClerkOrgID, &t.Name, &t.Slug, &t.Plan, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TenantRepository) GetBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	query := `
		SELECT id, clerk_org_id, name, slug, plan, created_at, updated_at
		FROM tenants WHERE slug = $1
	`
	var t model.Tenant
	err := r.q(ctx).QueryRowContext(ctx, query, slug).Scan(
		&t.ID, &t.ClerkOrgID, &t.Name, &t.Slug, &t.Plan, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Update rewrites a tenant's name / slug / plan. 0 rows returns
// ErrTenantNotFound (M47 W2 — see the sentinel's doc comment).
func (r *TenantRepository) Update(ctx context.Context, t *model.Tenant) error {
	query := `
		UPDATE tenants SET name = $1, slug = $2, plan = $3, updated_at = $4
		WHERE id = $5
	`
	t.UpdatedAt = time.Now()
	res, err := r.q(ctx).ExecContext(ctx, query, t.Name, t.Slug, t.Plan, t.UpdatedAt, t.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update tenants (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update tenant %s: %w", t.ID, ErrTenantNotFound)
	}
	return nil
}

// UpdatePlan sets a tenant's entitlement plan. 0 rows returns
// ErrTenantNotFound.
//
// M47 W2: this is the statement the M46 cross-tenant plan escalation
// terminated in, and it was the one link in that chain that could not
// report failure at all. Every billing caller already answers 5xx on
// error, so a plan grant against a tenant that does not exist now surfaces
// instead of being logged as a successful entitlement change.
func (r *TenantRepository) UpdatePlan(ctx context.Context, id uuid.UUID, plan string) error {
	query := `UPDATE tenants SET plan = $1, updated_at = $2 WHERE id = $3`
	res, err := r.q(ctx).ExecContext(ctx, query, plan, time.Now(), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update tenants plan (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update plan of tenant %s: %w", id, ErrTenantNotFound)
	}
	return nil
}

// Delete removes a tenant (cascading every tenant-scoped child row).
// 0 rows returns ErrTenantNotFound so a deletion that never happened
// cannot be reported as one — the Clerk organization.deleted path
// pre-checks with GetByClerkOrgID, so this only fires on a genuine race.
func (r *TenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM tenants WHERE id = $1`
	res, err := r.q(ctx).ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete tenants (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("delete tenant %s: %w", id, ErrTenantNotFound)
	}
	return nil
}

func (r *TenantRepository) GetWithStats(ctx context.Context, id uuid.UUID) (*model.TenantWithStats, error) {
	query := `
		SELECT
			t.id, t.clerk_org_id, t.name, t.slug, t.plan, t.created_at, t.updated_at,
			(SELECT COUNT(*) FROM tenant_users WHERE tenant_id = t.id) as user_count,
			(SELECT COUNT(*) FROM projects WHERE tenant_id = t.id) as project_count
		FROM tenants t
		WHERE t.id = $1
	`
	var ts model.TenantWithStats
	err := r.q(ctx).QueryRowContext(ctx, query, id).Scan(
		&ts.ID, &ts.ClerkOrgID, &ts.Name, &ts.Slug, &ts.Plan,
		&ts.CreatedAt, &ts.UpdatedAt, &ts.UserCount, &ts.ProjectCount)
	if err != nil {
		return nil, err
	}
	return &ts, nil
}

// SetCurrentTenant sets the current tenant for RLS policies
// SECURITY: Uses is_local=true to scope the setting to the current transaction only
// This prevents tenant ID leakage across pooled connections
func (r *TenantRepository) SetCurrentTenant(ctx context.Context, tenantID uuid.UUID) error {
	query := `SELECT set_config('app.current_tenant_id', $1, true)`
	_, err := r.q(ctx).ExecContext(ctx, query, tenantID.String())
	return err
}

// ClearCurrentTenant clears the current tenant setting
func (r *TenantRepository) ClearCurrentTenant(ctx context.Context) error {
	query := `SELECT set_config('app.current_tenant_id', '', true)`
	_, err := r.q(ctx).ExecContext(ctx, query)
	return err
}

// ListAllIDs returns the IDs of every tenant in creation order.
//
// This is the system-level (cross-tenant) enumeration used by background jobs
// — the scheduler must visit every tenant in turn so it can open a
// `WithTxFunc` per tenant with `SET LOCAL app.current_tenant_id` set before it
// touches RLS-enabled tables. Without this, a job running on a `sbomhub_app`
// connection (NOBYPASSRLS) silently sees zero rows for projects / sboms /
// report_settings / vulnerability_tickets etc. (codex-r4 Finding P1).
//
// The `tenants` table itself is intentionally NOT RLS-enabled (see migration
// 007 — only the per-tenant resource tables are protected), so this query is
// safe to run on the raw pool without any tenant GUC.
func (r *TenantRepository) ListAllIDs(ctx context.Context) ([]uuid.UUID, error) {
	// Use r.db directly (not r.q): this is a system-level enumeration that
	// must not piggyback on any request-scoped tenant tx.
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM tenants ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

// GetOrCreateDefault returns the default tenant for self-hosted mode
// Creates one if it doesn't exist
func (r *TenantRepository) GetOrCreateDefault(ctx context.Context) (*model.Tenant, error) {
	const defaultSlug = "default"

	// Try to get existing default tenant
	t, err := r.GetBySlug(ctx, defaultSlug)
	if err == nil {
		return t, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	// Create default tenant for self-hosted mode
	now := time.Now()
	t = &model.Tenant{
		ID:         uuid.New(),
		ClerkOrgID: "self-hosted",
		Name:       "Default Organization",
		Slug:       defaultSlug,
		Plan:       model.PlanEnterprise, // Self-hosted gets all features
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := r.Create(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// GetOrCreateByClerkOrgID returns the tenant for a Clerk org ID
// Creates one if it doesn't exist (auto-provisioning for SaaS mode)
func (r *TenantRepository) GetOrCreateByClerkOrgID(ctx context.Context, clerkOrgID string, orgName string) (*model.Tenant, error) {
	// Try to get existing tenant
	t, err := r.GetByClerkOrgID(ctx, clerkOrgID)
	if err == nil {
		return t, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	// Create tenant for this Clerk org (auto-provisioning)
	now := time.Now()
	slug := clerkOrgID // Use Clerk org ID as slug for uniqueness
	if orgName == "" {
		orgName = "Organization"
	}
	t = &model.Tenant{
		ID:         uuid.New(),
		ClerkOrgID: clerkOrgID,
		Name:       orgName,
		Slug:       slug,
		Plan:       "", // Empty - user must select plan on billing page
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := r.Create(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}
