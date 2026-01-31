package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type TenantRepository struct {
	db *sql.DB
}

func NewTenantRepository(db *sql.DB) *TenantRepository {
	return &TenantRepository{db: db}
}

func (r *TenantRepository) Create(ctx context.Context, t *model.Tenant) error {
	query := `
		INSERT INTO tenants (id, clerk_org_id, name, slug, plan, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.ExecContext(ctx, query,
		t.ID, t.ClerkOrgID, t.Name, t.Slug, t.Plan, t.CreatedAt, t.UpdatedAt)
	return err
}

func (r *TenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	query := `
		SELECT id, clerk_org_id, name, slug, plan, created_at, updated_at
		FROM tenants WHERE id = $1
	`
	var t model.Tenant
	err := r.db.QueryRowContext(ctx, query, id).Scan(
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
	err := r.db.QueryRowContext(ctx, query, clerkOrgID).Scan(
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
	err := r.db.QueryRowContext(ctx, query, slug).Scan(
		&t.ID, &t.ClerkOrgID, &t.Name, &t.Slug, &t.Plan, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TenantRepository) Update(ctx context.Context, t *model.Tenant) error {
	query := `
		UPDATE tenants SET name = $1, slug = $2, plan = $3, updated_at = $4
		WHERE id = $5
	`
	t.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, query, t.Name, t.Slug, t.Plan, t.UpdatedAt, t.ID)
	return err
}

func (r *TenantRepository) UpdatePlan(ctx context.Context, id uuid.UUID, plan string) error {
	query := `UPDATE tenants SET plan = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, plan, time.Now(), id)
	return err
}

func (r *TenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM tenants WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
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
	err := r.db.QueryRowContext(ctx, query, id).Scan(
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
	_, err := r.db.ExecContext(ctx, query, tenantID.String())
	return err
}

// ClearCurrentTenant clears the current tenant setting
func (r *TenantRepository) ClearCurrentTenant(ctx context.Context) error {
	query := `SELECT set_config('app.current_tenant_id', '', true)`
	_, err := r.db.ExecContext(ctx, query)
	return err
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
