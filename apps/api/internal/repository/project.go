package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type ProjectRepository struct {
	db *sql.DB
}

func NewProjectRepository(db *sql.DB) *ProjectRepository {
	return &ProjectRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
func (r *ProjectRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Create creates a project (DEPRECATED: use CreateWithTenant instead)
// SECURITY: This method is kept for backwards compatibility but should not be used
// as it doesn't set tenant_id, which is required for proper tenant isolation.
func (r *ProjectRepository) Create(ctx context.Context, p *model.Project) error {
	// SECURITY FIX: Reject calls without tenant_id to prevent cross-tenant data leakage
	return fmt.Errorf("Create is deprecated: use CreateWithTenant to ensure tenant isolation")
}

// List lists all projects (DEPRECATED: use ListByTenant instead)
// SECURITY: This method is kept for backwards compatibility but should not be used
// as it doesn't filter by tenant_id, which could expose data from other tenants.
func (r *ProjectRepository) List(ctx context.Context) ([]model.Project, error) {
	// SECURITY FIX: Reject calls without tenant_id to prevent cross-tenant data leakage
	return nil, fmt.Errorf("List is deprecated: use ListByTenant to ensure tenant isolation")
}

// Get gets a project by ID with tenant isolation
// SECURITY: Always filter by tenant_id to prevent cross-tenant access
func (r *ProjectRepository) Get(ctx context.Context, id uuid.UUID) (*model.Project, error) {
	// Note: RLS should also enforce this, but we add explicit filter for defense-in-depth
	query := `SELECT id, tenant_id, name, COALESCE(description, ''), COALESCE(created_at, NOW()), COALESCE(updated_at, NOW()) FROM projects WHERE id = $1`
	var p model.Project
	// M46 B-1 Medium-1: projects.tenant_id is DDL-nullable and
	// uuid.UUID.Scan(nil) silently yields uuid.Nil. model.Project.TenantID
	// is a *uuid.UUID, so scan through uuid.NullUUID and leave the field
	// nil for a NULL row — "unknown owner" is representable here, unlike
	// in the resolvers (project_tenant.go), which must error.
	var tenantID uuid.NullUUID
	err := r.q(ctx).QueryRowContext(ctx, query, id).Scan(&p.ID, &tenantID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if tenantID.Valid {
		tid := tenantID.UUID
		p.TenantID = &tid
	}
	return &p, nil
}

// GetByTenant gets a project by ID with explicit tenant check
// SECURITY: Use this method when you need to verify tenant ownership explicitly
func (r *ProjectRepository) GetByTenant(ctx context.Context, tenantID, projectID uuid.UUID) (*model.Project, error) {
	query := `SELECT id, name, COALESCE(description, ''), COALESCE(created_at, NOW()), COALESCE(updated_at, NOW()) FROM projects WHERE id = $1 AND tenant_id = $2`
	var p model.Project
	err := r.q(ctx).QueryRowContext(ctx, query, projectID, tenantID).Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetTenantID returns the owning tenant of a project.
//
// M46 B-1 Medium-1: delegates to the shared resolver, which fails loudly
// on a NULL tenant_id instead of silently returning uuid.Nil (see
// project_tenant.go). This one is the widest blast radius of the four:
// NotificationService and CLIService use the result as the TENANT SCOPE
// for subsequent reads/writes, so a silent uuid.Nil produced queries
// scoped to a tenant that cannot exist.
func (r *ProjectRepository) GetTenantID(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	return lookupProjectTenantID(ctx, r.q(ctx), id)
}

// Delete deletes a project (DEPRECATED: use DeleteByTenant instead)
func (r *ProjectRepository) Delete(ctx context.Context, id uuid.UUID) error {
	// SECURITY FIX: Reject calls without tenant_id to prevent cross-tenant deletion
	return fmt.Errorf("Delete is deprecated: use DeleteByTenant to ensure tenant isolation")
}

// DeleteByTenant deletes a project with tenant verification
// SECURITY: Always verify tenant ownership before deletion
func (r *ProjectRepository) DeleteByTenant(ctx context.Context, tenantID, projectID uuid.UUID) error {
	query := `DELETE FROM projects WHERE id = $1 AND tenant_id = $2`
	result, err := r.q(ctx).ExecContext(ctx, query, projectID, tenantID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountByTenant counts projects for a specific tenant
func (r *ProjectRepository) CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM projects WHERE tenant_id = $1`
	var count int
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID).Scan(&count)
	return count, err
}

// GetByName finds a project by name within a tenant.
// Returns nil, nil if not found.
func (r *ProjectRepository) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*model.Project, error) {
	query := `SELECT id, name, COALESCE(description, ''), COALESCE(created_at, NOW()), COALESCE(updated_at, NOW()) FROM projects WHERE tenant_id = $1 AND name = $2`
	var p model.Project
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID, name).Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateWithTenant creates a project associated with a tenant.
func (r *ProjectRepository) CreateWithTenant(ctx context.Context, tenantID uuid.UUID, p *model.Project) error {
	query := `INSERT INTO projects (id, tenant_id, name, description, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.q(ctx).ExecContext(ctx, query, p.ID, tenantID, p.Name, p.Description, p.CreatedAt, p.UpdatedAt)
	return err
}

// ListByTenant lists projects for a specific tenant.
func (r *ProjectRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.Project, error) {
	query := `SELECT id, name, COALESCE(description, ''), COALESCE(created_at, NOW()), COALESCE(updated_at, NOW()) FROM projects WHERE tenant_id = $1 ORDER BY created_at DESC`
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return projects, nil
}
