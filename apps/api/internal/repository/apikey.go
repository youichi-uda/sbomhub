package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type APIKeyRepository struct {
	db *sql.DB
}

func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
//
// NOTE: GetByKeyHash runs during MultiAuth / APIKeyAuth BEFORE TenantTx
// opens its transaction, so at that point ctx carries no transaction and we
// are querying `api_keys` directly against *sql.DB. Migration 028 drops the
// RLS policy on `api_keys` precisely so this authn lookup can succeed under
// the non-superuser `sbomhub_app` role; tenant scope on every other access
// path is enforced in this file via an explicit `tenant_id = $N` clause —
// see GetByID, ListByTenant, ListByProject, Delete*, UpdateLastUsed.
func (r *APIKeyRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

func (r *APIKeyRepository) Create(ctx context.Context, k *model.APIKey) error {
	query := `
		INSERT INTO api_keys (id, tenant_id, project_id, name, key_hash, key_prefix, permissions, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		k.ID, k.TenantID, k.ProjectID, k.Name, k.KeyHash, k.KeyPrefix, k.Permissions, k.ExpiresAt, k.CreatedAt,
	)
	return err
}

// GetByID looks up a single API key restricted to the calling tenant.
//
// Tenant scope is enforced here at the application layer because migration
// 028 dropped the RLS policy on `api_keys` (the authn lookup by key_hash
// has to run before the tenant is known). Callers MUST pass the tenant
// derived from the authenticated session — never a tenant_id read from a
// user-supplied request body — otherwise this becomes a cross-tenant
// information-disclosure primitive.
func (r *APIKeyRepository) GetByID(ctx context.Context, tenantID, id uuid.UUID) (*model.APIKey, error) {
	query := `
		SELECT id, tenant_id, project_id, name, key_hash, key_prefix, permissions, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE id = $1 AND tenant_id = $2
	`
	var k model.APIKey
	err := r.q(ctx).QueryRowContext(ctx, query, id, tenantID).Scan(
		&k.ID, &k.TenantID, &k.ProjectID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.Permissions, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// GetByKeyHash is the authentication lookup: given a SHA-256 of the raw
// `sbh_...` bearer token, return the owning row (which carries tenant_id).
// It is intentionally tenant-UNSCOPED — this is the call that decides which
// tenant the caller belongs to. All other reads MUST go through tenant-
// scoped helpers (GetByID, ListByTenant, ListByProject).
func (r *APIKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*model.APIKey, error) {
	query := `
		SELECT id, tenant_id, project_id, name, key_hash, key_prefix, permissions, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE key_hash = $1
	`
	var k model.APIKey
	err := r.q(ctx).QueryRowContext(ctx, query, keyHash).Scan(
		&k.ID, &k.TenantID, &k.ProjectID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.Permissions, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// ListByTenant returns all API keys for a tenant. With RLS gone (migration
// 028) this is the only safe way to list keys; the `tenant_id = $1` filter
// is what isolates tenants.
func (r *APIKeyRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.APIKey, error) {
	query := `
		SELECT id, tenant_id, project_id, name, key_hash, key_prefix, permissions, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []model.APIKey
	for rows.Next() {
		var k model.APIKey
		if err := rows.Scan(
			&k.ID, &k.TenantID, &k.ProjectID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.Permissions, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
		); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// ListByProject returns all API keys for a given project, restricted to the
// caller's tenant. Legacy / deprecated path. The tenant_id filter is what
// stops a caller from probing other tenants' projects by ID.
func (r *APIKeyRepository) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.APIKey, error) {
	query := `
		SELECT id, tenant_id, project_id, name, key_hash, key_prefix, permissions, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE project_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []model.APIKey
	for rows.Next() {
		var k model.APIKey
		if err := rows.Scan(
			&k.ID, &k.TenantID, &k.ProjectID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.Permissions, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
		); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Delete removes an API key restricted to the calling tenant. RLS is no
// longer enforcing the tenant scope (migration 028) so the `tenant_id = $2`
// clause is load-bearing — without it any authenticated session could
// delete any other tenant's key.
func (r *APIKeyRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2`
	result, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

// DeleteByTenant is the explicit tenant-scoped delete used by the new
// /apikeys/:key_id endpoint. Functionally equivalent to Delete; kept for
// callers that prefer the more explicit name.
func (r *APIKeyRepository) DeleteByTenant(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2`
	result, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("api key not found or not authorized")
	}
	return nil
}

// UpdateLastUsed bumps the last_used_at timestamp. We restrict the UPDATE
// to (id, tenant_id) as defense-in-depth even though the caller has just
// verified the key via GetByKeyHash and already knows the tenant — keeps
// the invariant "no api_keys mutation crosses tenant boundaries" uniform.
func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `UPDATE api_keys SET last_used_at = $1 WHERE id = $2 AND tenant_id = $3`
	_, err := r.q(ctx).ExecContext(ctx, query, time.Now(), id, tenantID)
	return err
}
