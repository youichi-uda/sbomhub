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

type PublicLinkRepository struct {
	db *sql.DB
}

func NewPublicLinkRepository(db *sql.DB) *PublicLinkRepository {
	return &PublicLinkRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
//
// RLS history note: migration 009 originally put public_links and
// public_link_access_logs under tenant-scoped RLS policies. That broke the
// anonymous /api/v1/public/:token endpoint because the token lookup has to
// run before any tenant context can be established (the lookup is itself
// what reveals which tenant the link belongs to). Migration 030 dropped the
// policies; tenant scope on every dashboard-side read/mutation is now
// enforced by explicit `tenant_id = $N` clauses in this file, and the
// token-by-secret lookup runs deliberately unscoped (the 256-bit token is
// the application-layer secret). See migration 030 and Trust Rescue
// codex-r5 for the full rationale.
func (r *PublicLinkRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

func (r *PublicLinkRepository) Create(ctx context.Context, link *model.PublicLink) error {
	query := `
		INSERT INTO public_links (
			id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		link.ID, link.TenantID, link.ProjectID, link.SbomID, link.Token, link.Name, link.ExpiresAt, link.IsActive,
		link.AllowedDownloads, link.PasswordHash, link.ViewCount, link.DownloadCount, link.CreatedAt, link.UpdatedAt,
	)
	return err
}

// ListByProject returns the public links for a (tenant, project) pair. The
// `tenant_id = $2` filter is load-bearing: migration 030 removed the RLS
// policy on public_links, so this clause is what isolates tenants from
// probing each other's project IDs.
func (r *PublicLinkRepository) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.PublicLink, error) {
	query := `
		SELECT id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at
		FROM public_links
		WHERE project_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []model.PublicLink
	for rows.Next() {
		var link model.PublicLink
		var passwordHash sql.NullString
		if err := rows.Scan(
			&link.ID, &link.TenantID, &link.ProjectID, &link.SbomID, &link.Token, &link.Name, &link.ExpiresAt, &link.IsActive,
			&link.AllowedDownloads, &passwordHash, &link.ViewCount, &link.DownloadCount, &link.CreatedAt, &link.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if passwordHash.Valid {
			link.PasswordHash = &passwordHash.String
		}
		links = append(links, link)
	}
	return links, nil
}

// GetByID looks up a single public link restricted to the calling tenant.
//
// Tenant scope is enforced here at the application layer because migration
// 030 dropped the RLS policy on public_links. Callers MUST pass the tenant
// derived from the authenticated session — never a tenant_id read from a
// user-supplied request body — otherwise this becomes a cross-tenant
// information-disclosure primitive.
func (r *PublicLinkRepository) GetByID(ctx context.Context, tenantID, id uuid.UUID) (*model.PublicLink, error) {
	query := `
		SELECT id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at
		FROM public_links
		WHERE id = $1 AND tenant_id = $2
	`
	var link model.PublicLink
	var passwordHash sql.NullString
	err := r.q(ctx).QueryRowContext(ctx, query, id, tenantID).Scan(
		&link.ID, &link.TenantID, &link.ProjectID, &link.SbomID, &link.Token, &link.Name, &link.ExpiresAt, &link.IsActive,
		&link.AllowedDownloads, &passwordHash, &link.ViewCount, &link.DownloadCount, &link.CreatedAt, &link.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if passwordHash.Valid {
		link.PasswordHash = &passwordHash.String
	}
	return &link, nil
}

// GetByToken is the public-share lookup: given the share token (64 hex
// chars = 256 bits of entropy from crypto/rand), return the owning row
// (which carries tenant_id, project_id and the optional sbom_id).
//
// It is intentionally tenant-UNSCOPED — this is the call that decides
// which tenant the anonymous caller is looking at. All other reads MUST
// go through tenant-scoped helpers (GetByID, ListByProject). The token
// itself is the application-layer secret; cross-tenant access requires
// guessing a 256-bit random string.
func (r *PublicLinkRepository) GetByToken(ctx context.Context, token string) (*model.PublicLink, error) {
	query := `
		SELECT id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at
		FROM public_links
		WHERE token = $1
	`
	var link model.PublicLink
	var passwordHash sql.NullString
	err := r.q(ctx).QueryRowContext(ctx, query, token).Scan(
		&link.ID, &link.TenantID, &link.ProjectID, &link.SbomID, &link.Token, &link.Name, &link.ExpiresAt, &link.IsActive,
		&link.AllowedDownloads, &passwordHash, &link.ViewCount, &link.DownloadCount, &link.CreatedAt, &link.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if passwordHash.Valid {
		link.PasswordHash = &passwordHash.String
	}
	return &link, nil
}

// Update mutates a public link restricted to the calling tenant. With RLS
// removed (migration 030), the `tenant_id = $9` filter is load-bearing —
// without it a session could mutate other tenants' links by UUID.
func (r *PublicLinkRepository) Update(ctx context.Context, tenantID uuid.UUID, link *model.PublicLink) error {
	query := `
		UPDATE public_links
		SET name = $1, sbom_id = $2, expires_at = $3, is_active = $4, allowed_downloads = $5, password_hash = $6,
			updated_at = $7
		WHERE id = $8 AND tenant_id = $9
	`
	result, err := r.q(ctx).ExecContext(ctx, query,
		link.Name, link.SbomID, link.ExpiresAt, link.IsActive, link.AllowedDownloads, link.PasswordHash, link.UpdatedAt,
		link.ID, tenantID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("public link not found")
	}
	return nil
}

// Delete removes a public link restricted to the calling tenant. With RLS
// removed (migration 030) the `tenant_id = $2` clause is what stops a
// session from deleting other tenants' links by UUID.
func (r *PublicLinkRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `DELETE FROM public_links WHERE id = $1 AND tenant_id = $2`
	result, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("public link not found")
	}
	return nil
}

// IncrementView bumps the view counter on a single link. Defense-in-depth:
// even though the caller has just successfully looked the link up by
// token, we still scope the UPDATE by (id, tenant_id) so the invariant
// "no public_links mutation crosses tenant boundaries" holds uniformly.
func (r *PublicLinkRepository) IncrementView(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `UPDATE public_links SET view_count = view_count + 1 WHERE id = $1 AND tenant_id = $2`
	_, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	return err
}

// IncrementDownload bumps the download counter on a single link. Same
// defense-in-depth as IncrementView.
func (r *PublicLinkRepository) IncrementDownload(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `UPDATE public_links SET download_count = download_count + 1 WHERE id = $1 AND tenant_id = $2`
	_, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	return err
}

// CreateAccessLog inserts a row into public_link_access_logs. The table's
// RLS policy was removed alongside public_links in migration 030; the
// public_link_id FK + ON DELETE CASCADE provides natural tenant scoping
// because access-log rows die with their parent link. No reader API
// exists for this table, so no extra application-layer filter is needed
// on the write side.
func (r *PublicLinkRepository) CreateAccessLog(ctx context.Context, log *model.PublicLinkAccessLog) error {
	query := `
		INSERT INTO public_link_access_logs (
			id, public_link_id, action, ip_address, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		log.ID, log.PublicLinkID, log.Action, log.IPAddress, log.UserAgent, log.CreatedAt,
	)
	return err
}

// IsDownloadLimitReached checks whether the optional per-link download cap
// has been reached. Scoped by (id, tenant_id) so callers cannot use this
// to probe whether arbitrary link UUIDs exist across tenants.
func (r *PublicLinkRepository) IsDownloadLimitReached(ctx context.Context, tenantID, id uuid.UUID) (bool, error) {
	query := `SELECT allowed_downloads, download_count FROM public_links WHERE id = $1 AND tenant_id = $2`
	var allowed sql.NullInt64
	var downloaded int
	if err := r.q(ctx).QueryRowContext(ctx, query, id, tenantID).Scan(&allowed, &downloaded); err != nil {
		return false, err
	}
	if !allowed.Valid {
		return false, nil
	}
	return downloaded >= int(allowed.Int64), nil
}

// UpdateCounts replaces view/download counters wholesale. Tenant-scoped
// for consistency with the rest of the mutating API.
func (r *PublicLinkRepository) UpdateCounts(ctx context.Context, tenantID, id uuid.UUID, viewCount, downloadCount int) error {
	query := `UPDATE public_links SET view_count = $1, download_count = $2 WHERE id = $3 AND tenant_id = $4`
	_, err := r.q(ctx).ExecContext(ctx, query, viewCount, downloadCount, id, tenantID)
	return err
}

// Touch bumps updated_at for the link. Tenant-scoped for consistency.
func (r *PublicLinkRepository) Touch(ctx context.Context, tenantID, id uuid.UUID, updatedAt time.Time) error {
	query := `UPDATE public_links SET updated_at = $1 WHERE id = $2 AND tenant_id = $3`
	_, err := r.q(ctx).ExecContext(ctx, query, updatedAt, id, tenantID)
	return err
}
