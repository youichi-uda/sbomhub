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

// ErrPublicLinkRowNotFound is returned by every `public_links` mutation that
// goes through execPublicLinkMutation when the statement matched no row for
// the calling tenant.
//
// The two exceptions are TryConsumeDownload and TryRegisterView, which report
// the same condition as `(false, nil)` — they are admission decisions on the
// anonymous share route, where "no row matched" is an expected answer the
// caller must branch on rather than an error it must inspect.
//
// M47 W2: `public_links` lost its RLS in migration 030, so `AND
// tenant_id = $N` is the whole boundary. Update / Delete /
// TryConsumeDownload / TryRegisterView already adjudicated their row count;
// IncrementView / IncrementDownload / UpdateCounts / Touch discarded it —
// the same table, the same predicate, four different contracts. They now
// share this one. Wraps sql.ErrNoRows — see ErrTenantUserNotFound
// (repository/user.go).
//
// M47R (Codex cross-wave review, Low): Update and Delete now use it too.
// They DID adjudicate the row count, but reported it as
// `fmt.Errorf("public link not found")` — an untyped string no caller could
// errors.Is, so PublicLinkHandler.Delete answered 500 for a link that simply
// was not there while Update answered 404 for the same condition on the same
// resource. One sentinel, one contract.
var ErrPublicLinkRowNotFound = fmt.Errorf("public_links: no row matched for this tenant: %w", sql.ErrNoRows)

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
// M46 W2 / B-1: is_active / view_count / download_count / created_at /
// updated_at were DDL-nullable with defaults (009: true / 0 / 0 / now() /
// now()); migration 058 made the first three NOT NULL. The COALESCEs
// survive for pre-058 rows and out-of-band SQL, but is_active does NOT
// take the DDL default:
//
//	is_active is AUTHORIZATION state for the anonymous
//	/api/v1/public/:token flow. Wave 2 used COALESCE(is_active, true),
//	which resolved a NULL in the ATTACKER's favour — a token holder
//	could read the SBOM of a link whose active flag was NULL (B-1
//	High-1, reproduced end-to-end in
//	service/m46_b1_public_link_failclosed_integration_test.go). It is
//	now COALESCE(is_active, false): a link that cannot prove it is
//	active is inactive. This constant is the single source for ALL read
//	paths (token, by-id, list) so the rule cannot diverge between the
//	anonymous and dashboard surfaces.
//
// The counters keep COALESCE(..., 0) — "never viewed / downloaded" is the
// safe reading there, and the cap check no longer depends on it anyway
// (see TryConsumeDownload).
const publicLinkSelectColumns = `id, tenant_id, project_id, sbom_id, token, name, expires_at, COALESCE(is_active, false),
			allowed_downloads, password_hash, COALESCE(view_count, 0), COALESCE(download_count, 0),
			COALESCE(created_at, NOW()), COALESCE(updated_at, NOW())`

func (r *PublicLinkRepository) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.PublicLink, error) {
	query := `
		SELECT ` + publicLinkSelectColumns + `
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
	if err := rows.Err(); err != nil {
		return nil, err
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
		SELECT ` + publicLinkSelectColumns + `
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
		SELECT ` + publicLinkSelectColumns + `
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
	return execPublicLinkMutation(ctx, r.q(ctx), "update link", query,
		link.Name, link.SbomID, link.ExpiresAt, link.IsActive, link.AllowedDownloads, link.PasswordHash, link.UpdatedAt,
		link.ID, tenantID,
	)
}

// Delete removes a public link restricted to the calling tenant. With RLS
// removed (migration 030) the `tenant_id = $2` clause is what stops a
// session from deleting other tenants' links by UUID.
func (r *PublicLinkRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `DELETE FROM public_links WHERE id = $1 AND tenant_id = $2`
	return execPublicLinkMutation(ctx, r.q(ctx), "delete link", query, id, tenantID)
}

// IncrementView bumps the view counter on a single link. Defense-in-depth:
// even though the caller has just successfully looked the link up by
// token, we still scope the UPDATE by (id, tenant_id) so the invariant
// "no public_links mutation crosses tenant boundaries" holds uniformly.
//
// M46 B-1 High-2: COALESCE the counter before incrementing. NULL + 1 =
// NULL in SQL, so a NULL view_count silently froze the counter forever
// (pre-058 rows / out-of-band SQL). Cosmetic here, load-bearing for the
// download counter below.
func (r *PublicLinkRepository) IncrementView(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `UPDATE public_links SET view_count = COALESCE(view_count, 0) + 1 WHERE id = $1 AND tenant_id = $2`
	return execPublicLinkMutation(ctx, r.q(ctx), "increment view_count", query, id, tenantID)
}

// IncrementDownload bumps the download counter on a single link. Same
// defense-in-depth as IncrementView.
//
// M46 B-1 High-2: the NULL + 1 = NULL freeze was an authorization bug
// here — a link with allowed_downloads = 1 and download_count = NULL
// passed `0 < 1` on every request, i.e. unlimited anonymous downloads.
// The COALESCE fixes the arithmetic; the anonymous download route uses
// TryConsumeDownload instead, which also closes the check-then-act race.
// This method remains for callers that only need the counter bumped
// (no cap semantics).
func (r *PublicLinkRepository) IncrementDownload(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `UPDATE public_links SET download_count = COALESCE(download_count, 0) + 1 WHERE id = $1 AND tenant_id = $2`
	return execPublicLinkMutation(ctx, r.q(ctx), "increment download_count", query, id, tenantID)
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
	// M46 W2: download_count COALESCE'd to its DDL default 0 (see
	// publicLinkSelectColumns) — a NULL counter means "never downloaded",
	// so the cap cannot be reached by it.
	query := `SELECT allowed_downloads, COALESCE(download_count, 0) FROM public_links WHERE id = $1 AND tenant_id = $2`
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

// publicLinkLivePredicate is the SQL form of "this share link is still
// authorized right now", evaluated server-side at the instant of the
// admission UPDATE.
//
// M46 B-1 codex round 1 / Medium-1: the anonymous flows validate
// IsActive + ExpiresAt in Go against the row read at the START of the
// request, then read the SBOM (a tenant-scoped tx, i.e. several more
// round-trips). An owner who revokes the link — or an expires_at that
// simply passes — during that window used to have no effect: the already
// loaded bytes were still sent. Making the final admission UPDATE re-check
// the same two conditions closes that window, because the UPDATE's WHERE
// is evaluated against the CURRENT committed row under a row lock.
//
// COALESCE(is_active, false) mirrors the read path: NULL is not active
// (High-1). expires_at is NOT NULL in the 009 DDL, so it needs no COALESCE.
//
// clock_timestamp(), NOT NOW() (codex round 2): NOW() is
// transaction_timestamp() — fixed when the statement's (implicit)
// transaction begins, and NOT re-read while the statement waits. An
// admission UPDATE that blocks on a row lock would otherwise evaluate
// expiry against its OWN pre-wait clock, admitting a request that queued
// one second before expires_at — exactly the window a burst of requests
// near expiry lands in. clock_timestamp() is the wall clock at the
// instant the predicate runs.
//
// It is evaluated on the FOR UPDATE-locked row, not inline in the UPDATE
// (codex round 3): under READ COMMITTED, an UPDATE that blocks on a row
// lock only re-evaluates its WHERE clause when the blocker COMMITS a
// modified row (EvalPlanQual). If the blocker ROLLS BACK — or only held
// SELECT ... FOR UPDATE — the waiting statement proceeds against the row
// it qualified BEFORE the wait, i.e. against a stale clock again. Locking
// first in a CTE and testing the locked row's values afterwards makes the
// order explicit: acquire lock, then read, then decide.
//
// COALESCE(is_active, false) mirrors the read path: NULL is not active
// (High-1). expires_at is NOT NULL in the 009 DDL, so it needs no
// COALESCE. The lock is always a primary-key lookup, so nothing here
// costs index usage.
const publicLinkLivePredicate = `COALESCE(l.is_active, false) = true AND l.expires_at > clock_timestamp()`

// publicLinkLockCTE locks the (id, tenant_id) row and exposes the columns
// the admission predicates need. FOR UPDATE returns the row as of AFTER
// the lock is granted, so a concurrent writer's committed change is
// visible and a rolled-back one is correctly ignored.
const publicLinkLockCTE = `
	WITH l AS (
		SELECT id, is_active, expires_at, allowed_downloads, download_count
		FROM public_links
		WHERE id = $1 AND tenant_id = $2
		FOR UPDATE
	)`

// TryConsumeDownload atomically re-authorizes the link AND consumes one
// download in a single statement (M46 B-1 High-2 + codex rounds 1-3).
//
// Returns true when the download was admitted (counter advanced), false
// when the link is inactive, expired, capped out, or does not exist for
// this tenant. Callers MUST NOT write response bytes when it returns
// false.
//
// Why one statement: the previous handler flow was check
// (IsDownloadLimitReached) → serve → increment, so N concurrent requests
// could all pass the check before any increment landed (TOCTOU) — a
// 1-download link could be downloaded N times. Here the row lock taken by
// the CTE serialises rivals and the cap is tested against the locked
// value, so at most allowed_downloads requests can ever succeed.
// COALESCE(download_count, 0) closes the NULL half of the bug: NULL + 1 =
// NULL never advanced the counter, making the cap unenforceable (fixed in
// migration 058 by NOT NULL; the COALESCE keeps pre-058 rows fail-closed
// too).
func (r *PublicLinkRepository) TryConsumeDownload(ctx context.Context, tenantID, id uuid.UUID) (bool, error) {
	query := publicLinkLockCTE + `
		UPDATE public_links p
		SET download_count = COALESCE(l.download_count, 0) + 1
		FROM l
		WHERE p.id = l.id
			AND ` + publicLinkLivePredicate + `
			AND (l.allowed_downloads IS NULL OR COALESCE(l.download_count, 0) < l.allowed_downloads)
	`
	result, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// TryRegisterView is the view-flow counterpart of TryConsumeDownload: it
// re-checks that the link is still active and unexpired at the moment the
// response is about to be sent, and bumps view_count in the same
// statement. Returns false when the link was revoked or expired while the
// request was assembling its view — the caller must then withhold the
// project metadata / component list it had already loaded.
//
// There is no cap on views, so this never refuses for accounting reasons.
func (r *PublicLinkRepository) TryRegisterView(ctx context.Context, tenantID, id uuid.UUID) (bool, error) {
	query := publicLinkLockCTE + `
		UPDATE public_links p
		SET view_count = COALESCE(p.view_count, 0) + 1
		FROM l
		WHERE p.id = l.id
			AND ` + publicLinkLivePredicate + `
	`
	result, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// UpdateCounts replaces view/download counters wholesale. Tenant-scoped
// for consistency with the rest of the mutating API.
func (r *PublicLinkRepository) UpdateCounts(ctx context.Context, tenantID, id uuid.UUID, viewCount, downloadCount int) error {
	query := `UPDATE public_links SET view_count = $1, download_count = $2 WHERE id = $3 AND tenant_id = $4`
	return execPublicLinkMutation(ctx, r.q(ctx), "replace counters", query, viewCount, downloadCount, id, tenantID)
}

// Touch bumps updated_at for the link. Tenant-scoped for consistency.
func (r *PublicLinkRepository) Touch(ctx context.Context, tenantID, id uuid.UUID, updatedAt time.Time) error {
	query := `UPDATE public_links SET updated_at = $1 WHERE id = $2 AND tenant_id = $3`
	return execPublicLinkMutation(ctx, r.q(ctx), "touch updated_at", query, updatedAt, id, tenantID)
}

// execPublicLinkMutation runs one tenant-scoped public_links UPDATE and
// applies the shared 0-row contract (M47 W2).
//
// Factored out rather than inlined four times so the counter/touch group
// cannot drift back into per-method contracts — drift is what produced the
// finding: four statements against the same table with the same
// `AND tenant_id = $N` predicate, none of which could report that the
// predicate had refused them.
func execPublicLinkMutation(ctx context.Context, q database.Queryable, what, query string, args ...any) error {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("public_links %s (RowsAffected): %w", what, err)
	}
	if n == 0 {
		return fmt.Errorf("public_links %s: %w", what, ErrPublicLinkRowNotFound)
	}
	return nil
}
