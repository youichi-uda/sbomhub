package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// M47 W2 — sentinels for the 0-row mutation contract on this repository.
//
// `ExecContext` returns a nil error for an UPDATE/DELETE that matched no
// row, so every mutation below that discarded its result reported a
// BLOCKED write as a completed one. That is the exact mechanism behind the
// M46 cross-tenant plan escalation (see repository/subscription.go and
// commit 08f98ae), and it bites hardest here: `users` and `tenant_users`
// carry NO row-level security at all (verified against pg_class), so the
// `WHERE tenant_id = $N AND user_id = $M` predicate is the ENTIRE tenant
// boundary for membership writes. A silently-0-row DELETE meant
// "remove this member" succeeded while the membership survived.
//
// Both sentinels WRAP sql.ErrNoRows. That is deliberate and follows the
// dominant shape already in this package (ProjectRepository.DeleteByTenant,
// CRAReportsRepository.UpdateDecision, MetiAssessmentsRepository.
// OverrideStatus, VEXDraftsRepository.UpdateDecision all answer a 0-row
// mutation with sql.ErrNoRows): callers that already map sql.ErrNoRows to
// 404 / idempotent-success keep working unchanged, while callers that need
// to distinguish WHICH resource was missing can errors.Is the named
// sentinel. Callers that legitimately tolerate a no-op must say so
// explicitly with errors.Is rather than by not looking.
var (
	// ErrUserNotFound is returned by Update / Delete when the statement
	// matched no `users` row.
	ErrUserNotFound = fmt.Errorf("users: no row matched: %w", sql.ErrNoRows)

	// ErrTenantUserNotFound is returned by RemoveFromTenant / UpdateRole
	// when the statement matched no `tenant_users` row — i.e. that user is
	// not a member of that tenant. Because `tenant_users` has no RLS, this
	// is also what a cross-tenant membership write looks like.
	ErrTenantUserNotFound = fmt.Errorf("tenant_users: no membership row matched for this tenant: %w", sql.ErrNoRows)
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, u *model.User) error {
	query := `
		INSERT INTO users (id, clerk_user_id, email, name, avatar_url, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.ExecContext(ctx, query,
		u.ID, u.ClerkUserID, u.Email, u.Name, u.AvatarURL, u.CreatedAt, u.UpdatedAt)
	return err
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	query := `
		SELECT id, clerk_user_id, email, COALESCE(name, ''), COALESCE(avatar_url, ''), created_at, updated_at
		FROM users WHERE id = $1
	`
	var u model.User
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID, &u.ClerkUserID, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) GetByClerkUserID(ctx context.Context, clerkUserID string) (*model.User, error) {
	query := `
		SELECT id, clerk_user_id, email, COALESCE(name, ''), COALESCE(avatar_url, ''), created_at, updated_at
		FROM users WHERE clerk_user_id = $1
	`
	var u model.User
	err := r.db.QueryRowContext(ctx, query, clerkUserID).Scan(
		&u.ID, &u.ClerkUserID, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `
		SELECT id, clerk_user_id, email, COALESCE(name, ''), COALESCE(avatar_url, ''), created_at, updated_at
		FROM users WHERE email = $1
	`
	var u model.User
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&u.ID, &u.ClerkUserID, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// Update rewrites a user's profile. 0 rows returns ErrUserNotFound (M47
// W2): the pre-fix statement discarded its result, so an update aimed at a
// stale / deleted user id was indistinguishable from a completed write and
// the caller went on to report success.
func (r *UserRepository) Update(ctx context.Context, u *model.User) error {
	query := `
		UPDATE users SET email = $1, name = $2, avatar_url = $3, updated_at = $4
		WHERE id = $5
	`
	u.UpdatedAt = time.Now()
	res, err := r.db.ExecContext(ctx, query, u.Email, u.Name, u.AvatarURL, u.UpdatedAt, u.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update users (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update user %s: %w", u.ID, ErrUserNotFound)
	}
	return nil
}

// Delete removes a user row. 0 rows returns ErrUserNotFound so a deletion
// that never happened cannot be reported as one (M47 W2). The Clerk
// user.deleted path pre-checks existence with GetByClerkUserID, so this
// only fires on a genuine race — which is exactly the case that must be
// redelivered rather than swallowed.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	res, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete users (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("delete user %s: %w", id, ErrUserNotFound)
	}
	return nil
}

// Upsert creates or updates a user (used by Clerk webhook).
//
// M47 W2 classification: BENIGN. `ON CONFLICT (clerk_user_id) DO UPDATE`
// carries no WHERE, so the statement always affects exactly one row —
// there is no 0-row outcome to check.
func (r *UserRepository) Upsert(ctx context.Context, u *model.User) error {
	query := `
		INSERT INTO users (id, clerk_user_id, email, name, avatar_url, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (clerk_user_id) DO UPDATE SET
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			avatar_url = EXCLUDED.avatar_url,
			updated_at = EXCLUDED.updated_at
	`
	_, err := r.db.ExecContext(ctx, query,
		u.ID, u.ClerkUserID, u.Email, u.Name, u.AvatarURL, u.CreatedAt, u.UpdatedAt)
	return err
}

// AddToTenant adds a user to a tenant.
//
// M47 W2 classification: BENIGN. `ON CONFLICT (tenant_id, user_id) DO
// UPDATE` has no WHERE guard, so it always affects exactly one row.
func (r *UserRepository) AddToTenant(ctx context.Context, tu *model.TenantUser) error {
	query := `
		INSERT INTO tenant_users (tenant_id, user_id, role, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role
	`
	_, err := r.db.ExecContext(ctx, query, tu.TenantID, tu.UserID, tu.Role, tu.CreatedAt)
	return err
}

// RemoveFromTenant removes a user from a tenant.
//
// M47 W2 (highest-impact case of the wave): `tenant_users` has no RLS, so
// `WHERE tenant_id = $1 AND user_id = $2` is the whole tenant boundary —
// and the result was discarded, so naming ANOTHER tenant's member returned
// nil. Member removal reported success while the membership survived
// untouched (pinned by TestM47W2_RemoveFromTenant_CrossTenantIsNotSuccess).
// 0 rows now returns ErrTenantUserNotFound.
//
// CALLER CONTRACT CHANGE: the only current caller is the Clerk
// organizationMembership.deleted webhook, whose semantics ARE idempotent
// (it mirrors the IdP's state, and Svix redelivers on 5xx). That caller
// must now tolerate the no-op EXPLICITLY —
//
//	if err := h.userRepo.RemoveFromTenant(ctx, tenant.ID, user.ID); err != nil {
//	    if errors.Is(err, sql.ErrNoRows) {   // already not a member
//	        return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "membership not found"})
//	    }
//	    ...500...
//	}
//
// — matching the sql.ErrNoRows branches the same handler already uses for
// its tenant/user lookups. Until that branch lands, a redelivered
// membership deletion answers 500 instead of 200. See the M47 W2 report.
func (r *UserRepository) RemoveFromTenant(ctx context.Context, tenantID, userID uuid.UUID) error {
	query := `DELETE FROM tenant_users WHERE tenant_id = $1 AND user_id = $2`
	res, err := r.db.ExecContext(ctx, query, tenantID, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete tenant_users (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("remove user %s from tenant %s: %w", userID, tenantID, ErrTenantUserNotFound)
	}
	return nil
}

// GetTenantUsers returns all users in a tenant
func (r *UserRepository) GetTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]model.UserWithRole, error) {
	query := `
		SELECT u.id, u.clerk_user_id, u.email, COALESCE(u.name, ''), COALESCE(u.avatar_url, ''), u.created_at, u.updated_at, tu.role
		FROM users u
		INNER JOIN tenant_users tu ON u.id = tu.user_id
		WHERE tu.tenant_id = $1
		ORDER BY tu.created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.UserWithRole
	for rows.Next() {
		var u model.UserWithRole
		if err := rows.Scan(&u.ID, &u.ClerkUserID, &u.Email, &u.Name, &u.AvatarURL,
			&u.CreatedAt, &u.UpdatedAt, &u.Role); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// GetUserRole returns the user's role in a tenant
func (r *UserRepository) GetUserRole(ctx context.Context, tenantID, userID uuid.UUID) (*model.TenantUser, error) {
	query := `
		SELECT tenant_id, user_id, role, created_at
		FROM tenant_users WHERE tenant_id = $1 AND user_id = $2
	`
	var tu model.TenantUser
	err := r.db.QueryRowContext(ctx, query, tenantID, userID).Scan(
		&tu.TenantID, &tu.UserID, &tu.Role, &tu.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &tu, nil
}

// UpdateRole updates a user's role in a tenant.
//
// M47 W2: the sibling of RemoveFromTenant on the same RLS-less table and
// with the same defect — a role change aimed at another tenant's member
// matched 0 rows and returned nil, so a privilege change that never
// happened looked like one that did. Both methods now share one contract
// (0 rows -> ErrTenantUserNotFound); the asymmetry was the bug.
func (r *UserRepository) UpdateRole(ctx context.Context, tenantID, userID uuid.UUID, role string) error {
	query := `UPDATE tenant_users SET role = $1 WHERE tenant_id = $2 AND user_id = $3`
	res, err := r.db.ExecContext(ctx, query, role, tenantID, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update tenant_users role (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update role of user %s in tenant %s: %w", userID, tenantID, ErrTenantUserNotFound)
	}
	return nil
}

// CountByTenant returns the number of users in a tenant
func (r *UserRepository) CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM tenant_users WHERE tenant_id = $1`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&count)
	return count, err
}

// GetOrCreateDefault returns the default user for self-hosted mode
func (r *UserRepository) GetOrCreateDefault(ctx context.Context, tenantID uuid.UUID) (*model.User, error) {
	const defaultEmail = "admin@localhost"

	// Try to get existing default user
	u, err := r.GetByEmail(ctx, defaultEmail)
	if err == nil {
		return u, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	// Create default user for self-hosted mode
	now := time.Now()
	u = &model.User{
		ID:          uuid.New(),
		ClerkUserID: "self-hosted",
		Email:       defaultEmail,
		Name:        "Administrator",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := r.Create(ctx, u); err != nil {
		return nil, err
	}

	// Add to default tenant as owner
	tu := &model.TenantUser{
		TenantID:  tenantID,
		UserID:    u.ID,
		Role:      model.RoleOwner,
		CreatedAt: now,
	}
	if err := r.AddToTenant(ctx, tu); err != nil {
		return nil, err
	}

	return u, nil
}

// GetOrCreateAPIKeyUser returns a synthetic per-tenant user that
// represents requests authenticated via API key (CLI / GitHub Actions).
//
// M1 Codex review #F14: API keys are tenant-scoped but carry no human
// user, while several downstream surfaces require a non-NULL user_id:
//   - audit_logs.user_id REFERENCES users(id) (migration 007), so a
//     synthetic uuid that does not exist in `users` would violate the FK.
//   - vex_drafts.decision_by is a soft uuid (no FK) but the handler's
//     own "user identity required to decide a vex draft (audit trail)"
//     guard and triage.UpdateDecision both reject nil user_id.
//
// We synthesise exactly one user per tenant so every API-key request for
// the same tenant shares the same created_by / decision_by pointer.
// Operators can filter audit_logs by `name = 'API Key User'` (or by the
// clerk_user_id prefix `api-key:`) to isolate CLI activity without
// inflating the user table per request.
//
// clerk_user_id is namespaced as `api-key:<tenant_uuid>` so SaaS mode
// does not collide on the global UNIQUE (clerk_user_id) constraint when
// multiple tenants each get their own synthetic user. The email is
// namespaced similarly but the schema only indexes — not UNIQUEs —
// email, so this is belt-and-braces.
func (r *UserRepository) GetOrCreateAPIKeyUser(ctx context.Context, tenantID uuid.UUID) (*model.User, error) {
	if tenantID == uuid.Nil {
		// Defensive — MultiAuth always supplies a non-nil tenant from the
		// API key row, but a nil tenant here would silently create a
		// global "api-key:00000000-..." user shared across tenants. Fail
		// loudly so the caller's misuse surfaces at the auth boundary
		// instead of leaking cross-tenant user ids into audit_logs.
		return nil, errors.New("GetOrCreateAPIKeyUser: tenantID is required")
	}

	clerkUserID := "api-key:" + tenantID.String()

	u, err := r.GetByClerkUserID(ctx, clerkUserID)
	if err == nil {
		return u, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	now := time.Now()
	u = &model.User{
		ID:          uuid.New(),
		ClerkUserID: clerkUserID,
		Email:       "api-key+" + tenantID.String() + "@localhost",
		Name:        "API Key User",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := r.Create(ctx, u); err != nil {
		return nil, err
	}

	// Bind to the tenant with member role so any downstream code path
	// that consults tenant_users.role (rather than ContextKeyRole set by
	// MultiAuth) still sees a writable role. MultiAuth is the source of
	// truth for ContextKeyRole — the API key's `permissions` field
	// determines whether this request can write, not tenant_users.role.
	tu := &model.TenantUser{
		TenantID:  tenantID,
		UserID:    u.ID,
		Role:      model.RoleMember,
		CreatedAt: now,
	}
	if err := r.AddToTenant(ctx, tu); err != nil {
		return nil, err
	}

	return u, nil
}
