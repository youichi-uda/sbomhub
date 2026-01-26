package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
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
		SELECT id, clerk_user_id, email, name, avatar_url, created_at, updated_at
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
		SELECT id, clerk_user_id, email, name, avatar_url, created_at, updated_at
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
		SELECT id, clerk_user_id, email, name, avatar_url, created_at, updated_at
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

func (r *UserRepository) Update(ctx context.Context, u *model.User) error {
	query := `
		UPDATE users SET email = $1, name = $2, avatar_url = $3, updated_at = $4
		WHERE id = $5
	`
	u.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, query, u.Email, u.Name, u.AvatarURL, u.UpdatedAt, u.ID)
	return err
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// Upsert creates or updates a user (used by Clerk webhook)
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

// AddToTenant adds a user to a tenant
func (r *UserRepository) AddToTenant(ctx context.Context, tu *model.TenantUser) error {
	query := `
		INSERT INTO tenant_users (tenant_id, user_id, role, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role
	`
	_, err := r.db.ExecContext(ctx, query, tu.TenantID, tu.UserID, tu.Role, tu.CreatedAt)
	return err
}

// RemoveFromTenant removes a user from a tenant
func (r *UserRepository) RemoveFromTenant(ctx context.Context, tenantID, userID uuid.UUID) error {
	query := `DELETE FROM tenant_users WHERE tenant_id = $1 AND user_id = $2`
	_, err := r.db.ExecContext(ctx, query, tenantID, userID)
	return err
}

// GetTenantUsers returns all users in a tenant
func (r *UserRepository) GetTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]model.UserWithRole, error) {
	query := `
		SELECT u.id, u.clerk_user_id, u.email, u.name, u.avatar_url, u.created_at, u.updated_at, tu.role
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

// UpdateRole updates a user's role in a tenant
func (r *UserRepository) UpdateRole(ctx context.Context, tenantID, userID uuid.UUID, role string) error {
	query := `UPDATE tenant_users SET role = $1 WHERE tenant_id = $2 AND user_id = $3`
	_, err := r.db.ExecContext(ctx, query, role, tenantID, userID)
	return err
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
