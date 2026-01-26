package model

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user synced from Clerk
type User struct {
	ID          uuid.UUID `json:"id" db:"id"`
	ClerkUserID string    `json:"clerk_user_id" db:"clerk_user_id"`
	Email       string    `json:"email" db:"email"`
	Name        string    `json:"name,omitempty" db:"name"`
	AvatarURL   string    `json:"avatar_url,omitempty" db:"avatar_url"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// TenantUser represents the relationship between a tenant and a user
type TenantUser struct {
	TenantID  uuid.UUID `json:"tenant_id" db:"tenant_id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Role      string    `json:"role" db:"role"` // owner, admin, member, viewer
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// UserWithRole includes user info with their role in a tenant
type UserWithRole struct {
	User
	Role string `json:"role"`
}

// UserRole constants
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
	RoleViewer = "viewer"
)

// HasPermission checks if the role has permission for a given action
func (tu *TenantUser) HasPermission(action string) bool {
	switch action {
	case "read":
		return true // All roles can read
	case "write":
		return tu.Role == RoleOwner || tu.Role == RoleAdmin || tu.Role == RoleMember
	case "admin":
		return tu.Role == RoleOwner || tu.Role == RoleAdmin
	case "owner":
		return tu.Role == RoleOwner
	default:
		return false
	}
}
