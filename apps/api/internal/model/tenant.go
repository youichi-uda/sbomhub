package model

import (
	"time"

	"github.com/google/uuid"
)

// Tenant represents an organization/workspace in the multi-tenant system
type Tenant struct {
	ID         uuid.UUID `json:"id" db:"id"`
	ClerkOrgID string    `json:"clerk_org_id" db:"clerk_org_id"`
	Name       string    `json:"name" db:"name"`
	Slug       string    `json:"slug" db:"slug"`
	Plan       string    `json:"plan" db:"plan"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// TenantWithStats includes tenant info with usage statistics
type TenantWithStats struct {
	Tenant
	UserCount    int `json:"user_count"`
	ProjectCount int `json:"project_count"`
}
