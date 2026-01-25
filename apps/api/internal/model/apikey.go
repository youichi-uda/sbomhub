package model

import (
	"time"

	"github.com/google/uuid"
)

// APIKey represents an API key for project access
type APIKey struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	ProjectID   uuid.UUID  `json:"project_id" db:"project_id"`
	Name        string     `json:"name" db:"name"`
	KeyHash     string     `json:"-" db:"key_hash"` // Never exposed in JSON
	KeyPrefix   string     `json:"key_prefix" db:"key_prefix"` // First 8 chars for identification
	Permissions string     `json:"permissions" db:"permissions"` // e.g., "read", "write", "admin"
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
}

// APIKeyWithSecret includes the raw key (only returned on creation)
type APIKeyWithSecret struct {
	APIKey
	Key string `json:"key"` // Only populated on creation
}
