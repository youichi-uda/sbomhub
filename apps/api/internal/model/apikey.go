package model

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// IsKnownAPIKeyPermission reports whether perm is one of the values
// the API-key permissions allowlist recognises (read / write / admin /
// owner). M1 Codex review #F17: APIKeyService.CreateKey consults this
// helper to refuse unknown values with a 400 rather than persisting
// them, and middleware.roleFromAPIKeyPermissions consults it implicitly
// — its switch arms cover the same set, defaulting unknown values to
// RoleViewer (fail-closed).
//
// The helper lives in the model package rather than middleware so the
// service layer can reference it without creating an import cycle
// (middleware → service for APIKeyService, would conflict with
// service → middleware for this validator). Comparison is
// case-insensitive with whitespace trimmed; the empty string is
// rejected because it has no documented meaning and was the original
// F17 attack surface (APIKeyService.CreateKey used to silently
// substitute "write" for empty input, so probing the default got an
// attacker a write-capable key without explicitly asking for one).
func IsKnownAPIKeyPermission(perm string) bool {
	switch strings.ToLower(strings.TrimSpace(perm)) {
	case "read", "write", "admin", "owner":
		return true
	default:
		return false
	}
}

// APIKey represents an API key for tenant access
type APIKey struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    uuid.UUID  `json:"tenant_id" db:"tenant_id"`                       // Required: tenant this key belongs to
	ProjectID   *uuid.UUID `json:"project_id,omitempty" db:"project_id"`           // Deprecated: legacy project-level keys only
	Name        string     `json:"name" db:"name"`
	KeyHash     string     `json:"-" db:"key_hash"`                                // Never exposed in JSON
	KeyPrefix   string     `json:"key_prefix" db:"key_prefix"`                     // First 8 chars for identification
	Permissions string     `json:"permissions" db:"permissions"`                   // e.g., "read", "write", "admin"
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
}

// APIKeyWithSecret includes the raw key (only returned on creation)
type APIKeyWithSecret struct {
	APIKey
	Key string `json:"key"` // Only populated on creation
}
