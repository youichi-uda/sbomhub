package model

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// AuditLog represents an audit trail entry
type AuditLog struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	TenantID     *uuid.UUID             `json:"tenant_id,omitempty" db:"tenant_id"`
	UserID       *uuid.UUID             `json:"user_id,omitempty" db:"user_id"`
	Action       string                 `json:"action" db:"action"`
	ResourceType string                 `json:"resource_type" db:"resource_type"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty" db:"resource_id"`
	Details      map[string]interface{} `json:"details,omitempty" db:"details"`
	IPAddress    net.IP                 `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent    string                 `json:"user_agent,omitempty" db:"user_agent"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

// Audit action constants
const (
	// User actions
	ActionUserSignIn     = "user.sign_in"
	ActionUserSignOut    = "user.sign_out"
	ActionUserCreated    = "user.created"
	ActionUserUpdated    = "user.updated"
	ActionUserDeleted    = "user.deleted"
	ActionUserInvited    = "user.invited"
	ActionUserRoleChanged = "user.role_changed"

	// Tenant actions
	ActionTenantCreated = "tenant.created"
	ActionTenantUpdated = "tenant.updated"
	ActionTenantDeleted = "tenant.deleted"

	// Project actions
	ActionProjectCreated = "project.created"
	ActionProjectUpdated = "project.updated"
	ActionProjectDeleted = "project.deleted"

	// SBOM actions
	ActionSBOMUploaded = "sbom.uploaded"
	ActionSBOMDeleted  = "sbom.deleted"
	ActionSBOMScanned  = "sbom.scanned"

	// VEX actions
	ActionVEXCreated = "vex.created"
	ActionVEXUpdated = "vex.updated"
	ActionVEXDeleted = "vex.deleted"

	// API Key actions
	ActionAPIKeyCreated = "apikey.created"
	ActionAPIKeyDeleted = "apikey.deleted"
	ActionAPIKeyUsed    = "apikey.used"

	// Subscription actions
	ActionSubscriptionCreated   = "subscription.created"
	ActionSubscriptionUpdated   = "subscription.updated"
	ActionSubscriptionCancelled = "subscription.cancelled"
	ActionSubscriptionRenewed   = "subscription.renewed"

	// Settings actions
	ActionSettingsUpdated = "settings.updated"
)

// Resource type constants
const (
	ResourceUser         = "user"
	ResourceTenant       = "tenant"
	ResourceProject      = "project"
	ResourceSBOM         = "sbom"
	ResourceVEX          = "vex"
	ResourceAPIKey       = "apikey"
	ResourceSubscription = "subscription"
	ResourceSettings     = "settings"
)

// CreateAuditLogInput is the input for creating an audit log
type CreateAuditLogInput struct {
	TenantID     *uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Details      map[string]interface{}
	IPAddress    string
	UserAgent    string
}
