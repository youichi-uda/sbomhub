package model

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// DiffWebhookSettings mirrors a row of tenant_diff_webhook_settings
// (migration 046, M11-4 #79). It is the persisted form of the per-
// tenant SBOM diff webhook destination + thresholds.
//
// SECURITY: EncryptedSecret holds the AES-256-GCM (nonce||sealed)
// ciphertext produced by internal/service/llm.Encrypt. The plaintext
// shared secret is NEVER persisted, returned from the API, or logged.
// The handler returns the literal "***" placeholder when surfacing the
// settings shape; the application decrypts just-in-time before signing
// each outgoing webhook payload.
type DiffWebhookSettings struct {
	TenantID uuid.UUID

	WebhookURL      string // may be "" when configured-but-paused
	EncryptedSecret []byte // nonce||sealed AES-256-GCM ciphertext, may be nil

	CriticalThreshold         int
	HighThreshold             int
	LicenseViolationThreshold int

	Format  string // "json" | "slack"
	Enabled bool

	LastFiredAt        sql.NullTime
	LastResponseStatus sql.NullInt64
	LastError          sql.NullString

	CreatedAt time.Time
	UpdatedAt time.Time
}

// HasSecret reports whether an encrypted secret has been persisted.
// Used by the handler to decide whether to surface the "***"
// placeholder vs. an empty string in the JSON response.
func (s *DiffWebhookSettings) HasSecret() bool {
	return s != nil && len(s.EncryptedSecret) > 0
}

// DiffWebhookFormat enumerates the supported webhook payload formats.
const (
	DiffWebhookFormatJSON  = "json"
	DiffWebhookFormatSlack = "slack"
)

// Audit action / resource constants for the diff webhook lifecycle.
const (
	AuditActionDiffWebhookUpdated = "diff_webhook_settings_updated"
	AuditActionDiffWebhookFired   = "diff_webhook_fired"
	AuditActionDiffWebhookFailed  = "diff_webhook_failed"

	ResourceTypeDiffWebhook = "diff_webhook"
)
