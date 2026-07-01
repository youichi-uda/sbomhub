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
//
// M12-4 (#85) introduces AuditActionDiffWebhookAutoFired as a SECOND
// audit row written alongside the existing diff_webhook_fired /
// diff_webhook_failed pair. The split is intentional:
//
//   - diff_webhook_{fired,failed} record the DELIVERY outcome
//     (settings.Get → HTTP POST → settings.UpdateFireResult). These
//     are the rows the M11-4 webhook detail screen surfaces under
//     "last delivery".
//
//   - diff_webhook_auto_fired records the AUTO-TRIGGER DECISION on
//     SBOM ingest (predecessor SBOM resolution → diff compute →
//     threshold evaluation → fire-or-not). It is keyed to the ingest
//     sbom_id (NOT the project) so an operator auditing "which SBOM
//     uploads triggered which webhooks" can walk the chain end-to-end
//     without joining timestamps.
//
// When the threshold is not met, only diff_webhook_auto_fired is
// written (status=threshold_not_exceeded). When the threshold IS met
// the two rows are written in order: delivery audit first (inside
// FireIfThreshold), then the auto_fired audit (status=success or
// failure mirroring the delivery outcome). Both writes honour F168
// audit-or-nothing: a failed audit Log returns the error to the
// background goroutine which logs at slog.Error level.
const (
	AuditActionDiffWebhookUpdated   = "diff_webhook_settings_updated"
	AuditActionDiffWebhookFired     = "diff_webhook_fired"
	AuditActionDiffWebhookFailed    = "diff_webhook_failed"
	AuditActionDiffWebhookAutoFired = "diff_webhook_auto_fired"

	// F296 (M20-1 Phase D R1, anti-pattern 58 3-axis full coverage —
	// handler-side ResourceType* orphan closure): the pre-F296 package-
	// local `ResourceTypeDiffWebhook = "diff_webhook"` constant lived
	// in the model package but OUTSIDE the model.Resource* universe
	// the F281 (M19-3) direction-1/direction-2 parity meta-test scans,
	// so a rename / typo at any of the three emit sites (handler/
	// settings_diff_webhook.go, handler/sbom.go auto-fire path, and
	// service/diff_webhook/diff_webhook.go delivery worker) was
	// compile-time invisible to the parity contract. F296 promotes the
	// value into audit.go as model.ResourceDiffWebhook (single source
	// of truth in the same model.Resource* block that F281 scans),
	// removes this definition, and swaps the three emit sites to
	// reference the new symbol so F281 direction-1 registration
	// enforces parity at CI time. See model/audit.go F296 head comment
	// for the full 3-axis full-coverage rationale.
)

// DiffWebhookAutoFireStatus enumerates the auto-trigger decision
// surfaced in the diff_webhook_auto_fired audit row's `status` detail.
// Operators key dashboards / alerting off these strings; do not rename
// existing values without a migration of downstream consumers.
const (
	// DiffWebhookAutoFireStatusSuccess: threshold exceeded, delivery
	// 2xx, both audit rows landed.
	DiffWebhookAutoFireStatusSuccess = "success"
	// DiffWebhookAutoFireStatusFailure: threshold exceeded, delivery
	// returned non-2xx or transport error. Operator should consult the
	// matching diff_webhook_failed row for details.
	DiffWebhookAutoFireStatusFailure = "failure"
	// DiffWebhookAutoFireStatusThresholdNotExceeded: settings configured
	// and enabled but the diff's critical/high/license counts were
	// below the configured thresholds.
	DiffWebhookAutoFireStatusThresholdNotExceeded = "threshold_not_exceeded"
	// DiffWebhookAutoFireStatusNoConfig: tenant has no webhook
	// configured (no row in tenant_diff_webhook_settings).
	DiffWebhookAutoFireStatusNoConfig = "no_config"
	// DiffWebhookAutoFireStatusDisabled: tenant has a webhook row but
	// Enabled=false (operator paused).
	DiffWebhookAutoFireStatusDisabled = "disabled"
	// DiffWebhookAutoFireStatusNoURL: configured row, enabled, but
	// webhook_url is empty (operator partially configured).
	DiffWebhookAutoFireStatusNoURL = "no_url"
	// DiffWebhookAutoFireStatusNoPredecessor: this ingest is the very
	// first SBOM for the project — no predecessor to diff against, so
	// the auto-trigger is a no-op. Distinct from no_config so an
	// operator polling the audit trail can tell "I haven't enabled
	// webhooks" apart from "first ever ingest".
	DiffWebhookAutoFireStatusNoPredecessor = "no_predecessor"
	// DiffWebhookAutoFireStatusError: diff compute or settings read
	// failed before threshold evaluation could occur. Details carry
	// the upstream error text.
	DiffWebhookAutoFireStatusError = "error"
)
