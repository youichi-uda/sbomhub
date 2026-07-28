// Package diff_webhook fires tenant-configured HTTP webhooks when an
// SBOM ingest produces a diff exceeding the operator-defined critical /
// high / license-violation thresholds (M11-4 #79).
//
// Design notes:
//
//   - One row per tenant in tenant_diff_webhook_settings (migration
//     046). Operators configure via PUT /api/v1/tenant/settings/
//     diff-webhook; this service consumes the row at fire time.
//
//   - The shared secret is AES-256-GCM ciphertext on disk; the
//     plaintext is decrypted just-in-time, used to compute the
//     HMAC-SHA256 signature on the outgoing payload, then zeroed in
//     its backing buffer. Plaintext never leaves the request frame.
//
//   - Two payload formats are supported:
//     json  — SBOMHub canonical envelope ({type, tenant_id,
//     project_id, from_sbom_id, to_sbom_id, counts:{...},
//     thresholds:{...}, generated_at}). This is what most
//     operators with their own ingest pipeline will want.
//     slack — text + attachments JSON shaped for Slack incoming
//     webhooks. Operators can paste a Slack webhook URL +
//     format=slack and get human-readable Slack messages
//     without an intermediate service.
//
//   - The HTTP delivery is bounded (10 s default) and uses simple
//     exponential backoff (3 attempts at 0 / 500 ms / 2 s). 5xx
//     responses retry; 4xx surface immediately (the webhook
//     configuration itself is the problem). The final outcome is
//     persisted to (last_fired_at, last_response_status, last_error)
//     so the operator can debug from the settings page without
//     trawling audit logs.
//
//   - Audit-or-nothing: every fire (success OR failure) writes an
//     audit_logs row. Action = diff_webhook_fired on 2xx,
//     diff_webhook_failed otherwise. resource_type = diff_webhook,
//     resource_id = the project the SBOM was ingested into.
package diff_webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/diff"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// ErrMsgMissingSecret is the FireDecision.ErrorMessage / audit-detail marker
// for a delivery refused because the tenant configured no signing secret
// (M48 FO-5). It is a fixed string for the same F445 reason the other
// messages in this package are: it reaches the tenant through
// GET /audit-logs and the diff-webhook test route.
const ErrMsgMissingSecret = "missing signing secret"

// SlackWebhookHost is the only host for which the signing-secret requirement
// is waived. Slack's incoming-webhook endpoints all live under
// https://hooks.slack.com/services/... .
const SlackWebhookHost = "hooks.slack.com"

// SignatureRequired reports whether a delivery must carry an
// X-SBOMHub-Signature header, i.e. whether the tenant must configure a shared
// secret before the webhook can fire.
//
// M48 (FO-5). The answer is not uniform, and the exemption is narrower than it
// first looks:
//
//   - Anything not addressed to Slack — a generic consumer endpoint we do not
//     control — requires a secret. The HMAC is the only thing that makes the
//     payload attributable to this installation.
//   - format "slack" delivered to https://hooks.slack.com does not. Slack does
//     not read X-SBOMHub-Signature and never will; that URL is itself the
//     credential, and https is enforced here rather than assumed.
//
// Codex round 1 (Medium) is why the URL is a parameter. The first version
// keyed the exemption on the format alone — a value the caller supplies in the
// request body — so an admin could label any endpoint, over plain HTTP,
// "slack" and post unsigned payloads to it indefinitely. The comment claimed
// "the delivery target is known" while the code checked nothing of the kind,
// and the accompanying test proved the point by exempting an
// httptest.Server on http://127.0.0.1.
//
// Both terms are required, so a Slack-compatible endpoint hosted elsewhere
// (Mattermost, a corporate relay) is treated as what it is: a generic
// consumer, which needs a secret.
func SignatureRequired(format, webhookURL string) bool {
	if format != model.DiffWebhookFormatSlack {
		return true
	}
	u, err := url.Parse(webhookURL)
	if err != nil {
		// Unparseable: fail closed. The settings handler parses and rejects
		// malformed URLs before they are stored (Codex round 2 made that
		// true — it used to be a prefix test only), so this is the defensive
		// arm for rows written before that check existed.
		return true
	}
	// Codex round 4 (Low): DNS names are case-insensitive and a terminal root
	// dot is equivalent, but url.Hostname() normalises neither. Comparing
	// verbatim rejected the perfectly ordinary "https://HOOKS.SLACK.COM/..."
	// and forced a secret onto a genuine Slack integration — a false denial,
	// not a false exemption, but wrong either way.
	host := strings.TrimSuffix(u.Hostname(), ".")
	return u.Scheme != "https" || !strings.EqualFold(host, SlackWebhookHost)
}

// SignatureHeader is the HTTP header carrying the HMAC-SHA256 hex
// digest of the request body. Downstream consumers verify by
// recomputing with the shared secret.
const SignatureHeader = "X-SBOMHub-Signature"

// EventHeader carries the canonical event name for routing on the
// consumer side. M11-4 only emits one event type.
const EventHeader = "X-SBOMHub-Event"

// EventTypeDiff is the event name for SBOM-diff-threshold-triggered
// webhook fires.
const EventTypeDiff = "sbom_diff_threshold"

// DefaultHTTPTimeout bounds a single delivery attempt.
const DefaultHTTPTimeout = 10 * time.Second

// DefaultRetryBackoffs is the per-attempt sleep schedule. The first
// attempt has no delay; subsequent retries sleep before issuing the
// next request.
var DefaultRetryBackoffs = []time.Duration{0, 500 * time.Millisecond, 2 * time.Second}

// WebhookSettingsReader is satisfied by *repository.DiffWebhookRepository.
type WebhookSettingsReader interface {
	Get(ctx context.Context, tenantID uuid.UUID) (*model.DiffWebhookSettings, error)
	UpdateFireResult(ctx context.Context, tenantID uuid.UUID, status int, errMsg string) error
}

// AuditWriter is satisfied by *repository.AuditRepository.Log.
type AuditWriter interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// HTTPDoer is the minimum http.Client surface this package needs.
//
// Production wiring passes NOTHING (Config.HTTPClient is nil), so NewService
// builds the client itself — which is what makes the redirect policy below
// effective. Codex round 4 (Low) noted the previous comment here claimed
// production supplied its own client; it does not, and if it ever did, the
// CheckRedirect that keeps an unsigned Slack-exempt delivery from being
// redirected off hooks.slack.com would be silently lost. A caller that does
// supply one owns that policy.
//
// Unit tests substitute a fake recording the outgoing request.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Service evaluates per-tenant thresholds + fires the webhook.
type Service struct {
	settings      WebhookSettingsReader
	audit         AuditWriter
	httpClient    HTTPDoer
	encryptionKey []byte
	retries       []time.Duration
	clock         func() time.Time
}

// Config bundles construction inputs.
type Config struct {
	Settings      WebhookSettingsReader
	Audit         AuditWriter
	HTTPClient    HTTPDoer // nil → &http.Client{Timeout: DefaultHTTPTimeout}
	EncryptionKey []byte
	Retries       []time.Duration // nil → DefaultRetryBackoffs
	Clock         func() time.Time
}

// NewService constructs the service. Required fields panic when nil.
func NewService(cfg Config) *Service {
	if cfg.Settings == nil {
		panic("diff_webhook.NewService: Settings is required")
	}
	if cfg.Audit == nil {
		panic("diff_webhook.NewService: Audit is required")
	}
	if len(cfg.EncryptionKey) != 32 {
		panic("diff_webhook.NewService: EncryptionKey must be 32 bytes")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: DefaultHTTPTimeout,
			// M48, Codex round 2 (Low): do not follow redirects.
			//
			// SignatureRequired waives the signing-secret requirement for
			// format=slack sent to https://hooks.slack.com. That check is
			// applied to the CONFIGURED url; a 307/308 preserves the method
			// and body, so a redirect could carry an unsigned payload off that
			// host and out from under the exemption. No exploitable Slack open
			// redirect was identified, so this is precautionary rather than a
			// fix for a demonstrated bypass.
			//
			// Refusing redirects outright is also the right policy for a
			// webhook independently of that: the destination is an operator-
			// configured endpoint, not a browsable resource, and a 3xx now
			// surfaces as a non-2xx delivery failure the operator can see on
			// the settings screen instead of silently retargeting.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	retries := cfg.Retries
	if len(retries) == 0 {
		// len, not nil (Codex round 5, Low): an explicitly EMPTY slice used to
		// skip the delivery loop entirely and return (0, ""), which
		// FireIfThreshold then recorded as a failed delivery with no reason —
		// a violation of the ErrorMessage contract for a supported
		// constructor input. Production passes nil and is unaffected; this
		// makes the empty case mean the same thing as the nil case.
		retries = DefaultRetryBackoffs
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		settings:      cfg.Settings,
		audit:         cfg.Audit,
		httpClient:    client,
		encryptionKey: cfg.EncryptionKey,
		retries:       retries,
		clock:         clock,
	}
}

// FireDecision summarises what FireIfThreshold did, so the caller
// (SBOM ingest pipeline / handler / tests) can log + assert.
type FireDecision struct {
	// Triggered reports that the thresholds SELECTED this delivery — not that
	// an HTTP request was issued. Two paths set it without reaching the
	// network: a secret that will not decrypt, and (M48) a missing signing
	// secret. Both are configuration failures the operator needs to see as
	// "your webhook tried and failed", not as a quiet period. (Codex round 2,
	// Low: the previous wording, "webhook was attempted", was narrower than
	// the code.)
	Triggered    bool
	Reason       string // empty when Triggered; reason ("no config", "disabled", "below thresholds", ...) when not
	Status       int    // HTTP status of the final attempt (0 if not triggered)
	ErrorMessage string // populated on delivery failure
}

// FireIfThreshold evaluates the diff against the tenant's thresholds.
// If any threshold is exceeded the configured webhook is invoked.
//
// The supplied diff.Response is the same envelope returned by the GET
// /diff endpoint — the SBOM ingest pipeline computes it once per
// upload and passes it through.
//
// Threshold evaluation rule: a threshold N is "exceeded" when the
// matching diff count is strictly greater than or equal to N AND N is
// > 0. A threshold of 0 means "any item triggers" — useful for the
// license-violation-threshold default of 0 since most operators want
// to know about the first violation.
//
// Returns a FireDecision describing the outcome. Errors are returned
// ONLY when the tenant-settings read itself fails; webhook delivery
// failures populate FireDecision.ErrorMessage but do not return an
// error from this method (the SBOM ingest pipeline should not abort
// just because the webhook is down).
func (s *Service) FireIfThreshold(
	ctx context.Context,
	tenantID, projectID uuid.UUID,
	d *diff.Response,
) (*FireDecision, error) {
	settings, err := s.settings.Get(ctx, tenantID)
	if errors.Is(err, repository.ErrDiffWebhookNotFound) {
		return &FireDecision{Reason: "no_config"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read diff webhook settings: %w", err)
	}
	if !settings.Enabled {
		return &FireDecision{Reason: "disabled"}, nil
	}
	if settings.WebhookURL == "" {
		return &FireDecision{Reason: "no_url"}, nil
	}

	counts := countSeverities(d)
	if !exceededThreshold(counts, settings) {
		return &FireDecision{Reason: "below_thresholds"}, nil
	}

	// Build payload.
	payload := buildPayload(settings.Format, tenantID, projectID, d, counts, settings)
	body, mErr := json.Marshal(payload)
	if mErr != nil {
		return nil, fmt.Errorf("marshal webhook payload: %w", mErr)
	}

	// Decrypt secret just-in-time.
	var secret []byte
	if settings.HasSecret() {
		plaintext, dErr := llm.Decrypt(settings.EncryptedSecret, s.encryptionKey)
		if dErr != nil {
			// M11 Phase D F168: audit-or-nothing. If even the failure
			// audit row cannot land, surface that to the caller — a
			// silent failure here is the exact UX regression F168
			// flagged.
			// F445: writeAudit stores errMsg into audit details["error"],
			// returned to the tenant via GET /audit-logs — keep the raw
			// crypto error out of it (log it, store the generic marker).
			slog.Warn("diff_webhook: decrypt secret failed", "tenant_id", tenantID, "project_id", projectID, "error", dErr)
			if aErr := s.writeAudit(ctx, tenantID, projectID, model.AuditActionDiffWebhookFailed, 0, "decrypt secret", counts); aErr != nil {
				return nil, fmt.Errorf("decrypt secret + audit log: %w", aErr)
			}
			return &FireDecision{Triggered: true, ErrorMessage: "decrypt secret"}, nil
		}
		secret = plaintext
		defer func() {
			for i := range secret {
				secret[i] = 0
			}
		}()
	}

	// M48 (FO-5): refuse to send an unsigned delivery that the receiver was
	// meant to be able to verify.
	//
	// The receiving half of this product was made fail-closed in M47 — with no
	// secret configured, /api/webhooks/* rejects every delivery. The SENDING
	// half still did the opposite: it dropped the X-SBOMHub-Signature header
	// and posted anyway, so a consumer following our own documented
	// verification step had nothing to verify and a consumer that trusted the
	// payload could not tell ours from anyone else's POST to the same URL.
	//
	// This check lives here as well as in the settings handler
	// (handler/settings_diff_webhook.go) because rows written before M48 are
	// already persisted with no secret; the handler-side refusal only governs
	// writes from here on.
	if len(secret) == 0 && SignatureRequired(settings.Format, settings.WebhookURL) {
		slog.Warn("diff_webhook: refusing to send an unsigned delivery",
			"tenant_id", tenantID, "project_id", projectID, "format", settings.Format)
		// Codex round 1 (Low): the settings screen reads last_error, and a
		// pre-M48 secret-less row that silently stops firing is exactly the
		// case where the operator goes looking there first. Without this the
		// screen would keep showing the last delivery from before the upgrade.
		// Status 0 matches the "never reached the network" convention the
		// decrypt-failure path above uses.
		//
		// Codex round 2 (Low): the error is handled rather than discarded. It
		// is logged rather than returned, because the audit row below is the
		// durable record this package promises (F168) and this write is the
		// convenience mirror for the settings screen — failing the whole
		// decision because the mirror could not be updated would trade a
		// visibility gap for a louder one. The gap is named in the log.
		if uErr := s.settings.UpdateFireResult(ctx, tenantID, 0, ErrMsgMissingSecret); uErr != nil {
			slog.Warn("diff_webhook: could not record the missing-secret refusal on the "+
				"settings row; the audit log is still authoritative",
				"tenant_id", tenantID, "project_id", projectID, "error", uErr)
		}
		if aErr := s.writeAudit(ctx, tenantID, projectID, model.AuditActionDiffWebhookFailed, 0, ErrMsgMissingSecret, counts); aErr != nil {
			return nil, fmt.Errorf("missing signing secret + audit log: %w", aErr)
		}
		// Triggered=true: the thresholds selected this delivery. Reporting it
		// as not-triggered would make a configuration failure indistinguishable
		// from a quiet period on the settings screen and in the caller's logs.
		// See FireDecision.Triggered, whose meaning is "selected by the
		// thresholds", not "an HTTP request was issued".
		return &FireDecision{Triggered: true, ErrorMessage: ErrMsgMissingSecret}, nil
	}

	signature := ""
	if len(secret) > 0 {
		signature = computeSignature(body, secret)
	}

	// Deliver with retries.
	status, errMsg := s.deliver(ctx, settings.WebhookURL, body, signature)

	// F445: errMsg from deliver() may embed a raw network/framework error or
	// remote HTTP status/body. It is persisted (settings.last_error, surfaced
	// by GET /tenant/settings/diff-webhook) and returned to the client
	// (FireDecision.ErrorMessage → diff-webhook test route). Keep the raw
	// detail server-side (slog) and downgrade to a generic message for
	// everything persisted or returned. The numeric HTTP status is carried
	// separately in Status/last_fired_at, so no operator visibility is lost.
	if errMsg != "" {
		slog.Warn("diff_webhook: delivery failed",
			"tenant_id", tenantID,
			"project_id", projectID,
			"status", status,
			"error", errMsg,
		)
		errMsg = "webhook delivery failed"
	}

	// Persist operational visibility.
	//
	// Codex round 3 (Low): handled, not discarded — the same treatment the
	// missing-secret path already got in round 2. A silent failure here leaves
	// last_fired_at / last_response_status / last_error showing the PREVIOUS
	// delivery, which is worse than showing nothing: the settings screen reads
	// as "the webhook is fine" while it is not. The audit row below remains
	// the authoritative record, so this is logged rather than returned.
	if uErr := s.settings.UpdateFireResult(ctx, tenantID, status, errMsg); uErr != nil {
		slog.Warn("diff_webhook: could not persist the delivery outcome to the settings row; "+
			"the settings screen may show a stale result. The audit log is authoritative",
			"tenant_id", tenantID, "project_id", projectID, "status", status, "error", uErr)
	}

	if status >= 200 && status < 300 && errMsg == "" {
		// F168: a 2xx webhook delivery that cannot audit MUST report
		// failure, not success — the audit row IS the durable record
		// the operator relies on.
		if aErr := s.writeAudit(ctx, tenantID, projectID, model.AuditActionDiffWebhookFired, status, "", counts); aErr != nil {
			return nil, fmt.Errorf("webhook delivered (status=%d) but audit log failed: %w", status, aErr)
		}
		return &FireDecision{Triggered: true, Status: status}, nil
	}
	if aErr := s.writeAudit(ctx, tenantID, projectID, model.AuditActionDiffWebhookFailed, status, errMsg, counts); aErr != nil {
		return nil, fmt.Errorf("webhook delivery failed (status=%d, err=%q) + audit log failed: %w", status, errMsg, aErr)
	}
	return &FireDecision{Triggered: true, Status: status, ErrorMessage: errMsg}, nil
}

// ---------- threshold evaluation ----------

type severityCounts struct {
	Critical  int
	High      int
	Medium    int
	Low       int
	Total     int
	Licenses  int
	Resolved  int
	SevChange int
}

func countSeverities(d *diff.Response) severityCounts {
	var c severityCounts
	for _, v := range d.Vulnerabilities.Added {
		c.Total++
		switch normaliseSeverity(v.Severity) {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		}
	}
	for _, v := range d.Vulnerabilities.SeverityChanged {
		// Only count upgrades (toward higher severity) as
		// threshold-relevant. We approximate by mapping both sides to
		// severity ranks and incrementing the rank-counter on a strict
		// upgrade.
		fromR := severityRank(v.FromSeverity)
		toR := severityRank(v.ToSeverity)
		if toR > fromR {
			c.SevChange++
			switch normaliseSeverity(v.ToSeverity) {
			case "critical":
				c.Critical++
			case "high":
				c.High++
			case "medium":
				c.Medium++
			case "low":
				c.Low++
			}
		}
	}
	c.Licenses = len(d.Licenses.AddedPolicyViolations)
	c.Resolved = len(d.Vulnerabilities.Resolved)
	return c
}

func exceededThreshold(c severityCounts, s *model.DiffWebhookSettings) bool {
	// "0 means any item triggers" rule for license_violation_threshold.
	if s.LicenseViolationThreshold == 0 && c.Licenses > 0 {
		return true
	}
	if s.LicenseViolationThreshold > 0 && c.Licenses >= s.LicenseViolationThreshold {
		return true
	}
	if s.CriticalThreshold > 0 && c.Critical >= s.CriticalThreshold {
		return true
	}
	if s.HighThreshold > 0 && c.High >= s.HighThreshold {
		return true
	}
	return false
}

func normaliseSeverity(s string) string {
	switch toLower(trimSpace(s)) {
	case "critical", "crit":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return ""
	}
}

func severityRank(s string) int {
	switch normaliseSeverity(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// minimal stdlib-equivalents kept inline so the package's lookup table
// is local + dependency-free.
func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// ---------- payload building ----------

// Payload is the canonical "json" format envelope. Slack format
// wraps a subset of these fields in a Slack-shaped object instead.
type Payload struct {
	Event       string            `json:"event"`
	TenantID    string            `json:"tenant_id"`
	ProjectID   string            `json:"project_id"`
	FromSbomID  string            `json:"from_sbom_id,omitempty"`
	ToSbomID    string            `json:"to_sbom_id,omitempty"`
	GeneratedAt string            `json:"generated_at"`
	Counts      payloadCounts     `json:"counts"`
	Thresholds  payloadThresholds `json:"thresholds"`
	URL         string            `json:"sbomhub_url,omitempty"`
}

type payloadCounts struct {
	ComponentsAdded      int `json:"components_added"`
	ComponentsRemoved    int `json:"components_removed"`
	ComponentsChanged    int `json:"components_version_changed"`
	VulnsAdded           int `json:"vulnerabilities_added"`
	VulnsResolved        int `json:"vulnerabilities_resolved"`
	VulnsSeverityChanged int `json:"vulnerabilities_severity_changed"`
	NewCriticalVulns     int `json:"new_critical_vulns"`
	NewHighVulns         int `json:"new_high_vulns"`
	NewLicenseViolations int `json:"new_license_violations"`
}

type payloadThresholds struct {
	Critical         int `json:"critical"`
	High             int `json:"high"`
	LicenseViolation int `json:"license_violation"`
}

func buildPayload(format string, tenantID, projectID uuid.UUID, d *diff.Response, c severityCounts, s *model.DiffWebhookSettings) interface{} {
	now := time.Now().UTC().Format(time.RFC3339)
	base := Payload{
		Event:       EventTypeDiff,
		TenantID:    tenantID.String(),
		ProjectID:   projectID.String(),
		GeneratedAt: now,
		Counts: payloadCounts{
			ComponentsAdded:      len(d.Components.Added),
			ComponentsRemoved:    len(d.Components.Removed),
			ComponentsChanged:    len(d.Components.VersionChanged),
			VulnsAdded:           len(d.Vulnerabilities.Added),
			VulnsResolved:        len(d.Vulnerabilities.Resolved),
			VulnsSeverityChanged: len(d.Vulnerabilities.SeverityChanged),
			NewCriticalVulns:     c.Critical,
			NewHighVulns:         c.High,
			NewLicenseViolations: c.Licenses,
		},
		Thresholds: payloadThresholds{
			Critical:         s.CriticalThreshold,
			High:             s.HighThreshold,
			LicenseViolation: s.LicenseViolationThreshold,
		},
	}
	if d.From != nil {
		base.FromSbomID = d.From.SbomID.String()
	}
	if d.To != nil {
		base.ToSbomID = d.To.SbomID.String()
	}

	if format != model.DiffWebhookFormatSlack {
		return base
	}

	// Slack format: pre-formatted text + attachment with the same
	// counts so a Slack channel can render the alert without an
	// intermediate worker.
	return map[string]interface{}{
		"text": fmt.Sprintf(
			"SBOMHub diff alert: %d new critical / %d new high vulns, %d new license violations on project %s",
			c.Critical, c.High, c.Licenses, projectID.String(),
		),
		"attachments": []map[string]interface{}{
			{
				"color": pickSlackColor(c),
				"fields": []map[string]interface{}{
					{"title": "Critical (new)", "value": c.Critical, "short": true},
					{"title": "High (new)", "value": c.High, "short": true},
					{"title": "License violations (new)", "value": c.Licenses, "short": true},
					{"title": "Resolved", "value": c.Resolved, "short": true},
					{"title": "Project ID", "value": projectID.String(), "short": false},
				},
				"ts": time.Now().Unix(),
			},
		},
		// The canonical envelope is embedded so a consumer that DOES verify
		// has the same fields the json format carries, and the signature (when
		// one is computed) covers the whole body. M48: for the slack format
		// delivered to hooks.slack.com there is normally no signature at all —
		// Slack does not read the header — so this is about payload parity,
		// not about verifiability.
		"sbomhub": base,
	}
}

func pickSlackColor(c severityCounts) string {
	if c.Critical > 0 {
		return "danger"
	}
	if c.High > 0 {
		return "warning"
	}
	return "good"
}

// ---------- HTTP delivery ----------

func (s *Service) deliver(ctx context.Context, url string, body []byte, signature string) (int, string) {
	var lastStatus int
	var lastErr string
	for i, backoff := range s.retries {
		if backoff > 0 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return lastStatus, ctx.Err().Error()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return 0, "build request: " + err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(EventHeader, EventTypeDiff)
		req.Header.Set("User-Agent", "SBOMHub-Webhook/1.0")
		if signature != "" {
			req.Header.Set(SignatureHeader, "sha256="+signature)
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = err.Error()
			lastStatus = 0
			slog.Warn("diff_webhook: delivery attempt failed",
				"attempt", i+1,
				"error", err.Error(),
			)
			continue
		}
		// Drain body so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastStatus = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return lastStatus, ""
		}
		// 3xx → no retry. The client is configured with
		// CheckRedirect: ErrUseLastResponse (see NewService), so a redirect
		// arrives here as an ordinary response rather than being followed.
		//
		// Codex round 3 (Low): without this arm a 3xx fell through to the
		// "retry" tail, was retried on every attempt, and returned an empty
		// ErrorMessage — so the operator saw a failed delivery with no reason,
		// contradicting FireDecision.ErrorMessage's contract. A redirect is a
		// consumer-side configuration problem exactly like a 4xx: the operator
		// should configure the final URL.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return lastStatus, fmt.Sprintf("HTTP %d (redirect not followed)", resp.StatusCode)
		}
		// 4xx → no retry (config error on the consumer side).
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return lastStatus, fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		// Anything else (5xx, and any status outside 1xx-5xx such as a
		// stray 101) → retry with the next backoff. Codex round 4 (Low):
		// this arm is the catch-all precisely so no status can reach the
		// return below with lastErr empty, which would produce a failed
		// FireDecision carrying no reason.
		lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return lastStatus, lastErr
}

// ---------- signature ----------

func computeSignature(body, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// ---------- audit ----------

// writeAudit writes a diff_webhook audit row. M11 Phase D F168: returns
// the error from the underlying audit Log so callers can enforce the
// package's audit-or-nothing contract. A 2xx webhook delivery that
// cannot persist its audit row MUST be reported as a failure, not a
// success — otherwise the operator sees `Triggered=true` with no
// matching `diff_webhook_fired` row, which contradicts the audit-trail
// guarantee CLAUDE.md requires.
func (s *Service) writeAudit(
	ctx context.Context, tenantID, projectID uuid.UUID,
	action string, status int, errMsg string,
	c severityCounts,
) error {
	details := map[string]interface{}{
		"http_status":       status,
		"critical_new":      c.Critical,
		"high_new":          c.High,
		"license_new":       c.Licenses,
		"resolved":          c.Resolved,
		"severity_upgrades": c.SevChange,
	}
	if errMsg != "" {
		details["error"] = errMsg
	}
	tenant := tenantID
	input := &model.CreateAuditLogInput{
		TenantID:     &tenant,
		Action:       action,
		ResourceType: model.ResourceDiffWebhook,
		ResourceID:   &projectID,
		Details:      details,
	}
	if err := s.audit.Log(ctx, input); err != nil {
		slog.Error("diff_webhook: audit log write failed",
			"tenant_id", tenantID.String(),
			"action", action,
			"error", err.Error(),
		)
		return err
	}
	return nil
}
