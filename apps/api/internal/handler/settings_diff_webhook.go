package handler

// settings_diff_webhook.go — M11-4 (#79) — operator-facing settings
// endpoints for the per-tenant SBOM diff webhook (migration 046 /
// internal/service/diff_webhook).
//
// Mirrors settings_llm.go in shape:
//
//   GET  /api/v1/tenant/settings/diff-webhook
//   PUT  /api/v1/tenant/settings/diff-webhook
//
// SECURITY: the webhook_secret is AES-256-GCM ciphertext on disk. The
// plaintext NEVER leaves the request handler that wrote it; GET
// surfaces the literal "***" placeholder when a secret is configured.

import (
	"errors"
	"log/slog"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/diff_webhook"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// webhookSecretPlaceholder mirrors apiKeyPlaceholder in settings_llm.go.
const webhookSecretPlaceholder = "***"

// SettingsDiffWebhookHandler exposes the tenant-scoped diff webhook
// settings to /api/v1/tenant/settings/diff-webhook.
type SettingsDiffWebhookHandler struct {
	repo      *repository.DiffWebhookRepository
	auditRepo *repository.AuditRepository
	cfg       *config.Config
}

// NewSettingsDiffWebhookHandler wires the handler.
func NewSettingsDiffWebhookHandler(
	repo *repository.DiffWebhookRepository,
	auditRepo *repository.AuditRepository,
	cfg *config.Config,
) *SettingsDiffWebhookHandler {
	return &SettingsDiffWebhookHandler{
		repo:      repo,
		auditRepo: auditRepo,
		cfg:       cfg,
	}
}

type settingsDiffWebhookResponse struct {
	Enabled                   bool       `json:"enabled"`
	WebhookURL                string     `json:"webhook_url"`
	SecretConfigured          bool       `json:"secret_configured"`
	Secret                    string     `json:"webhook_secret"` // always "" or "***"
	Format                    string     `json:"format"`
	CriticalThreshold         int        `json:"critical_threshold"`
	HighThreshold             int        `json:"high_threshold"`
	LicenseViolationThreshold int        `json:"license_violation_threshold"`
	LastFiredAt               *time.Time `json:"last_fired_at,omitempty"`
	LastResponseStatus        *int       `json:"last_response_status,omitempty"`
	LastError                 string     `json:"last_error,omitempty"`
	UpdatedAt                 *time.Time `json:"updated_at,omitempty"`
}

type settingsDiffWebhookRequest struct {
	Enabled                   bool   `json:"enabled"`
	WebhookURL                string `json:"webhook_url"`
	WebhookSecret             string `json:"webhook_secret"`
	Format                    string `json:"format"`
	CriticalThreshold         int    `json:"critical_threshold"`
	HighThreshold             int    `json:"high_threshold"`
	LicenseViolationThreshold int    `json:"license_violation_threshold"`
}

// Get returns the current settings with the secret replaced by "***"
// when configured. Empty initial state (no row) renders as Enabled=false
// + default thresholds so the UI can render the empty form.
func (h *SettingsDiffWebhookHandler) Get(c echo.Context) error {
	ctx := c.Request().Context()
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	row, err := h.repo.Get(ctx, tc.TenantID())
	if errors.Is(err, repository.ErrDiffWebhookNotFound) {
		return c.JSON(http.StatusOK, settingsDiffWebhookResponse{
			Enabled:                   false,
			Format:                    model.DiffWebhookFormatJSON,
			CriticalThreshold:         1,
			HighThreshold:             5,
			LicenseViolationThreshold: 0,
		})
	}
	if err != nil {
		slog.Error("settings_diff_webhook: get failed",
			"tenant_id", tc.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to load diff webhook settings",
		})
	}

	resp := settingsDiffWebhookResponse{
		Enabled:                   row.Enabled,
		WebhookURL:                row.WebhookURL,
		SecretConfigured:          row.HasSecret(),
		Format:                    row.Format,
		CriticalThreshold:         row.CriticalThreshold,
		HighThreshold:             row.HighThreshold,
		LicenseViolationThreshold: row.LicenseViolationThreshold,
		UpdatedAt:                 ptrTime(row.UpdatedAt),
	}
	if row.HasSecret() {
		resp.Secret = webhookSecretPlaceholder
	}
	if row.LastFiredAt.Valid {
		t := row.LastFiredAt.Time
		resp.LastFiredAt = &t
	}
	if row.LastResponseStatus.Valid {
		s := int(row.LastResponseStatus.Int64)
		resp.LastResponseStatus = &s
	}
	if row.LastError.Valid {
		resp.LastError = row.LastError.String
	}
	return c.JSON(http.StatusOK, resp)
}

// Update upserts the settings, encrypts a newly-supplied secret, and
// writes an audit row. Admin-only.
func (h *SettingsDiffWebhookHandler) Update(c echo.Context) error {
	ctx := c.Request().Context()
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	if !tc.CanAdmin() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "admin permission required"})
	}

	var req settingsDiffWebhookRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Validation. URL is required when enabled.
	url := strings.TrimSpace(req.WebhookURL)
	if req.Enabled && url == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "webhook_url is required when enabled=true",
		})
	}
	// Codex round 2 (Low): the prefix test alone accepted "https://" with no
	// host at all, while diff_webhook.SignatureRequired's comment claimed this
	// handler rejects malformed URLs. Parse it, so that claim is true and so
	// the Slack-host comparison downstream has something well-formed to work
	// with.
	if url != "" {
		// Codex round 3 (Low): Hostname(), not Host. "http://:80/path" has a
		// non-empty Host and no hostname at all, and would have satisfied a
		// check that claimed to require one.
		parsed, perr := neturl.Parse(url)
		if perr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "webhook_url must be a valid absolute http:// or https:// URL with a host",
			})
		}
	}

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = model.DiffWebhookFormatJSON
	}
	if format != model.DiffWebhookFormatJSON && format != model.DiffWebhookFormatSlack {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "format must be 'json' or 'slack'",
		})
	}
	if req.CriticalThreshold < 0 || req.HighThreshold < 0 || req.LicenseViolationThreshold < 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "thresholds must be >= 0",
		})
	}

	// Look up the existing row to (a) preserve the existing secret when
	// the request body re-submits the placeholder, (b) decide
	// configured-vs-rotated for the audit row.
	existing, err := h.repo.Get(ctx, tc.TenantID())
	if err != nil && !errors.Is(err, repository.ErrDiffWebhookNotFound) {
		slog.Error("settings_diff_webhook: existing lookup failed",
			"tenant_id", tc.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to load existing settings",
		})
	}

	// M48 (FO-5): a webhook that will fire must be able to be verified by the
	// thing receiving it.
	//
	// The sender used to omit X-SBOMHub-Signature whenever no secret was
	// configured and POST anyway, which is the mirror image of the fail-open
	// M47 closed on the receiving side. Refusing here is the half that keeps
	// new rows out of that state; diff_webhook.FireIfThreshold refuses at send
	// time for rows that predate this check.
	//
	// Scoped by diff_webhook.SignatureRequired, which exempts ONLY
	// format=slack delivered over https to hooks.slack.com — Slack does not
	// read our signature header and that URL is itself the credential.
	//
	// The condition asks whether a secret will EXIST after this write, not
	// whether the request carried one — re-submitting the "***" placeholder
	// preserves the stored secret (repository.Upsert COALESCEs a nil
	// EncryptedSecret onto the stored column) and must keep working.
	raw := req.WebhookSecret
	secretWillExist := (raw != "" && raw != webhookSecretPlaceholder) ||
		(existing != nil && existing.HasSecret())
	if req.Enabled && diff_webhook.SignatureRequired(format, url) && !secretWillExist {
		// Codex round 2 (Low): the message used to say the requirement applied
		// to format='json' and suggest switching to 'slack'. Since the slack
		// exemption also checks the host, that advice was wrong for the
		// commonest way to hit this — format='slack' pointed at a
		// Slack-compatible relay — and would have sent the operator round in a
		// circle.
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "webhook_secret is required when enabled=true: without it the payload is " +
				"delivered unsigned and the receiver cannot verify it came from this SBOMHub " +
				"installation. The only exception is format='slack' sent to " +
				"https://hooks.slack.com/... , where the webhook URL is itself the credential; " +
				"any other destination — including a Slack-compatible relay — needs a shared secret.",
		})
	}

	// Encrypt secret if provided + not placeholder.
	var encryptedSecret []byte
	secretTouched := raw != "" && raw != webhookSecretPlaceholder
	if secretTouched { //nolint:nestif // unchanged pre-M48 shape
		masterKey, gerr := h.cfg.GetEncryptionKey()
		if gerr != nil {
			slog.Error("settings_diff_webhook: master key unavailable", "error", gerr)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "server is missing a valid ENCRYPTION_KEY",
			})
		}
		ct, encErr := llm.Encrypt([]byte(raw), masterKey)
		if encErr != nil {
			slog.Error("settings_diff_webhook: encrypt failed", "error", encErr)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to encrypt webhook secret",
			})
		}
		encryptedSecret = ct
	}

	row, err := h.repo.Upsert(ctx, repository.UpsertDiffWebhookParams{
		TenantID:                  tc.TenantID(),
		WebhookURL:                url,
		EncryptedSecret:           encryptedSecret,
		CriticalThreshold:         req.CriticalThreshold,
		HighThreshold:             req.HighThreshold,
		LicenseViolationThreshold: req.LicenseViolationThreshold,
		Format:                    format,
		Enabled:                   req.Enabled,
	})
	if err != nil {
		slog.Error("settings_diff_webhook: upsert failed",
			"tenant_id", tc.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to persist settings",
		})
	}

	// Audit (best-effort — do not fail the request on audit failure).
	tenant := tc.TenantID()
	user := tc.UserID()
	details := map[string]interface{}{
		"enabled":                     row.Enabled,
		"webhook_url_set":             row.WebhookURL != "",
		"secret_rotated":              secretTouched && existing != nil && existing.HasSecret(),
		"secret_configured":           row.HasSecret(),
		"format":                      row.Format,
		"critical_threshold":          row.CriticalThreshold,
		"high_threshold":              row.HighThreshold,
		"license_violation_threshold": row.LicenseViolationThreshold,
	}
	input := &model.CreateAuditLogInput{
		TenantID:     &tenant,
		UserID:       &user,
		Action:       model.AuditActionDiffWebhookUpdated,
		ResourceType: model.ResourceDiffWebhook,
		ResourceID:   &tenant,
		Details:      details,
	}
	if aerr := h.auditRepo.Log(ctx, input); aerr != nil {
		slog.Warn("settings_diff_webhook: audit log failed",
			"tenant_id", tenant, "error", aerr)
	}

	// Re-render via GET to keep response shape consistent.
	return h.Get(c)
}

func ptrTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
