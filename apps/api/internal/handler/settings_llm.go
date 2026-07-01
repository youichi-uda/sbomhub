package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// apiKeyPlaceholder is what we surface in JSON responses when a tenant has
// a configured API key. The plaintext NEVER leaves the request handler
// that wrote it (LLM_PROVIDER_DESIGN.md §7.1 — never log policy applies to
// API responses too).
const apiKeyPlaceholder = "***"

// supportedLLMProviders mirrors the set enforced by
// internal/service/llm/factory.go NewProviderFromEnv. Kept here as a small
// allowlist so an arbitrary string from the request body cannot land in
// the DB. The three-way parity between this map, the factory switch arms
// (NewProviderFromEnv + NewProviderFromConfigWithAzure), and the web
// dropdown (apps/web/src/app/[locale]/(dashboard)/settings/llm/page.tsx
// PROVIDERS array) is enforced at CI time by
// TestLLMProviderRegistryParity_F318 — the second horizontal
// replication of anti-pattern 58 (emit / registry parity in dual-list
// systems; see M21-1). Adding a new provider requires updating this
// map + both factory switches + the web PROVIDERS array + the
// Provider.Name() doc-comment in service/llm/provider.go
// simultaneously; the meta-test fails loudly otherwise.
var supportedLLMProviders = map[string]struct{}{
	"openai":       {},
	"anthropic":    {},
	"gemini":       {},
	"azure_openai": {},
	"ollama":       {},
}

// SettingsLLMHandler serves /api/v1/settings/llm.
//
// Reads:
//
//	GET  /api/v1/settings/llm
//	  Returns the persisted config with the api_key field replaced by a
//	  placeholder ("***") when one is configured, or empty when not.
//
// Writes:
//
//	PUT  /api/v1/settings/llm
//	  Encrypts the supplied API key with internal/service/llm.Encrypt
//	  (AES-256-GCM, ENCRYPTION_KEY) and upserts the row. Records a
//	  llm_key_set / llm_key_rotated audit log (the key itself is NEVER
//	  written to logs / audit details).
type SettingsLLMHandler struct {
	repo      *repository.TenantLLMConfigRepository
	auditRepo *repository.AuditRepository
	cfg       *config.Config
}

// NewSettingsLLMHandler wires the handler.
func NewSettingsLLMHandler(
	repo *repository.TenantLLMConfigRepository,
	auditRepo *repository.AuditRepository,
	cfg *config.Config,
) *SettingsLLMHandler {
	return &SettingsLLMHandler{
		repo:      repo,
		auditRepo: auditRepo,
		cfg:       cfg,
	}
}

// settingsLLMResponse is the shape returned to the browser. The api_key
// field intentionally surfaces only a placeholder, never the plaintext.
type settingsLLMResponse struct {
	Mode             string `json:"mode"`
	Provider         string `json:"provider"`
	Model            string `json:"model"`
	APIKeyConfigured bool   `json:"api_key_configured"`
	APIKey           string `json:"api_key"` // always "" or "***"
	AzureEndpoint    string `json:"azure_endpoint,omitempty"`
	AzureDeployment  string `json:"azure_deployment,omitempty"`
	OllamaURL        string `json:"ollama_url,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// settingsLLMRequest is the PUT body.
//
// api_key:
//   - non-empty AND not equal to the placeholder → encrypt + persist
//   - "" or equal to placeholder                 → preserve existing key
//
// This matches the typical pattern where the UI re-submits the placeholder
// untouched when the operator only wanted to edit provider/model.
type settingsLLMRequest struct {
	Mode            string `json:"mode"`
	Provider        string `json:"provider"`
	Model           string `json:"model"`
	APIKey          string `json:"api_key"`
	AzureEndpoint   string `json:"azure_endpoint"`
	AzureDeployment string `json:"azure_deployment"`
	OllamaURL       string `json:"ollama_url"`
}

// Get returns the current LLM config (api_key as placeholder).
// GET /api/v1/settings/llm
func (h *SettingsLLMHandler) Get(c echo.Context) error {
	ctx := c.Request().Context()

	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	cfg, err := h.repo.Get(ctx, tc.TenantID())
	if errors.Is(err, repository.ErrTenantLLMConfigNotFound) {
		// Not configured yet — surface an empty response so the UI can
		// render the empty form without flashing a 404.
		return c.JSON(http.StatusOK, settingsLLMResponse{Mode: "byok"})
	}
	if err != nil {
		slog.Error("settings_llm: get failed",
			"tenant_id", tc.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to load LLM settings",
		})
	}

	return c.JSON(http.StatusOK, toResponse(cfg))
}

// Update upserts the LLM config. Encrypts the API key before persisting and
// emits a llm_key_set / llm_key_rotated audit record.
// PUT /api/v1/settings/llm
func (h *SettingsLLMHandler) Update(c echo.Context) error {
	ctx := c.Request().Context()

	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	if !tc.CanAdmin() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "admin permission required"})
	}

	var req settingsLLMRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Normalise + validate mode. OSS only ever writes "byok"; we accept the
	// empty string for compatibility with the empty initial form payload.
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "byok"
	}
	if mode != "byok" && mode != "managed_gemini" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "mode must be 'byok' or 'managed_gemini'",
		})
	}

	provider := strings.TrimSpace(strings.ToLower(req.Provider))
	if mode == "byok" {
		if provider == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "provider is required in byok mode",
			})
		}
		if _, ok := supportedLLMProviders[provider]; !ok {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "unsupported provider (expected openai|anthropic|gemini|azure_openai|ollama)",
			})
		}
	}

	// Look up the existing row so we can (a) decide if this is a new key vs
	// a rotation for the audit log, and (b) preserve the existing
	// ciphertext when the request body re-submits the placeholder.
	existing, err := h.repo.Get(ctx, tc.TenantID())
	if err != nil && !errors.Is(err, repository.ErrTenantLLMConfigNotFound) {
		slog.Error("settings_llm: existing lookup failed",
			"tenant_id", tc.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to load existing LLM settings",
		})
	}
	hadKey := existing != nil && existing.HasAPIKey()

	// Decide whether the request is updating the API key. Ollama doesn't
	// require one; for the other providers the key is mandatory on first
	// configuration.
	var encryptedKey []byte
	rawKey := req.APIKey
	keyTouched := rawKey != "" && rawKey != apiKeyPlaceholder

	if keyTouched {
		masterKey, err := h.cfg.GetEncryptionKey()
		if err != nil {
			slog.Error("settings_llm: master key unavailable", "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "server is missing a valid ENCRYPTION_KEY",
			})
		}
		// llm.Encrypt(plaintext, key []byte) ([]byte, error) — arg
		// order (secret, master) matches (plaintext, key) in
		// service/llm/crypto.go. The signature has been stable since
		// M1; a change would require updating this call site (compiler
		// will catch it) plus repository.TenantLLMConfigRepository's
		// decrypt path, so the coupling is caught at build time rather
		// than by hand-maintained sync warnings.
		ct, encErr := llm.Encrypt([]byte(rawKey), masterKey)
		if encErr != nil {
			slog.Error("settings_llm: encrypt failed", "error", encErr)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to encrypt API key",
			})
		}
		encryptedKey = ct
	} else if mode == "byok" && provider != "ollama" && !hadKey {
		// First configuration for a provider that needs a key but no key
		// was supplied — refuse rather than silently storing junk.
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "api_key is required for provider " + provider,
		})
	}

	saved, err := h.repo.Upsert(ctx, repository.UpsertParams{
		TenantID:        tc.TenantID(),
		Mode:            mode,
		Provider:        provider,
		EncryptedAPIKey: encryptedKey, // nil → preserve existing
		Model:           strings.TrimSpace(req.Model),
		AzureEndpoint:   strings.TrimSpace(req.AzureEndpoint),
		AzureDeployment: strings.TrimSpace(req.AzureDeployment),
		OllamaURL:       strings.TrimSpace(req.OllamaURL),
	})
	if err != nil {
		slog.Error("settings_llm: upsert failed",
			"tenant_id", tc.TenantID(), "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to save LLM settings",
		})
	}

	// Audit log. We log set vs rotated based on whether a key already
	// existed; the plaintext key is NEVER included in details. The audit
	// middleware also emits a generic settings.updated row — that's fine,
	// the explicit llm_key_* row is the load-bearing one for compliance.
	if keyTouched {
		action := model.ActionLLMKeySet
		if hadKey {
			action = model.ActionLLMKeyRotated
		}
		tenantID := tc.TenantID()
		userID := tc.UserID()
		var userIDPtr *uuid.UUID
		if userID != uuid.Nil {
			u := userID
			userIDPtr = &u
		}
		_ = h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
			TenantID:     &tenantID,
			UserID:       userIDPtr,
			Action:       action,
			ResourceType: model.ResourceLLMConfig,
			Details: map[string]interface{}{
				"provider": provider,
				"model":    saved.Model,
				// Deliberately NO api_key field — design §7.2 never-log policy.
			},
			IPAddress: c.RealIP(),
			UserAgent: c.Request().UserAgent(),
		})
	}

	return c.JSON(http.StatusOK, toResponse(saved))
}

// toResponse converts a repo row into the wire format, replacing the
// ciphertext with a placeholder.
func toResponse(cfg *repository.TenantLLMConfig) settingsLLMResponse {
	if cfg == nil {
		return settingsLLMResponse{Mode: "byok"}
	}
	resp := settingsLLMResponse{
		Mode:             cfg.Mode,
		Provider:         cfg.Provider,
		Model:            cfg.Model,
		APIKeyConfigured: cfg.HasAPIKey(),
		AzureEndpoint:    cfg.AzureEndpoint,
		AzureDeployment:  cfg.AzureDeployment,
		OllamaURL:        cfg.OllamaURL,
	}
	if cfg.HasAPIKey() {
		resp.APIKey = apiKeyPlaceholder
	}
	if !cfg.UpdatedAt.IsZero() {
		resp.UpdatedAt = cfg.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	return resp
}
