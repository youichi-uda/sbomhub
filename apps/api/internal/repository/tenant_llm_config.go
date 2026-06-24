package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
)

// TenantLLMConfig mirrors a row of the tenant_llm_config table
// (migration 036). It is the persisted form of the BYOK LLM provider
// configuration the operator wires up in /settings/llm.
//
// SECURITY: EncryptedAPIKey holds the nonce||sealed AES-256-GCM ciphertext
// produced by internal/service/llm.Encrypt. The plaintext API key MUST
// NEVER be put on this struct, in logs, or in JSON responses. The handler
// layer surfaces a placeholder ("***") instead. // ※要確認: cross-check the
// crypto helper signature once agent B's internal/service/llm/crypto.go is
// merged.
type TenantLLMConfig struct {
	TenantID uuid.UUID

	// Mode is "byok" in OSS / self-host. SaaS may also write
	// "managed_gemini" (LLM_PROVIDER_DESIGN.md §4.2) — out of scope for M1.
	Mode string

	Provider        string
	EncryptedAPIKey []byte
	Model           string

	AzureEndpoint   string
	AzureDeployment string
	OllamaURL       string

	// SaaS-only quota counters (NULL in OSS).
	QuotaMonthlyTokens      sql.NullInt64
	QuotaMonthlyTriageCount sql.NullInt64

	CreatedAt time.Time
	UpdatedAt time.Time
}

// HasAPIKey reports whether an encrypted key has been persisted for this
// tenant. Used by the handler to decide whether to surface a "***"
// placeholder vs. an empty string in the JSON response.
func (c *TenantLLMConfig) HasAPIKey() bool {
	return c != nil && len(c.EncryptedAPIKey) > 0
}

// TenantLLMConfigRepository persists tenant_llm_config rows.
type TenantLLMConfigRepository struct {
	db *sql.DB
}

// NewTenantLLMConfigRepository constructs the repository.
func NewTenantLLMConfigRepository(db *sql.DB) *TenantLLMConfigRepository {
	return &TenantLLMConfigRepository{db: db}
}

// ErrTenantLLMConfigNotFound is returned by Get when no row exists for the
// given tenant. The handler translates this to "AI disabled, no config" in
// the API response (rather than a 404) so the UI can render the empty
// form.
var ErrTenantLLMConfigNotFound = errors.New("tenant_llm_config: not found")

// q routes the statement through the request-scoped tx (Trust Rescue 9.1.2 /
// #3) when one is attached to ctx; falls back to r.db otherwise. Same
// pattern as audit / notification / scan-settings repositories.
func (r *TenantLLMConfigRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Get fetches the row for tenantID. Returns ErrTenantLLMConfigNotFound when
// no row exists so callers can distinguish "absent" from a real error.
func (r *TenantLLMConfigRepository) Get(ctx context.Context, tenantID uuid.UUID) (*TenantLLMConfig, error) {
	const query = `
		SELECT tenant_id, mode, provider, encrypted_api_key, model,
		       azure_endpoint, azure_deployment, ollama_url,
		       quota_monthly_tokens, quota_monthly_triage_count,
		       created_at, updated_at
		FROM tenant_llm_config
		WHERE tenant_id = $1
	`

	var (
		cfg             TenantLLMConfig
		provider        sql.NullString
		encryptedAPIKey []byte
		model           sql.NullString
		azureEndpoint   sql.NullString
		azureDeployment sql.NullString
		ollamaURL       sql.NullString
	)

	err := r.q(ctx).QueryRowContext(ctx, query, tenantID).Scan(
		&cfg.TenantID,
		&cfg.Mode,
		&provider,
		&encryptedAPIKey,
		&model,
		&azureEndpoint,
		&azureDeployment,
		&ollamaURL,
		&cfg.QuotaMonthlyTokens,
		&cfg.QuotaMonthlyTriageCount,
		&cfg.CreatedAt,
		&cfg.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrTenantLLMConfigNotFound
	}
	if err != nil {
		return nil, err
	}

	cfg.Provider = provider.String
	cfg.EncryptedAPIKey = encryptedAPIKey
	cfg.Model = model.String
	cfg.AzureEndpoint = azureEndpoint.String
	cfg.AzureDeployment = azureDeployment.String
	cfg.OllamaURL = ollamaURL.String
	return &cfg, nil
}

// UpsertParams is the input to Upsert. EncryptedAPIKey may be nil if the
// caller is only updating non-secret fields (the handler MUST preserve the
// existing ciphertext in that case by reading via Get first; this repository
// does NOT clear the key on a nil input).
type UpsertParams struct {
	TenantID uuid.UUID
	Mode     string

	Provider        string
	EncryptedAPIKey []byte // nil → preserve existing ciphertext
	Model           string

	AzureEndpoint   string
	AzureDeployment string
	OllamaURL       string
}

// Upsert inserts a row or updates the existing one (PK = tenant_id).
//
// Secret-handling contract:
//   - EncryptedAPIKey is BYTEA in the DB. When the input is nil we keep the
//     existing column value via COALESCE; passing a zero-length slice has
//     the same effect (treated as "preserve").
//   - To clear the key explicitly the caller should Delete or pass a marker
//     value; we deliberately do NOT expose a "clear" knob here so accidental
//     UI bugs cannot wipe an operator's key.
func (r *TenantLLMConfigRepository) Upsert(ctx context.Context, params UpsertParams) (*TenantLLMConfig, error) {
	const query = `
		INSERT INTO tenant_llm_config (
			tenant_id, mode, provider, encrypted_api_key, model,
			azure_endpoint, azure_deployment, ollama_url,
			created_at, updated_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, NULLIF($5, ''),
			NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''),
			NOW(), NOW()
		)
		ON CONFLICT (tenant_id) DO UPDATE
		SET mode              = EXCLUDED.mode,
		    provider          = EXCLUDED.provider,
		    encrypted_api_key = COALESCE(EXCLUDED.encrypted_api_key, tenant_llm_config.encrypted_api_key),
		    model             = EXCLUDED.model,
		    azure_endpoint    = EXCLUDED.azure_endpoint,
		    azure_deployment  = EXCLUDED.azure_deployment,
		    ollama_url        = EXCLUDED.ollama_url,
		    updated_at        = NOW()
	`

	// Treat a zero-length slice the same as nil so the COALESCE branch fires
	// and we preserve the existing ciphertext (avoids accidental wipe when
	// the JSON omits the api_key field).
	var keyArg interface{}
	if len(params.EncryptedAPIKey) == 0 {
		keyArg = nil
	} else {
		keyArg = params.EncryptedAPIKey
	}

	mode := params.Mode
	if mode == "" {
		mode = "byok"
	}

	if _, err := r.q(ctx).ExecContext(ctx, query,
		params.TenantID,
		mode,
		params.Provider,
		keyArg,
		params.Model,
		params.AzureEndpoint,
		params.AzureDeployment,
		params.OllamaURL,
	); err != nil {
		return nil, err
	}

	return r.Get(ctx, params.TenantID)
}

// Delete removes the row entirely. Used by key-rotation flows that want to
// reset the config to "AI disabled".
func (r *TenantLLMConfigRepository) Delete(ctx context.Context, tenantID uuid.UUID) error {
	_, err := r.q(ctx).ExecContext(ctx,
		`DELETE FROM tenant_llm_config WHERE tenant_id = $1`, tenantID)
	return err
}
