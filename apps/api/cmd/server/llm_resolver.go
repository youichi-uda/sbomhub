package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// tenantLLMConfigGetter is the minimum-needed contract for the
// per-tenant LLM resolver. It is satisfied by
// *repository.TenantLLMConfigRepository in the production wiring; tests
// substitute a fake to avoid spinning up Postgres just to verify which
// llm.Provider variant the resolver constructs.
type tenantLLMConfigGetter interface {
	Get(ctx context.Context, tenantID uuid.UUID) (*repository.TenantLLMConfig, error)
}

// newTenantLLMProviderResolver returns the per-tenant Provider resolver
// used by both triage and CRA runners (M1 Codex review #F2 introduced it,
// M4 Codex review #F40 fixed the silent disable for azure_openai).
//
// Behaviour:
//   - tenant has no row → fall back to defaultProvider (env-resolved).
//   - tenant row's provider is non-ollama AND no API key → fall back to
//     defaultProvider so the runner's #F4 ai_disabled path only fires
//     when BOTH the tenant config AND the env default are missing.
//   - otherwise → build a fresh llm.Provider from the tenant row, threading
//     through the Azure OpenAI BYOK fields (azure_endpoint /
//     azure_deployment) via NewProviderFromConfigWithAzure. Without this
//     wiring the resolver previously called the no-Azure variant and the
//     factory silent-disabled azure_openai tenants even when the
//     /settings/llm UI had persisted endpoint + deployment.
//
// The schema (migration 036) does not persist azure_api_version, so the
// resolver passes "" and azure_openai.go falls back to its
// defaultAzureAPIVersion ("2024-10-21").
//
// SECURITY: the decrypted plaintext API key is zeroed in its backing
// buffer before this function returns, matching the original closure
// implementation in main.go.
func newTenantLLMProviderResolver(
	repo tenantLLMConfigGetter,
	defaultProvider llm.Provider,
	encryptionKey []byte,
) func(ctx context.Context, tenantID uuid.UUID) (llm.Provider, error) {
	return func(ctx context.Context, tenantID uuid.UUID) (llm.Provider, error) {
		cfg, err := repo.Get(ctx, tenantID)
		if errors.Is(err, repository.ErrTenantLLMConfigNotFound) {
			// Tenant has not configured BYOK — fall back to env default.
			return defaultProvider, nil
		}
		if err != nil {
			return nil, fmt.Errorf("load tenant_llm_config: %w", err)
		}
		// Ollama (M4) has no API key. For everything else, a missing key
		// means "BYOK configured but incomplete" — fall back to env so
		// the runner's #F4 ai_disabled path only fires when BOTH are
		// missing.
		needsKey := strings.ToLower(strings.TrimSpace(cfg.Provider)) != "ollama"
		if needsKey && !cfg.HasAPIKey() {
			return defaultProvider, nil
		}
		var apiKey string
		if cfg.HasAPIKey() {
			plaintext, decErr := llm.Decrypt(cfg.EncryptedAPIKey, encryptionKey)
			if decErr != nil {
				return nil, fmt.Errorf("decrypt tenant llm key: %w", decErr)
			}
			apiKey = string(plaintext)
			// Best-effort: zero the plaintext buffer once we've handed
			// the string to the provider. (Go strings are immutable, so
			// once apiKey is built the byte slice can be wiped.)
			for i := range plaintext {
				plaintext[i] = 0
			}
		}
		// M4 Codex review #F40: thread the per-tenant Azure OpenAI
		// fields (azure_endpoint / azure_deployment) through the
		// extended factory so `provider = azure_openai` + tenant BYOK
		// key is not silent-disabled. Without this, the resolver hit
		// the old `NewProviderFromConfig` (empty Azure inputs) and the
		// factory downgraded to DisabledProvider even when the
		// /settings/llm UI had persisted both endpoint and deployment.
		// The schema (migration 036) has no azure_api_version column,
		// so we pass "" and let azure_openai.go fall back to its
		// defaultAzureAPIVersion ("2024-10-21").
		p, perr := llm.NewProviderFromConfigWithAzure(
			cfg.Provider,
			cfg.Model,
			apiKey,
			cfg.AzureEndpoint,
			cfg.AzureDeployment,
			"", // azure_api_version not in tenant_llm_config schema
		)
		if perr != nil {
			return nil, fmt.Errorf("build tenant provider: %w", perr)
		}
		return p, nil
	}
}
