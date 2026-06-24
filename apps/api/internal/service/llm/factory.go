package llm

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Env var names. Centralised so misspellings are caught at compile time and
// so the env contract matches LLM_PROVIDER_DESIGN.md §3.1.
const (
	EnvProvider = "SBOMHUB_LLM_PROVIDER" // openai | anthropic | gemini | azure_openai | ollama
	EnvAPIKey   = "SBOMHUB_LLM_API_KEY"
	EnvModel    = "SBOMHUB_LLM_MODEL"

	EnvAzureEndpoint   = "SBOMHUB_LLM_AZURE_ENDPOINT"
	EnvAzureDeployment = "SBOMHUB_LLM_AZURE_DEPLOYMENT"
	EnvOllamaURL       = "SBOMHUB_LLM_OLLAMA_URL"
)

// NewProviderFromEnv constructs a Provider from process environment.
//
// Behaviour matches LLM_PROVIDER_DESIGN.md §2.3:
//   - SBOMHUB_LLM_PROVIDER unset  → DisabledProvider (NOT an error).
//   - API key required for everything except ollama; missing key →
//     DisabledProvider (NOT an error).
//   - Unknown provider           → returns an error.
//   - Azure / Ollama             → not implemented in M1, returns an error.
//
// The context is reserved for future use (e.g. fetching keys from a secrets
// manager); current providers do not call it.
//
// PRODUCT_REBOOT_PLAN.md §20: OSS must not bundle keys nor hardcode provider
// URLs — all configuration flows through env.
func NewProviderFromEnv(_ context.Context) (Provider, error) {
	providerName := strings.ToLower(strings.TrimSpace(os.Getenv(EnvProvider)))
	if providerName == "" {
		return &DisabledProvider{Reason: EnvProvider + " is not set (BYOK required)"}, nil
	}

	apiKey := os.Getenv(EnvAPIKey)
	model := os.Getenv(EnvModel)

	// Ollama is local — no API key required.
	if providerName != "ollama" && apiKey == "" {
		return &DisabledProvider{Reason: EnvAPIKey + " is not set (BYOK required for provider " + providerName + ")"}, nil
	}

	switch providerName {
	case "openai":
		return NewOpenAI(apiKey, model), nil
	case "anthropic":
		return NewAnthropic(apiKey, model), nil
	case "gemini":
		return NewGemini(apiKey, model), nil
	case "azure_openai":
		// ※要確認: M2 will implement Azure OpenAI. We surface a clear error
		// today rather than silently degrading to DisabledProvider so
		// operators don't think they configured the wrong env.
		_ = os.Getenv(EnvAzureEndpoint)
		_ = os.Getenv(EnvAzureDeployment)
		return nil, fmt.Errorf("llm: provider %q is not implemented in M1 (planned for M2)", providerName)
	case "ollama":
		// ※要確認: M4 will implement Ollama (local LLM). See
		// PRODUCT_REBOOT_PLAN.md §13 milestone M4.
		_ = os.Getenv(EnvOllamaURL)
		return nil, fmt.Errorf("llm: provider %q is not implemented in M1 (planned for M4)", providerName)
	default:
		return nil, fmt.Errorf("llm: unknown provider %q (expected openai|anthropic|gemini|azure_openai|ollama)", providerName)
	}
}

// NewProviderFromConfig constructs a Provider from explicit values rather than
// process environment. Used by per-tenant BYOK resolution (M1 Codex review #F2):
// /settings/llm stores the encrypted API key in tenant_llm_config, the triage
// runner decrypts it per request, then calls this helper to build a
// tenant-scoped Provider so the request uses the tenant's chosen model rather
// than the server-startup env defaults.
//
// Behaviour matches NewProviderFromEnv except the inputs come from
// tenant_llm_config:
//   - provider == "" → DisabledProvider (caller should fall back to default).
//   - apiKey required for all providers except "ollama"; missing → DisabledProvider.
//   - unknown provider → error.
//   - azure_openai / ollama → not implemented in M1 (returns error). // ※要確認
//
// SECURITY: apiKey is a decrypted secret. The caller must zero its backing
// buffer after this returns. We deliberately do NOT log apiKey here (provider
// implementations honour the slog.LogValuer contract from provider.go).
func NewProviderFromConfig(provider, model, apiKey string) (Provider, error) {
	name := strings.ToLower(strings.TrimSpace(provider))
	if name == "" {
		return &DisabledProvider{Reason: "tenant_llm_config.provider is empty (BYOK required)"}, nil
	}
	if name != "ollama" && apiKey == "" {
		return &DisabledProvider{Reason: "tenant_llm_config.encrypted_api_key is empty (BYOK required for provider " + name + ")"}, nil
	}
	switch name {
	case "openai":
		return NewOpenAI(apiKey, model), nil
	case "anthropic":
		return NewAnthropic(apiKey, model), nil
	case "gemini":
		return NewGemini(apiKey, model), nil
	case "azure_openai":
		// ※要確認: M2 will implement Azure OpenAI per LLM_PROVIDER_DESIGN.md.
		return nil, fmt.Errorf("llm: provider %q is not implemented in M1 (planned for M2)", name)
	case "ollama":
		// ※要確認: M4 will implement Ollama (local LLM).
		return nil, fmt.Errorf("llm: provider %q is not implemented in M1 (planned for M4)", name)
	default:
		return nil, fmt.Errorf("llm: unknown provider %q (expected openai|anthropic|gemini|azure_openai|ollama)", name)
	}
}
