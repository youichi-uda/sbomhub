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
