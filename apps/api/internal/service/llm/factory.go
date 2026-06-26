package llm

import (
	"context"
	"fmt"
	"log/slog"
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
	// EnvAzureAPIVersion pins the Azure OpenAI `api-version` query string.
	// Optional: when unset, azure_openai.go's defaultAzureAPIVersion is
	// used. Operators should set this if their Azure deployment is
	// pinned to a specific contract version (e.g. preview-only features).
	EnvAzureAPIVersion = "SBOMHUB_LLM_AZURE_API_VERSION"
	EnvOllamaURL       = "SBOMHUB_LLM_OLLAMA_URL"

	// Provider-specific API key env aliases (M4 Codex review #F47).
	//
	// docs/configuration.md / README.md / CLAUDE.md document the
	// provider-native env names (OPENAI_API_KEY, ANTHROPIC_API_KEY,
	// GOOGLE_API_KEY, OLLAMA_HOST) — the same names each provider's
	// official SDK and CLI honour. Before F47 the runtime factory only
	// consulted the canonical SBOMHUB_LLM_API_KEY / SBOMHUB_LLM_OLLAMA_URL,
	// so an operator who followed the docs got a silently disabled
	// provider (and Ollama silently fell back to http://localhost:11434
	// even when OLLAMA_HOST pointed at a remote GPU node).
	//
	// Precedence is canonical-first so existing self-host deployments
	// that set SBOMHUB_LLM_API_KEY keep working unchanged; the aliases
	// are pure fall-back. See resolveAPIKey / ollamaBaseURLFromEnv for
	// the resolution order.
	EnvOpenAIAPIKey    = "OPENAI_API_KEY"
	EnvAnthropicAPIKey = "ANTHROPIC_API_KEY"
	EnvGeminiAPIKey    = "GOOGLE_API_KEY"
	EnvGeminiAPIKeyAlt = "GEMINI_API_KEY" // Some Google docs / SDK paths use GEMINI_API_KEY in addition to GOOGLE_API_KEY.
	EnvAzureAPIKey     = "AZURE_OPENAI_API_KEY"
	EnvOllamaHost      = "OLLAMA_HOST"
)

// apiKeyEnvCandidates returns the env var names checked for the given
// provider, in canonical-first precedence order. Exposed (instead of inlined
// inside resolveAPIKey) so the DisabledProvider Reason can list the same
// envs the resolver consulted, and so factory_test.go can assert the
// precedence without re-deriving it.
func apiKeyEnvCandidates(providerName string) []string {
	candidates := []string{EnvAPIKey}
	switch providerName {
	case "openai":
		candidates = append(candidates, EnvOpenAIAPIKey)
	case "anthropic":
		candidates = append(candidates, EnvAnthropicAPIKey)
	case "gemini":
		candidates = append(candidates, EnvGeminiAPIKey, EnvGeminiAPIKeyAlt)
	case "azure_openai":
		// Azure's official SDK env name is AZURE_OPENAI_API_KEY; we do
		// NOT alias OPENAI_API_KEY here because mixing the two would
		// silently cause an Azure deployment to authenticate with an
		// OpenAI.com key (and vice versa).
		candidates = append(candidates, EnvAzureAPIKey)
	}
	return candidates
}

// resolveAPIKey returns the API key + the env var name it was resolved
// from for the given provider, walking canonical-first precedence
// (apiKeyEnvCandidates). Returns ("", "") when no key is configured.
//
// The second return value is the source env name — exposed so the
// factory can log which env was selected at slog.Debug without leaking
// the key value itself. Callers MUST NOT log the first return value.
func resolveAPIKey(providerName string) (key, source string) {
	for _, name := range apiKeyEnvCandidates(providerName) {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v, name
		}
	}
	return "", ""
}

// NewProviderFromEnv constructs a Provider from process environment.
//
// Behaviour matches LLM_PROVIDER_DESIGN.md §2.3:
//   - SBOMHUB_LLM_PROVIDER unset  → DisabledProvider (NOT an error).
//   - API key required for everything except ollama; missing key →
//     DisabledProvider (NOT an error).
//   - Unknown provider           → returns an error.
//   - Azure (M4-2)                → requires SBOMHUB_LLM_AZURE_ENDPOINT and
//     SBOMHUB_LLM_AZURE_DEPLOYMENT; missing → DisabledProvider (NOT an error).
//   - Ollama (M4)                 → requires SBOMHUB_LLM_MODEL; missing →
//     DisabledProvider (NOT an error).
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

	model := os.Getenv(EnvModel)

	// Ollama is local — no API key required. Every other provider has
	// canonical-first precedence (SBOMHUB_LLM_API_KEY > provider-native
	// alias). See M4 Codex review #F47: docs / README direct operators
	// at the provider-native env names (OPENAI_API_KEY, etc.), so the
	// factory must honour them as fall-backs to avoid silently disabling
	// a correctly-configured deployment.
	var apiKey string
	if providerName != "ollama" {
		var keySource string
		apiKey, keySource = resolveAPIKey(providerName)
		if apiKey == "" {
			candidates := apiKeyEnvCandidates(providerName)
			return &DisabledProvider{
				Reason: fmt.Sprintf("no API key found for provider %s (set one of %s; %s wins on tie)",
					providerName, strings.Join(candidates, ", "), EnvAPIKey),
			}, nil
		}
		// Operator observability: log which env was selected so a
		// misconfigured deployment ("I set OPENAI_API_KEY but it says
		// disabled") can be diagnosed without scraping the secret value.
		// SECURITY: keySource is the env name, NOT the key value; the
		// key itself is never logged here.
		slog.Debug("llm: resolved provider API key from env",
			"provider", providerName, "env", keySource)
	}

	switch providerName {
	case "openai":
		return NewOpenAI(apiKey, model), nil
	case "anthropic":
		return NewAnthropic(apiKey, model), nil
	case "gemini":
		return NewGemini(apiKey, model), nil
	case "azure_openai":
		// M4 Wave M4-2: Azure OpenAI Service. The deployment URL embeds
		// the model name (Azure routes by deployment, not body field),
		// so both endpoint + deployment are required. apiVersion is
		// optional — azure_openai.go defaults to a GA-stable value.
		endpoint := strings.TrimSpace(os.Getenv(EnvAzureEndpoint))
		deployment := strings.TrimSpace(os.Getenv(EnvAzureDeployment))
		if endpoint == "" {
			return &DisabledProvider{Reason: EnvAzureEndpoint + " is required for azure_openai"}, nil
		}
		if deployment == "" {
			return &DisabledProvider{Reason: EnvAzureDeployment + " is required for azure_openai"}, nil
		}
		apiVersion := strings.TrimSpace(os.Getenv(EnvAzureAPIVersion))
		return NewAzureOpenAI(apiKey, endpoint, deployment, apiVersion, model), nil
	case "ollama":
		// M4 Wave M4-1: Local LLM path for manufacturers who cannot
		// send proprietary code to external APIs. Unlike the BYOK
		// providers, Ollama has no API key — the operator is
		// responsible for restricting access to the Ollama service
		// (TLS + IP allowlist on the reverse proxy).
		//
		// We require SBOMHUB_LLM_MODEL explicitly rather than fetching
		// the first chat-capable tag from GET /api/tags at boot. This
		// keeps the factory fully sync + offline (no startup HTTP
		// dependency on the LLM service) and makes the configured
		// model auditable from env alone. ※要確認: M4-3 bench may
		// re-evaluate whether a /api/tags auto-detect helper is worth
		// the boot-time coupling.
		if model == "" {
			return &DisabledProvider{Reason: EnvModel + " is required for Ollama (no auto-detect; set e.g. qwen2.5-coder:7b)"}, nil
		}
		return NewOllama(ollamaBaseURLFromEnv(), model), nil
	default:
		return nil, fmt.Errorf("llm: unknown provider %q (expected openai|anthropic|gemini|azure_openai|ollama)", providerName)
	}
}

// ollamaBaseURLFromEnv reads SBOMHUB_LLM_OLLAMA_URL, falling back to
// http://localhost:11434 when unset. Centralised so both
// NewProviderFromEnv and NewProviderFromConfig pick up the same value
// without each one re-implementing the default.
//
// ※要確認: NewProviderFromConfig is per-tenant; if a future milestone
// wants per-tenant Ollama URLs (e.g. one tenant points at a GPU node
// in their own VPC) this helper should be replaced by a field on
// tenant_llm_config. For M4 the typical OSS / self-host deployment is
// single-tenant, so env is sufficient and we avoid a breaking
// signature change on NewProviderFromConfig (called from
// apps/api/cmd/server/main.go).
func ollamaBaseURLFromEnv() string {
	if v := strings.TrimSpace(os.Getenv(EnvOllamaURL)); v != "" {
		slog.Debug("llm: resolved Ollama base URL from env",
			"env", EnvOllamaURL)
		return v
	}
	// M4 Codex review #F47: OLLAMA_HOST is the Ollama project's official
	// env (their CLI / SDK consult it directly). Honouring it as a
	// fall-back means an operator who followed README / docs and only
	// set OLLAMA_HOST gets their configured base URL instead of being
	// silently redirected to http://localhost:11434.
	//
	// The value is passed through verbatim — Ollama accepts both
	// `host:port` and `scheme://host:port` formats; URL normalisation is
	// the provider's responsibility, not the factory's.
	if v := strings.TrimSpace(os.Getenv(EnvOllamaHost)); v != "" {
		slog.Debug("llm: resolved Ollama base URL from env",
			"env", EnvOllamaHost)
		return v
	}
	return defaultOllamaEndpoint
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
//   - azure_openai (M4-2) → requires Azure endpoint + deployment; when the
//     caller cannot supply them via this signature, returns DisabledProvider
//     and the caller should switch to NewProviderFromConfigWithAzure (which
//     accepts the additional fields persisted on tenant_llm_config).
//   - ollama (M4) → requires non-empty model; missing → DisabledProvider.
//
// SECURITY: apiKey is a decrypted secret. The caller must zero its backing
// buffer after this returns. We deliberately do NOT log apiKey here (provider
// implementations honour the slog.LogValuer contract from provider.go).
//
// This wraps NewProviderFromConfigWithAzure with empty Azure fields to
// preserve the existing call signature for triage / cra / meti callers
// that have not yet been updated to pass the per-tenant Azure
// endpoint/deployment from tenant_llm_config. ※要確認: M4 follow-up to
// thread tenant_llm_config.azure_endpoint/azure_deployment through the
// resolver in cmd/server/main.go so Azure BYOK works at the tenant level.
func NewProviderFromConfig(provider, model, apiKey string) (Provider, error) {
	return NewProviderFromConfigWithAzure(provider, model, apiKey, "", "", "")
}

// NewProviderFromConfigWithAzure is the extended variant that accepts
// per-tenant Azure OpenAI fields (azure_endpoint / azure_deployment /
// optional azure_api_version) alongside the BYOK key. Used by the M4-2
// per-tenant resolver path once the resolver in cmd/server/main.go is
// updated to read tenant_llm_config.AzureEndpoint / AzureDeployment.
//
// Behaviour is identical to NewProviderFromConfig for every provider
// other than azure_openai. For azure_openai, missing endpoint or
// deployment downgrades to DisabledProvider (not an error) so the
// resolver can fall back to the env-resolved default the same way it
// does when api_key is missing.
//
// SECURITY: apiKey, azureEndpoint, and azureDeployment can carry
// tenant-scoped metadata; we do NOT log them here (provider impl
// honours slog.LogValuer).
func NewProviderFromConfigWithAzure(provider, model, apiKey, azureEndpoint, azureDeployment, azureAPIVersion string) (Provider, error) {
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
		// M4 Wave M4-2: per-tenant Azure OpenAI. Both endpoint and
		// deployment must be supplied by the caller (the resolver reads
		// them from tenant_llm_config). Missing fields downgrade to
		// DisabledProvider so the resolver can fall back to the env
		// default exactly the way it does for missing API keys.
		endpoint := strings.TrimSpace(azureEndpoint)
		deployment := strings.TrimSpace(azureDeployment)
		if endpoint == "" {
			return &DisabledProvider{Reason: "tenant_llm_config.azure_endpoint is required for azure_openai"}, nil
		}
		if deployment == "" {
			return &DisabledProvider{Reason: "tenant_llm_config.azure_deployment is required for azure_openai"}, nil
		}
		return NewAzureOpenAI(apiKey, endpoint, deployment, strings.TrimSpace(azureAPIVersion), model), nil
	case "ollama":
		// M4 Wave M4-1: Per-tenant Ollama. The model is required (no
		// auto-detect — see NewProviderFromEnv comment). The base URL
		// comes from env rather than tenant_llm_config because the
		// typical OSS / self-host deployment is single-tenant; a
		// per-tenant URL would require a NewProviderFromConfig
		// signature change. ※要確認: revisit if M2+ adds multi-tenant
		// self-host with per-tenant GPU pools.
		if model == "" {
			return &DisabledProvider{Reason: "tenant_llm_config.model is required for Ollama (no auto-detect)"}, nil
		}
		return NewOllama(ollamaBaseURLFromEnv(), model), nil
	default:
		return nil, fmt.Errorf("llm: unknown provider %q (expected openai|anthropic|gemini|azure_openai|ollama)", name)
	}
}
