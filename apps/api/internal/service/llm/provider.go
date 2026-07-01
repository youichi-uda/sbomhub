// Package llm provides a provider-agnostic abstraction over LLM backends
// (OpenAI / Anthropic / Google Gemini / Azure OpenAI / Ollama).
//
// Design reference: sbomhub-internal/planning/LLM_PROVIDER_DESIGN.md §2.
// Policy reference: sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §20
// (OSS は BYOK 必須 / バンドル LLM key を持たない / 未設定時は disable).
//
// All provider implementations must:
//   - Never log API keys, neither directly nor via panic stack traces.
//   - Implement slog.LogValuer so that logging a *Provider only surfaces
//     {provider, model} and never the secret.
//   - Use httptest-friendly endpoints (configurable base URL) so unit tests
//     can run without touching real APIs.
package llm

import (
	"context"
	"errors"
)

// Provider is the common abstraction over LLM backends.
//
// Implementations are constructed via NewProviderFromEnv (OSS / self-host) or
// (under //go:build saas) NewProviderForTenant. Callers must treat Provider
// as immutable after construction.
type Provider interface {
	// Name returns the provider identifier. The identifier universe
	// splits by build variant:
	//   - OSS build (default): openai, anthropic, gemini, azure_openai,
	//     ollama. All five are listed in
	//     handler/settings_llm.go supportedLLMProviders and mirrored in
	//     apps/web/src/app/[locale]/(dashboard)/settings/llm/page.tsx
	//     PROVIDERS array.
	//   - SaaS build (//go:build saas): the OSS 5 plus managed_gemini
	//     (compiled from managed_gemini.go only under this build tag).
	//   - disabled is the sentinel returned by DisabledProvider.Name()
	//     for the missing-key / unset-provider path; it is not a real
	//     provider entry.
	// See TestLLMProviderRegistryParity_F318 in handler/ for the
	// enforced parity contract (M21-1, anti-pattern 58 horizontal
	// replication).
	Name() string

	// Model returns the model ID currently in use ("" for disabled).
	Model() string

	// Complete generates a chat completion.
	Complete(ctx context.Context, req CompleteRequest) (*CompleteResponse, error)

	// Embed produces embedding vectors.
	//
	// M1 scope: providers may return ErrNotImplemented. The interface keeps
	// the method so that M2 reachability / search features can introduce
	// embeddings without breaking callers.
	Embed(ctx context.Context, req EmbedRequest) (*EmbedResponse, error)

	// Capabilities returns the provider/model feature flags
	// (JSON mode, function calling, vision, embedding, context window).
	Capabilities() Capabilities
}

// CompleteRequest is the unified chat completion input.
type CompleteRequest struct {
	// System prompt (optional). Providers that lack a dedicated system slot
	// (e.g. Gemini < 1.5) will inline this as a user/assistant pair.
	System string

	// Messages is the chat history (excluding System).
	Messages []Message

	// Temperature 0.0 means deterministic where supported.
	Temperature float32

	// MaxTokens caps the response length. 0 means provider default.
	MaxTokens int

	// JSONMode requests JSON-only output if the provider supports it.
	JSONMode bool

	// JSONSchema requests structured output conforming to the given JSON
	// schema (OpenAI / Gemini). Ignored if unsupported.
	JSONSchema map[string]interface{}

	// Stop sequences (provider-specific limits apply).
	Stop []string

	// TenantID / UserID are recorded by the audit layer (llm_calls table).
	TenantID string
	UserID   string

	// Purpose is a short label for audit & cost analytics
	// ("vex_triage" / "cra_draft" / "meti_prefill" / "embed").
	Purpose string
}

// Message is a single turn in a chat history.
type Message struct {
	// Role is "user" | "assistant" | "tool".
	Role    string
	Content string
}

// CompleteResponse is the unified chat completion output.
type CompleteResponse struct {
	Content      string
	InputTokens  int
	OutputTokens int
	Model        string
	FinishReason string
	CostUSD      float64
	// RawResponse is the raw HTTP body, retained for audit hashing.
	// Callers should hash this before persisting (see audit layer).
	RawResponse []byte
}

// EmbedRequest is the unified embedding input.
type EmbedRequest struct {
	Texts    []string
	TenantID string
	UserID   string
	Purpose  string
}

// EmbedResponse is the unified embedding output.
type EmbedResponse struct {
	Vectors     [][]float32
	InputTokens int
	Model       string
	CostUSD     float64
}

// Capabilities describes static provider/model feature flags.
type Capabilities struct {
	SupportsJSONMode     bool
	SupportsJSONSchema   bool
	SupportsFunctionCall bool
	SupportsVision       bool
	SupportsEmbedding    bool
	// MaxContextTokens is the model context window. 0 if unknown.
	MaxContextTokens int
	// EmbeddingDimensions is the dimensionality of the embedding vectors
	// produced by this provider/model. 0 when embeddings are not supported
	// or when the operator has not pinned a known model (e.g. an Azure
	// deployment whose name does not match a known family — operators can
	// still call Embed; downstream vector storage callers should query
	// this only as a hint, not as a contract).
	EmbeddingDimensions int
}

// ErrNotImplemented is returned by Embed (or any optional method) when the
// current provider has not implemented it in this milestone.
var ErrNotImplemented = errors.New("llm: feature not implemented in this milestone")

// roleUser / roleAssistant / roleSystem normalise role names across providers.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleSystem    = "system"
	RoleTool      = "tool"
)
