package llm

import (
	"context"
	"log/slog"
)

// DisabledProvider is the fallback Provider returned by NewProviderFromEnv
// when BYOK is not configured (no SBOMHUB_LLM_PROVIDER, no
// SBOMHUB_LLM_API_KEY, etc.). It always returns *DisabledError from Complete
// / Embed so the HTTP layer can translate to 503 + a UI-friendly message.
//
// Reference: LLM_PROVIDER_DESIGN.md §2.5.
type DisabledProvider struct {
	// Reason explains why AI features are disabled (logged + surfaced via
	// HTTP). Must not contain any secret material.
	Reason string
}

// Compile-time interface conformance.
var _ Provider = (*DisabledProvider)(nil)

// Name returns "disabled".
func (p *DisabledProvider) Name() string { return "disabled" }

// Model returns "".
func (p *DisabledProvider) Model() string { return "" }

// Complete always returns *DisabledError.
func (p *DisabledProvider) Complete(_ context.Context, _ CompleteRequest) (*CompleteResponse, error) {
	return nil, &DisabledError{Reason: p.Reason}
}

// Embed always returns *DisabledError.
func (p *DisabledProvider) Embed(_ context.Context, _ EmbedRequest) (*EmbedResponse, error) {
	return nil, &DisabledError{Reason: p.Reason}
}

// Capabilities returns a zero-value Capabilities (everything disabled).
func (p *DisabledProvider) Capabilities() Capabilities { return Capabilities{} }

// LogValue implements slog.LogValuer so structured logs only surface
// {provider, reason} and never leak secrets. (DisabledProvider does not hold
// secrets, but we implement the interface for parity with real providers.)
func (p *DisabledProvider) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", "disabled"),
		slog.String("reason", p.Reason),
	)
}

// DisabledError signals that the LLM stack is intentionally disabled.
// HTTP handlers should translate this to 503 Service Unavailable with the
// Reason as the operator-facing message.
type DisabledError struct {
	Reason string
}

// Error implements the error interface.
func (e *DisabledError) Error() string {
	if e.Reason == "" {
		return "LLM provider is disabled"
	}
	return "LLM provider is disabled: " + e.Reason
}

// HTTPStatus returns 503 so handler middleware can convert to a proper
// HTTP response without coupling to a specific framework.
func (e *DisabledError) HTTPStatus() int { return 503 }

// IsDisabled reports whether err is (or wraps) a *DisabledError.
func IsDisabled(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*DisabledError)
	return ok
}
