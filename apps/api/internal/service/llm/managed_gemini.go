//go:build saas

// Package llm — SaaS-only layer.
//
// This file is excluded from the OSS build via the `saas` build tag. It is
// intentionally left as a placeholder skeleton in M1: the SaaS reboot is
// blocked behind PRODUCT_REBOOT_PLAN.md §20 ("SaaS sunset" until BYOK rails
// are stable). Wiring tenant-scoped managed Gemini, quota tracking, and
// per-tenant LLM config will land in a follow-up milestone.
package llm

import (
	"context"
	"errors"
)

// ErrManagedGeminiNotConfigured is returned by the SaaS factory path when
// the operator has not provisioned the system-level Gemini key.
var ErrManagedGeminiNotConfigured = errors.New("llm: managed_gemini is not configured")

// NewManagedGemini constructs a Provider that uses the SaaS-operator-owned
// Gemini key (not BYOK). M1 leaves this as a stub: it returns a
// DisabledProvider so any premature call surfaces a clear operator message
// instead of silently calling out to Google.
//
// Real implementation will:
//   - read the system key from a secrets manager (NOT env in SaaS prod)
//   - enforce per-tenant quota (checkQuota in LLM_PROVIDER_DESIGN.md §5.2)
//   - increment tenant_llm_usage on each call
//   - emit billing events for the SaaS finance pipeline
func NewManagedGemini(_ string, _ string) Provider {
	return &DisabledProvider{
		Reason: "managed_gemini stub — implement before SaaS reopen (see PRODUCT_REBOOT_PLAN §20)",
	}
}

// NewProviderForTenant is the SaaS-only entry point that resolves which
// Provider to use for a given tenant (BYOK vs managed_gemini). The full
// implementation reads from tenant_llm_config and dispatches accordingly —
// see LLM_PROVIDER_DESIGN.md §2.4. Stubbed in M1.
func NewProviderForTenant(_ context.Context, _ string) (Provider, error) {
	return &DisabledProvider{
		Reason: "NewProviderForTenant stub — SaaS layer not wired in M1",
	}, nil
}
