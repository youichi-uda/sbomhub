package llm

import (
	"context"
	"strings"
	"testing"
)

// withEnv sets the named env vars for the test's lifetime via t.Setenv (so
// they are restored when the test exits).
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	// Always clear the canonical contract envs + the M4 #F47 provider-
	// specific aliases so tests stay hermetic even if the developer has
	// these set in their shell (a stray OPENAI_API_KEY in the env would
	// otherwise mask a "factory disables provider when key missing"
	// regression).
	for _, k := range []string{
		EnvProvider, EnvAPIKey, EnvModel,
		EnvAzureEndpoint, EnvAzureDeployment, EnvAzureAPIVersion,
		EnvOllamaURL,
		EnvOpenAIAPIKey, EnvAnthropicAPIKey,
		EnvGeminiAPIKey, EnvGeminiAPIKeyAlt,
		EnvAzureAPIKey, EnvOllamaHost,
		// F52 Azure endpoint / api-version / deployment aliases — clear
		// so a stray AZURE_OPENAI_* in the developer's shell does not
		// mask a "factory disables when endpoint missing" regression.
		EnvAzureEndpointAlias, EnvAzureAPIVersionAlias, EnvAzureDeploymentAlias,
	} {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestNewProviderFromEnv_DisabledWhenProviderUnset(t *testing.T) {
	withEnv(t, nil)
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if p.Name() != "disabled" {
		t.Errorf("Name() = %q, want %q", p.Name(), "disabled")
	}
}

func TestNewProviderFromEnv_DisabledWhenAPIKeyMissing(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic", "gemini"} {
		t.Run(provider, func(t *testing.T) {
			withEnv(t, map[string]string{EnvProvider: provider})
			p, err := NewProviderFromEnv(context.Background())
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if p.Name() != "disabled" {
				t.Errorf("Name() = %q, want %q", p.Name(), "disabled")
			}
			de, ok := p.(*DisabledProvider)
			if !ok {
				t.Fatalf("type = %T, want *DisabledProvider", p)
			}
			if !strings.Contains(de.Reason, EnvAPIKey) {
				t.Errorf("Reason = %q, want substring %q", de.Reason, EnvAPIKey)
			}
		})
	}
}

func TestNewProviderFromEnv_HappyPaths(t *testing.T) {
	cases := []struct {
		provider string
		wantName string
	}{
		{"openai", "openai"},
		{"anthropic", "anthropic"},
		{"gemini", "gemini"},
		// Case insensitivity:
		{"OpenAI", "openai"},
		{"  Anthropic  ", "anthropic"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			withEnv(t, map[string]string{
				EnvProvider: tc.provider,
				EnvAPIKey:   "dummy-key",
			})
			p, err := NewProviderFromEnv(context.Background())
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if p.Name() != tc.wantName {
				t.Errorf("Name() = %q, want %q", p.Name(), tc.wantName)
			}
		})
	}
}

func TestNewProviderFromEnv_DefaultModels(t *testing.T) {
	cases := []struct {
		provider string
		wantSub  string // substring expected in the default model
	}{
		{"openai", "gpt-"},
		{"anthropic", "claude-"},
		{"gemini", "gemini-"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			withEnv(t, map[string]string{
				EnvProvider: tc.provider,
				EnvAPIKey:   "dummy",
				// No EnvModel: factory should pick a default.
			})
			p, err := NewProviderFromEnv(context.Background())
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if !strings.Contains(p.Model(), tc.wantSub) {
				t.Errorf("Model() = %q, want substring %q", p.Model(), tc.wantSub)
			}
		})
	}
}

func TestNewProviderFromEnv_RespectsExplicitModel(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider: "openai",
		EnvAPIKey:   "dummy",
		EnvModel:    "gpt-4o",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if p.Model() != "gpt-4o" {
		t.Errorf("Model() = %q, want %q", p.Model(), "gpt-4o")
	}
}

func TestNewProviderFromEnv_UnknownProvider(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider: "vertex_ai",
		EnvAPIKey:   "dummy",
	})
	_, err := NewProviderFromEnv(context.Background())
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "vertex_ai") {
		t.Errorf("err = %v, want to mention the unknown provider name", err)
	}
}

// TestNewProviderFromConfig_DisabledWhenEmpty verifies the helper returns a
// DisabledProvider (no error) when the tenant_llm_config row carries no
// provider or no API key — the runner is expected to fall back to the env
// default in those cases (M1 Codex review #F2).
func TestNewProviderFromConfig_DisabledWhenEmpty(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		apiKey   string
	}{
		{"provider blank", "", "k"},
		{"openai missing key", "openai", ""},
		{"anthropic missing key", "  Anthropic  ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProviderFromConfig(tc.provider, "", tc.apiKey)
			if err != nil {
				t.Fatalf("err = %v, want nil (DisabledProvider should be returned in-band)", err)
			}
			if p.Name() != "disabled" {
				t.Errorf("Name() = %q, want disabled", p.Name())
			}
		})
	}
}

func TestNewProviderFromConfig_HappyPaths(t *testing.T) {
	cases := []struct {
		provider string
		wantName string
	}{
		{"openai", "openai"},
		{"anthropic", "anthropic"},
		{"gemini", "gemini"},
		{"OpenAI", "openai"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			p, err := NewProviderFromConfig(tc.provider, "", "dummy-key")
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if p.Name() != tc.wantName {
				t.Errorf("Name() = %q, want %q", p.Name(), tc.wantName)
			}
		})
	}
}

func TestNewProviderFromConfig_UnknownProviderIsError(t *testing.T) {
	_, err := NewProviderFromConfig("vertex_ai", "", "dummy")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

// (Azure OpenAI factory tests are owned by Wave M4-2 — see azure_openai.go
// landed by the parallel agent; this file no longer asserts the pre-M4
// "not implemented" behaviour for azure_openai.)

// TestNewProviderFromEnv_OllamaHappyPath covers Wave M4-1: with provider +
// model set, the factory must build a real OllamaProvider rather than the
// pre-M4 "not implemented" error.
func TestNewProviderFromEnv_OllamaHappyPath(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider: "ollama",
		EnvModel:    "qwen2.5-coder:7b",
		// No EnvAPIKey — Ollama is local and BYOK-exempt.
		// No EnvOllamaURL — factory should default to localhost:11434.
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if p.Name() != "ollama" {
		t.Errorf("Name() = %q, want ollama", p.Name())
	}
	if p.Model() != "qwen2.5-coder:7b" {
		t.Errorf("Model() = %q", p.Model())
	}
}

// TestNewProviderFromEnv_OllamaRequiresModel covers the model-required
// guard rail: without SBOMHUB_LLM_MODEL the factory returns
// DisabledProvider (NOT an error) so the rest of the product keeps
// working and the operator gets a clear reason at the HTTP layer.
// ※要確認: see ollama.go comment on /api/tags auto-detect — current
// design is sync + offline, model is required.
func TestNewProviderFromEnv_OllamaRequiresModel(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider: "ollama",
		// No EnvModel.
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil (DisabledProvider returned in-band)", err)
	}
	if p.Name() != "disabled" {
		t.Errorf("Name() = %q, want disabled", p.Name())
	}
	de, ok := p.(*DisabledProvider)
	if !ok {
		t.Fatalf("type = %T, want *DisabledProvider", p)
	}
	if !strings.Contains(de.Reason, EnvModel) {
		t.Errorf("Reason = %q, want substring %q", de.Reason, EnvModel)
	}
}

// TestNewProviderFromEnv_OllamaRespectsURL covers the SBOMHUB_LLM_OLLAMA_URL
// override path. We cannot easily peek at the baseURL field through the
// Provider interface, but constructing a server then pointing the env at it
// gives end-to-end confidence that the URL flows through.
func TestNewProviderFromEnv_OllamaRespectsURL(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:  "ollama",
		EnvModel:     "qwen2.5-coder:7b",
		EnvOllamaURL: "http://ollama.test:11434",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	op, ok := p.(*OllamaProvider)
	if !ok {
		t.Fatalf("type = %T, want *OllamaProvider", p)
	}
	if op.baseURL != "http://ollama.test:11434" {
		t.Errorf("baseURL = %q, want %q", op.baseURL, "http://ollama.test:11434")
	}
}

// TestNewProviderFromConfig_OllamaHappyPath mirrors the env-side test for
// the per-tenant resolver (M1 #F2). Ollama does not require an API key.
func TestNewProviderFromConfig_OllamaHappyPath(t *testing.T) {
	p, err := NewProviderFromConfig("ollama", "qwen2.5-coder:7b", "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if p.Name() != "ollama" {
		t.Errorf("Name() = %q, want ollama", p.Name())
	}
}

// TestNewProviderFromConfig_OllamaRequiresModel covers the per-tenant
// model-required guard: tenant_llm_config.model empty + provider ollama
// must return DisabledProvider rather than an error.
func TestNewProviderFromConfig_OllamaRequiresModel(t *testing.T) {
	p, err := NewProviderFromConfig("ollama", "", "")
	if err != nil {
		t.Fatalf("err = %v, want nil (DisabledProvider returned in-band)", err)
	}
	if p.Name() != "disabled" {
		t.Errorf("Name() = %q, want disabled", p.Name())
	}
}

// ---------------------------------------------------------------------------
// M4 Codex review #F47 — provider-specific API key env aliases.
//
// docs/configuration.md / README.md / CLAUDE.md document the provider-native
// env names (OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY / GEMINI_API_KEY,
// AZURE_OPENAI_API_KEY, OLLAMA_HOST). Before F47 the runtime factory only
// consulted the canonical SBOMHUB_LLM_API_KEY / SBOMHUB_LLM_OLLAMA_URL, so an
// operator who followed the docs got a silently disabled provider. These
// tests lock in the canonical-first precedence and the alias fall-back for
// every provider.
// ---------------------------------------------------------------------------

// TestResolveAPIKey_Canonical covers the "operator already on the existing
// canonical env" path — SBOMHUB_LLM_API_KEY alone resolves for every BYOK
// provider, regardless of which provider name is requested.
func TestResolveAPIKey_Canonical(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic", "gemini", "azure_openai"} {
		t.Run(provider, func(t *testing.T) {
			withEnv(t, map[string]string{EnvAPIKey: "canonical-key"})
			key, source := resolveAPIKey(provider)
			if key != "canonical-key" {
				t.Errorf("key = %q, want %q", key, "canonical-key")
			}
			if source != EnvAPIKey {
				t.Errorf("source = %q, want %q", source, EnvAPIKey)
			}
		})
	}
}

// TestResolveAPIKey_AliasOnly covers the doc-following operator path: only
// the provider-native env is set, the factory must pick it up.
func TestResolveAPIKey_AliasOnly(t *testing.T) {
	cases := []struct {
		provider   string
		aliasEnv   string
		aliasValue string
	}{
		{"openai", EnvOpenAIAPIKey, "openai-alias-key"},
		{"anthropic", EnvAnthropicAPIKey, "anthropic-alias-key"},
		{"gemini", EnvGeminiAPIKey, "gemini-google-key"},
		{"gemini", EnvGeminiAPIKeyAlt, "gemini-alt-key"},
		{"azure_openai", EnvAzureAPIKey, "azure-alias-key"},
	}
	for _, tc := range cases {
		t.Run(tc.provider+"/"+tc.aliasEnv, func(t *testing.T) {
			withEnv(t, map[string]string{tc.aliasEnv: tc.aliasValue})
			key, source := resolveAPIKey(tc.provider)
			if key != tc.aliasValue {
				t.Errorf("key = %q, want %q", key, tc.aliasValue)
			}
			if source != tc.aliasEnv {
				t.Errorf("source = %q, want %q", source, tc.aliasEnv)
			}
		})
	}
}

// TestResolveAPIKey_CanonicalWinsOnTie covers the precedence guarantee:
// existing self-host deployments that already set SBOMHUB_LLM_API_KEY must
// continue to use it even when a stray provider-native alias is also set
// in the shell environment.
func TestResolveAPIKey_CanonicalWinsOnTie(t *testing.T) {
	cases := []struct {
		provider string
		aliasEnv string
	}{
		{"openai", EnvOpenAIAPIKey},
		{"anthropic", EnvAnthropicAPIKey},
		{"gemini", EnvGeminiAPIKey},
		{"azure_openai", EnvAzureAPIKey},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			withEnv(t, map[string]string{
				EnvAPIKey:   "canonical-wins",
				tc.aliasEnv: "alias-loses",
			})
			key, source := resolveAPIKey(tc.provider)
			if key != "canonical-wins" {
				t.Errorf("key = %q, want canonical to win", key)
			}
			if source != EnvAPIKey {
				t.Errorf("source = %q, want %q", source, EnvAPIKey)
			}
		})
	}
}

// TestResolveAPIKey_GeminiGoogleBeatsGeminiAlt locks in the documented
// Gemini precedence: SBOMHUB_LLM_API_KEY > GOOGLE_API_KEY > GEMINI_API_KEY.
// The first two are documented in CLAUDE.md / README; GEMINI_API_KEY is a
// fallback used in some Google SDK paths.
func TestResolveAPIKey_GeminiGoogleBeatsGeminiAlt(t *testing.T) {
	withEnv(t, map[string]string{
		EnvGeminiAPIKey:    "google-wins",
		EnvGeminiAPIKeyAlt: "alt-loses",
	})
	key, source := resolveAPIKey("gemini")
	if key != "google-wins" {
		t.Errorf("key = %q, want %q", key, "google-wins")
	}
	if source != EnvGeminiAPIKey {
		t.Errorf("source = %q, want %q", source, EnvGeminiAPIKey)
	}
}

// TestResolveAPIKey_Empty covers the "no env at all" path: empty key + empty
// source signals to the caller that DisabledProvider should be returned.
func TestResolveAPIKey_Empty(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic", "gemini", "azure_openai"} {
		t.Run(provider, func(t *testing.T) {
			withEnv(t, nil)
			key, source := resolveAPIKey(provider)
			if key != "" || source != "" {
				t.Errorf("key=%q source=%q, want both empty", key, source)
			}
		})
	}
}

// TestNewProviderFromEnv_AliasHappyPath is the end-to-end alias test: only
// the provider-native env is set, NewProviderFromEnv must build a real
// provider (not DisabledProvider). This is the operator-facing assertion
// that the F47 bug is fixed.
func TestNewProviderFromEnv_AliasHappyPath(t *testing.T) {
	cases := []struct {
		provider string
		aliasEnv string
		wantName string
	}{
		{"openai", EnvOpenAIAPIKey, "openai"},
		{"anthropic", EnvAnthropicAPIKey, "anthropic"},
		{"gemini", EnvGeminiAPIKey, "gemini"},
		{"gemini", EnvGeminiAPIKeyAlt, "gemini"},
	}
	for _, tc := range cases {
		t.Run(tc.provider+"/"+tc.aliasEnv, func(t *testing.T) {
			withEnv(t, map[string]string{
				EnvProvider: tc.provider,
				tc.aliasEnv: "alias-key",
			})
			p, err := NewProviderFromEnv(context.Background())
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if p.Name() != tc.wantName {
				t.Errorf("Name() = %q, want %q", p.Name(), tc.wantName)
			}
		})
	}
}

// TestNewProviderFromEnv_AzureAliasHappyPath separates Azure because it
// requires endpoint + deployment in addition to the API key, so the alias
// path is exercised on top of the full Azure env contract.
func TestNewProviderFromEnv_AzureAliasHappyPath(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:        "azure_openai",
		EnvAzureAPIKey:     "azure-alias-key",
		EnvAzureEndpoint:   "https://example.openai.azure.com",
		EnvAzureDeployment: "gpt-4o-deployment",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if p.Name() != "azure_openai" {
		t.Errorf("Name() = %q, want azure_openai", p.Name())
	}
}

// TestNewProviderFromEnv_DisabledReasonListsAliases verifies the
// DisabledProvider Reason message names every env the factory consulted —
// the previous message said only "SBOMHUB_LLM_API_KEY is not set", which
// did not help operators who had OPENAI_API_KEY (etc.) set but a typo in
// the provider name.
func TestNewProviderFromEnv_DisabledReasonListsAliases(t *testing.T) {
	cases := []struct {
		provider     string
		wantContains []string
	}{
		{"openai", []string{EnvAPIKey, EnvOpenAIAPIKey}},
		{"anthropic", []string{EnvAPIKey, EnvAnthropicAPIKey}},
		{"gemini", []string{EnvAPIKey, EnvGeminiAPIKey, EnvGeminiAPIKeyAlt}},
		{"azure_openai", []string{EnvAPIKey, EnvAzureAPIKey}},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			withEnv(t, map[string]string{EnvProvider: tc.provider})
			p, err := NewProviderFromEnv(context.Background())
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			de, ok := p.(*DisabledProvider)
			if !ok {
				t.Fatalf("type = %T, want *DisabledProvider", p)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(de.Reason, want) {
					t.Errorf("Reason = %q, want substring %q", de.Reason, want)
				}
			}
		})
	}
}

// TestOllamaBaseURL_Canonical locks in the canonical-first precedence for
// the Ollama base URL: SBOMHUB_LLM_OLLAMA_URL wins when set, regardless of
// OLLAMA_HOST.
func TestOllamaBaseURL_Canonical(t *testing.T) {
	withEnv(t, map[string]string{
		EnvOllamaURL:  "http://canonical.test:11434",
		EnvOllamaHost: "http://alias.test:11434",
	})
	if got := ollamaBaseURLFromEnv(); got != "http://canonical.test:11434" {
		t.Errorf("ollamaBaseURLFromEnv() = %q, want canonical", got)
	}
}

// TestOllamaBaseURL_Alias is the F47 fix: when only OLLAMA_HOST is set
// (the operator followed the README), the factory must respect it
// instead of silently falling back to http://localhost:11434.
func TestOllamaBaseURL_Alias(t *testing.T) {
	withEnv(t, map[string]string{
		EnvOllamaHost: "http://ollama-host.test:11434",
	})
	if got := ollamaBaseURLFromEnv(); got != "http://ollama-host.test:11434" {
		t.Errorf("ollamaBaseURLFromEnv() = %q, want %q", got, "http://ollama-host.test:11434")
	}
}

// TestOllamaBaseURL_Default covers the no-env path: factory must return
// the documented localhost default so a stock `ollama serve` works out
// of the box.
func TestOllamaBaseURL_Default(t *testing.T) {
	withEnv(t, nil)
	if got := ollamaBaseURLFromEnv(); got != defaultOllamaEndpoint {
		t.Errorf("ollamaBaseURLFromEnv() = %q, want %q", got, defaultOllamaEndpoint)
	}
}

// TestNewProviderFromEnv_OllamaRespectsHostAlias is the end-to-end Ollama
// alias test: only OLLAMA_HOST is set, the resulting OllamaProvider must
// carry that base URL through.
func TestNewProviderFromEnv_OllamaRespectsHostAlias(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:   "ollama",
		EnvModel:      "qwen2.5-coder:7b",
		EnvOllamaHost: "http://ollama-host.test:11434",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	op, ok := p.(*OllamaProvider)
	if !ok {
		t.Fatalf("type = %T, want *OllamaProvider", p)
	}
	if op.baseURL != "http://ollama-host.test:11434" {
		t.Errorf("baseURL = %q, want %q", op.baseURL, "http://ollama-host.test:11434")
	}
}

// ---------------------------------------------------------------------------
// M4 Codex review #F52 — Azure endpoint / api-version / deployment env aliases.
//
// Before F52 the factory only consulted the SBOMHUB_LLM_AZURE_* canonical
// envs for Azure endpoint / api-version / deployment. An operator who
// followed Microsoft Learn (which directs at AZURE_OPENAI_ENDPOINT /
// AZURE_OPENAI_API_VERSION / AZURE_OPENAI_DEPLOYMENT) plus the F47 API
// key alias (AZURE_OPENAI_API_KEY) got API key resolved but endpoint
// missing → DisabledProvider. These tests lock in canonical-first
// precedence + alias fallback for every Azure config field.
// ---------------------------------------------------------------------------

// TestResolveAzureField_CanonicalWinsOnTie covers the precedence
// guarantee for each Azure field: existing self-host deployments that
// already set SBOMHUB_LLM_AZURE_* must continue to use it even when a
// stray AZURE_OPENAI_* alias is also set in the shell environment.
func TestResolveAzureField_CanonicalWinsOnTie(t *testing.T) {
	cases := []struct {
		field        string
		canonicalEnv string
		aliasEnv     string
	}{
		{"endpoint", EnvAzureEndpoint, EnvAzureEndpointAlias},
		{"api_version", EnvAzureAPIVersion, EnvAzureAPIVersionAlias},
		{"deployment", EnvAzureDeployment, EnvAzureDeploymentAlias},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			withEnv(t, map[string]string{
				tc.canonicalEnv: "canonical-wins",
				tc.aliasEnv:     "alias-loses",
			})
			value, source := resolveAzureField(tc.field)
			if value != "canonical-wins" {
				t.Errorf("value = %q, want canonical-wins", value)
			}
			if source != tc.canonicalEnv {
				t.Errorf("source = %q, want %q", source, tc.canonicalEnv)
			}
		})
	}
}

// TestResolveAzureField_AliasOnly covers the doc-following operator
// path: only the Microsoft-documented alias is set, the factory must
// pick it up.
func TestResolveAzureField_AliasOnly(t *testing.T) {
	cases := []struct {
		field    string
		aliasEnv string
	}{
		{"endpoint", EnvAzureEndpointAlias},
		{"api_version", EnvAzureAPIVersionAlias},
		{"deployment", EnvAzureDeploymentAlias},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			withEnv(t, map[string]string{tc.aliasEnv: "alias-value"})
			value, source := resolveAzureField(tc.field)
			if value != "alias-value" {
				t.Errorf("value = %q, want alias-value (alias not honoured)", value)
			}
			if source != tc.aliasEnv {
				t.Errorf("source = %q, want %q", source, tc.aliasEnv)
			}
		})
	}
}

// TestResolveAzureField_Empty pins the "no env at all" path: empty
// value + empty source signals to the caller that DisabledProvider
// should be returned.
func TestResolveAzureField_Empty(t *testing.T) {
	for _, field := range []string{"endpoint", "api_version", "deployment"} {
		t.Run(field, func(t *testing.T) {
			withEnv(t, nil)
			value, source := resolveAzureField(field)
			if value != "" || source != "" {
				t.Errorf("value=%q source=%q, want both empty", value, source)
			}
		})
	}
}

// TestNewProviderFromEnv_AzureAliasEndpointHappyPath is the end-to-end
// Azure alias test: the operator set the full Microsoft-documented env
// trio (AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT +
// AZURE_OPENAI_API_VERSION + AZURE_OPENAI_DEPLOYMENT) and zero
// SBOMHUB_LLM_AZURE_* canonical envs. NewProviderFromEnv must build a
// real azure_openai provider rather than DisabledProvider — this is
// the operator-facing assertion that F52 is fixed.
func TestNewProviderFromEnv_AzureAliasEndpointHappyPath(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:             "azure_openai",
		EnvAzureAPIKey:          "azure-alias-key",
		EnvAzureEndpointAlias:   "https://example.openai.azure.com",
		EnvAzureAPIVersionAlias: "2024-08-01-preview",
		EnvAzureDeploymentAlias: "gpt-4o-deployment",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if p.Name() != "azure_openai" {
		t.Errorf("Name() = %q, want azure_openai", p.Name())
	}
	if _, isDisabled := p.(*DisabledProvider); isDisabled {
		t.Errorf("got DisabledProvider, want real azure_openai provider (F52 regression: alias envs not honoured)")
	}
}

// TestNewProviderFromEnv_AzureCanonicalWinsAtFactory locks in the
// end-to-end precedence guarantee — when both canonical and alias envs
// are set for Azure endpoint/deployment, the canonical value must
// reach the provider constructor. We exercise this via a happy-path
// build with both envs distinguishable, and rely on the unit-level
// TestResolveAzureField_CanonicalWinsOnTie above for the precedence
// assertion at the helper level.
func TestNewProviderFromEnv_AzureCanonicalWinsAtFactory(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:             "azure_openai",
		EnvAPIKey:               "canonical-key",
		EnvAzureEndpoint:        "https://canonical.openai.azure.com",
		EnvAzureDeployment:      "canonical-deployment",
		EnvAzureEndpointAlias:   "https://alias.openai.azure.com",
		EnvAzureDeploymentAlias: "alias-deployment",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	azp, ok := p.(*AzureOpenAIProvider)
	if !ok {
		t.Fatalf("type = %T, want *AzureOpenAIProvider", p)
	}
	if !strings.Contains(azp.endpoint, "canonical") {
		t.Errorf("endpoint = %q, want canonical to win", azp.endpoint)
	}
	if !strings.Contains(azp.deployment, "canonical") {
		t.Errorf("deployment = %q, want canonical to win", azp.deployment)
	}
}

// TestNewProviderFromEnv_AzureDisabledReasonListsAliases verifies the
// DisabledProvider Reason message names every Azure endpoint /
// deployment env the factory consulted — operators who set
// AZURE_OPENAI_ENDPOINT but typo'd AZURE_OPENAI_DEPLOYMENT need the
// error to mention both candidates so they can diff their shell env
// against the ones the factory checked.
func TestNewProviderFromEnv_AzureDisabledReasonListsAliases(t *testing.T) {
	t.Run("endpoint missing", func(t *testing.T) {
		// API key satisfied via alias; endpoint deliberately omitted.
		withEnv(t, map[string]string{
			EnvProvider:    "azure_openai",
			EnvAzureAPIKey: "k",
		})
		p, err := NewProviderFromEnv(context.Background())
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		de, ok := p.(*DisabledProvider)
		if !ok {
			t.Fatalf("type = %T, want *DisabledProvider", p)
		}
		for _, want := range []string{EnvAzureEndpoint, EnvAzureEndpointAlias} {
			if !strings.Contains(de.Reason, want) {
				t.Errorf("Reason = %q, want substring %q", de.Reason, want)
			}
		}
	})
	t.Run("deployment missing", func(t *testing.T) {
		// API key + endpoint present, deployment missing.
		withEnv(t, map[string]string{
			EnvProvider:           "azure_openai",
			EnvAzureAPIKey:        "k",
			EnvAzureEndpointAlias: "https://example.openai.azure.com",
		})
		p, err := NewProviderFromEnv(context.Background())
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		de, ok := p.(*DisabledProvider)
		if !ok {
			t.Fatalf("type = %T, want *DisabledProvider", p)
		}
		for _, want := range []string{EnvAzureDeployment, EnvAzureDeploymentAlias} {
			if !strings.Contains(de.Reason, want) {
				t.Errorf("Reason = %q, want substring %q", de.Reason, want)
			}
		}
	})
}
