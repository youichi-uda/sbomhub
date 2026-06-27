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
		// F59: extra Microsoft-documented deployment-name variants
		// (AKS quickstart + Azure Agent Framework) — clear so a stray
		// shell env does not mask the "deployment missing" path.
		EnvAzureDeploymentNameAlias, EnvAzureChatDeploymentNameAlias,
		// M5-3 (#51) Azure embedding envs — clear so a stray shell env
		// (e.g. an operator running the test suite with their real
		// embedding deployment exported) does not silently turn on
		// SupportsEmbedding in factory tests that expect the M4 default.
		EnvAzureEmbeddingDeployment, EnvAzureEmbeddingDeploymentAlias,
		EnvAzureEmbeddingAPIVersion, EnvAzureEmbeddingModel,
		EnvOpenAIEmbeddingModel, EnvGeminiEmbeddingModel, EnvOllamaEmbeddingModel,
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

func TestNewProviderFromEnv_EmbeddingModelEnv(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		wantDim   int
		wantEmbed bool
	}{
		{
			name: "openai explicit large",
			env: map[string]string{
				EnvProvider:             "openai",
				EnvAPIKey:               "dummy",
				EnvOpenAIEmbeddingModel: "text-embedding-3-large",
			},
			wantDim:   3072,
			wantEmbed: true,
		},
		{
			name: "gemini default",
			env: map[string]string{
				EnvProvider: "gemini",
				EnvAPIKey:   "dummy",
			},
			wantDim:   3072,
			wantEmbed: true,
		},
		{
			name: "ollama explicit mxbai",
			env: map[string]string{
				EnvProvider:             "ollama",
				EnvModel:                "qwen2.5-coder:7b",
				EnvOllamaEmbeddingModel: "mxbai-embed-large",
			},
			wantDim:   1024,
			wantEmbed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEnv(t, tc.env)
			p, err := NewProviderFromEnv(context.Background())
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			cap := p.Capabilities()
			if cap.SupportsEmbedding != tc.wantEmbed {
				t.Fatalf("SupportsEmbedding = %v, want %v", cap.SupportsEmbedding, tc.wantEmbed)
			}
			if cap.EmbeddingDimensions != tc.wantDim {
				t.Fatalf("EmbeddingDimensions = %d, want %d", cap.EmbeddingDimensions, tc.wantDim)
			}
		})
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

// ---------------------------------------------------------------------------
// M4 Codex review #F59 — Azure deployment-name env aliases (broader coverage).
//
// Microsoft documentation is not internally consistent on the env var name
// for an Azure OpenAI deployment:
//   - AZURE_OPENAI_DEPLOYMENT — most code samples (covered by F52)
//   - AZURE_OPENAI_DEPLOYMENT_NAME — Microsoft Learn AKS OpenAI quickstart,
//     Azure SDK for JS / Python OpenAI library
//   - AZURE_OPENAI_CHAT_DEPLOYMENT_NAME — Azure Agent Framework (it
//     disambiguates chat vs embedding deployments)
//
// Pre-F59 the factory accepted only the first form; operators following the
// AKS or Agent-Framework docs got endpoint + api-version + key resolved but
// deployment missing → DisabledProvider. These tests lock in the four-deep
// canonical-first precedence ladder so future regressions are caught.
// ---------------------------------------------------------------------------

// TestResolveAzureField_DeploymentAliases covers each Microsoft-documented
// deployment-name variant in isolation: when only one of the four envs is
// set, resolveAzureField must pick it up and report it as the source.
func TestResolveAzureField_DeploymentAliases(t *testing.T) {
	cases := []struct {
		name string
		env  string
	}{
		{"canonical SBOMHUB_LLM_AZURE_DEPLOYMENT", EnvAzureDeployment},
		{"alias AZURE_OPENAI_DEPLOYMENT", EnvAzureDeploymentAlias},
		{"alias AZURE_OPENAI_DEPLOYMENT_NAME", EnvAzureDeploymentNameAlias},
		{"alias AZURE_OPENAI_CHAT_DEPLOYMENT_NAME", EnvAzureChatDeploymentNameAlias},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEnv(t, map[string]string{tc.env: "dep-value"})
			value, source := resolveAzureField("deployment")
			if value != "dep-value" {
				t.Errorf("value = %q, want dep-value (alias %s not honoured)", value, tc.env)
			}
			if source != tc.env {
				t.Errorf("source = %q, want %q", source, tc.env)
			}
		})
	}
}

// TestResolveAzureField_DeploymentCanonicalWinsOverAllAliases verifies the
// full precedence ladder: with every env set to a distinguishable value,
// the canonical SBOMHUB_LLM_AZURE_DEPLOYMENT must win, followed by
// AZURE_OPENAI_DEPLOYMENT > AZURE_OPENAI_DEPLOYMENT_NAME >
// AZURE_OPENAI_CHAT_DEPLOYMENT_NAME. The test peels the precedence layers
// one at a time so a future reorder of azureFieldEnvCandidates is caught
// explicitly (rather than silently picking a different winner).
func TestResolveAzureField_DeploymentCanonicalWinsOverAllAliases(t *testing.T) {
	// Layer 1: every env set, canonical must win.
	withEnv(t, map[string]string{
		EnvAzureDeployment:              "win-canonical",
		EnvAzureDeploymentAlias:         "lose-deployment",
		EnvAzureDeploymentNameAlias:     "lose-deployment-name",
		EnvAzureChatDeploymentNameAlias: "lose-chat",
	})
	value, source := resolveAzureField("deployment")
	if value != "win-canonical" || source != EnvAzureDeployment {
		t.Fatalf("layer 1: value=%q source=%q, want canonical win", value, source)
	}

	// Layer 2: canonical cleared, AZURE_OPENAI_DEPLOYMENT must win over
	// the two _NAME variants.
	withEnv(t, map[string]string{
		EnvAzureDeploymentAlias:         "win-deployment",
		EnvAzureDeploymentNameAlias:     "lose-deployment-name",
		EnvAzureChatDeploymentNameAlias: "lose-chat",
	})
	value, source = resolveAzureField("deployment")
	if value != "win-deployment" || source != EnvAzureDeploymentAlias {
		t.Fatalf("layer 2: value=%q source=%q, want AZURE_OPENAI_DEPLOYMENT win", value, source)
	}

	// Layer 3: only the two _NAME variants set — DEPLOYMENT_NAME must
	// beat CHAT_DEPLOYMENT_NAME (the bare _NAME is the more general
	// form; CHAT_ disambiguates only when both deployments are
	// configured, which sbomhub does not support today).
	withEnv(t, map[string]string{
		EnvAzureDeploymentNameAlias:     "win-deployment-name",
		EnvAzureChatDeploymentNameAlias: "lose-chat",
	})
	value, source = resolveAzureField("deployment")
	if value != "win-deployment-name" || source != EnvAzureDeploymentNameAlias {
		t.Fatalf("layer 3: value=%q source=%q, want AZURE_OPENAI_DEPLOYMENT_NAME win", value, source)
	}

	// Layer 4: only the most-specific alias set — CHAT_DEPLOYMENT_NAME
	// is the last-resort fallback and must still resolve.
	withEnv(t, map[string]string{
		EnvAzureChatDeploymentNameAlias: "win-chat",
	})
	value, source = resolveAzureField("deployment")
	if value != "win-chat" || source != EnvAzureChatDeploymentNameAlias {
		t.Fatalf("layer 4: value=%q source=%q, want AZURE_OPENAI_CHAT_DEPLOYMENT_NAME win", value, source)
	}
}

// TestNewProviderFromEnv_AzureDeploymentNameAliasHappyPath is the
// end-to-end AKS-quickstart operator path: only AZURE_OPENAI_DEPLOYMENT_NAME
// is set for the deployment field (plus the other Azure envs via their
// aliases). NewProviderFromEnv must build a real azure_openai provider
// rather than DisabledProvider.
func TestNewProviderFromEnv_AzureDeploymentNameAliasHappyPath(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:                 "azure_openai",
		EnvAzureAPIKey:              "azure-alias-key",
		EnvAzureEndpointAlias:       "https://example.openai.azure.com",
		EnvAzureDeploymentNameAlias: "gpt-4o-deployment",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if _, isDisabled := p.(*DisabledProvider); isDisabled {
		t.Errorf("got DisabledProvider, want real azure_openai provider (F59 regression: AZURE_OPENAI_DEPLOYMENT_NAME not honoured)")
	}
	if p.Name() != "azure_openai" {
		t.Errorf("Name() = %q, want azure_openai", p.Name())
	}
}

// TestNewProviderFromEnv_AzureChatDeploymentNameAliasHappyPath covers the
// Azure Agent Framework operator path: only AZURE_OPENAI_CHAT_DEPLOYMENT_NAME
// is set. The factory must still build a real provider — the chat-specific
// qualifier is the legitimate config for sbomhub (which is chat-only today).
func TestNewProviderFromEnv_AzureChatDeploymentNameAliasHappyPath(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:                     "azure_openai",
		EnvAzureAPIKey:                  "azure-alias-key",
		EnvAzureEndpointAlias:           "https://example.openai.azure.com",
		EnvAzureChatDeploymentNameAlias: "gpt-4o-chat-deployment",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if _, isDisabled := p.(*DisabledProvider); isDisabled {
		t.Errorf("got DisabledProvider, want real azure_openai provider (F59 regression: AZURE_OPENAI_CHAT_DEPLOYMENT_NAME not honoured)")
	}
	if p.Name() != "azure_openai" {
		t.Errorf("Name() = %q, want azure_openai", p.Name())
	}
}

// TestNewProviderFromEnv_AzureDeploymentDisabledReasonListsAllAliases
// verifies the DisabledProvider Reason message names every deployment env
// the factory consulted — F52 covered DEPLOYMENT + DEPLOYMENT_ALIAS; F59
// extends to the two _NAME variants so an operator who typo'd
// AZURE_OPENAI_DEPLOYMENT_NAME can find it in the error and diff against
// their shell env.
func TestNewProviderFromEnv_AzureDeploymentDisabledReasonListsAllAliases(t *testing.T) {
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
	for _, want := range []string{
		EnvAzureDeployment,
		EnvAzureDeploymentAlias,
		EnvAzureDeploymentNameAlias,
		EnvAzureChatDeploymentNameAlias,
	} {
		if !strings.Contains(de.Reason, want) {
			t.Errorf("Reason = %q, want substring %q", de.Reason, want)
		}
	}
}

// ---------------------------------------------------------------------------
// M5 Wave M5-3 (issue #51) — Azure embedding deployment env wiring.
// ---------------------------------------------------------------------------

// TestResolveAzureField_EmbeddingDeployment locks in the M5-3 embedding
// deployment alias precedence: canonical SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT
// beats AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME (Azure Agent Framework form).
func TestResolveAzureField_EmbeddingDeployment(t *testing.T) {
	t.Run("canonical wins on tie", func(t *testing.T) {
		withEnv(t, map[string]string{
			EnvAzureEmbeddingDeployment:      "canonical-wins",
			EnvAzureEmbeddingDeploymentAlias: "alias-loses",
		})
		v, src := resolveAzureField("embedding_deployment")
		if v != "canonical-wins" || src != EnvAzureEmbeddingDeployment {
			t.Errorf("got value=%q src=%q, want canonical-wins / %s", v, src, EnvAzureEmbeddingDeployment)
		}
	})
	t.Run("alias-only", func(t *testing.T) {
		withEnv(t, map[string]string{
			EnvAzureEmbeddingDeploymentAlias: "alias-value",
		})
		v, src := resolveAzureField("embedding_deployment")
		if v != "alias-value" || src != EnvAzureEmbeddingDeploymentAlias {
			t.Errorf("got value=%q src=%q, want alias-value / %s", v, src, EnvAzureEmbeddingDeploymentAlias)
		}
	})
	t.Run("empty", func(t *testing.T) {
		withEnv(t, nil)
		v, src := resolveAzureField("embedding_deployment")
		if v != "" || src != "" {
			t.Errorf("got value=%q src=%q, want both empty", v, src)
		}
	})
}

// TestResolveAzureField_EmbeddingAPIVersionAndModel pins the resolution
// of the optional embedding api-version override and the optional
// canonical embedding model identifier.
func TestResolveAzureField_EmbeddingAPIVersionAndModel(t *testing.T) {
	t.Run("api_version set", func(t *testing.T) {
		withEnv(t, map[string]string{EnvAzureEmbeddingAPIVersion: "2024-08-01-preview"})
		v, src := resolveAzureField("embedding_api_version")
		if v != "2024-08-01-preview" || src != EnvAzureEmbeddingAPIVersion {
			t.Errorf("got value=%q src=%q", v, src)
		}
	})
	t.Run("api_version empty", func(t *testing.T) {
		withEnv(t, nil)
		v, src := resolveAzureField("embedding_api_version")
		if v != "" || src != "" {
			t.Errorf("got value=%q src=%q, want both empty", v, src)
		}
	})
	t.Run("model set", func(t *testing.T) {
		withEnv(t, map[string]string{EnvAzureEmbeddingModel: "text-embedding-3-small"})
		v, src := resolveAzureField("embedding_model")
		if v != "text-embedding-3-small" || src != EnvAzureEmbeddingModel {
			t.Errorf("got value=%q src=%q", v, src)
		}
	})
}

// TestNewProviderFromEnv_AzureEmbeddingDisabledByDefault verifies the
// regression-safe default: an Azure provider built from env without the
// new embedding envs has SupportsEmbedding=false and Embed returns
// DisabledError. M4-2 chat-only deployments must keep working
// unchanged.
func TestNewProviderFromEnv_AzureEmbeddingDisabledByDefault(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:        "azure_openai",
		EnvAPIKey:          "k",
		EnvAzureEndpoint:   "https://example.openai.azure.com",
		EnvAzureDeployment: "gpt-4o-deployment",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	azp, ok := p.(*AzureOpenAIProvider)
	if !ok {
		t.Fatalf("type = %T, want *AzureOpenAIProvider", p)
	}
	cap := azp.Capabilities()
	if cap.SupportsEmbedding {
		t.Error("SupportsEmbedding = true, want false when no embedding deployment env is set")
	}
	if cap.EmbeddingDimensions != 0 {
		t.Errorf("EmbeddingDimensions = %d, want 0", cap.EmbeddingDimensions)
	}
}

// TestNewProviderFromEnv_AzureEmbeddingHappyPath wires the canonical
// embedding envs and verifies that SupportsEmbedding flips true and
// dimensions resolve from the canonical model name.
func TestNewProviderFromEnv_AzureEmbeddingHappyPath(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:                 "azure_openai",
		EnvAPIKey:                   "k",
		EnvAzureEndpoint:            "https://example.openai.azure.com",
		EnvAzureDeployment:          "gpt-4o-deployment",
		EnvAzureEmbeddingDeployment: "text-embed-3-small-prod",
		EnvAzureEmbeddingModel:      "text-embedding-3-small",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	azp, ok := p.(*AzureOpenAIProvider)
	if !ok {
		t.Fatalf("type = %T, want *AzureOpenAIProvider", p)
	}
	cap := azp.Capabilities()
	if !cap.SupportsEmbedding {
		t.Error("SupportsEmbedding = false, want true when embedding deployment is set")
	}
	if cap.EmbeddingDimensions != 1536 {
		t.Errorf("EmbeddingDimensions = %d, want 1536 (text-embedding-3-small)", cap.EmbeddingDimensions)
	}
}

// TestNewProviderFromEnv_AzureEmbeddingAliasHappyPath covers the
// Microsoft-documented env path (operator follows Azure Agent Framework
// docs verbatim): only the alias is set. The factory must still build
// an embedding-capable provider.
func TestNewProviderFromEnv_AzureEmbeddingAliasHappyPath(t *testing.T) {
	withEnv(t, map[string]string{
		EnvProvider:                      "azure_openai",
		EnvAzureAPIKey:                   "k",
		EnvAzureEndpointAlias:            "https://example.openai.azure.com",
		EnvAzureDeploymentAlias:          "gpt-4o-deployment",
		EnvAzureEmbeddingDeploymentAlias: "text-embedding-3-large-prod",
	})
	p, err := NewProviderFromEnv(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	azp, ok := p.(*AzureOpenAIProvider)
	if !ok {
		t.Fatalf("type = %T, want *AzureOpenAIProvider", p)
	}
	cap := azp.Capabilities()
	if !cap.SupportsEmbedding {
		t.Error("SupportsEmbedding = false, want true (alias env not honoured)")
	}
	// Deployment-name sniff path — embedding model env is unset, so
	// dimensions should still resolve from the deployment name prefix.
	if cap.EmbeddingDimensions != 3072 {
		t.Errorf("EmbeddingDimensions = %d, want 3072 (sniffed from deployment name)", cap.EmbeddingDimensions)
	}
}

// TestNewProviderFromConfigWithAzure_EmbeddingFallsBackToEnv pins the
// per-tenant Azure embedding rule: tenant_llm_config does not yet have
// embedding columns, so the embedding deployment falls back to env (the
// same precedent ollamaBaseURLFromEnv sets for the Ollama URL). When
// env is set, the tenant-built provider gains SupportsEmbedding.
func TestNewProviderFromConfigWithAzure_EmbeddingFallsBackToEnv(t *testing.T) {
	withEnv(t, map[string]string{
		EnvAzureEmbeddingDeployment: "shared-embed-dep",
		EnvAzureEmbeddingModel:      "text-embedding-3-small",
	})
	p, err := NewProviderFromConfigWithAzure(
		"azure_openai", "gpt-4o", "tenant-api-key",
		"https://tenant.openai.azure.com", "tenant-chat-dep", "2024-10-21",
	)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	azp, ok := p.(*AzureOpenAIProvider)
	if !ok {
		t.Fatalf("type = %T, want *AzureOpenAIProvider", p)
	}
	cap := azp.Capabilities()
	if !cap.SupportsEmbedding {
		t.Error("SupportsEmbedding = false, want true (env fallback not honoured for tenant config)")
	}
	if cap.EmbeddingDimensions != 1536 {
		t.Errorf("EmbeddingDimensions = %d, want 1536", cap.EmbeddingDimensions)
	}
}
