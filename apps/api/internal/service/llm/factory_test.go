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
	// Always clear the canonical contract envs so tests stay hermetic even
	// if the developer has these set in their shell.
	for _, k := range []string{EnvProvider, EnvAPIKey, EnvModel, EnvAzureEndpoint, EnvAzureDeployment, EnvOllamaURL} {
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
