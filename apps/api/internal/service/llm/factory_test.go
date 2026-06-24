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

func TestNewProviderFromEnv_AzureAndOllamaReturnNotImplemented(t *testing.T) {
	cases := []struct {
		provider string
		needsKey bool
	}{
		{"azure_openai", true},
		{"ollama", false},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			env := map[string]string{EnvProvider: tc.provider}
			if tc.needsKey {
				env[EnvAPIKey] = "dummy"
			}
			withEnv(t, env)
			_, err := NewProviderFromEnv(context.Background())
			if err == nil {
				t.Fatalf("expected 'not implemented' error for %s", tc.provider)
			}
			if !strings.Contains(err.Error(), "not implemented") {
				t.Errorf("err = %v, want 'not implemented'", err)
			}
		})
	}
}
