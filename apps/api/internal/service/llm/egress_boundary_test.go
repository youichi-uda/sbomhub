package llm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/egress"
)

// TestOllamaBaseURLIgnoresTenantColumn pins the boundary the M50 egress work
// depends on.
//
// tenant_llm_config.ollama_url is persisted by the settings handler but is NOT
// read here: the ollama arm resolves its base URL from
// SBOMHUB_LLM_OLLAMA_URL / OLLAMA_HOST. That is why the handler applies only a
// shape check to that column instead of the destination policy — the column is
// not a destination — and why the documented self-hosted default
// http://localhost:11434 keeps working with the guard enabled.
//
// If a future change wires the column through to the provider, this test fails,
// and the endpoint must be routed through the guard at the same time.
func TestOllamaBaseURLIgnoresTenantColumn(t *testing.T) {
	t.Setenv(EnvOllamaURL, "http://ollama.operator.test:11434")
	t.Setenv(EnvOllamaHost, "")

	p, err := NewProviderFromConfigWithAzure(
		egress.NewSet(egress.Settings{}).TenantLLM,
		"ollama", "qwen2.5-coder:7b", "", "", "", "")
	if err != nil {
		t.Fatalf("NewProviderFromConfigWithAzure: %v", err)
	}
	op, ok := p.(*OllamaProvider)
	if !ok {
		t.Fatalf("provider = %T, want *OllamaProvider", p)
	}
	if op.baseURL != "http://ollama.operator.test:11434" {
		t.Errorf("baseURL = %q, want the env-resolved value — the tenant column must not be a destination", op.baseURL)
	}
}

// TestOllamaLocalhostDefaultSurvivesStrictGuard is the product-level assertion
// behind that boundary: the deployment the documentation recommends to
// manufacturers (Ollama on localhost) must not be broken by turning the
// tenant-egress policy on.
func TestOllamaLocalhostDefaultSurvivesStrictGuard(t *testing.T) {
	t.Setenv(EnvOllamaURL, "")
	t.Setenv(EnvOllamaHost, "")

	p, err := NewProviderFromConfigWithAzure(
		egress.NewSet(egress.Settings{}).TenantLLM,
		"ollama", "qwen2.5-coder:7b", "", "", "", "")
	if err != nil {
		t.Fatalf("NewProviderFromConfigWithAzure: %v", err)
	}
	op, ok := p.(*OllamaProvider)
	if !ok {
		t.Fatalf("provider = %T, want *OllamaProvider (a DisabledProvider here would mean the guard broke the documented default)", p)
	}
	if op.baseURL != "http://localhost:11434" {
		t.Errorf("baseURL = %q, want http://localhost:11434", op.baseURL)
	}
}

// TestAzureTenantEndpointIsGuarded is the other side: the tenant-supplied Azure
// endpoint IS a destination, and the strict policy refuses an internal one.
func TestAzureTenantEndpointIsGuarded(t *testing.T) {
	guard := egress.NewSet(egress.Settings{}).TenantLLM

	p, err := NewProviderFromConfigWithAzure(guard,
		"azure_openai", "gpt-4o", "key", "http://169.254.169.254/", "dep", "")
	if err != nil {
		t.Fatalf("NewProviderFromConfigWithAzure: %v", err)
	}
	dp, ok := p.(*DisabledProvider)
	if !ok {
		t.Fatalf("provider = %T, want *DisabledProvider for a metadata endpoint", p)
	}
	if !strings.Contains(dp.Reason, "not an allowed destination") {
		t.Errorf("reason = %q, want it to name the destination refusal", dp.Reason)
	}
}

// TestAzureTenantEndpointGuardAppliesAtDialTime asserts the client the provider
// will actually use carries the guard. Validation alone is not the defence — a
// hostname that passes ValidateURL can still resolve internally — so the
// constructed provider has to be dialing through the guarded transport.
func TestAzureTenantEndpointGuardAppliesAtDialTime(t *testing.T) {
	guard := egress.NewSet(egress.Settings{}).TenantLLM

	p, err := NewProviderFromConfigWithAzure(guard,
		"azure_openai", "gpt-4o", "key", "https://acme.openai.azure.com", "dep", "")
	if err != nil {
		t.Fatalf("NewProviderFromConfigWithAzure: %v", err)
	}
	ap, ok := p.(*AzureOpenAIProvider)
	if !ok {
		t.Fatalf("provider = %T, want *AzureOpenAIProvider", p)
	}

	// Drive a real request at a loopback listener through the provider's own
	// client. Asserting on the transport's type would only prove which object
	// is installed; this proves the object refuses.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, derr := ap.client.Do(req)
	if derr == nil {
		_ = resp.Body.Close()
		t.Fatal("the provider's client reached a loopback address")
	}
	if !errors.Is(derr, egress.ErrBlockedDestination) {
		t.Errorf("provider client returned %v, want ErrBlockedDestination", derr)
	}
	if ap.client.CheckRedirect == nil {
		t.Error("the tenant Azure provider must carry the guard's redirect policy")
	}
}

// TestNewProviderFromConfigWithAzure_NilGuardIsStrict is the Codex round 2
// (Medium) regression: a nil guard used to mean "no policy" for this per-tenant
// constructor, so a caller that omitted the argument got an unguarded client for
// a URL a tenant typed. A caller who did not say which policy applies must get
// the strictest one.
func TestNewProviderFromConfigWithAzure_NilGuardIsStrict(t *testing.T) {
	p, err := NewProviderFromConfigWithAzure(nil,
		"azure_openai", "gpt-4o", "key", "http://169.254.169.254/", "dep", "")
	if err != nil {
		t.Fatalf("NewProviderFromConfigWithAzure: %v", err)
	}
	if _, ok := p.(*DisabledProvider); !ok {
		t.Fatalf("provider = %T, want *DisabledProvider — a nil guard must not permit the metadata endpoint", p)
	}

	// And a permitted endpoint must still come back guarded, not bare.
	p2, err := NewProviderFromConfigWithAzure(nil,
		"azure_openai", "gpt-4o", "key", "https://acme.openai.azure.com", "dep", "")
	if err != nil {
		t.Fatalf("NewProviderFromConfigWithAzure: %v", err)
	}
	ap, ok := p2.(*AzureOpenAIProvider)
	if !ok {
		t.Fatalf("provider = %T, want *AzureOpenAIProvider", p2)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, derr := ap.client.Do(req)
	if derr == nil {
		_ = resp.Body.Close()
		t.Fatal("a nil-guard provider reached a loopback address")
	}
	if !errors.Is(derr, egress.ErrBlockedDestination) {
		t.Errorf("got %v, want ErrBlockedDestination", derr)
	}
}
