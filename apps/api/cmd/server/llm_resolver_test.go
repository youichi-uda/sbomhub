package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// fakeTenantLLMConfigRepo is a stand-in for *repository.TenantLLMConfigRepository
// in the resolver tests. It returns the configured row (or
// ErrTenantLLMConfigNotFound) without touching Postgres. The body of the
// resolver is what we're exercising; the repo here is purely a test seam.
type fakeTenantLLMConfigRepo struct {
	cfg      *repository.TenantLLMConfig
	notFound bool
	err      error
}

func (f *fakeTenantLLMConfigRepo) Get(_ context.Context, _ uuid.UUID) (*repository.TenantLLMConfig, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.notFound {
		return nil, repository.ErrTenantLLMConfigNotFound
	}
	return f.cfg, nil
}

// disabledSentinel is the default Provider used by the resolver fallback
// path. We compare by pointer identity in the tests below to verify when
// the resolver hands back the env default vs. building a fresh per-tenant
// Provider.
var disabledSentinel = &llm.DisabledProvider{Reason: "test: env-default fallback"}

// testEncryptionKey is a fixed 32-byte key used to encrypt the fake tenant
// API key. The resolver decrypts via llm.Decrypt(cfg.EncryptedAPIKey, key)
// so the test must encrypt with the same key.
var testEncryptionKey = []byte("0123456789abcdef0123456789abcdef") // 32 bytes

// TestNewProviderFromConfigWithAzure_TenantScoped is the M4 Codex review
// #F40 regression test: with provider = azure_openai and both Azure
// fields populated on tenant_llm_config, the resolver MUST construct an
// AzureOpenAIProvider — NOT silent-fall-back to DisabledProvider the way
// it did when the resolver used the no-Azure NewProviderFromConfig
// variant.
func TestNewProviderFromConfigWithAzure_TenantScoped(t *testing.T) {
	encryptedKey, err := llm.Encrypt([]byte("tenant-azure-key"), testEncryptionKey)
	if err != nil {
		t.Fatalf("seed Encrypt: %v", err)
	}
	repo := &fakeTenantLLMConfigRepo{
		cfg: &repository.TenantLLMConfig{
			TenantID:        uuid.New(),
			Mode:            "byok",
			Provider:        "azure_openai",
			EncryptedAPIKey: encryptedKey,
			Model:           "gpt-4o",
			AzureEndpoint:   "https://my-resource.openai.azure.com",
			AzureDeployment: "gpt-4o-prod",
		},
	}

	resolver := newTenantLLMProviderResolver(repo, disabledSentinel, testEncryptionKey)
	p, err := resolver(context.Background(), repo.cfg.TenantID)
	if err != nil {
		t.Fatalf("resolver err = %v, want nil", err)
	}
	if p == disabledSentinel {
		t.Fatalf("resolver returned env-default fallback, want fresh Azure provider built from tenant_llm_config — this is the #F40 silent disable")
	}
	if p.Name() != "azure_openai" {
		t.Fatalf("p.Name() = %q, want azure_openai", p.Name())
	}
	if p.Model() != "gpt-4o" {
		t.Errorf("p.Model() = %q, want gpt-4o (canonical model identifier from tenant config)", p.Model())
	}
}

// TestNewProviderFromConfigWithAzure_TenantScoped_AzureFieldsMissing
// verifies that when provider = azure_openai is configured but either
// Azure field is empty, the resolver does NOT return an error and
// instead surfaces a DisabledProvider with a reason mentioning the
// missing field — the same behaviour the env-side path
// (NewProviderFromEnv) follows. The caller (triage/cra runner) then
// emits the #F4 ai_disabled draft path. Without this, an operator who
// fills in api_key but forgets endpoint would see a confusing 500
// rather than the documented "AI disabled" path.
func TestNewProviderFromConfigWithAzure_TenantScoped_AzureFieldsMissing(t *testing.T) {
	encryptedKey, err := llm.Encrypt([]byte("tenant-azure-key"), testEncryptionKey)
	if err != nil {
		t.Fatalf("seed Encrypt: %v", err)
	}
	cases := []struct {
		name       string
		endpoint   string
		deployment string
	}{
		{"endpoint missing", "", "gpt-4o-prod"},
		{"deployment missing", "https://my-resource.openai.azure.com", ""},
		{"both missing", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeTenantLLMConfigRepo{
				cfg: &repository.TenantLLMConfig{
					TenantID:        uuid.New(),
					Mode:            "byok",
					Provider:        "azure_openai",
					EncryptedAPIKey: encryptedKey,
					Model:           "gpt-4o",
					AzureEndpoint:   tc.endpoint,
					AzureDeployment: tc.deployment,
				},
			}
			resolver := newTenantLLMProviderResolver(repo, disabledSentinel, testEncryptionKey)
			p, err := resolver(context.Background(), repo.cfg.TenantID)
			if err != nil {
				t.Fatalf("resolver err = %v, want nil (DisabledProvider returned in-band)", err)
			}
			if p.Name() != "disabled" {
				t.Errorf("p.Name() = %q, want disabled (Azure fields missing should downgrade, not error)", p.Name())
			}
		})
	}
}

// TestNewTenantLLMProviderResolver_NotFoundFallsBackToDefault checks the
// "tenant has no row" branch: the resolver MUST return the env-resolved
// default verbatim (pointer-identity match) so a fresh tenant doesn't
// inherit a Disabled state and the runner can still attempt the call
// against the operator-configured env default.
func TestNewTenantLLMProviderResolver_NotFoundFallsBackToDefault(t *testing.T) {
	repo := &fakeTenantLLMConfigRepo{notFound: true}
	resolver := newTenantLLMProviderResolver(repo, disabledSentinel, testEncryptionKey)
	p, err := resolver(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("resolver err = %v, want nil", err)
	}
	if p != disabledSentinel {
		t.Errorf("resolver returned %T, want env-default sentinel (pointer identity)", p)
	}
}

// TestNewTenantLLMProviderResolver_NonOllamaMissingKeyFallsBack covers
// the F2/F4 behaviour: a tenant row exists with provider = openai but no
// encrypted_api_key — the resolver hands back the env default (not a
// per-tenant Disabled) so AI features still work when the operator
// configured env-level BYOK as a baseline.
func TestNewTenantLLMProviderResolver_NonOllamaMissingKeyFallsBack(t *testing.T) {
	repo := &fakeTenantLLMConfigRepo{
		cfg: &repository.TenantLLMConfig{
			TenantID:        uuid.New(),
			Mode:            "byok",
			Provider:        "openai",
			EncryptedAPIKey: nil, // BYOK incomplete
			Model:           "gpt-4o",
		},
	}
	resolver := newTenantLLMProviderResolver(repo, disabledSentinel, testEncryptionKey)
	p, err := resolver(context.Background(), repo.cfg.TenantID)
	if err != nil {
		t.Fatalf("resolver err = %v, want nil", err)
	}
	if p != disabledSentinel {
		t.Errorf("resolver returned %T, want env-default sentinel (per-#F4 'fall back to env when BYOK incomplete')", p)
	}
}

// TestNewTenantLLMProviderResolver_OllamaTenantBuildsProvider covers the
// per-tenant Ollama path: no API key is required, model alone is enough.
// This is here mainly as a regression net so a future change to the
// resolver doesn't accidentally re-introduce the needsKey check for
// ollama tenants.
func TestNewTenantLLMProviderResolver_OllamaTenantBuildsProvider(t *testing.T) {
	repo := &fakeTenantLLMConfigRepo{
		cfg: &repository.TenantLLMConfig{
			TenantID: uuid.New(),
			Mode:     "byok",
			Provider: "ollama",
			Model:    "qwen2.5-coder:7b",
		},
	}
	resolver := newTenantLLMProviderResolver(repo, disabledSentinel, testEncryptionKey)
	p, err := resolver(context.Background(), repo.cfg.TenantID)
	if err != nil {
		t.Fatalf("resolver err = %v, want nil", err)
	}
	if p.Name() != "ollama" {
		t.Errorf("p.Name() = %q, want ollama", p.Name())
	}
}

// TestNewTenantLLMProviderResolver_RepoErrorPropagates verifies generic
// repo errors (network blip, RLS violation, etc.) flow back to the
// caller wrapped — they MUST NOT be swallowed into a silent fallback,
// because that would hide DB issues behind "AI disabled" drafts.
func TestNewTenantLLMProviderResolver_RepoErrorPropagates(t *testing.T) {
	boom := errors.New("rls: permission denied for table tenant_llm_config")
	repo := &fakeTenantLLMConfigRepo{err: boom}
	resolver := newTenantLLMProviderResolver(repo, disabledSentinel, testEncryptionKey)
	_, err := resolver(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("resolver returned nil error, want repo error wrapped")
	}
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want errors.Is to match the underlying repo error", err)
	}
}
