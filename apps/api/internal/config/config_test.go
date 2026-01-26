package config

import (
	"os"
	"testing"
)

func TestLoad_SelfHostedMode(t *testing.T) {
	// Clear any existing env vars
	os.Unsetenv("CLERK_SECRET_KEY")
	os.Unsetenv("LEMONSQUEEZY_API_KEY")

	cfg := Load()

	if cfg.Mode() != ModeSelfHosted {
		t.Errorf("expected mode %s, got %s", ModeSelfHosted, cfg.Mode())
	}
	if cfg.IsSaaS() {
		t.Error("expected IsSaaS to be false")
	}
	if !cfg.IsSelfHosted() {
		t.Error("expected IsSelfHosted to be true")
	}
	if cfg.IsAuthEnabled() {
		t.Error("expected IsAuthEnabled to be false")
	}
	if cfg.IsBillingEnabled() {
		t.Error("expected IsBillingEnabled to be false")
	}
}

func TestLoad_SaaSMode(t *testing.T) {
	// Set Clerk secret key to enable SaaS mode
	os.Setenv("CLERK_SECRET_KEY", "sk_test_xxxxx")
	defer os.Unsetenv("CLERK_SECRET_KEY")

	cfg := Load()

	if cfg.Mode() != ModeSaaS {
		t.Errorf("expected mode %s, got %s", ModeSaaS, cfg.Mode())
	}
	if !cfg.IsSaaS() {
		t.Error("expected IsSaaS to be true")
	}
	if cfg.IsSelfHosted() {
		t.Error("expected IsSelfHosted to be false")
	}
	if !cfg.IsAuthEnabled() {
		t.Error("expected IsAuthEnabled to be true")
	}
}

func TestLoad_BillingEnabled(t *testing.T) {
	os.Setenv("CLERK_SECRET_KEY", "sk_test_xxxxx")
	os.Setenv("LEMONSQUEEZY_API_KEY", "ls_test_xxxxx")
	defer os.Unsetenv("CLERK_SECRET_KEY")
	defer os.Unsetenv("LEMONSQUEEZY_API_KEY")

	cfg := Load()

	if !cfg.IsBillingEnabled() {
		t.Error("expected IsBillingEnabled to be true")
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	// Clear all env vars
	envVars := []string{
		"PORT", "DATABASE_URL", "REDIS_URL", "ENVIRONMENT",
		"CLERK_SECRET_KEY", "LEMONSQUEEZY_API_KEY",
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}

	cfg := Load()

	if cfg.Port != "8080" {
		t.Errorf("expected default port 8080, got %s", cfg.Port)
	}
	if cfg.Environment != "development" {
		t.Errorf("expected default environment development, got %s", cfg.Environment)
	}
}

func TestIsProduction(t *testing.T) {
	os.Setenv("ENVIRONMENT", "production")
	defer os.Unsetenv("ENVIRONMENT")

	cfg := Load()

	if !cfg.IsProduction() {
		t.Error("expected IsProduction to be true")
	}
}
