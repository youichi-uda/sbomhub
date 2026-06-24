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
		"PORT", "DATABASE_URL", "REDIS_URL", "APP_ENV", "ENVIRONMENT",
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
	os.Unsetenv("APP_ENV")

	cfg := Load()

	if !cfg.IsProduction() {
		t.Error("expected IsProduction to be true")
	}
}

// TestLoad_AppEnvPreferredOverEnvironment covers codex-r18 P1: cfg.IsProduction
// must agree with the APP_ENV-driven startup guards in cmd/server/main.go.
// Without this fix, a production deployment that only sets APP_ENV=production
// would leave cfg.Environment="" and let webhook handlers skip signature
// verification.
func TestLoad_AppEnvPreferredOverEnvironment(t *testing.T) {
	cases := []struct {
		name           string
		appEnv         string
		environment    string
		wantEnv        string
		wantProduction bool
	}{
		{
			name:           "APP_ENV=production canonical path",
			appEnv:         "production",
			environment:    "",
			wantEnv:        "production",
			wantProduction: true,
		},
		{
			name:           "APP_ENV wins over legacy ENVIRONMENT when both set",
			appEnv:         "development",
			environment:    "production",
			wantEnv:        "development",
			wantProduction: false,
		},
		{
			name:           "ENVIRONMENT fallback when APP_ENV unset (legacy self-host)",
			appEnv:         "",
			environment:    "production",
			wantEnv:        "production",
			wantProduction: true,
		},
		{
			name:           "Both unset defaults to development",
			appEnv:         "",
			environment:    "",
			wantEnv:        "development",
			wantProduction: false,
		},
		{
			name:           "APP_ENV=staging neither production nor development",
			appEnv:         "staging",
			environment:    "",
			wantEnv:        "staging",
			wantProduction: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Unsetenv("APP_ENV")
			os.Unsetenv("ENVIRONMENT")
			if tc.appEnv != "" {
				os.Setenv("APP_ENV", tc.appEnv)
				defer os.Unsetenv("APP_ENV")
			}
			if tc.environment != "" {
				os.Setenv("ENVIRONMENT", tc.environment)
				defer os.Unsetenv("ENVIRONMENT")
			}

			cfg := Load()

			if cfg.Environment != tc.wantEnv {
				t.Errorf("Environment = %q, want %q (APP_ENV=%q ENVIRONMENT=%q)",
					cfg.Environment, tc.wantEnv, tc.appEnv, tc.environment)
			}
			if got := cfg.IsProduction(); got != tc.wantProduction {
				t.Errorf("IsProduction() = %t, want %t (APP_ENV=%q ENVIRONMENT=%q)",
					got, tc.wantProduction, tc.appEnv, tc.environment)
			}
		})
	}
}
