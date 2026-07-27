package config

import (
	"fmt"
	"os"
	"strings"
)

// Mode represents the application deployment mode
type Mode string

const (
	ModeSelfHosted Mode = "self-hosted"
	ModeSaaS       Mode = "saas"
)

type Config struct {
	// Core settings
	Port        string
	DatabaseURL string
	RedisURL    string
	NVDAPIKey   string
	BaseURL     string
	Environment string // development, staging, production

	// External data-source URL overrides (M40). Empty = use the service's
	// built-in default endpoint. Set to point a source at an internal mirror for
	// air-gapped / firewalled deployments (SBOMHUB_<SRC>_URL).
	EPSSURL string // FIRST.org EPSS
	KEVURL  string // CISA KEV catalog
	NVDURL  string // NVD (shared by the per-SBOM keyword scan and the delta-feed sync)
	EOLURL  string // endoflife.date
	JVNURL  string // JVN / MyJVN
	OSVURL  string // OSV.dev

	// Offline / air-gapped mode (M40, SBOMHUB_OFFLINE). When true, every external
	// vulnerability data-source sync (EPSS, KEV, NVD, EOL, JVN, OSV, IPA) skips
	// its outbound fetch and degrades gracefully (structured log, no error)
	// instead of failing — the product keeps running on already-synced data.
	// Mirrors the LLM "disabled provider" degrade shape. (The GHSA advisory
	// client used for AI-triage grounding is not gated here — see carry-over.)
	Offline bool

	// Clerk authentication (SaaS mode)
	ClerkSecretKey     string
	ClerkWebhookSecret string

	// AllowUnsignedWebhooks (SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS) is the explicit,
	// operator-named opt-in that lets the Clerk / Lemon Squeezy receivers accept
	// webhooks WITHOUT verifying their signature — and only while no secret is
	// configured for that receiver at all.
	//
	// M47: it replaces the inferred bypass those receivers used to apply
	// (`if secret == "" { return !IsProduction() }`), which turned every
	// deployment that had simply not set the secret — APP_ENV defaults to
	// "development" when unset — into an open webhook endpoint. The flag is
	// refused at startup in production (see cmd/server/main.go
	// validateWebhookVerification) AND re-checked at request time, so the
	// bypass cannot be reached there by any combination of env vars.
	//
	// A configured secret always wins: the flag never disables verification
	// for a receiver whose secret is set.
	AllowUnsignedWebhooks bool

	// Lemon Squeezy billing (SaaS mode)
	LemonSqueezyAPIKey         string
	LemonSqueezyWebhookSecret  string
	LemonSqueezyStoreID        string
	LemonSqueezyStarterVariant string
	LemonSqueezyProVariant     string
	LemonSqueezyTeamVariant    string

	// Security
	EncryptionKey string // For encrypting sensitive data like API tokens

	// SMTP settings (for email notifications)
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string

	// Derived settings
	mode Mode
}

func Load() *Config {
	// SECURITY (codex-r18 P1): APP_ENV is the canonical deployment-mode env,
	// matching docker-compose.yml and the startup guards in cmd/server/main.go
	// (assertAppRoleNotBypassRLS, validateEncryptionKey). The legacy
	// ENVIRONMENT variable is kept as a backward-compat fallback for pre-M0
	// self-host deployments. Reading APP_ENV first ensures cfg.IsProduction()
	// agrees with the startup gate, so webhook handlers that fall back to
	// "skip signature verification when not production" cannot be tricked into
	// skipping in a production deployment that only sets APP_ENV.
	env := getEnv("APP_ENV", "")
	if env == "" {
		env = getEnv("ENVIRONMENT", "development")
	}

	cfg := &Config{
		// Core
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
		NVDAPIKey:   getEnv("NVD_API_KEY", ""),
		BaseURL:     getEnv("BASE_URL", "http://localhost:3000"),
		Environment: env,

		// External data-source URL overrides + offline mode (M40). Defaults are
		// empty so each service falls back to its own built-in const (single
		// source of truth for the default URL — not duplicated here).
		EPSSURL: getEnv("SBOMHUB_EPSS_URL", ""),
		KEVURL:  getEnv("SBOMHUB_KEV_URL", ""),
		NVDURL:  getEnv("SBOMHUB_NVD_URL", ""),
		EOLURL:  getEnv("SBOMHUB_EOL_URL", ""),
		JVNURL:  getEnv("SBOMHUB_JVN_URL", ""),
		OSVURL:  getEnv("SBOMHUB_OSV_URL", ""),
		Offline: getEnvBool("SBOMHUB_OFFLINE", false),

		// Clerk
		ClerkSecretKey:     getEnv("CLERK_SECRET_KEY", ""),
		ClerkWebhookSecret: getEnv("CLERK_WEBHOOK_SECRET", ""),

		// Webhook signature verification (M47). Default false = fail-closed.
		AllowUnsignedWebhooks: getEnvBool("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", false),

		// Lemon Squeezy
		LemonSqueezyAPIKey:         getEnv("LEMONSQUEEZY_API_KEY", ""),
		LemonSqueezyWebhookSecret:  getEnv("LEMONSQUEEZY_WEBHOOK_SECRET", ""),
		LemonSqueezyStoreID:        getEnv("LEMONSQUEEZY_STORE_ID", ""),
		LemonSqueezyStarterVariant: getEnv("LEMONSQUEEZY_STARTER_VARIANT_ID", ""),
		LemonSqueezyProVariant:     getEnv("LEMONSQUEEZY_PRO_VARIANT_ID", ""),
		LemonSqueezyTeamVariant:    getEnv("LEMONSQUEEZY_TEAM_VARIANT_ID", ""),

		// Security
		// SECURITY: Default key is only for development. Production requires explicit key.
		EncryptionKey: getEnv("ENCRYPTION_KEY", ""),

		// SMTP
		SMTPHost:     getEnv("SMTP_HOST", ""),
		SMTPPort:     getEnv("SMTP_PORT", "587"),
		SMTPUser:     getEnv("SMTP_USER", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("SMTP_FROM", "noreply@sbomhub.app"),
	}

	// Determine mode based on configuration
	if cfg.ClerkSecretKey != "" {
		cfg.mode = ModeSaaS
	} else {
		cfg.mode = ModeSelfHosted
	}

	return cfg
}

// Mode returns the current deployment mode
func (c *Config) Mode() Mode {
	return c.mode
}

// IsSaaS returns true if running in SaaS mode
func (c *Config) IsSaaS() bool {
	return c.mode == ModeSaaS
}

// IsSelfHosted returns true if running in self-hosted mode
func (c *Config) IsSelfHosted() bool {
	return c.mode == ModeSelfHosted
}

// IsAuthEnabled returns true if authentication is enabled (Clerk configured)
func (c *Config) IsAuthEnabled() bool {
	return c.ClerkSecretKey != ""
}

// IsBillingEnabled returns true if billing is enabled (Lemon Squeezy configured)
func (c *Config) IsBillingEnabled() bool {
	return c.LemonSqueezyAPIKey != ""
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in the development environment.
// This is the single source of truth for the "warn instead of hard-fail"
// downgrade applied to Trust Rescue startup guards
// (validateEncryptionKey / assertAppRoleNotBypassRLS in cmd/server/main.go).
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// UnsignedWebhooksAllowed reports whether a webhook receiver with NO secret
// configured may skip signature verification. It is the single source of
// truth shared by the Clerk and Lemon Squeezy receivers.
//
// Both conditions are required: the operator asked for it by name
// (SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS) AND the process is running in
// DEVELOPMENT specifically.
//
// It checks IsDevelopment(), not !IsProduction() (Codex round 3, Low): the
// latter also admits staging and every typo of "production", which is the
// opposite of the fail-closed posture this flag exists inside. APP_ENV unset
// still resolves to "development" (config.Load's fallback), so the local flow
// that needs the bypass keeps working without setting anything.
//
// The environment term is deliberately redundant with the startup guard in
// cmd/server/main.go, so the runtime decision does not depend on that guard
// having run (tests construct a Config directly; so could a future embedding
// of this package).
//
// Callers must consult this ONLY when their secret is empty. A configured
// secret is always verified.
func (c *Config) UnsignedWebhooksAllowed() bool {
	return c.AllowUnsignedWebhooks && c.IsDevelopment()
}

// IsEmailEnabled returns true if email notifications are configured
func (c *Config) IsEmailEnabled() bool {
	return c.SMTPHost != "" && c.SMTPFrom != ""
}

// Validate checks for security-critical configuration errors
// Returns an error if the configuration is insecure for the current environment
func (c *Config) Validate() error {
	// SECURITY: Encryption key validation
	if c.EncryptionKey == "" {
		if c.IsProduction() {
			return fmt.Errorf("ENCRYPTION_KEY must be set in production environment")
		}
		// Use a development-only default key (this is logged as a warning)
		c.EncryptionKey = "dev-only-insecure-key-32bytes!!"
	}

	// SECURITY: Key length validation - AES-256 requires exactly 32 bytes
	if len(c.EncryptionKey) < 32 {
		if c.IsProduction() {
			return fmt.Errorf("ENCRYPTION_KEY must be at least 32 bytes for AES-256 (got %d bytes)", len(c.EncryptionKey))
		}
	}

	// SECURITY: Warn about weak keys that look like defaults
	weakKeys := []string{
		"sbomhub-default-encryption-key-32",
		"dev-only-insecure-key-32bytes!!",
		"00000000000000000000000000000000",
		"11111111111111111111111111111111",
	}
	for _, weak := range weakKeys {
		if c.EncryptionKey == weak && c.IsProduction() {
			return fmt.Errorf("ENCRYPTION_KEY appears to be a default/weak key - please use a cryptographically random key in production")
		}
	}

	return nil
}

// GetEncryptionKey returns the encryption key as a 32-byte slice for AES-256
// SECURITY: This method ensures proper key length without silent zero-padding
func (c *Config) GetEncryptionKey() ([]byte, error) {
	if len(c.EncryptionKey) < 32 {
		return nil, fmt.Errorf("encryption key too short: need 32 bytes, got %d", len(c.EncryptionKey))
	}
	// Use first 32 bytes if key is longer
	return []byte(c.EncryptionKey)[:32], nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool reads a boolean env var. Accepts 1/true/yes/on (case-insensitive)
// as true and 0/false/no/off as false; any other value (including unset/empty)
// falls back to defaultValue.
func getEnvBool(key string, defaultValue bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}
