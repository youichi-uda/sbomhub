package config

import "os"

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

	// Clerk authentication (SaaS mode)
	ClerkSecretKey     string
	ClerkWebhookSecret string

	// Lemon Squeezy billing (SaaS mode)
	LemonSqueezyAPIKey        string
	LemonSqueezyWebhookSecret string
	LemonSqueezyStoreID       string
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
	cfg := &Config{
		// Core
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
		NVDAPIKey:   getEnv("NVD_API_KEY", ""),
		BaseURL:     getEnv("BASE_URL", "http://localhost:3000"),
		Environment: getEnv("ENVIRONMENT", "development"),

		// Clerk
		ClerkSecretKey:     getEnv("CLERK_SECRET_KEY", ""),
		ClerkWebhookSecret: getEnv("CLERK_WEBHOOK_SECRET", ""),

		// Lemon Squeezy
		LemonSqueezyAPIKey:         getEnv("LEMONSQUEEZY_API_KEY", ""),
		LemonSqueezyWebhookSecret:  getEnv("LEMONSQUEEZY_WEBHOOK_SECRET", ""),
		LemonSqueezyStoreID:        getEnv("LEMONSQUEEZY_STORE_ID", ""),
		LemonSqueezyStarterVariant: getEnv("LEMONSQUEEZY_STARTER_VARIANT_ID", ""),
		LemonSqueezyProVariant:     getEnv("LEMONSQUEEZY_PRO_VARIANT_ID", ""),
		LemonSqueezyTeamVariant:    getEnv("LEMONSQUEEZY_TEAM_VARIANT_ID", ""),

		// Security
		EncryptionKey: getEnv("ENCRYPTION_KEY", "sbomhub-default-encryption-key-32"),

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

// IsEmailEnabled returns true if email notifications are configured
func (c *Config) IsEmailEnabled() bool {
	return c.SMTPHost != "" && c.SMTPFrom != ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
