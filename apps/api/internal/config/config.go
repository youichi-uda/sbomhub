package config

import "os"

type Config struct {
	Port        string
	DatabaseURL string
	RedisURL    string
	NVDAPIKey   string
	BaseURL     string
}

func Load() *Config {
	return &Config{
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
		NVDAPIKey:   getEnv("NVD_API_KEY", ""),
		BaseURL:     getEnv("BASE_URL", "http://localhost:3000"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
