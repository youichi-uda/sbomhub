package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// M72 settings: the Redis circuit breaker and the per-tenant scan concurrency
// limit. Like SBOMHUB_SCAN_DEADLINE, an unusable value refuses startup rather
// than being replaced by a default the operator did not choose.

// Redis circuit breaker defaults (equal to internal/redis.DefaultBreaker*).
const (
	DefaultRedisBreakerThreshold = 5
	DefaultRedisBreakerCooldown  = 5 * time.Second
)

// RedisBreaker returns SBOMHUB_REDIS_BREAKER_THRESHOLD (consecutive failures
// that open the breaker, 1-1000, default 5) and SBOMHUB_REDIS_BREAKER_COOLDOWN
// (how long it stays open before one probe, 1s-5m, default 5s).
func (c *Config) RedisBreaker() (threshold int, cooldown time.Duration, err error) {
	threshold, cooldown = DefaultRedisBreakerThreshold, DefaultRedisBreakerCooldown
	if v := strings.TrimSpace(c.RedisBreakerThresholdRaw); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 1 || n > 1000 {
			return 0, 0, fmt.Errorf("SBOMHUB_REDIS_BREAKER_THRESHOLD=%q: want a whole number from 1 to 1000", c.RedisBreakerThresholdRaw)
		}
		threshold = n
	}
	if v := strings.TrimSpace(c.RedisBreakerCooldownRaw); v != "" {
		d, perr := time.ParseDuration(v)
		if perr != nil || d < time.Second || d > 5*time.Minute {
			return 0, 0, fmt.Errorf("SBOMHUB_REDIS_BREAKER_COOLDOWN=%q: want a duration from 1s to 5m, such as \"5s\"", c.RedisBreakerCooldownRaw)
		}
		cooldown = d
	}
	return threshold, cooldown, nil
}

// DefaultScanTenantConcurrency is how many SBOM scans of ONE tenant run at
// once in one API process when SBOMHUB_SCAN_TENANT_CONCURRENCY is unset.
const DefaultScanTenantConcurrency = 2

// ScanTenantConcurrency returns SBOMHUB_SCAN_TENANT_CONCURRENCY: 1-64, or 0
// for "off" (no per-tenant limit, the pre-M72 behaviour).
func (c *Config) ScanTenantConcurrency() (int, error) {
	v := strings.ToLower(strings.TrimSpace(c.ScanTenantConcurrencyRaw))
	switch v {
	case "":
		return DefaultScanTenantConcurrency, nil
	case "off":
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 64 {
		return 0, fmt.Errorf("SBOMHUB_SCAN_TENANT_CONCURRENCY=%q: want a whole number from 1 to 64, or \"off\"", c.ScanTenantConcurrencyRaw)
	}
	return n, nil
}
