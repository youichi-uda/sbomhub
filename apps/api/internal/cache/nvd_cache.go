package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// NVDCacheTTL is the TTL for NVD vulnerability cache entries
	NVDCacheTTL = 24 * time.Hour
	// NVDCachePrefix is the prefix for all NVD cache keys
	NVDCachePrefix = "nvd:vuln:"
)

// VulnCacheEntry represents cached vulnerability data for a component
type VulnCacheEntry struct {
	Vulnerabilities []CachedVuln `json:"vulnerabilities"`
	CachedAt        time.Time    `json:"cached_at"`
}

// CachedVuln represents a cached vulnerability
type CachedVuln struct {
	CVEID       string    `json:"cve_id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSSScore   float64   `json:"cvss_score"`
	PublishedAt time.Time `json:"published_at"`
}

// NVDCache provides caching for NVD API responses
type NVDCache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewNVDCache creates a new NVD cache instance
func NewNVDCache(client *redis.Client) *NVDCache {
	return &NVDCache{
		client: client,
		ttl:    NVDCacheTTL,
	}
}

// NewNVDCacheWithTTL creates a new NVD cache instance with custom TTL
func NewNVDCacheWithTTL(client *redis.Client, ttl time.Duration) *NVDCache {
	return &NVDCache{
		client: client,
		ttl:    ttl,
	}
}

// cacheKey generates the cache key for a component
func (c *NVDCache) cacheKey(name, version string) string {
	if version == "" {
		return fmt.Sprintf("%s%s", NVDCachePrefix, name)
	}
	return fmt.Sprintf("%s%s:%s", NVDCachePrefix, name, version)
}

// Get retrieves cached vulnerabilities for a component
// Returns nil, nil if not found (cache miss)
func (c *NVDCache) Get(ctx context.Context, name, version string) (*VulnCacheEntry, error) {
	key := c.cacheKey(name, version)

	data, err := c.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil // Cache miss
	}
	if err != nil {
		return nil, fmt.Errorf("redis get error: %w", err)
	}

	var entry VulnCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		// Invalid cache entry, treat as miss
		return nil, nil
	}

	return &entry, nil
}

// Set stores vulnerabilities in cache for a component
func (c *NVDCache) Set(ctx context.Context, name, version string, vulns []CachedVuln) error {
	key := c.cacheKey(name, version)

	entry := VulnCacheEntry{
		Vulnerabilities: vulns,
		CachedAt:        time.Now(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	if err := c.client.Set(ctx, key, data, c.ttl).Err(); err != nil {
		return fmt.Errorf("redis set error: %w", err)
	}

	return nil
}

// Delete removes a cache entry
func (c *NVDCache) Delete(ctx context.Context, name, version string) error {
	key := c.cacheKey(name, version)
	return c.client.Del(ctx, key).Err()
}

// Stats returns cache statistics
type CacheStats struct {
	Keys      int64 `json:"keys"`
	HitCount  int64 `json:"hit_count"`
	MissCount int64 `json:"miss_count"`
}

// GetStats returns cache statistics (approximate)
func (c *NVDCache) GetStats(ctx context.Context) (*CacheStats, error) {
	// Count keys with NVD prefix
	var cursor uint64
	var count int64

	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, NVDCachePrefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}
		count += int64(len(keys))
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return &CacheStats{
		Keys: count,
	}, nil
}

// Clear removes all NVD cache entries
func (c *NVDCache) Clear(ctx context.Context) error {
	var cursor uint64
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, NVDCachePrefix+"*", 100).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}
