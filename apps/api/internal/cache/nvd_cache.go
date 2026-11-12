package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	sbomredis "github.com/sbomhub/sbomhub/internal/redis"
)

const (
	// NVDCacheTTL is the TTL for NVD vulnerability cache entries
	NVDCacheTTL = 24 * time.Hour

	// NVDCachePrefix is the prefix for all NVD cache keys.
	//
	// # Why this is `nvdv2:` and not `nvd:vuln:` (M55 follow-up)
	//
	// cacheKey below interpolates a caller-supplied string, and that string
	// reaches this package from an uploaded SBOM's component name — an
	// arbitrary byte string. So the set of keys a caller can construct is
	// exactly `NVDCachePrefix + <anything>`, and two builds that share this
	// prefix share a key space no matter how either of them encodes the rest.
	//
	// service.nvdCacheName now hashes (name, version) into
	// `m55.<sha256>` precisely so that no two components collide WITHIN a
	// build. That does not help ACROSS builds: an attacker computes the digest
	// offline, names a component `m55.<digest>`, and a pre-M55 instance — one
	// mid-rolling-upgrade, or left pointed at the same Redis — keys it by the
	// raw name and lands on the exact key this build reads for the component
	// the digest stands for. NVD answers nothing for that nonsense keyword, so
	// this build then serves an empty, complete-looking result to every tenant
	// (this cache is global, not tenant-scoped) until the TTL expires.
	//
	// Bumping the prefix only closes that if the new prefix is NOT reachable
	// from the old one. `nvd:vuln:v2:` would NOT have worked: it is a
	// prefix-extension of `nvd:vuln:`, so a pre-M55 writer still reaches it by
	// scanning a component literally named `v2:m55.<digest>`. `nvdv2:` shares
	// no prefix with `nvd:vuln:` at all, so no component name lets the old code
	// path construct a key this build reads. That is what makes the two key
	// spaces disjoint rather than merely differently-spelled.
	//
	// Cost of the bump, stated: every entry written by an older build is
	// orphaned. Nothing reads them and nothing deletes them — Clear and
	// GetStats below scan this prefix only — so they expire on their own
	// NVDCacheTTL (24h). The first scan after an upgrade therefore refetches
	// from NVD instead of serving cache. That is the intended trade: a cold
	// cache for one TTL, against serving a poisoned empty answer for one.
	NVDCachePrefix = "nvdv2:"
)

// VulnCacheEntry represents cached vulnerability data for a component
type VulnCacheEntry struct {
	Vulnerabilities []CachedVuln `json:"vulnerabilities"`
	CachedAt        time.Time    `json:"cached_at"`
	// CVSSRule is the CVSS selection rule revision the entry's scores were
	// chosen under (M67). Set always stamps CVSSRuleCurrent; an entry written
	// by an older build decodes with 0 and the scanner re-fetches it rather
	// than create a catalogue row from a score internal/cvss never chose.
	CVSSRule int `json:"cvss_rule,omitempty"`
}

// CVSSRuleCurrent is the revision of internal/cvss.Select's rule. Bump it when
// that rule changes so cached scores chosen by the previous one are re-fetched.
const CVSSRuleCurrent = 1

// CachedVuln represents a cached vulnerability.
//
// M46 B2: CVSSScore / PublishedAt mirror model.Vulnerability's pointer
// fields so the cache preserves "un-scored" / "no timestamp" fidelity
// instead of flattening them to 0.0 / zero time. Old Redis entries
// (numeric 0 / zero-time JSON) still decode — they land as pointers to
// the old sentinel values, exactly what the old code stored.
type CachedVuln struct {
	CVEID       string   `json:"cve_id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CVSSScore   *float64 `json:"cvss_score,omitempty"`
	// CVSSVersion is the version of the chosen assessment (M67), written by
	// both the keyword and the CPE path; nil when no assessment was chosen.
	// Pre-M67 entries are refused by VulnCacheEntry.CVSSRule, not by this.
	CVSSVersion *string    `json:"cvss_version,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

// NVDCache provides caching for NVD API responses
type NVDCache struct {
	client *redis.Client
	ttl    time.Duration
}

// OpTimeout bounds each cache round trip (one GET / SET / DEL, or one SCAN
// page) regardless of the caller's context. The cache is an optimisation: the
// scanner treats any error as a miss and asks NVD, so a slow or hung Redis
// must produce that error quickly instead of stalling every component of a
// scan, whose own context may live for hours. It is shorter than
// redis.CommandTimeout (the API's bound for security bookkeeping) because a
// healthy Redis answers in milliseconds and a cache miss costs nothing but
// the NVD request that would happen anyway.
const OpTimeout = 1 * time.Second

// opContext also tags the call best-effort for the Redis circuit breaker
// (M72): a slow cache read fails the cache fast, it does not open the
// breaker of the rate limiters.
func opContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(sbomredis.WithBreakerClass(ctx, sbomredis.ClassBestEffort), OpTimeout)
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

	ctx, cancel := opContext(ctx)
	defer cancel()
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
		CVSSRule:        CVSSRuleCurrent,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	ctx, cancel := opContext(ctx)
	defer cancel()
	if err := c.client.Set(ctx, key, data, c.ttl).Err(); err != nil {
		return fmt.Errorf("redis set error: %w", err)
	}

	return nil
}

// Delete removes a cache entry
func (c *NVDCache) Delete(ctx context.Context, name, version string) error {
	key := c.cacheKey(name, version)
	ctx, cancel := opContext(ctx)
	defer cancel()
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
		opCtx, cancel := opContext(ctx)
		keys, nextCursor, err := c.client.Scan(opCtx, cursor, NVDCachePrefix+"*", 100).Result()
		cancel()
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
		opCtx, cancel := opContext(ctx)
		keys, nextCursor, err := c.client.Scan(opCtx, cursor, NVDCachePrefix+"*", 100).Result()
		if err == nil && len(keys) > 0 {
			err = c.client.Del(opCtx, keys...).Err()
		}
		cancel()
		if err != nil {
			return err
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}
