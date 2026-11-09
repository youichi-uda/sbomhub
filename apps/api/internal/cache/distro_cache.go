package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Distro fixed-version cache (M70).
//
// One entry per OSV package query (ecosystem, package name), holding the
// reduced answer the distro step needs. Like the NVD cache it is GLOBAL (not
// tenant-scoped): the package name comes from an uploaded SBOM, so the key is a
// length-prefixed SHA-256 of the pair under its own prefix, and no other key
// space of this or an older build (`nvd:vuln:`, `nvdv2:`) shares a prefix with
// it. Only this build writes the entries, and only from an OSV answer that
// decoded completely; a tenant can make an answer be CACHED, never make one up.
//
// The cache is an optimisation: every error is a miss, every round trip is
// bounded by OpTimeout (M64), and a stale entry can at worst carry yesterday's
// distro data.
const (
	// DistroCachePrefix is the key prefix of this cache. Bump the version when
	// the entry format changes so an older build's entries are never read.
	DistroCachePrefix = "distro1:"
	// DistroCacheTTL matches NVDCacheTTL.
	DistroCacheTTL = 24 * time.Hour
	// DistroCacheMaxBytes bounds an entry read back: a larger value (not one
	// this build writes — a reduced Debian "linux" answer is a few MB) is a
	// miss, never decoded.
	DistroCacheMaxBytes = 32 << 20
)

// DistroCache stores reduced OSV package answers.
type DistroCache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewDistroCache returns a cache on client (nil client: every Get misses and
// every Set is a no-op).
func NewDistroCache(client *redis.Client) *DistroCache {
	return &DistroCache{client: client, ttl: DistroCacheTTL}
}

// DistroCacheEntry is one cached package answer. Payload is opaque here (the
// service owns its format); FetchedAt is when OSV answered.
type DistroCacheEntry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Payload   json.RawMessage `json:"payload"`
}

// DistroCacheKey is the Redis key of (source, ecosystem, name). source is the
// data source's endpoint (SBOMHUB_OSV_URL): two deployments pointed at
// different mirrors share no entry (Codex M70 R2 Medium-6). A trailing '/' is
// not part of the identity.
func DistroCacheKey(source, ecosystem, name string) string {
	source = strings.TrimRight(strings.TrimSpace(source), "/")
	sum := sha256.Sum256([]byte(strconv.Itoa(len(source)) + ":" + source +
		strconv.Itoa(len(ecosystem)) + ":" + ecosystem + name))
	return DistroCachePrefix + hex.EncodeToString(sum[:])
}

// Get returns the entry, or (nil, nil) on a miss or an undecodable entry.
func (c *DistroCache) Get(ctx context.Context, source, ecosystem, name string) (*DistroCacheEntry, error) {
	if c == nil || c.client == nil {
		return nil, nil
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	// One bounded read (Codex M70 R4 Medium-4): GETRANGE returns at most
	// DistroCacheMaxBytes+1 bytes whatever the stored value is, and a value
	// longer than the bound is a miss.
	data, err := c.client.GetRange(ctx, DistroCacheKey(source, ecosystem, name), 0, DistroCacheMaxBytes).Bytes()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("redis getrange error: %w", err)
	}
	if len(data) == 0 || len(data) > DistroCacheMaxBytes {
		return nil, nil
	}
	var e DistroCacheEntry
	if err := json.Unmarshal(data, &e); err != nil || e.FetchedAt.IsZero() || len(e.Payload) == 0 {
		return nil, nil
	}
	return &e, nil
}

// Set stores an entry.
func (c *DistroCache) Set(ctx context.Context, source, ecosystem, name string, e DistroCacheEntry) error {
	if c == nil || c.client == nil {
		return nil
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to marshal distro cache entry: %w", err)
	}
	if len(data) > DistroCacheMaxBytes {
		return fmt.Errorf("distro cache entry of %d bytes exceeds %d", len(data), DistroCacheMaxBytes)
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	if err := c.client.Set(ctx, DistroCacheKey(source, ecosystem, name), data, c.ttl).Err(); err != nil {
		return fmt.Errorf("redis set error: %w", err)
	}
	return nil
}
