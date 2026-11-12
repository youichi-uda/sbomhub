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
	// DataModified is the data's own revision (fixed-width UTC RFC 3339).
	DataModified string `json:"data_modified"`
	// Generation orders writes: a value from NextGeneration taken when the
	// fetch STARTED (a Redis INCR, so it is monotonic across replicas, as a
	// fixed-width decimal string, so Lua compares it without float loss).
	// Set never replaces an entry of a later generation: a fetch that began
	// earlier but finished later cannot leave its older answer cached
	// (Codex M70 R8 High-4, R9 High-2, R10 Medium-4). "" is the oldest.
	Generation string `json:"generation"`
}

// distroSetIfNotNewer writes ARGV[1] (data revision ARGV[4], generation
// ARGV[2]) unless the stored entry has a HIGHER data revision, or the same
// revision and a later generation: a later fetch that saw older data (a
// lagging replica) never replaces newer data; generation only breaks ties
// (Codex M70 R16 High-2). Both are fixed-width strings ("" is the lowest).
var distroSetIfNotNewer = redis.NewScript(`
-- KEYS[2]: the newest generation any COMPLETED fetch of this package
-- started at, whatever its revision (Codex M70 R43 High-1).
local lg = redis.call('GET', KEYS[2])
if (not lg) or ARGV[2] > lg then
  redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3])
end
local cur = redis.call('GET', KEYS[1])
if cur then
  local ok, obj = pcall(cjson.decode, cur)
  if ok and type(obj) == 'table' then
    local dm = obj['data_modified']
    local gen = obj['generation']
    if type(dm) ~= 'string' then dm = '' end
    if type(gen) ~= 'string' then gen = '' end
    if dm > ARGV[4] then
      -- A completed observation with a LOWER revision (a withdrawal) makes
      -- the kept payload doubtful whatever the fetch order: it is dropped,
      -- so the next read fetches again (Codex M70 R49 High-1).
      redis.call('DEL', KEYS[1])
      return 0
    end
    if dm == ARGV[4] and gen > ARGV[2] then return 0 end
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
-- the fence lives at least as long as the payload it fences
redis.call('PEXPIRE', KEYS[2], ARGV[3])
return 1`)

// distroGet reads an entry (at most ARGV[1]+1 bytes) and its fence in one
// command: {payload ("" when absent), fence (nil when absent)}.
var distroGet = redis.NewScript(`
local d = redis.call('GETRANGE', KEYS[1], 0, ARGV[1])
local lg = redis.call('GET', KEYS[2])
return {d, lg}`)

// DistroCacheKey is the Redis key of (source, ecosystem, name). source is the
// data source's endpoint (SBOMHUB_OSV_URL): two deployments pointed at
// different mirrors share no entry (Codex M70 R2 Medium-6). A trailing '/' is
// not part of the identity.
func DistroCacheKey(source, ecosystem, name string) string {
	source = strings.TrimRight(strings.TrimSpace(source), "/")
	sum := sha256.Sum256([]byte(strconv.Itoa(len(source)) + ":" + source +
		strconv.Itoa(len(ecosystem)) + ":" + ecosystem + name))
	// A hash tag keeps the entry and its latest-generation key in one slot.
	return DistroCachePrefix + "{" + hex.EncodeToString(sum[:]) + "}"
}

// distroLatestGenKey holds the newest completed fetch generation of the
// package keyed by entryKey.
func distroLatestGenKey(entryKey string) string {
	return entryKey + ":lg"
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
	// longer than the bound is a miss. The payload and its fence are read in
	// ONE command (M72, Codex M72 R11 Medium-2): as two, a fast payload read
	// reset the Redis circuit breaker's failure count every time before the
	// fence read timed out, so a cache failing every lookup never opened it.
	key := DistroCacheKey(source, ecosystem, name)
	res, err := distroGet.Run(ctx, c.client, []string{key, distroLatestGenKey(key)}, DistroCacheMaxBytes).Slice()
	if err != nil {
		return nil, fmt.Errorf("redis distro get error: %w", err)
	}
	if len(res) != 2 {
		return nil, fmt.Errorf("redis distro get: unexpected reply of %d values", len(res))
	}
	data, _ := res[0].(string)
	if len(data) == 0 || len(data) > DistroCacheMaxBytes {
		return nil, nil
	}
	var e DistroCacheEntry
	if err := json.Unmarshal([]byte(data), &e); err != nil || e.FetchedAt.IsZero() || len(e.Payload) == 0 {
		return nil, nil
	}
	// Kept by revision, but superseded when a LATER fetch completed with
	// other data (a withdrawal lowers the revision): then it is a miss and
	// the package is read again (Codex M70 R43 High-1).
	lg, ok := res[1].(string)
	if !ok {
		// No fence (evicted, or expired): whether a later fetch saw other
		// data is unknown, so it is a miss (Codex M70 R44 High-1).
		return nil, nil
	}
	if lg > e.Generation {
		return nil, nil
	}
	return &e, nil
}

// distroGenerationKey is the shared sequence of fetch generations.
const distroGenerationKey = DistroCachePrefix + "generation"

// NextGeneration returns the next fetch generation (a Redis INCR), as a
// fixed-width decimal string; "" when there is no cache or Redis fails.
func (c *DistroCache) NextGeneration(ctx context.Context) string {
	if c == nil || c.client == nil {
		return ""
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	n, err := c.client.Incr(ctx, distroGenerationKey).Result()
	if err != nil || n < 0 {
		return ""
	}
	return fmt.Sprintf("%020d", n)
}

// Set stores an entry. won is false when the stored entry was newer and was
// kept: the caller must then use THAT entry, not its own (Codex M70 R21
// High-1).
func (c *DistroCache) Set(ctx context.Context, source, ecosystem, name string, e DistroCacheEntry) (won bool, err error) {
	if c == nil || c.client == nil {
		return true, nil
	}
	data, err := json.Marshal(e)
	if err != nil {
		return false, fmt.Errorf("failed to marshal distro cache entry: %w", err)
	}
	if len(data) > DistroCacheMaxBytes {
		return false, fmt.Errorf("distro cache entry of %d bytes exceeds %d", len(data), DistroCacheMaxBytes)
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	key := DistroCacheKey(source, ecosystem, name)
	n, err := distroSetIfNotNewer.Run(ctx, c.client, []string{key, distroLatestGenKey(key)},
		data, e.Generation, c.ttl.Milliseconds(), e.DataModified).Int()
	if err != nil {
		return false, fmt.Errorf("redis set error: %w", err)
	}
	return n == 1, nil
}
