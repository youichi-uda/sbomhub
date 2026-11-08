// Package redis builds the API's go-redis client with explicit, bounded
// timeouts.
package redis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Timeouts applied when REDIS_URL does not set them. REDIS_URL accepts
// go-redis's own query parameters (dial_timeout, read_timeout, write_timeout,
// pool_timeout, e.g. redis://redis:6379/0?read_timeout=1s), and a value set
// there wins; these are only the defaults. They are tighter than go-redis's
// implicit ones (5s dial / 5s read / read+1s pool): every key the API keeps
// in Redis is a small counter, lease or cache entry, so a healthy server
// answers in milliseconds and a reply that takes seconds means it is hung.
const (
	DefaultDialTimeout  = 3 * time.Second
	DefaultReadTimeout  = 2 * time.Second
	DefaultWriteTimeout = 2 * time.Second
	// DefaultPoolTimeout bounds the wait for a free pooled connection when
	// every connection is busy (for example all stuck on a hung server).
	DefaultPoolTimeout = 3 * time.Second
)

// CommandTimeout bounds one logical Redis operation at a call site
// (CommandContext), retries included, independent of the caller's context.
// Request contexts have no deadline of their own, and a scan's context lives
// for the whole scan, so the call sites must not rely on them.
const CommandTimeout = 3 * time.Second

// StartupPingTimeout bounds the connectivity check NewClient makes. A Redis
// that is unreachable or hung at boot fails startup within this.
const StartupPingTimeout = 5 * time.Second

// Options parses redisURL and fills in explicit timeouts for anything the URL
// leaves unset. ContextTimeoutEnabled is always on: without it go-redis
// ignores a context's deadline for socket I/O and only the read/write
// timeouts apply, so CommandContext (and any caller's deadline) would not
// actually shorten a hung call.
//
// A negative value in the URL (go-redis's "-1 = no timeout") is respected;
// call sites still bound each operation with CommandContext.
func Options(redisURL string) (*redis.Options, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis url: %w", err)
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = DefaultDialTimeout
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = DefaultReadTimeout
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = DefaultWriteTimeout
	}
	if opts.PoolTimeout == 0 {
		opts.PoolTimeout = DefaultPoolTimeout
	}
	// No automatic retries. go-redis replays a command whose reply was lost
	// (EOF, reset) up to 3 times by default, and the commands the API sends
	// that matter — INCR and the public-link Lua scripts — are not
	// idempotent: a replay after Redis executed the command charged one
	// request several times (Codex R1 Medium). Every caller already handles
	// an error (fail closed, or cache miss). A max_retries in the URL is kept.
	if opts.MaxRetries == 0 && !strings.Contains(redisURL, "max_retries=") {
		opts.MaxRetries = -1
	}
	opts.ContextTimeoutEnabled = true
	return opts, nil
}

// NewClient builds the client from Options and checks connectivity, giving up
// after StartupPingTimeout.
func NewClient(redisURL string) (*redis.Client, error) {
	opts, err := Options(redisURL)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), StartupPingTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}
	return client, nil
}

// CommandContext derives the context for one Redis operation: the parent's
// values and cancellation, and a deadline at most CommandTimeout away.
func CommandContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, CommandTimeout)
}
