package redis

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/sbomhub/sbomhub/internal/redis/redistest"
)

func TestOptions_ExplicitTimeoutsWhenURLHasNone(t *testing.T) {
	opts, err := Options("redis://localhost:6379/0")
	if err != nil {
		t.Fatal(err)
	}
	if opts.DialTimeout != DefaultDialTimeout || opts.ReadTimeout != DefaultReadTimeout ||
		opts.WriteTimeout != DefaultWriteTimeout || opts.PoolTimeout != DefaultPoolTimeout {
		t.Fatalf("timeouts dial=%v read=%v write=%v pool=%v, want %v/%v/%v/%v",
			opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout, opts.PoolTimeout,
			DefaultDialTimeout, DefaultReadTimeout, DefaultWriteTimeout, DefaultPoolTimeout)
	}
	if !opts.ContextTimeoutEnabled {
		t.Fatal("ContextTimeoutEnabled must be on, or a caller's context deadline is ignored by the socket I/O")
	}
}

// REDIS_URL query parameters (go-redis's own syntax) still win, so an
// operator who already tuned them keeps their values.
func TestOptions_URLValuesWin(t *testing.T) {
	opts, err := Options("redis://localhost:6379/0?dial_timeout=7s&read_timeout=9s&write_timeout=4s&pool_timeout=11s")
	if err != nil {
		t.Fatal(err)
	}
	if opts.DialTimeout != 7*time.Second || opts.ReadTimeout != 9*time.Second ||
		opts.WriteTimeout != 4*time.Second || opts.PoolTimeout != 11*time.Second {
		t.Fatalf("URL values not kept: dial=%v read=%v write=%v pool=%v",
			opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout, opts.PoolTimeout)
	}
	if !opts.ContextTimeoutEnabled {
		t.Fatal("ContextTimeoutEnabled must be on regardless of the URL")
	}
}

// A hung Redis at boot must fail startup promptly, not after go-redis's
// default 5s read timeout times its retries.
func TestNewClient_BlackHoledRedisFailsFast(t *testing.T) {
	url := redistest.BlackHole(t)
	start := time.Now()
	c, err := NewClient(url)
	elapsed := time.Since(start)
	if err == nil {
		_ = c.Close()
		t.Fatal("NewClient succeeded against a Redis that never answers")
	}
	if elapsed > StartupPingTimeout+2*time.Second {
		t.Fatalf("NewClient took %v to give up (bound %v)", elapsed, StartupPingTimeout)
	}
}

// One command under CommandContext gives up within CommandTimeout even when
// the caller's own context has no deadline.
func TestCommandContext_BoundsAHungCommand(t *testing.T) {
	opts, err := Options(redistest.BlackHole(t))
	if err != nil {
		t.Fatal(err)
	}
	c := goredis.NewClient(opts)
	defer c.Close()

	ctx, cancel := CommandContext(context.Background())
	defer cancel()
	start := time.Now()
	err = c.Get(ctx, "k").Err()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("GET against a black hole succeeded")
	}
	if elapsed > CommandTimeout+time.Second {
		t.Fatalf("GET took %v (bound %v)", elapsed, CommandTimeout)
	}
}
