package redis

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
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

// Codex R1 Medium: go-redis retries a command whose reply was lost (EOF /
// connection reset) up to MaxRetries times — 3 by default. INCR and the
// public-link Lua scripts are not idempotent, so a reply lost after Redis
// executed the command charged one request several times. The API's client
// does not retry.
func TestOptions_NoAutomaticRetries(t *testing.T) {
	var (
		mu    sync.Mutex
		incrs int
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					// Read one RESP array command: *N then N bulk strings.
					head, err := r.ReadString('\n')
					if err != nil || !strings.HasPrefix(head, "*") {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(head[1:]))
					var args []string
					for i := 0; i < n; i++ {
						if _, err := r.ReadString('\n'); err != nil { // $len
							return
						}
						a, err := r.ReadString('\n')
						if err != nil {
							return
						}
						args = append(args, strings.TrimSpace(a))
					}
					if len(args) > 0 && strings.EqualFold(args[0], "INCR") {
						mu.Lock()
						incrs++
						mu.Unlock()
						return // "executed", reply lost: close without answering
					}
					if len(args) > 0 && strings.EqualFold(args[0], "CLIENT") {
						_, _ = c.Write([]byte("+OK\r\n")) // CLIENT SETNAME / SETINFO
						continue
					}
					_, _ = c.Write([]byte("-ERR unknown command\r\n"))
				}
			}(c)
		}
	}()

	// The second URL carries "max_retries=" only inside another option's
	// value (Codex R2 Medium): it must not count as an explicit setting.
	for _, u := range []string{
		"redis://" + ln.Addr().String(),
		"redis://" + ln.Addr().String() + "?client_name=max_retries=",
	} {
		mu.Lock()
		incrs = 0
		mu.Unlock()
		opts, err := Options(u)
		if err != nil {
			t.Fatal(err)
		}
		c := goredis.NewClient(opts)
		ctx, cancel := CommandContext(context.Background())
		if err := c.Incr(ctx, "k").Err(); err == nil {
			t.Fatalf("%s: INCR with a lost reply reported success", u)
		}
		cancel()
		_ = c.Close()
		mu.Lock()
		n := incrs
		mu.Unlock()
		if n != 1 {
			t.Fatalf("%s: INCR reached the server %d times for one call, want 1 (no automatic retry)", u, n)
		}
	}
}
