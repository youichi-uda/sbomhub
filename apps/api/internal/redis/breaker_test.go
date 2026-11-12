package redis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
func newFakeClock() *fakeClock           { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func timeoutErr() error                  { return &net.OpError{Op: "read", Err: errTimeout{}} }
func (errTimeout) Error() string         { return "i/o timeout" }
func (errTimeout) Timeout() bool         { return true }
func (errTimeout) Temporary() bool       { return true }

type errTimeout struct{}

// replyErr is an error reply (go-redis's proto.RedisError is internal).
type replyErr string

func (e replyErr) Error() string { return string(e) }
func (replyErr) RedisError()     {}

func newTestBreaker(t *testing.T, clk *fakeClock, buf *bytes.Buffer) *Breaker {
	t.Helper()
	var log *slog.Logger
	if buf != nil {
		log = slog.New(slog.NewJSONHandler(buf, nil))
	}
	return NewBreaker(BreakerConfig{FailureThreshold: 3, Cooldown: 10 * time.Second, Now: clk.Now, Logger: log})
}

// call runs one admitted call with the given result, or reports refusal.
func call(b *Breaker, err error) error {
	t, aerr := b.allow()
	if aerr != nil {
		return aerr
	}
	b.record(t, classify(context.Background(), err))
	return err
}

func TestBreaker_OpensAfterThresholdConsecutiveFailures(t *testing.T) {
	clk := newFakeClock()
	var buf bytes.Buffer
	b := newTestBreaker(t, clk, &buf)

	_ = call(b, timeoutErr())
	_ = call(b, timeoutErr())
	if b.State() != BreakerClosed {
		t.Fatalf("2 failures (threshold 3): state %v, want closed", b.State())
	}
	// A success resets the count: failures must be consecutive.
	_ = call(b, nil)
	_ = call(b, timeoutErr())
	_ = call(b, timeoutErr())
	if b.State() != BreakerClosed {
		t.Fatalf("success between failures must reset the count: state %v", b.State())
	}
	_ = call(b, timeoutErr())
	if b.State() != BreakerOpen {
		t.Fatalf("3rd consecutive failure: state %v, want open", b.State())
	}
	if err := call(b, nil); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("call while open: %v, want ErrCircuitOpen", err)
	}
	if !strings.Contains(buf.String(), `"to":"open"`) {
		t.Fatalf("open transition not logged: %s", buf.String())
	}
}

func TestBreaker_HalfOpenAdmitsExactlyOneProbe(t *testing.T) {
	clk := newFakeClock()
	b := newTestBreaker(t, clk, nil)
	for i := 0; i < 3; i++ {
		_ = call(b, timeoutErr())
	}
	clk.Add(9 * time.Second)
	if _, err := b.allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("before the cool-down: %v, want ErrCircuitOpen", err)
	}
	clk.Add(time.Second)
	if b.State() != BreakerHalfOpen {
		t.Fatalf("after the cool-down: state %v, want half_open", b.State())
	}
	probe, err := b.allow()
	if err != nil || !probe.probe {
		t.Fatalf("first call after the cool-down must be the probe: %+v %v", probe, err)
	}
	// While the probe is in flight every other call fails fast.
	for i := 0; i < 5; i++ {
		if _, err := b.allow(); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("second call during the probe: %v, want ErrCircuitOpen", err)
		}
	}
	b.record(probe, outcomeSuccess)
	if b.State() != BreakerClosed {
		t.Fatalf("probe success: state %v, want closed", b.State())
	}
	if err := call(b, nil); err != nil {
		t.Fatalf("closed again: %v", err)
	}
}

func TestBreaker_FailedProbeReopensForAnotherCooldown(t *testing.T) {
	clk := newFakeClock()
	b := newTestBreaker(t, clk, nil)
	for i := 0; i < 3; i++ {
		_ = call(b, timeoutErr())
	}
	clk.Add(10 * time.Second)
	if err := call(b, timeoutErr()); err == nil || errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("the probe must be admitted and fail: %v", err)
	}
	if b.State() != BreakerOpen {
		t.Fatalf("failed probe: state %v, want open", b.State())
	}
	clk.Add(9 * time.Second)
	if err := call(b, nil); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("a new cool-down starts at the failed probe: %v", err)
	}
	clk.Add(time.Second)
	if err := call(b, nil); err != nil {
		t.Fatalf("second probe: %v", err)
	}
	if b.State() != BreakerClosed {
		t.Fatalf("state %v, want closed", b.State())
	}
}

func TestBreaker_NeutralProbeReleasesTheSlot(t *testing.T) {
	clk := newFakeClock()
	b := newTestBreaker(t, clk, nil)
	for i := 0; i < 3; i++ {
		_ = call(b, timeoutErr())
	}
	clk.Add(10 * time.Second)
	probe, err := b.allow()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.record(probe, classify(ctx, context.Canceled))
	if b.State() != BreakerHalfOpen {
		t.Fatalf("a cancelled probe proves nothing: state %v, want half_open", b.State())
	}
	if p2, err := b.allow(); err != nil || !p2.probe {
		t.Fatalf("the next call must probe: %+v %v", p2, err)
	}
}

func TestBreaker_StaleAnswerFromBeforeATransitionIsIgnored(t *testing.T) {
	clk := newFakeClock()
	b := newTestBreaker(t, clk, nil)
	slow, _ := b.allow() // admitted while closed, answers late
	for i := 0; i < 3; i++ {
		_ = call(b, timeoutErr())
	}
	b.record(slow, outcomeSuccess)
	if b.State() != BreakerOpen {
		t.Fatalf("a late success admitted before the breaker opened must not close it: %v", b.State())
	}
}

func TestClassify(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	bg := context.Background()
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want outcome
	}{
		{"nil", bg, nil, outcomeSuccess},
		{"redis.Nil", bg, goredis.Nil, outcomeSuccess},
		{"error reply", bg, replyErr("NOSCRIPT No matching script"), outcomeSuccess},
		{"wrapped error reply", bg, fmt.Errorf("x: %w", replyErr("WRONGTYPE")), outcomeSuccess},
		{"i/o timeout", bg, timeoutErr(), outcomeFailure},
		{"refused", bg, &net.OpError{Op: "dial", Err: errors.New("connection refused")}, outcomeFailure},
		{"deadline", bg, context.DeadlineExceeded, outcomeFailure},
		{"pool timeout", bg, errors.New("redis: connection pool timeout"), outcomeFailure},
		{"caller cancelled", cancelled, context.Canceled, outcomeNeutral},
		{"client closed", bg, goredis.ErrClosed, outcomeNeutral},
		{"breaker", bg, ErrCircuitOpen, outcomeNeutral},
	}
	for _, c := range cases {
		if got := classify(c.ctx, c.err); got != c.want {
			t.Errorf("%s: classify = %v, want %v", c.name, got, c.want)
		}
	}
}

// scriptedServer is an inner go-redis hook standing in for the server: it
// answers every command with the current error (nil = OK) and counts calls.
type scriptedServer struct {
	err   atomic.Pointer[error]
	calls atomic.Int64
}

func (s *scriptedServer) set(err error)                                   { s.err.Store(&err) }
func (s *scriptedServer) DialHook(next goredis.DialHook) goredis.DialHook { return next }
func (s *scriptedServer) ProcessHook(goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		s.calls.Add(1)
		err := *s.err.Load()
		cmd.SetErr(err)
		return err
	}
}
func (s *scriptedServer) ProcessPipelineHook(goredis.ProcessPipelineHook) goredis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []goredis.Cmder) error {
		s.calls.Add(1)
		return *s.err.Load()
	}
}

// TestBreakerHook_ClientFailsFastWithoutReachingTheServer drives the hook on a
// real go-redis client: once open, commands, scripts and pipelines return
// ErrCircuitOpen without reaching the (scripted) server.
func TestBreakerHook_ClientFailsFastWithoutReachingTheServer(t *testing.T) {
	clk := newFakeClock()
	b := newTestBreaker(t, clk, nil)
	c := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = c.Close() })
	srv := &scriptedServer{}
	srv.set(timeoutErr())
	c.AddHook(b.Hook()) // outer
	c.AddHook(srv)      // inner: the "server"
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := c.Get(ctx, "k").Err(); err == nil || errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("call %d: %v, want a timeout", i, err)
		}
	}
	before := srv.calls.Load()
	if err := c.Get(ctx, "k").Err(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("GET while open: %v", err)
	}
	if err := goredis.NewScript("return 1").Run(ctx, c, []string{"k"}).Err(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("script while open: %v", err)
	}
	_, err := c.Pipelined(ctx, func(p goredis.Pipeliner) error { p.Incr(ctx, "k"); return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("pipeline while open: %v", err)
	}
	if got := srv.calls.Load(); got != before {
		t.Fatalf("server reached %d times while open", got-before)
	}

	srv.set(nil)
	clk.Add(10 * time.Second)
	if err := c.Set(ctx, "k", "v", 0).Err(); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if b.State() != BreakerClosed {
		t.Fatalf("state %v, want closed", b.State())
	}
}

// TestBreakerHook_NestedCallOfAnAdmittedCallIsNotRefused: a probe that must dial runs the
// connection handshake through the same hooks; the breaker must not refuse its
// own probe's handshake. Against a black-holed listener the probe fails as a
// timeout, never as ErrCircuitOpen.
func TestBreakerHook_NestedCallOfAnAdmittedCallIsNotRefused(t *testing.T) {
	clk := newFakeClock()
	b := newTestBreaker(t, clk, nil)
	for i := 0; i < 3; i++ {
		_ = call(b, timeoutErr())
	}
	clk.Add(10 * time.Second)
	var inner error
	h := b.Hook().ProcessHook(func(ctx context.Context, cmd goredis.Cmder) error {
		// What go-redis's initConn does: a handshake command through the
		// same hook chain, with the outer call's context.
		inner = b.Hook().ProcessHook(func(context.Context, goredis.Cmder) error { return nil })(ctx, goredis.NewCmd(ctx, "hello"))
		return nil
	})
	if err := h(context.Background(), goredis.NewCmd(context.Background(), "get", "k")); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if inner != nil {
		t.Fatalf("the probe's own handshake was refused: %v", inner)
	}
	if b.State() != BreakerClosed {
		t.Fatalf("state %v, want closed", b.State())
	}
}

// A slow best-effort caller (a cache read timing out on a large value) opens
// only the best-effort breaker; the rate limiters' default class stays closed.
func TestBreakers_ClassesOpenIndependently(t *testing.T) {
	clk := newFakeClock()
	bs := NewBreakers(BreakerConfig{FailureThreshold: 3, Cooldown: 10 * time.Second, Now: clk.Now})
	c := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = c.Close() })
	srv := &scriptedServer{}
	srv.set(timeoutErr())
	c.AddHook(bs.Hook())
	c.AddHook(srv)
	cacheCtx := WithBreakerClass(context.Background(), ClassBestEffort)
	for i := 0; i < 3; i++ {
		_ = c.Get(cacheCtx, "k").Err()
	}
	if bs.Class(ClassBestEffort).State() != BreakerOpen {
		t.Fatalf("best-effort breaker: %v, want open", bs.Class(ClassBestEffort).State())
	}
	if bs.Class(ClassDefault).State() != BreakerClosed {
		t.Fatalf("default breaker: %v, want closed", bs.Class(ClassDefault).State())
	}
	srv.set(nil)
	if err := c.Incr(context.Background(), "k").Err(); err != nil {
		t.Fatalf("rate-limit call while only the cache breaker is open: %v", err)
	}
	if err := c.Get(cacheCtx, "k").Err(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("cache call: %v, want ErrCircuitOpen", err)
	}
}

// Codex M72 R1 Medium-7: the scan-status store has its own class, so slow
// cache reads cannot keep its lease renewals failing fast.
func TestBreakers_StatusClassIsSeparateFromTheCaches(t *testing.T) {
	bs := NewBreakers(BreakerConfig{FailureThreshold: 1})
	if bs.Class(ClassStatus) == bs.Class(ClassBestEffort) || bs.Class(ClassStatus) == bs.Class(ClassDefault) {
		t.Fatal("ClassStatus shares a breaker")
	}
}
