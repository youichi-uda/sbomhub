package redis

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Circuit breaker around the API's Redis client (M72).
//
// M64 bounded every Redis operation (dial 3s, read/write 2s, pool 3s; 1s per
// cache round trip, 3s for rate-limit bookkeeping) and turned retries off. That
// bounds a hung or unreachable Redis, but every call still PAYS the bound: a
// scan of N components with Redis black-holed spent N x 1s on cache misses, and
// every rate-limited request waited ~3s before its 500/503. The breaker makes
// that cost paid once per cool-down instead of once per call:
//
//   - closed: calls go through. FailureThreshold consecutive failures open it.
//   - open: every call fails at once with ErrCircuitOpen (no socket I/O) until
//     Cooldown has passed.
//   - half-open: exactly one call (the probe) goes through; every other call
//     still fails at once. The probe's success closes the breaker, its failure
//     opens it for another Cooldown.
//
// It is installed as a go-redis hook (Hook), so every caller of the shared
// client — the NVD and distro caches, both rate limiters, the scan-status
// store — goes through it without code of its own; what each caller does with
// the error is unchanged (see docs/UPGRADE.md §25).
//
// What counts as a failure: anything that says the server could not be talked
// to — a dial/read/write error, a timeout (the call's own deadline), a pool
// timeout. NOT a failure: a reply (redis.Nil, or any error reply such as
// NOSCRIPT or WRONGTYPE: the server answered), a call whose caller cancelled it
// (context.Canceled while the caller's context is done), and a call on a closed
// client. Neutral outcomes neither reset nor advance the count.

// ErrCircuitOpen is returned, without any network I/O, for a call made while
// the breaker is open (or half-open with its probe in flight).
var ErrCircuitOpen = errors.New("redis: circuit breaker open")

// Breaker defaults (SBOMHUB_REDIS_BREAKER_THRESHOLD / _COOLDOWN).
const (
	DefaultBreakerThreshold = 5
	DefaultBreakerCooldown  = 5 * time.Second
	DefaultBreakerSlowCall  = 1 * time.Second
)

// BreakerState is the breaker's state.
type BreakerState int

const (
	BreakerClosed BreakerState = iota
	BreakerOpen
	BreakerHalfOpen
)

func (s BreakerState) String() string {
	switch s {
	case BreakerClosed:
		return "closed"
	case BreakerOpen:
		return "open"
	case BreakerHalfOpen:
		return "half_open"
	}
	return "unknown"
}

// BreakerConfig configures a Breaker. Zero values take the defaults.
type BreakerConfig struct {
	// FailureThreshold consecutive failures open the breaker.
	FailureThreshold int
	// Cooldown is how long the breaker stays open before a probe.
	Cooldown time.Duration
	// SlowCall: an answer that took at least this long counts as a failure
	// (Codex M72 R12 Medium-3). A healthy Redis answers in milliseconds; one
	// answering each command in a second or more fails every multi-command
	// caller's deadline while its single successes kept resetting the count.
	SlowCall time.Duration
	// Now is the clock (tests); nil is time.Now.
	Now func() time.Time
	// Logger receives the state transitions; nil is slog.Default().
	Logger *slog.Logger
}

// Breaker is a consecutive-failure circuit breaker. It is safe for concurrent
// use.
type Breaker struct {
	threshold int
	cooldown  time.Duration
	slowCall  time.Duration
	now       func() time.Time
	log       *slog.Logger

	mu       sync.Mutex
	state    BreakerState
	failures int
	openedAt time.Time
	// epoch increments on every transition. A call records its outcome only
	// if no transition happened since it was admitted, so a late answer to a
	// call admitted while closed cannot close a breaker that has opened since,
	// nor count against the next closed period.
	epoch uint64
	// probing: in half-open, the probe has been admitted and not finished.
	probing bool
	// rejected counts calls failed fast since the breaker last opened (for
	// the closing log line).
	rejected uint64
}

// NewBreaker returns a closed breaker.
func NewBreaker(cfg BreakerConfig) *Breaker {
	b := &Breaker{threshold: cfg.FailureThreshold, cooldown: cfg.Cooldown, slowCall: cfg.SlowCall, now: cfg.Now, log: cfg.Logger}
	if b.slowCall <= 0 {
		b.slowCall = DefaultBreakerSlowCall
	}
	if b.threshold <= 0 {
		b.threshold = DefaultBreakerThreshold
	}
	if b.cooldown <= 0 {
		b.cooldown = DefaultBreakerCooldown
	}
	if b.now == nil {
		b.now = time.Now
	}
	if b.log == nil {
		b.log = slog.Default()
	}
	return b
}

// State returns the current state. An open breaker whose cool-down has passed
// reads half_open (the next call is the probe).
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == BreakerOpen && !b.now().Before(b.openedAt.Add(b.cooldown)) {
		return BreakerHalfOpen
	}
	return b.state
}

// ticket is an admitted call.
type ticket struct {
	epoch uint64
	probe bool
	start time.Time
}

// allow admits a call or refuses it with ErrCircuitOpen.
func (b *Breaker) allow() (ticket, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case BreakerClosed:
		return ticket{epoch: b.epoch, start: b.now()}, nil
	case BreakerOpen:
		if b.now().Before(b.openedAt.Add(b.cooldown)) {
			b.rejected++
			return ticket{}, ErrCircuitOpen
		}
		b.transition(BreakerHalfOpen, "cool-down elapsed; probing with one call")
		fallthrough
	default: // half-open
		if b.probing {
			b.rejected++
			return ticket{}, ErrCircuitOpen
		}
		b.probing = true
		return ticket{epoch: b.epoch, probe: true, start: b.now()}, nil
	}
}

type outcome int

const (
	outcomeSuccess outcome = iota
	outcomeFailure
	outcomeNeutral
)

// record applies an admitted call's outcome.
func (b *Breaker) record(t ticket, o outcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if o == outcomeSuccess && !t.start.IsZero() && b.now().Sub(t.start) >= b.slowCall {
		o = outcomeFailure // answered, but too slowly to count as healthy
	}
	if t.epoch != b.epoch {
		return // admitted before a transition; its answer is stale
	}
	if t.probe {
		b.probing = false
		switch o {
		case outcomeSuccess:
			b.failures = 0
			b.transition(BreakerClosed, "probe succeeded")
		case outcomeFailure:
			b.openedAt = b.now()
			b.transition(BreakerOpen, "probe failed")
		}
		// neutral: the probe slot is released; the next call probes.
		return
	}
	switch o {
	case outcomeSuccess:
		b.failures = 0
	case outcomeFailure:
		b.failures++
		if b.state == BreakerClosed && b.failures >= b.threshold {
			b.openedAt = b.now()
			b.transition(BreakerOpen, "consecutive failures reached the threshold")
		}
	}
}

// transition changes state and logs it. b.mu is held.
func (b *Breaker) transition(to BreakerState, why string) {
	from := b.state
	b.state = to
	b.epoch++
	attrs := []any{"from", from.String(), "to", to.String(), "reason", why}
	switch to {
	case BreakerOpen:
		attrs = append(attrs, "consecutive_failures", b.failures, "cooldown", b.cooldown.String())
		b.rejected = 0
		b.log.Warn("redis circuit breaker opened: Redis calls fail fast until the cool-down ends", attrs...)
	case BreakerHalfOpen:
		b.log.Info("redis circuit breaker half-open", attrs...)
	case BreakerClosed:
		attrs = append(attrs, "rejected_while_open", b.rejected)
		b.rejected = 0
		b.log.Info("redis circuit breaker closed: Redis answered again", attrs...)
	}
	if to != BreakerHalfOpen {
		b.failures = 0
	}
}

// classify maps a call's error to an outcome. ctx is the context the call was
// made with.
func classify(ctx context.Context, err error) outcome {
	if err == nil || errors.Is(err, redis.Nil) {
		return outcomeSuccess
	}
	if errors.Is(err, ErrCircuitOpen) || errors.Is(err, redis.ErrClosed) {
		return outcomeNeutral
	}
	// An error REPLY: the server is there and answering — even if it
	// arrived as the call's deadline fired (Codex M72 R10 Low-2).
	var nerr net.Error
	var rerr redis.Error
	if errors.As(err, &rerr) && !errors.As(err, &nerr) {
		return outcomeSuccess
	}
	// The call's context ended. Only the call's OWN bound (ErrOpTimeout, set
	// by CommandContext / OpContext) says Redis did not answer in time; a
	// cancellation, or a deadline the call inherited (a scan's, a request's),
	// says nothing about Redis (Codex M72 R2 Low-5) — whatever error go-redis
	// reported for it (context error or socket timeout).
	if ctx.Err() != nil {
		if errors.Is(context.Cause(ctx), ErrOpTimeout) {
			return outcomeFailure
		}
		return outcomeNeutral
	}
	return outcomeFailure
}

// admittedKey marks a context whose call the breaker already admitted. go-redis
// runs a new connection's handshake (HELLO, CLIENT SETINFO) through the same
// hooks with the outer call's context; without the mark a half-open probe that
// has to dial would be refused by its own handshake.
type admittedKey struct{}

// Hook returns the go-redis hook that applies the breaker to every command and
// pipeline of the client it is added to (client.AddHook).
func (b *Breaker) Hook() redis.Hook {
	return breakerHook{pick: func(context.Context) *Breaker { return b }}
}

// BreakerClass separates callers whose failures must not open each other's
// breaker. The caches can be slowed by their own large values (a distro entry
// is up to 32 MB, read under a 1s bound) on a Redis that is otherwise fine;
// that must fail the CACHE fast, not turn every rate-limited request into a
// 500 for a cool-down. When Redis is really down every class sees the
// failures and opens on its own.
type BreakerClass int

const (
	// ClassDefault: security bookkeeping (rate limiters) and anything
	// untagged.
	ClassDefault BreakerClass = iota
	// ClassBestEffort: callers that treat every error as a miss (the NVD and
	// distro caches).
	ClassBestEffort
	// ClassStatus: the scan-status store. Its own class (Codex M72 R1
	// Medium-7): its calls are tiny and its leases must be renewed, so slow
	// cache reads must not keep it failing fast.
	ClassStatus
	numBreakerClasses
)

func (c BreakerClass) String() string {
	switch c {
	case ClassBestEffort:
		return "best_effort"
	case ClassStatus:
		return "status"
	}
	return "default"
}

type breakerClassKey struct{}

// WithBreakerClass tags ctx so the calls made with it use class's breaker.
func WithBreakerClass(ctx context.Context, class BreakerClass) context.Context {
	return context.WithValue(ctx, breakerClassKey{}, class)
}

// Breakers is one breaker per BreakerClass behind one hook.
type Breakers struct {
	byClass [numBreakerClasses]*Breaker
}

// NewBreakers returns one breaker per class, all configured by cfg.
func NewBreakers(cfg BreakerConfig) *Breakers {
	bs := &Breakers{}
	for c := range bs.byClass {
		cc := cfg
		log := cfg.Logger
		if log == nil {
			log = slog.Default()
		}
		cc.Logger = log.With("breaker_class", BreakerClass(c).String())
		bs.byClass[c] = NewBreaker(cc)
	}
	return bs
}

// Class returns class's breaker.
func (bs *Breakers) Class(c BreakerClass) *Breaker {
	if c < 0 || c >= numBreakerClasses {
		c = ClassDefault
	}
	return bs.byClass[c]
}

// Hook routes each call to the breaker of its context's class.
func (bs *Breakers) Hook() redis.Hook {
	return breakerHook{pick: func(ctx context.Context) *Breaker {
		c, _ := ctx.Value(breakerClassKey{}).(BreakerClass)
		return bs.Class(c)
	}}
}

type breakerHook struct {
	pick func(context.Context) *Breaker
}

func (h breakerHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h breakerHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if ctx.Value(admittedKey{}) != nil || ctx.Err() != nil {
			// Nested handshake of an admitted call, or a call whose context
			// is already over (go-redis fails it without I/O): not ours to
			// judge.
			return next(ctx, cmd)
		}
		b := h.pick(ctx)
		t, err := b.allow()
		if err != nil {
			cmd.SetErr(err)
			return err
		}
		err = next(context.WithValue(ctx, admittedKey{}, true), cmd)
		b.record(t, classify(ctx, err))
		return err
	}
}

func (h breakerHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if ctx.Value(admittedKey{}) != nil || ctx.Err() != nil {
			return next(ctx, cmds)
		}
		b := h.pick(ctx)
		t, err := b.allow()
		if err != nil {
			for _, c := range cmds {
				c.SetErr(err)
			}
			return err
		}
		err = next(context.WithValue(ctx, admittedKey{}, true), cmds)
		b.record(t, classify(ctx, err))
		return err
	}
}
