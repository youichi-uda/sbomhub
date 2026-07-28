//go:build integration

// Package middleware — M48 FO-6: the anonymous public-link routes had no
// brute-force budget.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M48PublicLink' ./internal/middleware
//
// -count=1 is load-bearing: live Redis state is not an input to go's test
// cache.
//
// # The finding
//
// GET /api/v1/public/:token and .../download are the only unauthenticated
// routes in the product that take a caller-supplied credential and do
// expensive work with it. (/api/v1/health is anonymous too but answers a
// constant; /api/webhooks/* is anonymous but verifies an HMAC.) When the link
// carries a password,
// service.PublicLinkService verifies it with
// bcrypt.CompareHashAndPassword — and nothing bounded how many times an
// anonymous caller could ask. That is two problems wearing one coat: an
// unlimited password oracle, and an unlimited supply of intentionally-slow
// hashes aimed at the API's CPU (bcrypt.DefaultCost, the cost the links are
// created with in service/public_link.go).
//
// These tests drive the real middleware against the real Redis the compose
// stack runs, because the thing under test IS the Redis bookkeeping — a fake
// would be asserting on my own mock.
package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func m48Redis(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("REDIS_URL")
	if url == "" {
		url = "redis://localhost:6379"
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse REDIS_URL %q: %v", url, err)
	}
	c := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis unreachable at %s: %v — this test asserts on real Redis bookkeeping", url, err)
	}
	return c
}

// m48Harness wires the middleware onto a route whose handler always answers
// with the status the caller asks for, so a test can drive the "rejected" and
// "served" paths without standing up the whole public-link stack.
type m48Harness struct {
	e      *echo.Echo
	rdb    *redis.Client
	status int // what the stub handler returns
	calls  int // how many times the handler actually ran
}

func newM48Harness(t *testing.T, perToken, perIP int) *m48Harness {
	t.Helper()
	h := &m48Harness{e: echo.New(), rdb: m48Redis(t), status: http.StatusForbidden}
	h.e.GET("/api/v1/public/:token", func(c echo.Context) error {
		h.calls++
		return c.JSON(h.status, map[string]string{"stub": "public link"})
	}, RateLimitPublicLink(h.rdb, perToken, perIP, PublicLinkWindow))
	return h
}

// get issues one request and returns the response recorder.
func (h *m48Harness) get(token, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/"+token, nil)
	req.Header.Set("X-Real-IP", ip)
	rec := httptest.NewRecorder()
	h.e.ServeHTTP(rec, req)
	return rec
}

// cleanup removes the buckets this test created so a rerun inside the same
// hour starts from zero (the cumulative window is fixed, keyed on the wall
// clock). The in-flight keys are cleared too: they are not window-scoped, so a
// leaked reservation from an earlier run would silently shrink the cap.
func (h *m48Harness) cleanup(t *testing.T, tokens, ips []string) {
	t.Helper()
	ctx := context.Background()
	windowKey := calculateWindowKey(time.Now().UTC(), PublicLinkWindow)
	for _, tok := range tokens {
		h.rdb.Del(ctx,
			"publiclink:fail:token:"+hashForKey(tok)+":"+windowKey,
			"publiclink:inflight:token:"+hashForKey(tok))
	}
	for _, ip := range ips {
		h.rdb.Del(ctx,
			"publiclink:fail:ip:"+hashForKey(ip)+":"+windowKey,
			"publiclink:inflight:ip:"+hashForKey(ip))
	}
}

// TestM48PublicLinkPerTokenBudget is the finding, in its load-bearing form.
//
// Pre-M48 the handler ran on every one of these requests — 40 bcrypt
// verifications against one link, and nothing to stop the 41st.
func TestM48PublicLinkPerTokenBudget(t *testing.T) {
	const (
		token  = "m48-fo6-token-per-token-budget"
		ip     = "203.0.113.10"
		budget = 5
	)
	h := newM48Harness(t, budget, 1000) // per-IP set high so it cannot interfere
	h.cleanup(t, []string{token}, []string{ip})
	defer h.cleanup(t, []string{token}, []string{ip})

	// Spend exactly the budget. Each is a 403 — a rejected attempt.
	for i := range budget {
		rec := h.get(token, ip)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: status %d, want 403 (the stub's answer)", i+1, rec.Code)
		}
	}
	if h.calls != budget {
		t.Fatalf("handler ran %d times during the budget, want %d", h.calls, budget)
	}

	// The next one must not reach the handler at all — that is the whole
	// point, since reaching it is what costs a bcrypt.
	before := h.calls
	rec := h.get(token, ip)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d: status %d, want 429 — an unlimited password oracle "+
			"and an unlimited bcrypt DoS are the same missing limiter", budget+1, rec.Code)
	}
	if h.calls != before {
		t.Errorf("the handler ran on a throttled request: bcrypt still executed")
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Error("429 carried no Retry-After header")
	}
}

// TestM48PublicLinkSuccessIsNotCounted is the property that makes this
// limiter safe to put in front of an anonymous, legitimately-popular route: a
// link being viewed normally must never throttle itself.
func TestM48PublicLinkSuccessIsNotCounted(t *testing.T) {
	const (
		token = "m48-fo6-token-success-not-counted"
		ip    = "203.0.113.11"
	)
	h := newM48Harness(t, 3, 1000)
	h.cleanup(t, []string{token}, []string{ip})
	defer h.cleanup(t, []string{token}, []string{ip})

	h.status = http.StatusOK
	for i := range 20 {
		rec := h.get(token, ip)
		if rec.Code != http.StatusOK {
			t.Fatalf("successful view %d was throttled (status %d) — counting requests "+
				"rather than failures would break every popular share link", i+1, rec.Code)
		}
	}
	if h.calls != 20 {
		t.Errorf("handler ran %d times, want 20", h.calls)
	}
}

// TestM48PublicLinkPerIPBudgetSpansTokens covers enumeration: one source
// walking many tokens never spends any single token's budget, so the per-token
// counter alone would not see it.
func TestM48PublicLinkPerIPBudgetSpansTokens(t *testing.T) {
	const (
		ip     = "203.0.113.12"
		budget = 6
	)
	h := newM48Harness(t, 1000, budget) // per-token set high so it cannot interfere

	tokens := make([]string, 0, budget+1)
	for i := range budget + 1 {
		tokens = append(tokens, fmt.Sprintf("m48-fo6-enum-%d", i))
	}
	h.cleanup(t, tokens, []string{ip})
	defer h.cleanup(t, tokens, []string{ip})

	for i := range budget {
		if rec := h.get(tokens[i], ip); rec.Code != http.StatusForbidden {
			t.Fatalf("enumeration probe %d: status %d, want 403", i+1, rec.Code)
		}
	}
	if rec := h.get(tokens[budget], ip); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("probe %d against a FRESH token: status %d, want 429 — the per-IP bucket "+
			"is what sees a sweep across tokens", budget+1, rec.Code)
	}
}

// TestM48PublicLinkBudgetsAreIsolatedPerToken checks the converse: exhausting
// one link's budget must not lock out a different link. Otherwise anyone could
// deny service to every share link in the installation by burning one.
func TestM48PublicLinkBudgetsAreIsolatedPerToken(t *testing.T) {
	const (
		victimToken = "m48-fo6-victim"
		attackToken = "m48-fo6-attacker"
		attackerIP  = "203.0.113.13"
		victimIP    = "203.0.113.14"
		budget      = 4
	)
	h := newM48Harness(t, budget, 1000)
	toks := []string{victimToken, attackToken}
	ips := []string{attackerIP, victimIP}
	h.cleanup(t, toks, ips)
	defer h.cleanup(t, toks, ips)

	for range budget + 2 {
		h.get(attackToken, attackerIP)
	}
	if rec := h.get(attackToken, attackerIP); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the attacked token was not throttled: status %d", rec.Code)
	}

	h.status = http.StatusOK
	if rec := h.get(victimToken, victimIP); rec.Code != http.StatusOK {
		t.Fatalf("an unrelated link returned %d — one caller burning their own budget "+
			"must not take down every share link in the installation", rec.Code)
	}
}

// TestM48PublicLinkConcurrentBurstIsBounded is the defect my own review of
// this middleware turned up after the first version was written and passing.
//
// The cumulative counter is READ before the handler and WRITTEN after it, so a
// simultaneous burst all reads the same pre-burst value. Measured with only
// that check in place: 300 concurrent attempts against a budget of 10 put
// **101** requests through to the handler — 101 bcrypt verifications, a 10x
// overshoot of the budget, available to anyone who can open connections in
// parallel. Every one of the other tests in this file passed while that was
// true, because every one of them is sequential.
//
// The fix is the separate atomic in-flight reservation. It does NOT make the
// total exactly failureBudget + inFlightCap — see the ceiling chosen below and
// the doc comment on RateLimitPublicLink — it makes the overshoot a small
// multiple of the cap instead of a function of the attacker's connection
// count.
func TestM48PublicLinkConcurrentBurstIsBounded(t *testing.T) {
	const (
		token  = "m48-fo6-concurrent-burst"
		ip     = "198.51.100.7"
		budget = 10
	)
	h := newM48Harness(t, budget, 1000)
	h.cleanup(t, []string{token}, []string{ip})
	defer h.cleanup(t, []string{token}, []string{ip})

	var reached int64
	e := echo.New()
	e.GET("/api/v1/public/:token", func(c echo.Context) error {
		atomic.AddInt64(&reached, 1)
		// Stand-in for bcrypt.CompareHashAndPassword at DefaultCost, which is
		// the work an attacker is trying to make the server do.
		time.Sleep(40 * time.Millisecond)
		return c.JSON(http.StatusForbidden, map[string]string{"stub": "denied"})
	}, RateLimitPublicLink(h.rdb, budget, 1000, PublicLinkWindow))

	var wg sync.WaitGroup
	for range 300 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/public/"+token, nil)
			req.Header.Set("X-Real-IP", ip)
			e.ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	wg.Wait()

	// The bound asserted here is NOT `budget + inFlightCap`. That was the
	// first version, and it was wrong: reservations are released as requests
	// finish, so a burst drains in waves and a request admitted early in the
	// drain can still read a cumulative count that predates the previous
	// wave's charges. Running exactly this test under `-race` — slower
	// scheduling, wider windows — produced 28 against a nominal 26 and
	// falsified it. That was a comment stronger than the implementation, in a
	// test that was passing.
	//
	// What the design bounds is ADMISSIONS holding a live lease — not work
	// executing, and not a cumulative total — so the assertion is a generous
	// multiple of the in-flight cap: enough to catch the real regression
	// (removing the reservation put 101 through, and removing the limiter
	// entirely puts all 300 through) without pretending to a precision the
	// mechanism does not have.
	max := int64(budget + 4*PublicLinkInFlightPerToken)
	if reached > max {
		t.Fatalf("%d of 300 concurrent attempts reached the handler (ceiling %d). A "+
			"read-then-write counter alone does not survive a parallel burst; the atomic "+
			"in-flight reservation is what keeps this a small multiple of the cap rather "+
			"than a function of how many connections the attacker opens.", reached, max)
	}
	if reached == 0 {
		t.Fatal("no request reached the handler — the harness is not exercising the path")
	}
	t.Logf("300 concurrent attempts -> %d reached the handler (ceiling %d; "+
		"was 101 before the in-flight reservation existed)", reached, max)
}

// TestM48PublicLinkConcurrentSuccessesAreNotCappedAtTheFailureBudget is the
// property that ruled out the simpler fix.
//
// Making the cumulative counter atomic (INCR on entry, refund on success)
// would have bounded the burst in one mechanism — and would also have capped
// simultaneous legitimate viewers at the failure budget, which for a share
// link mailed to a customer is exactly the wrong trade. The in-flight cap is
// separate, and looser, so that concurrent successes well past the failure
// budget still pass.
func TestM48PublicLinkConcurrentSuccessesAreNotCappedAtTheFailureBudget(t *testing.T) {
	const (
		token  = "m48-fo6-concurrent-success"
		ip     = "198.51.100.8"
		budget = 3 // deliberately tiny: successes must not consult it at all
	)
	h := newM48Harness(t, budget, 1000)
	h.cleanup(t, []string{token}, []string{ip})
	defer h.cleanup(t, []string{token}, []string{ip})

	var served, throttled int64
	e := echo.New()
	e.GET("/api/v1/public/:token", func(c echo.Context) error {
		atomic.AddInt64(&served, 1)
		time.Sleep(20 * time.Millisecond)
		return c.NoContent(http.StatusOK)
	}, RateLimitPublicLink(h.rdb, budget, 1000, PublicLinkWindow))

	// Kept under PublicLinkInFlightPerToken so this asserts on the failure
	// budget's non-involvement, not on the concurrency cap.
	const viewers = 12
	var wg sync.WaitGroup
	for range viewers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/public/"+token, nil)
			req.Header.Set("X-Real-IP", ip)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code == http.StatusTooManyRequests {
				atomic.AddInt64(&throttled, 1)
			}
		}()
	}
	wg.Wait()

	if throttled != 0 {
		t.Fatalf("%d of %d SIMULTANEOUS successful viewers were throttled against a failure "+
			"budget of %d — a share link must not be limited by its own popularity",
			throttled, viewers, budget)
	}
	if served != viewers {
		t.Fatalf("served %d of %d", served, viewers)
	}
}

// TestM48PublicLinkInFlightReservationIsReleased checks the defer: a
// reservation that is taken and not given back would permanently shrink the
// link's concurrency until the TTL expired.
func TestM48PublicLinkInFlightReservationIsReleased(t *testing.T) {
	const (
		token = "m48-fo6-reservation-release"
		ip    = "198.51.100.9"
	)
	h := newM48Harness(t, 1000, 1000)
	h.cleanup(t, []string{token}, []string{ip})
	defer h.cleanup(t, []string{token}, []string{ip})

	h.status = http.StatusOK
	for range 5 {
		h.get(token, ip)
	}
	// Also drive the rejected path, which returns before the handler.
	h.status = http.StatusForbidden
	for range 5 {
		h.get(token, ip)
	}

	ctx := context.Background()
	for _, key := range []string{
		"publiclink:inflight:token:" + hashForKey(token),
		"publiclink:inflight:ip:" + hashForKey(ip),
	} {
		n, err := h.rdb.Get(ctx, key).Int64()
		if errors.Is(err, redis.Nil) {
			continue // never created, or already gone: nothing is held
		}
		if err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if n != 0 {
			t.Errorf("%s = %d after every request finished, want 0 — reservations are leaking "+
				"and the concurrency cap will close on legitimate traffic", key, n)
		}
	}
}

// TestM48PublicLinkCancelledRequestIsStillCharged is Codex round 1 (Medium 4).
//
// The middleware used to do its Redis bookkeeping on the request context. Go
// cancels that context when the client disconnects — but the handler's bcrypt
// keeps running to completion — so an attacker who opened a connection, let
// the hash start, and hung up would have the work done for free: the
// post-handler INCR and the deferred DECR would both fail with
// context.Canceled, and the cumulative counter would sit at zero no matter how
// many attempts were made.
//
// The fix is context.WithoutCancel. This test drives the exact shape: a
// request whose context is already cancelled when the middleware runs.
func TestM48PublicLinkCancelledRequestIsStillCharged(t *testing.T) {
	const (
		token = "m48-fo6-cancelled-request"
		ip    = "198.51.100.20"
	)
	h := newM48Harness(t, 1000, 1000)
	h.cleanup(t, []string{token}, []string{ip})
	defer h.cleanup(t, []string{token}, []string{ip})

	e := echo.New()
	e.GET("/api/v1/public/:token", func(c echo.Context) error {
		return c.JSON(http.StatusForbidden, map[string]string{"stub": "denied"})
	}, RateLimitPublicLink(h.rdb, 1000, 1000, PublicLinkWindow))

	const attempts = 4
	for range attempts {
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel() // the client has hung up before we even dispatch
		req := httptest.NewRequest(http.MethodGet, "/api/v1/public/"+token, nil).
			WithContext(cancelledCtx)
		req.Header.Set("X-Real-IP", ip)
		e.ServeHTTP(httptest.NewRecorder(), req)
	}

	windowKey := calculateWindowKey(time.Now().UTC(), PublicLinkWindow)
	got, err := h.rdb.Get(context.Background(),
		"publiclink:fail:token:"+hashForKey(token)+":"+windowKey).Int64()
	if err != nil {
		t.Fatalf("read the failure counter: %v — it was never written, so a caller that "+
			"disconnects mid-request gets unlimited free attempts", err)
	}
	if got != attempts {
		t.Errorf("failure counter = %d after %d cancelled attempts, want %d", got, attempts, attempts)
	}

	// And the reservations must still have been given back.
	n, err := h.rdb.Get(context.Background(), "publiclink:inflight:token:"+hashForKey(token)).Int64()
	if err == nil && n != 0 {
		t.Errorf("in-flight counter = %d after every cancelled request finished, want 0", n)
	}
}

// TestM48PublicLinkFailsClosedWhenRedisIsUnavailable pins the direction of the
// Redis-outage trade.
//
// The alternative — admit the request when the counter cannot be read — would
// hand an attacker the original finding back for the price of one Redis
// outage, which is not a high bar for an endpoint whose whole risk is
// unlimited attempts. Anonymous share links stop working during an outage;
// that is the cost, and it is stated in docs/security/self-host-deployment.md.
func TestM48PublicLinkFailsClosedWhenRedisIsUnavailable(t *testing.T) {
	// A client pointed at a port with nothing on it: Get returns an error
	// that is not redis.Nil, which is the branch under test.
	dead := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 200 * time.Millisecond,
		MaxRetries:  -1,
	})
	defer dead.Close()

	e := echo.New()
	handlerRan := false
	e.GET("/api/v1/public/:token", func(c echo.Context) error {
		handlerRan = true
		return c.NoContent(http.StatusOK)
	}, RateLimitPublicLink(dead, 10, 60, PublicLinkWindow))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/anything", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 — with the counter unreadable the endpoint must deny, "+
			"not admit unlimited bcrypt work", rec.Code)
	}
	if handlerRan {
		t.Error("the handler ran despite an unreadable rate-limit counter")
	}
}

// TestM48RejectedReservationAddsNothing is Codex round 4's coverage gap for
// round 3's M3 fix.
//
// The reservation used to ZADD first and let Go compare afterwards, so every
// over-cap request inserted its own member before being told 429. A burst
// could then grow the sorted set in proportion to the attacker's concurrency
// rather than to the cap — a TTL bounds a key's lifetime, not its cardinality.
// The cap is now enforced inside the Lua script, which returns -1 without
// adding anything.
func TestM48RejectedReservationAddsNothing(t *testing.T) {
	const (
		token = "m48-fo6-rejected-reservation"
		ip    = "198.51.100.30"
	)
	h := newM48Harness(t, 1000, 1000)
	h.cleanup(t, []string{token}, []string{ip})
	defer h.cleanup(t, []string{token}, []string{ip})

	ctx := context.Background()
	key := "publiclink:inflight:token:" + hashForKey(token)

	// Fill the cap with leases that are NOT released, by reserving directly.
	const cap = 3
	for i := range cap {
		n, err := inFlightReserve.Run(ctx, h.rdb, []string{key},
			time.Now().UTC().UnixMilli(), PublicLinkWindow.Milliseconds(),
			fmt.Sprintf("held-%d", i), 120, cap).Int64()
		if err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
		if n != int64(i+1) {
			t.Fatalf("reserve %d returned %d, want %d", i, n, i+1)
		}
	}

	// Every further reservation must be refused AND leave the set untouched.
	for i := range 50 {
		n, err := inFlightReserve.Run(ctx, h.rdb, []string{key},
			time.Now().UTC().UnixMilli(), PublicLinkWindow.Milliseconds(),
			fmt.Sprintf("rejected-%d", i), 120, cap).Int64()
		if err != nil {
			t.Fatalf("over-cap reserve %d: %v", i, err)
		}
		if n != -1 {
			t.Fatalf("over-cap reserve %d returned %d, want the -1 rejection sentinel", i, n)
		}
	}

	card, err := h.rdb.ZCard(ctx, key).Result()
	if err != nil {
		t.Fatalf("zcard: %v", err)
	}
	if card != cap {
		t.Errorf("the set holds %d members after 50 rejected reservations, want %d — a "+
			"rejected request must not be able to grow anonymous-controlled Redis state", card, cap)
	}
}

// TestM48ReleaseRemovesOnlyItsOwnLease is the identity property the sorted set
// exists for: the ABA failure a plain counter had was one request's release
// cancelling another's reservation.
func TestM48ReleaseRemovesOnlyItsOwnLease(t *testing.T) {
	const token = "m48-fo6-lease-identity"
	h := newM48Harness(t, 1000, 1000)
	h.cleanup(t, []string{token}, nil)
	defer h.cleanup(t, []string{token}, nil)

	ctx := context.Background()
	key := "publiclink:inflight:token:" + hashForKey(token)
	now := time.Now().UTC().UnixMilli()

	for _, m := range []string{"lease-a", "lease-b", "lease-c"} {
		if _, err := inFlightReserve.Run(ctx, h.rdb, []string{key},
			now, PublicLinkWindow.Milliseconds(), m, 120, 10).Result(); err != nil {
			t.Fatalf("reserve %s: %v", m, err)
		}
	}

	// Release one, twice — the second is the "my lease already aged out" case.
	for range 2 {
		if err := inFlightRelease.Run(ctx, h.rdb, []string{key}, "lease-b").Err(); err != nil {
			t.Fatalf("release: %v", err)
		}
	}

	members, err := h.rdb.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		t.Fatalf("zrange: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("members = %v, want exactly lease-a and lease-c — a release must remove only "+
			"its own lease, and a repeated release must not remove someone else's", members)
	}
	for _, m := range members {
		if m == "lease-b" {
			t.Error("lease-b survived its own release")
		}
	}
}

// TestM48LeaseIDsAreUnique pins the property round 3's L4 fix protects: two
// requests sharing a member would be counted as one, and either release would
// cancel the other.
func TestM48LeaseIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 10000 {
		id, err := newLeaseID()
		if err != nil {
			t.Fatalf("newLeaseID: %v — it must fail closed rather than return a "+
				"non-unique fallback, and the caller answers 503", err)
		}
		if seen[id] {
			t.Fatalf("duplicate lease id %q", id)
		}
		seen[id] = true
	}
}
