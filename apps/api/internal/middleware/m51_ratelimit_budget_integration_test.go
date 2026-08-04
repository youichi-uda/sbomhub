//go:build integration

// Package middleware — M51: RateLimitByAPIKey's counter was not separated by
// anything, so every route in the product shared ONE bucket per API key.
//
// Run with:
//
//	cd apps/api && REDIS_URL=redis://localhost:6379 go test -tags=integration \
//	    -count=1 -run 'M51RateLimitBudget' ./internal/middleware
//
// -count=1 is load-bearing: live Redis state is not an input to go's test
// cache.
//
// # The finding
//
// cmd/server/main.go configures 28 rate-limit middlewares with two different
// ceilings — 60/min for uploads and one-shot reads, 300/min for the polling
// and list surfaces the CLI hammers. The Redis key those middlewares INCR was
//
//	"mcp:ratelimit:" + key.ID.String() + ":" + windowKey
//
// which names the API key and the minute and nothing else. Every route
// therefore advanced the SAME integer, and the only thing a route's own limit
// decided was the threshold that integer was compared against.
//
// Measured on a throwaway stack (2026-08-04, api built from a85a0fb,
// postgres 15 / redis 7, self-host `anonymous`), one API key, one minute:
//
//	61 x GET .../sboms/:sbom_id/scan-status   (limit 300)  ->  200
//	 1 x GET .../sbom                         (limit  60)  ->  429   <- FIRST call
//	 1 x GET .../vulnerabilities              (limit  60)  ->  429   <- FIRST call
//
// A route whose configured budget is 60 requests per minute was exhausted
// having served zero. That is not a stricter limit than advertised, it is a
// different limit: what a caller may do on any route depends on what it did on
// every other route.
//
// The direction that costs the product a legitimate client is the same one:
// `sbomhub scan --fail-on <severity>` polls scan-status once a second, which
// is exactly what the 300 budget was raised for — and after 60 of those polls
// the next SBOM upload with the same key is refused.
//
// # What these tests pin
//
// The property is NOT "one bucket per route" (see the Budget doc comment in
// ratelimit.go for why that was rejected: it multiplies what one key may spend
// by the size of the route table). It is:
//
//	a request may only advance a counter whose ceiling is the ceiling
//	configured for that request's route.
//
// Budgets are therefore the unit of separation, and a Budget carries its own
// limit so no two call sites can name one bucket with two different ceilings.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	"github.com/sbomhub/sbomhub/internal/model"
)

// m51Redis is m48Redis with its own name so the two files stay independent.
func m51Redis(t *testing.T) *redis.Client {
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
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// m51Harness mounts several rate-limited routes over ONE API key, which is the
// shape that matters: the defect is invisible to a test that drives one route.
type m51Harness struct {
	e   *echo.Echo
	rdb *redis.Client
	key *model.APIKey
}

// newM51Harness registers one route per budget. The stub handler answers 200,
// so any non-200 in these tests came from the limiter.
func newM51Harness(t *testing.T, budgets map[string]Budget) *m51Harness {
	t.Helper()
	h := &m51Harness{
		e:   echo.New(),
		rdb: m51Redis(t),
		key: &model.APIKey{ID: uuid.New(), TenantID: uuid.New(), Permissions: "write"},
	}
	// Stands in for MultiAuth / APIKeyAuth: the limiter is a no-op unless an
	// authenticated key is on the context.
	authenticated := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(ContextKeyAPI, h.key)
			return next(c)
		}
	}
	for path, b := range budgets {
		h.e.GET(path, func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]string{"stub": "ok"})
		}, authenticated, RateLimitByAPIKey(h.rdb, b))
	}
	t.Cleanup(func() { h.cleanup(t, budgets) })
	return h
}

// m51Result is one observation off the wire.
type m51Result struct {
	status    int
	limit     string
	remaining string
}

func (r m51Result) String() string {
	return fmt.Sprintf("status=%d X-RateLimit-Limit=%s X-RateLimit-Remaining=%s",
		r.status, r.limit, r.remaining)
}

func (h *m51Harness) get(path string) m51Result {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.e.ServeHTTP(rec, req)
	return m51Result{
		status:    rec.Code,
		limit:     rec.Header().Get("X-RateLimit-Limit"),
		remaining: rec.Header().Get("X-RateLimit-Remaining"),
	}
}

// cleanup drops this key's buckets. The window is a fixed wall-clock minute,
// so a rerun inside the same minute would otherwise start mid-budget.
func (h *m51Harness) cleanup(t *testing.T, budgets map[string]Budget) {
	t.Helper()
	ctx := context.Background()
	for _, b := range budgets {
		h.rdb.Del(ctx, rateLimitRedisKey(h.key, b, time.Now().UTC()))
	}
	// Belt and braces: the pre-M51 key shape, which no longer has a
	// constructor, so a failed run cannot poison the next one.
	h.rdb.Del(ctx, "mcp:ratelimit:"+h.key.ID.String()+":"+
		calculateWindowKey(time.Now().UTC(), time.Minute))
}

// TestM51RateLimitBudgetsAreSeparate is the finding, stated as the property it
// violates. Exhausting the polling budget must not spend the upload budget.
//
// Pre-M51 the last two lines of the table below were 429, having served zero
// requests each.
func TestM51RateLimitBudgetsAreSeparate(t *testing.T) {
	budgets := map[string]Budget{
		"/poll":  BudgetPoll,
		"/std":   BudgetStandard,
		"/mcp":   BudgetMCP,
		"/cliep": BudgetCLI,
	}
	h := newM51Harness(t, budgets)

	// Spend more of the polling budget than the standard budget's whole
	// ceiling, which is what a `sbomhub scan --fail-on` run does in its first
	// minute of polling.
	spend := BudgetStandard.Limit + 1
	for i := 0; i < spend; i++ {
		if got := h.get("/poll"); got.status != http.StatusOK {
			t.Fatalf("/poll request %d/%d: %s, want 200 — the polling budget is %d",
				i+1, spend, got, BudgetPoll.Limit)
		}
	}

	for _, tc := range []struct {
		path string
		b    Budget
	}{
		{"/std", BudgetStandard},
		{"/mcp", BudgetMCP},
		{"/cliep", BudgetCLI},
	} {
		got := h.get(tc.path)
		if got.status != http.StatusOK {
			t.Errorf("%s (budget %q, limit %d) answered %s on its FIRST request, "+
				"after %d requests to a route on budget %q — the two budgets share one counter",
				tc.path, tc.b.Name, tc.b.Limit, got, spend, BudgetPoll.Name)
		}
		if want := fmt.Sprintf("%d", tc.b.Limit); got.limit != want {
			t.Errorf("%s: X-RateLimit-Limit=%s, want %s", tc.path, got.limit, want)
		}
		if want := fmt.Sprintf("%d", tc.b.Limit-1); got.remaining != want {
			t.Errorf("%s: X-RateLimit-Remaining=%s after its first request, want %s — "+
				"a remaining count that already reflects OTHER routes' traffic is the "+
				"same defect seen from the client side",
				tc.path, got.remaining, want)
		}
	}
}

// TestM51RateLimitOneBudgetIsOneCounter is the other half, and it is what stops
// the fix from being "give every route its own bucket": routes that share a
// budget must still share its counter, or the ceiling means nothing.
func TestM51RateLimitOneBudgetIsOneCounter(t *testing.T) {
	budgets := map[string]Budget{
		"/std/a": BudgetStandard,
		"/std/b": BudgetStandard,
	}
	h := newM51Harness(t, budgets)

	// The counting window is a wall-clock minute, so a run that straddles a
	// minute boundary spends part of the budget in one bucket and part in the
	// next — and the "it must refuse now" assertion below would then be
	// measuring the clock rather than the limiter. The loop takes tens of
	// milliseconds against a local Redis, so the straddle is rare (~0.05% of
	// runs) and never happens twice; detecting it and redoing the loop turns a
	// rare red build on correct code into no red build at all, which matters
	// because a flaky security gate is a gate someone disables.
	for attempt := 1; ; attempt++ {
		before := calculateWindowKey(time.Now().UTC(), BudgetStandard.Window)
		for i := 0; i < BudgetStandard.Limit; i++ {
			path := "/std/a"
			if i%2 == 1 {
				path = "/std/b"
			}
			if got := h.get(path); got.status != http.StatusOK {
				t.Fatalf("%s request %d: %s, want 200", path, i+1, got)
			}
		}
		if after := calculateWindowKey(time.Now().UTC(), BudgetStandard.Window); after == before {
			break
		}
		if attempt == 2 {
			t.Fatalf("the counting window rolled over on both attempts (started in %s); "+
				"this test cannot tell a spent budget from a fresh bucket", before)
		}
		// Start the second attempt from zero in the CURRENT bucket.
		h.rdb.Del(context.Background(),
			rateLimitRedisKey(h.key, BudgetStandard, time.Now().UTC()))
	}

	// The budget is spent. BOTH routes must now refuse — a caller who
	// alternates paths must not get two ceilings.
	for _, path := range []string{"/std/a", "/std/b"} {
		if got := h.get(path); got.status != http.StatusTooManyRequests {
			t.Errorf("%s: %s after the shared budget %q (limit %d) was spent, want 429",
				path, got, BudgetStandard.Name, BudgetStandard.Limit)
		}
	}
}

// TestM51RateLimitRedisKeyNamesTheBudget pins the key shape itself, because the
// property above is a consequence of it and a future refactor that drops the
// budget from the key would reintroduce the defect wholesale.
func TestM51RateLimitRedisKeyNamesTheBudget(t *testing.T) {
	key := &model.APIKey{ID: uuid.New(), TenantID: uuid.New()}
	now := time.Date(2026, 8, 4, 17, 43, 0, 0, time.UTC)

	std := rateLimitRedisKey(key, BudgetStandard, now)
	poll := rateLimitRedisKey(key, BudgetPoll, now)
	if std == poll {
		t.Fatalf("BudgetStandard and BudgetPoll produce the SAME Redis key %q — "+
			"two ceilings over one counter is the M51 defect", std)
	}
	for _, b := range AllBudgets() {
		k := rateLimitRedisKey(key, b, now)
		if !strings.Contains(k, b.Name) {
			t.Errorf("budget %q: key %q does not name the budget", b.Name, k)
		}
		if !strings.Contains(k, key.ID.String()) {
			t.Errorf("budget %q: key %q does not name the API key — one tenant's "+
				"traffic would throttle another's", b.Name, k)
		}
	}
}
