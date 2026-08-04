package main

import (
	"regexp"
	"strings"
	"testing"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
)

// ---------------------------------------------------------------------------
// M51 — the rate limiter's counter was not separated by anything, so 28 route
// families shared one integer per API key and the per-route ceilings were
// decoration. internal/middleware/m51_ratelimit_budget_integration_test.go
// proves the middleware now separates budgets; this file proves main.go asks
// it to, which is the half a behaviour test cannot see.
//
// The load-bearing property is NOT "every call site passes some budget". It is
// that a ceiling can no longer be spelled at a call site at all: the ceiling
// lives on the Budget, so two routes naming one counter cannot disagree about
// its size. A literal `60` reappearing here is the defect coming back.
//
// Source-level, for the reason m47r_route_role_gate_test.go documents at
// length: Echo exposes no way to enumerate a route's middleware after
// registration, and main() cannot be invoked from a test.
// ---------------------------------------------------------------------------

// rateLimitCallRe matches a rate-limit middleware construction in main() as
// mainCalls renders it. The budget is captured so the sweep can check it is a
// declared one rather than any expression at all.
var rateLimitCallRe = regexp.MustCompile(
	`^appmw\.RateLimitByAPIKey\(rdb, appmw\.(Budget[A-Za-z]+)\)$`)

// TestM51EveryRateLimitCallSiteNamesADeclaredBudget sweeps every
// RateLimitByAPIKey construction in main().
//
// A call site that passed a numeric ceiling is what the whole wave removes, so
// the assertion is on the SHAPE of the argument, not merely on the call being
// present.
func TestM51EveryRateLimitCallSiteNamesADeclaredBudget(t *testing.T) {
	declared := map[string]appmw.Budget{
		"BudgetStandard": appmw.BudgetStandard,
		"BudgetPoll":     appmw.BudgetPoll,
		"BudgetMCP":      appmw.BudgetMCP,
		"BudgetCLI":      appmw.BudgetCLI,
	}
	// The map above is a transcription, so it is checked against the package's
	// own enumeration: a budget added to ratelimit.go and forgotten here would
	// otherwise be reported as undeclared at its first call site.
	if got, want := len(declared), len(appmw.AllBudgets()); got != want {
		t.Fatalf("this test knows %d budgets, middleware.AllBudgets() returns %d — "+
			"add the new one here", got, want)
	}
	for _, b := range appmw.AllBudgets() {
		found := false
		for _, known := range declared {
			if known == b {
				found = true
			}
		}
		if !found {
			t.Fatalf("middleware budget %+v is not in this test's map", b)
		}
	}

	calls := mainCalls(t)
	sites := 0
	for _, call := range calls {
		if !strings.HasPrefix(call, "appmw.RateLimitByAPIKey(") {
			continue
		}
		sites++
		m := rateLimitCallRe.FindStringSubmatch(call)
		if m == nil {
			t.Errorf("rate-limit call site %q does not name a declared budget.\n"+
				"A ceiling passed at the call site is exactly the M51 defect: two "+
				"routes could then name one Redis counter with two different limits, "+
				"and the counter would enforce whichever route the caller happened to "+
				"hit. Use appmw.RateLimitByAPIKey(rdb, appmw.Budget<X>).", call)
			continue
		}
		if _, ok := declared[m[1]]; !ok {
			t.Errorf("rate-limit call site %q names appmw.%s, which is not a "+
				"declared budget", call, m[1])
		}
	}

	// Anti-vacuity: a sweep that finds nothing passes. 28 is what a85a0fb had
	// and what this wave rewrote one-for-one; the check is >= so adding a route
	// is not a test failure, while deleting the wiring wholesale is.
	if sites < 28 {
		t.Errorf("found %d RateLimitByAPIKey call sites in main(), expected at least 28 — "+
			"either the wiring was removed or this sweep stopped seeing it", sites)
	}
}

// TestM51NoBareLimitReachesTheLimiter is the narrower half stated on its own,
// because it is the regression that would be easiest to reintroduce: a new
// route copied from a pre-M51 example.
func TestM51NoBareLimitReachesTheLimiter(t *testing.T) {
	numeric := regexp.MustCompile(`RateLimitByAPIKey\([^)]*\b\d+\b`)
	for _, call := range mainCalls(t) {
		if numeric.MatchString(call) {
			t.Errorf("%q passes a numeric ceiling to the rate limiter. "+
				"Ceilings live on the Budget (internal/middleware/ratelimit.go) so "+
				"one counter cannot be given two of them.", call)
		}
	}
}

// TestM51PollBudgetIsWiredToThePollingSurfaces pins the two routes whose
// higher ceiling was the ORIGINAL reason the limits differed — and therefore
// the two that made the shared counter observable.
//
// scan-status is polled about once a second by `sbomhub scan --fail-on`; with
// one counter, 60 of those polls locked the same key out of the SBOM upload it
// had just made. If either of these silently reverts to BudgetStandard the
// polling loop breaks at 60 requests and no behaviour test in this repo runs
// long enough to notice.
func TestM51PollBudgetIsWiredToThePollingSurfaces(t *testing.T) {
	body := mainFuncBody(t)
	for _, route := range []struct {
		path string
		why  string
	}{
		{
			path: `e.GET("/api/v1/projects/:id/sboms/:sbom_id/scan-status"`,
			why:  "the CLI polls this once a second while a scan runs",
		},
		{
			path: `e.GET("/api/v1/projects/:id/vex-drafts"`,
			why:  "the triage list surface, read in a loop by the CLI",
		},
	} {
		idx := strings.Index(body, route.path)
		if idx < 0 {
			t.Fatalf("route %s is no longer registered in main() — this test's "+
				"anchor drifted", route.path)
		}
		// The middleware list is the remainder of the registration call.
		end := strings.Index(body[idx:], "auditMiddleware)")
		if end < 0 {
			end = 600
		}
		if window := body[idx : idx+end]; !strings.Contains(window, "appmw.BudgetPoll") {
			t.Errorf("%s is not on appmw.BudgetPoll (%s).\nregistration: %s",
				route.path, route.why, window)
		}
	}
}
