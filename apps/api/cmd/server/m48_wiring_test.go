package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// M48 — Codex round 1 (Low 9): the behaviour tests all call the guards
// directly, so deleting the CALL SITES leaves every one of them green.
//
// That is the same hole M47R found in its own first attempt: a test that
// exercises a middleware proves the middleware works, not that anything uses
// it. These assert the wiring in main.go, which is where all four fixes are
// actually switched on.
//
// Source-level, for the reason m47r_route_role_gate_test.go documents at
// length: Echo exposes no way to enumerate a route's middleware after
// registration, and main() cannot be invoked from a test.
// ---------------------------------------------------------------------------

// mainFuncBody returns the rendered source of main.go's `func main()`.
//
// Used only for assertions where the exact ARGUMENTS matter. Anything that
// asserts a call HAPPENS uses mainCalls instead — Codex round 4 (Low) pointed
// out that substring-searching rendered source is satisfied by a call that has
// been commented out, which is precisely the regression these tests exist to
// catch.
func mainFuncBody(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, token.NewFileSet(), mainFuncDecl(t, token.NewFileSet()).Body); err != nil {
		t.Fatalf("render main body: %v", err)
	}
	return buf.String()
}

func mainFuncDecl(t *testing.T, fset *token.FileSet) *ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "main" && fn.Recv == nil {
			return fn
		}
	}
	t.Fatal("main.go declares no func main()")
	return nil
}

// mainCalls returns every call expression in main(), rendered as source, in
// source order. A commented-out or deleted call is simply absent — unlike a
// substring search over the rendered body, which a comment satisfies.
func mainCalls(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	fn := mainFuncDecl(t, fset)
	var calls []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, call); err != nil {
			t.Fatalf("render call: %v", err)
		}
		calls = append(calls, buf.String())
		return true
	})
	return calls
}

// callIndex returns the position of the first call equal to want, or -1.
func callIndex(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

// TestM48StartupGuardsAreCalledFromMain pins that the guards run at all.
//
// Each of these refuses to start on a configuration that was measured serving
// traffic before M48. A guard that is never called is a guard that does not
// exist, and no other test in this milestone would notice.
func TestM48StartupGuardsAreCalledFromMain(t *testing.T) {
	calls := mainCalls(t)

	for _, guard := range []struct {
		call string
		why  string
	}{
		{
			call: "validateAppEnv(cfg)",
			why: "APP_ENV unset resolved to development, under which the ENCRYPTION_KEY and " +
				"BYPASSRLS guards are warnings; measured serving traffic with tenant isolation off",
		},
		{
			call: "validateAuthMode(cfg)",
			why: "self-hosted mode serves the Clerk-fronted route groups as Owner with no " +
				"credential; measured minting a live API key over an unauthenticated POST. " +
				"Unlike the guards below it, this one refuses in every environment",
		},
		{
			call: "validateEncryptionKey(cfg)",
			why:  "pre-existing (M0) — asserted here so the M48 insertions cannot displace it",
		},
		{
			call: "validateWebhookVerification(cfg)",
			why:  "pre-existing (M47) — same reason",
		},
		{
			call: "assertAppRoleNotBypassRLS(db, cfg)",
			why:  "pre-existing (M0) — same reason",
		},
	} {
		if callIndex(calls, guard.call) < 0 {
			t.Errorf("main() does not call %s — %s", guard.call, guard.why)
		}
	}

	if callIndex(calls, "announceAuthMode(cfg)") < 0 {
		t.Error("main() does not call announceAuthMode(cfg): the startup log would go back to " +
			"naming the cause (\"Clerk secret key not set\") instead of the consequence, which " +
			"is how this was missed in the first place")
	}
}

// TestM48AppEnvGuardRunsFirst pins the ORDER, which is load-bearing rather
// than cosmetic: validateEncryptionKey, evaluateAppRoleRLS and
// validateWebhookVerification each downgrade themselves to a warning under
// cfg.IsDevelopment(). If APP_ENV were validated after them, an unset or
// misspelled value would still be able to disarm the ones that ran earlier.
// (validateAuthMode is in the list below because it must be able to quote a
// validated APP_ENV, not because it downgrades — it does not.)
func TestM48AppEnvGuardRunsFirst(t *testing.T) {
	calls := mainCalls(t)

	appEnvAt := callIndex(calls, "validateAppEnv(cfg)")
	if appEnvAt < 0 {
		t.Fatal("main() does not call validateAppEnv(cfg)")
	}
	for _, later := range []string{
		"validateAuthMode(cfg)",
		"validateEncryptionKey(cfg)",
		"validateWebhookVerification(cfg)",
		"cfg.Validate()",
		"assertAppRoleNotBypassRLS(db, cfg)",
	} {
		at := callIndex(calls, later)
		if at < 0 {
			t.Errorf("main() does not call %s", later)
			continue
		}
		if at < appEnvAt {
			t.Errorf("%s runs BEFORE validateAppEnv(cfg) — it branches on the environment, so "+
				"it must not run until the environment has been established as a deliberate "+
				"operator statement rather than a default", later)
		}
	}
}

// TestM48PublicLinkRoutesCarryTheRateLimiter is the other half of Low 9: the
// limiter's own tests register a synthetic route, so removing it from the two
// real registrations leaves them all green.
//
// Both routes reach service.PublicLinkService, which runs
// bcrypt.CompareHashAndPassword on a caller-supplied password. Measured
// pre-M48 against a real server: 40 of 40 wrong-password attempts reached
// bcrypt, 1.68s of server-side hashing, with no upper bound.
func TestM48PublicLinkRoutesCarryTheRateLimiter(t *testing.T) {
	routes, _ := parseRoutes(t)

	want := map[string]bool{
		"GET /api/v1/public/:token":          false,
		"GET /api/v1/public/:token/download": false,
	}

	// main.go builds the middleware once and shares it between the two
	// routes, so the chain holds a local identifier rather than the call.
	// Resolve any `x := ...RateLimitPublicLink(...)` in main() to that
	// identifier, and accept either spelling — a test that only matched the
	// literal call would break the moment someone hoisted the variable, which
	// is a refactor, not a regression.
	aliases := map[string]bool{}
	for _, line := range strings.Split(mainFuncBody(t), "\n") {
		if !strings.Contains(line, "RateLimitPublicLink(") {
			continue
		}
		name, _, ok := strings.Cut(strings.TrimSpace(line), ":=")
		if !ok {
			continue
		}
		aliases[strings.TrimSpace(name)] = true
	}
	if len(aliases) == 0 {
		t.Log("note: RateLimitPublicLink is not bound to a local; expecting the call inline")
	}

	for _, r := range routes {
		key := r.method + " " + r.fullPath
		if _, ok := want[key]; !ok {
			continue
		}
		want[key] = true
		var limited bool
		for _, mw := range r.chain {
			if strings.Contains(mw, "RateLimitPublicLink") || aliases[strings.TrimSpace(mw)] {
				limited = true
			}
		}
		if !limited {
			t.Errorf("main.go:%d %s has no RateLimitPublicLink in its middleware chain (%v) — "+
				"this route runs bcrypt for an anonymous caller and is the only thing "+
				"standing between a share-link password and unlimited guesses",
				r.line, key, r.chain)
		}
	}

	for key, seen := range want {
		if !seen {
			t.Errorf("main.go no longer registers %q — if the route was renamed, move the "+
				"limiter with it and update this test rather than dropping the assertion", key)
		}
	}
}

// TestM48LimiterUsesTheSharedBudgetConstants keeps the wired limits and the
// documented limits from drifting apart. The doc comment on
// RateLimitPublicLink, docs/security/self-host-deployment.md §10.2 and
// docs/UPGRADE.md all quote these numbers.
func TestM48LimiterUsesTheSharedBudgetConstants(t *testing.T) {
	// Codex round 5 (Low): find the RateLimitPublicLink call and inspect ITS
	// arguments. Searching the rendered body for the identifiers is satisfied
	// by a commented-out earlier version of the call, which is the same defect
	// the guard-presence checks were moved off rendered text to avoid.
	var found bool
	for _, call := range mainCalls(t) {
		if !strings.HasPrefix(call, "appmw.RateLimitPublicLink(") {
			continue
		}
		found = true
		for _, ident := range []string{
			"appmw.PublicLinkFailuresPerToken",
			"appmw.PublicLinkFailuresPerIP",
			"appmw.PublicLinkWindow",
		} {
			if !strings.Contains(call, ident) {
				t.Errorf("the RateLimitPublicLink call does not pass %s — the wired budget "+
					"and the documented budget must come from one place.\nCall: %s", ident, call)
			}
		}
	}
	if !found {
		t.Error("main() contains no appmw.RateLimitPublicLink(...) call")
	}
}
