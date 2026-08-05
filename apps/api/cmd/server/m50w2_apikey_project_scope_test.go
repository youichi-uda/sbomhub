package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
)

// ---------------------------------------------------------------------------
// M50 W2 — every route an API key can reach must be classified for project scope.
//
// # Why a source-level test
//
// Echo exposes no way to enumerate a route's middleware after registration
// (e.Routes() returns method / path / handler-name only), so the only place a
// route's auth wiring is observable is the registration site — the same reason
// m47r_route_role_gate_test.go is a source test. This file reuses that file's
// parseRoutes (same package) and asks a different question of the result: which
// routes accept an `Authorization: Bearer sbh_...` API key, and is every one of
// them classified in middleware.apiKeyRouteScope?
//
// Without this test the route table would be a hand-maintained list, and a hand-
// maintained list is exactly what went wrong before: one route was fixed and 37
// structurally identical ones were left alone because nothing enumerated them.
// With it, adding a route to any API-key-fronted chain fails the build until
// somebody classifies it — and the classification is default-DENY anyway, so the
// intermediate state is safe rather than tenant-wide.
// ---------------------------------------------------------------------------

// apiKeyAuthMiddlewares are the middleware constructors that make a route
// reachable with a Bearer API key.
//
//   - MultiAuth accepts `Bearer sbh_...` on the canonical routes registered
//     directly on the Echo instance (its handleAPIKeyAuth branch).
//   - APIKeyAuth is the /api/v1/{mcp,cli}/* groups' authenticator.
//   - OptionalAPIKeyAuth validates a key when one is present. It is currently
//     registered nowhere (TestM50W2OptionalAPIKeyAuthIsUnwired), and is listed
//     here so that wiring it up later is covered on arrival rather than
//     silently unclassified.
//
// Anything NOT in this list (appmw.Auth, the publicLinkLimit chain, the two
// webhook routes) cannot see an API key: Auth() either verifies a Clerk JWT or,
// in self-hosted mode, ignores the Authorization header entirely.
var apiKeyAuthMiddlewares = []string{"MultiAuth", "APIKeyAuth", "OptionalAPIKeyAuth"}

// apiKeyMiddlewareAliases finds local variables that HOLD one of the API-key
// middlewares, e.g. main.go's `triageMultiAuth := appmw.MultiAuth(...)`, so a
// chain entry of `triageMultiAuth` is recognised.
//
// Matching the raw middleware text against "MultiAuth" happens to catch
// `triageMultiAuth` by substring, but only by luck — a variable named
// `sharedAuth` would not be caught. Resolving the assignment removes the luck.
func apiKeyMiddlewareAliases(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	render := func(n ast.Node) string {
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, n); err != nil {
			t.Fatalf("render node: %v", err)
		}
		return buf.String()
	}

	aliases := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, mw := range apiKeyAuthMiddlewares {
			if sel.Sel.Name == mw {
				aliases[name.Name] = render(assign.Rhs[0])
			}
		}
		return true
	})
	return aliases
}

// apiKeyReachable reports whether an effective middleware chain admits a Bearer
// API key.
func apiKeyReachable(chain []string, aliases map[string]string) bool {
	for _, m := range chain {
		trimmed := strings.TrimSpace(m)
		if _, ok := aliases[trimmed]; ok {
			return true
		}
		for _, mw := range apiKeyAuthMiddlewares {
			// `appmw.MultiAuth(` / `appmw.APIKeyAuth(` as written at the
			// registration site.
			if strings.Contains(m, mw+"(") {
				return true
			}
		}
	}
	return false
}

// apiKeyReachableRoutes returns the "<METHOD> <full path>" set of routes an API
// key can reach, derived from main.go.
func apiKeyReachableRoutes(t *testing.T) map[string]routeReg {
	t.Helper()
	routes, _ := parseRoutes(t)
	if len(routes) < 100 {
		t.Fatalf("parsed only %d routes from main.go — the parser is blind, not the router",
			len(routes))
	}
	aliases := apiKeyMiddlewareAliases(t)
	if len(aliases) == 0 {
		t.Fatal("resolved no API-key middleware aliases from main.go; main.go declares " +
			"`triageMultiAuth := appmw.MultiAuth(...)`, so zero means the resolver is blind")
	}

	out := map[string]routeReg{}
	for _, r := range routes {
		if apiKeyReachable(r.chain, aliases) {
			out[r.method+" "+r.fullPath] = r
		}
	}
	return out
}

// TestM50W2APIKeyReachableRoutesAreAllClassified is the sweep.
func TestM50W2APIKeyReachableRoutesAreAllClassified(t *testing.T) {
	reachable := apiKeyReachableRoutes(t)
	if len(reachable) == 0 {
		t.Fatal("found no API-key-reachable routes in main.go — the sweep is blind")
	}

	classified := map[string]bool{}
	for _, k := range appmw.APIKeyRouteScopeKeys() {
		classified[k] = true
	}

	var missing []string
	for key, r := range reachable {
		if !classified[key] {
			missing = append(missing, key+"  (main.go:"+strconv.Itoa(r.line)+", "+r.handler+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s accepts a Bearer API key but middleware.apiKeyRouteScope does not "+
			"classify it. A project-scoped key is DENIED on it until you do (fail-closed), "+
			"so this is a functionality gap rather than a hole — but classify it explicitly "+
			"with a reason so the denial is intentional.", m)
	}

	var stale []string
	for key := range classified {
		if _, ok := reachable[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("middleware.apiKeyRouteScope classifies %q, which main.go no longer "+
			"registers on an API-key-fronted chain. Drop the entry: a stale rule silently "+
			"pre-approves a future route that happens to reuse the path.", s)
	}
}

// TestM50W2APIKeyReachableRouteCountIsPinned records the size of the surface so a
// change in it is visible in a diff rather than only in the table.
//
// 39 as of 2026-08-05: 8 on the /api/v1/mcp group, 5 on /api/v1/cli, and 26
// registered directly on the Echo instance behind MultiAuth. The remaining 142
// of main.go's 181 registrations sit on appmw.Auth (Clerk JWT / self-hosted
// default), which never inspects an API key.
//
// It was 38 until M53 W1 moved POST /api/v1/projects/:id/scan off the Clerk-only
// `authWrite` group — the route the shipped GitHub Action calls, which had never
// worked with an API key.
//
// This is a tripwire, not a contract: if you add or remove an API-key-fronted
// route, update the number AND the breakdown above.
func TestM50W2APIKeyReachableRouteCountIsPinned(t *testing.T) {
	const want = 39
	reachable := apiKeyReachableRoutes(t)
	if len(reachable) != want {
		keys := make([]string, 0, len(reachable))
		for k := range reachable {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Errorf("API-key-reachable routes = %d, pinned at %d.\n%s",
			len(reachable), want, strings.Join(keys, "\n"))
	}
}

// TestM50W2NoWildcardRouteIsAPIKeyReachable underwrites the one shortcut in
// apiKeyProjectScopeAllowed's default branch.
//
// Echo's per-prefix RouteNotFound catch-all makes the group middleware run for
// unmatched paths with c.Path() = "/api/v1/cli/*", which the table does not
// contain and which is therefore denied. That is accepted deliberately (a
// project-scoped key sees 403 instead of 404 on a mistyped URL under /mcp or
// /cli) because the alternative — treating a `*` path as "not a real route" and
// waving it through — would also wave through a genuine wildcard route.
//
// This test is what makes that trade safe: it asserts no genuine wildcard route
// exists. If one is ever registered, the trade has to be revisited rather than
// silently inherited.
func TestM50W2NoWildcardRouteIsAPIKeyReachable(t *testing.T) {
	routes, _ := parseRoutes(t)
	for _, r := range routes {
		if strings.Contains(r.fullPath, "*") {
			t.Errorf("main.go:%d registers the wildcard route %s %s. "+
				"middleware.apiKeyProjectScopeAllowed treats a `*` path as unclassified "+
				"and denies it, which is correct for Echo's RouteNotFound catch-all but "+
				"would also deny this route for every project-scoped key. Classify it in "+
				"apiKeyRouteScope or reconsider the catch-all handling.",
				r.line, r.method, r.fullPath)
		}
	}
}

// TestM50W2OptionalAPIKeyAuthIsUnwired pins the claim made in
// OptionalAPIKeyAuth's comment and in apiKeyAuthMiddlewares above: it is
// registered on no route. If it ever is, the route(s) behind it need entries in
// apiKeyRouteScope — which TestM50W2APIKeyReachableRoutesAreAllClassified will
// then demand, because apiKeyAuthMiddlewares already lists it.
//
// The value of pinning it separately is the comment: "currently unwired" is a
// claim about main.go made in another package, and this is the only thing that
// keeps it true.
func TestM50W2OptionalAPIKeyAuthIsUnwired(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if strings.Contains(string(src), "OptionalAPIKeyAuth") {
		t.Error("main.go now references OptionalAPIKeyAuth. Update the 'currently unwired' " +
			"claims in middleware/apikey.go and middleware/project_scope.go, and make sure " +
			"the routes behind it are classified in apiKeyRouteScope.")
	}
}
