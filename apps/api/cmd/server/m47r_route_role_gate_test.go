package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// ---------------------------------------------------------------------------
// M47R — every mutating route must carry a role gate, and the gate must run
// BEFORE the transaction it guards.
//
// Two findings, one instrument, because they are the same wiring decision.
//
// # Why a source-level test
//
// Echo exposes no way to enumerate a route's middleware after registration
// (e.Routes() returns method / path / handler-name only), so the only place
// the wiring is observable is the registration site. That is also where it
// regressed: M47 W1 added RequireWrite to POST /projects/:id/scan and left the
// structurally identical POST /projects/:id/eol-check on the bare `auth`
// group. The middlewares themselves are behaviour-tested in
// middleware.TestRequireWrite_RoleMatrix / TestRequireAdmin_RoleMatrix; this
// file asserts only that they are wired, which is exactly the claim.
//
// It supersedes the two hand-listed guards in
// m47_w1_global_sync_admin_gate_test.go: those enumerate the routes they
// protect, so a NEW ungated route is invisible to them. This one enumerates
// what main.go actually registers, so the default for anything new is
// "flagged".
// ---------------------------------------------------------------------------

// routeReg is one `<group>.<METHOD>("<path>", handler, mw...)` call, with the
// group's own middleware already resolved in front of the route's.
type routeReg struct {
	group   string
	method  string
	path    string
	handler string
	// chain is the EFFECTIVE middleware order: the group's list (itself
	// inherited from its parent groups) followed by the per-route arguments.
	// This is exactly how echo.Group.Add composes them, outermost first.
	chain    []string
	line     int
	fullPath string
}

// groupDecl is one `<name> := <parent>.Group("<prefix>", mw...)` declaration,
// flattened through its parents. `order` is its position among all group
// declarations in main.go, which decides who owns the per-prefix
// RouteNotFound catch-all echo.Group.Use installs (last wins).
type groupDecl struct {
	name   string
	prefix string
	mw     []string
	order  int
}

var httpVerbs = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true, "Any": true,
}

func mutating(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// parseRoutes walks main.go's AST and returns every route registration,
// resolving each group's inherited middleware chain from the source rather
// than from a hand-maintained table.
//
// Deriving the groups is the point: the first version of this test hardcoded
// "the `auth` group is the one that carries TenantTx", and the Codex review
// promptly found the identical defect on the `cli` group, which it could not
// see. Anything main.go declares with .Group() is now in scope automatically.
func parseRoutes(t *testing.T) ([]routeReg, map[string]groupDecl) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
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

	// `e` is the Echo instance: no prefix, no group middleware. Everything
	// else is discovered below, in source order, so a parent is always known
	// before its children.
	groups := map[string]groupDecl{"e": {}}
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
		if !ok || sel.Sel.Name != "Group" || len(call.Args) == 0 {
			return true
		}
		parentIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		parent, known := groups[parentIdent.Name]
		if !known {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		prefix, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		mw := append([]string{}, parent.mw...)
		for _, a := range call.Args[1:] {
			mw = append(mw, render(a))
		}
		groups[name.Name] = groupDecl{
			name: name.Name, prefix: parent.prefix + prefix, mw: mw, order: len(groups),
		}
		return true
	})
	if len(groups) < 5 {
		t.Fatalf("resolved only %d route groups from main.go — the parser is blind", len(groups))
	}

	var out []routeReg
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !httpVerbs[sel.Sel.Name] {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		grp, known := groups[recv.Name]
		if !known {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		path, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		reg := routeReg{
			group:    recv.Name,
			method:   sel.Sel.Name,
			path:     path,
			handler:  render(call.Args[1]),
			line:     fset.Position(call.Pos()).Line,
			fullPath: grp.prefix + path,
			chain:    append([]string{}, grp.mw...),
		}
		for _, a := range call.Args[2:] {
			reg.chain = append(reg.chain, render(a))
		}
		out = append(out, reg)
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].line < out[j].line })
	return out, groups
}

func isGate(mw string) bool {
	return strings.Contains(mw, "RequireWrite") || strings.Contains(mw, "RequireAdmin") ||
		strings.Contains(mw, "adminOnly")
}

func hasGate(chain []string) bool {
	for _, m := range chain {
		if isGate(m) {
			return true
		}
	}
	return false
}

// indexOf returns the position of the first element satisfying pred, or -1.
func indexOf(chain []string, pred func(string) bool) int {
	for i, m := range chain {
		if pred(m) {
			return i
		}
	}
	return -1
}

// ungatedByDesign lists every mutating registration that legitimately carries
// no role gate, with the reason. A route is exempt only because it writes
// NOTHING or because it has no tenant role to check — never because "the
// handler checks it itself" (a handler-side check is fine as defence in depth
// but is not what this guard is about: the route-level gate is what keeps a
// denied request out of the transaction).
//
// Keyed by "<METHOD> <full path>".
var ungatedByDesign = map[string]string{
	"POST /api/webhooks/clerk": "unauthenticated provider callback: Svix-signed, no tenant " +
		"context exists to check a role against (handler resolves the tenant from the payload)",
	"POST /api/webhooks/lemonsqueezy": "unauthenticated provider callback: HMAC-signed, no " +
		"tenant context exists to check a role against",
	"POST /api/v1/sbom/diff": "read-only computation; POST only because the two SBOM ids " +
		"travel in the body. SbomDiffHandler.Diff issues no write",
	"POST /api/v1/mcp/sbom/diff": "same handler as /api/v1/sbom/diff — read-only computation",
	"POST /api/v1/cli/check": "read-only vulnerability lookup against OSV; CLIHandler.Check " +
		"persists nothing (that is what /cli/upload is for, and it IS gated)",
	"POST /api/v1/ssvc/calculate": "pure function over the request body: " +
		"SSVCHandler.CalculateDecision touches no repository at all",
}

// TestM47RMutatingRoutesCarryARoleGate is the mechanical sweep.
func TestM47RMutatingRoutesCarryARoleGate(t *testing.T) {
	routes, _ := parseRoutes(t)
	if len(routes) < 100 {
		t.Fatalf("parsed only %d routes from main.go — the parser is blind, not the router", len(routes))
	}

	var ungated []routeReg
	seenExempt := map[string]bool{}
	for _, r := range routes {
		if !mutating(r.method) {
			continue
		}
		key := r.method + " " + r.fullPath
		if _, ok := ungatedByDesign[key]; ok {
			seenExempt[key] = true
			if hasGate(r.chain) {
				t.Errorf("main.go:%d %s is on the by-design-ungated list but IS gated — "+
					"remove it from ungatedByDesign", r.line, key)
			}
			continue
		}
		if hasGate(r.chain) {
			continue
		}
		ungated = append(ungated, r)
	}

	for _, r := range ungated {
		t.Errorf("main.go:%d %s %s (%s) mutates but has no role gate — a Viewer, whose whole "+
			"definition is read-only access, can drive it. Register it on authWrite/authAdmin "+
			"or, if it truly writes nothing, add it to ungatedByDesign with the reason.",
			r.line, r.method, r.fullPath, r.handler)
	}

	// A stale exemption is as dangerous as a missing gate: it keeps a route
	// invisible to this sweep after the route itself has changed shape.
	for key := range ungatedByDesign {
		if !seenExempt[key] {
			t.Errorf("ungatedByDesign lists %q, which main.go no longer registers — "+
				"drop the entry so it cannot silently exempt a future route of the same name", key)
		}
	}
}

// TestM47RRoleGateRunsBeforeTheTransaction is the M47R Low: the guard must be
// OUTSIDE TenantTx, not inside it.
//
// Echo composes `g.Add(method, path, h, m...)` as groupMiddleware ++
// routeMiddleware, outermost first. So `auth.POST(p, h, RequireWrite())` runs
// Auth -> TenantTx -> Audit -> RequireWrite -> handler: the transaction is
// already open (and `SET LOCAL app.current_tenant_id` already issued) when the
// guard finally refuses. Two consequences, both wrong:
//
//   - a Postgres outage turns a 403 into a 500, because TenantTx's BeginTx
//     fails before the guard is ever consulted. (The 403 is not made
//     independent of Postgres — the auth middleware ahead of the guard reads
//     tenants/users — but it is made independent of the REQUEST transaction,
//     which is the second database interaction and the one that costs a
//     pooled connection.);
//   - TenantTx rolls back on any status >= 400, so the audit row the Audit
//     middleware writes for the 403 is rolled back with it. role_guard.go's
//     comment claimed that row as forensic evidence; it never survived.
//
// The rule is ONE comparison over the EFFECTIVE chain (group middleware ++
// route middleware, which is how echo.Group.Add composes them), so it covers
// every registration shape at once: gates as group middleware, gates as
// per-route arguments on a plain group, and the explicit chains on `e`.
//
// The first version of this test special-cased "the `auth` group", and the
// Codex review immediately found the same defect on the `cli` group, which was
// outside its field of view. Comparing positions in the resolved chain has no
// such blind spot.
func TestM47RRoleGateRunsBeforeTheTransaction(t *testing.T) {
	routes, _ := parseRoutes(t)
	for _, r := range routes {
		gateAt := indexOf(r.chain, isGate)
		txAt := indexOf(r.chain, func(m string) bool { return strings.Contains(m, "TenantTx(") })
		if gateAt < 0 || txAt < 0 || gateAt < txAt {
			continue
		}
		t.Errorf("main.go:%d %s %s runs its role gate (position %d) AFTER TenantTx "+
			"(position %d) in the effective chain %v.\n"+
			"Echo composes groupMiddleware ++ routeMiddleware outermost-first, so a gate "+
			"passed as a ROUTE argument to a group that already carries TenantTx always "+
			"lands inside it: BEGIN happens before the guard refuses, a DB outage answers "+
			"500 instead of 403, and the 403's audit row is rolled back. Move the gate onto "+
			"a group declared ahead of TenantTx.",
			r.line, r.method, r.fullPath, gateAt, txAt, r.chain)
	}
}

// TestM47RGatedGroupsAreDeclaredCorrectly pins the group declarations the
// sweep above trusts. Without it, renaming a group to `authWrite` while
// dropping RequireWrite from it would make every route on it "gated".
func TestM47RGatedGroupsAreDeclaredCorrectly(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)

	// `adminOnly` is the single shared RequireAdmin instance the authAdmin
	// group is built from (and the one
	// TestM47W1AdminOnlyIsDeclaredBeforeItsFirstUse keeps unique). Pin what it
	// actually is, so accepting the alias below cannot accept something else.
	if decl := findDecl(t, body, "adminOnly"); !strings.Contains(decl, "appmw.RequireAdmin()") {
		t.Fatalf("`adminOnly` is not appmw.RequireAdmin(): %s", decl)
	}

	for _, tc := range []struct{ name, guard string }{
		{"authWrite", "RequireWrite()"},
		{"authAdmin", "adminOnly"},
	} {
		decl := findDecl(t, body, tc.name)
		if !strings.Contains(decl, tc.guard) {
			t.Errorf("`%s` is declared without %s:\n\t%s", tc.name, tc.guard, decl)
			continue
		}
		if !strings.Contains(decl, "TenantTx(") {
			t.Errorf("`%s` is declared without TenantTx — routes on it would run with no "+
				"tenant GUC bound:\n\t%s", tc.name, decl)
			continue
		}
		if strings.Index(decl, tc.guard) > strings.Index(decl, "TenantTx(") {
			t.Errorf("`%s` lists %s after TenantTx; the guard must be the outer one:\n\t%s",
				tc.name, tc.guard, decl)
		}
	}

}

// TestM47RUngatedGroupOwnsTheCatchAll pins the declaration-order rule, for
// every prefix, mechanically.
//
// echo.Group.Use installs a RouteNotFound catch-all pair for the group's
// PREFIX (verified in TestM47REchoGroupSemantics), so N groups sharing one
// prefix register it N times and the LAST declared wins. If a GATED group were
// last, every unmatched path under that prefix would be answered from behind a
// role gate — a Viewer would get 403 where a 404 is correct, and the request
// would be judged by a guard that has nothing to guard.
//
// The rule is therefore: for any prefix declared more than once, the
// last-declared group must carry no role gate.
func TestM47RUngatedGroupOwnsTheCatchAll(t *testing.T) {
	_, groups := parseRoutes(t)

	byPrefix := map[string][]groupDecl{}
	for _, g := range groups {
		if g.name == "" {
			continue // the synthetic `e` entry
		}
		byPrefix[g.prefix] = append(byPrefix[g.prefix], g)
	}
	for prefix, decls := range byPrefix {
		if len(decls) < 2 {
			continue
		}
		sort.Slice(decls, func(i, j int) bool { return decls[i].order < decls[j].order })
		last := decls[len(decls)-1]
		if hasGate(last.mw) {
			names := make([]string, 0, len(decls))
			for _, d := range decls {
				names = append(names, d.name)
			}
			t.Errorf("prefix %q is declared by %v; the LAST one (%s) carries a role gate, so it "+
				"owns the RouteNotFound catch-all and every unmatched path under %q is answered "+
				"from behind that gate. Declare the ungated group last.",
				prefix, names, last.name, prefix)
		}
	}
}

// TestM47REchoGroupSemantics pins the two Echo behaviours main.go's group
// split depends on. Both are framework behaviour, not our code, so they are
// exercised against a real echo.Echo rather than asserted from the source:
// if a future Echo upgrade changes either, this fails instead of the wiring
// silently becoming wrong.
//
//  1. group middleware runs OUTSIDE per-route middleware, which is why the
//     guard had to move from a route argument onto the group;
//  2. echo.Group.Use installs a RouteNotFound catch-all per PREFIX, so with
//     three groups on "/api/v1" the last declared owns unmatched paths —
//     which is why `auth` is declared last.
func TestM47REchoGroupSemantics(t *testing.T) {
	var seen []string
	mw := func(name string) echo.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				seen = append(seen, name)
				return next(c)
			}
		}
	}
	hit := func(c echo.Context) error {
		seen = append(seen, "handler")
		return c.NoContent(http.StatusNoContent)
	}

	e := echo.New()
	api := e.Group("/api/v1")
	authBase := api.Group("", mw("auth"))
	// Same declaration order as main.go: gated groups first, plain read group
	// last.
	authAdmin := authBase.Group("", mw("admin-gate"), mw("tx"), mw("audit"))
	authWrite := authBase.Group("", mw("write-gate"), mw("tx"), mw("audit"))
	plain := authBase.Group("", mw("tx"), mw("audit"))

	authAdmin.POST("/admin", hit)
	authWrite.POST("/write", hit)
	plain.GET("/read", hit)
	// The shape M47R removed, kept as the contrast.
	plain.POST("/legacy", hit, mw("route-gate"))

	do := func(method, path string) []string {
		seen = nil
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return seen
	}

	cases := []struct {
		name, method, path string
		want               []string
	}{
		{"admin group", http.MethodPost, "/api/v1/admin",
			[]string{"auth", "admin-gate", "tx", "audit", "handler"}},
		{"write group", http.MethodPost, "/api/v1/write",
			[]string{"auth", "write-gate", "tx", "audit", "handler"}},
		{"read group", http.MethodGet, "/api/v1/read",
			[]string{"auth", "tx", "audit", "handler"}},
		{"per-route gate lands INSIDE the group's tx (the removed shape)",
			http.MethodPost, "/api/v1/legacy",
			[]string{"auth", "tx", "audit", "route-gate", "handler"}},
		{"unmatched path falls to the LAST-declared group's chain",
			http.MethodGet, "/api/v1/does-not-exist",
			[]string{"auth", "tx", "audit"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := do(tc.method, tc.path)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("chain = %v, want %v", got, tc.want)
			}
		})
	}
}

// findDecl returns the source line(s) of `<name> := ...` up to the closing
// parenthesis of the call.
func findDecl(t *testing.T, body, name string) string {
	t.Helper()
	i := strings.Index(body, "\t"+name+" := ")
	if i < 0 {
		t.Fatalf("main.go declares no `%s`", name)
	}
	rest := body[i:]
	depth := 0
	for j, r := range rest {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return strings.TrimSpace(rest[:j+1])
			}
		}
	}
	t.Fatalf("unbalanced parentheses in the `%s` declaration", name)
	return ""
}
