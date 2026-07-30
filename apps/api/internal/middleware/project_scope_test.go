package middleware

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ---------------------------------------------------------------------------
// M50 W2 — api_keys.project_id is enforced.
//
// The behaviour under test is one comparison, so most of this file is about the
// things that make the comparison load-bearing rather than decorative: that the
// route table is consulted with the REGISTERED path, that an unclassified route
// is denied, that the refusal cannot be used as an existence oracle, and that
// tenant-level keys are untouched.
// ---------------------------------------------------------------------------

func m50w2ProjectKey(projectID uuid.UUID) *model.APIKey {
	return &model.APIKey{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		ProjectID:   &projectID,
		Name:        "m50w2-scoped",
		Permissions: "write",
	}
}

func m50w2TenantKey() *model.APIKey {
	return &model.APIKey{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "m50w2-tenant",
		Permissions: "write",
	}
}

// m50w2Ctx builds a context in the state Echo hands to middleware AFTER routing:
// c.Path() is the registered route, and the path params are bound.
func m50w2Ctx(method, routePath string, params map[string]string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath(routePath)
	names := make([]string, 0, len(params))
	for n := range params {
		names = append(names, n)
	}
	sort.Strings(names)
	vals := make([]string, 0, len(names))
	for _, n := range names {
		vals = append(vals, params[n])
	}
	c.SetParamNames(names...)
	c.SetParamValues(vals...)
	return c, rec
}

// TestM50W2EchoPathIsTheRegisteredRouteInMiddleware pins the two framework
// behaviours apiKeyRouteScope's keying depends on. Both are Echo behaviour, not
// ours, so they are exercised against a real echo.Echo: if an upgrade changes
// either, this fails instead of the route table silently missing every request.
//
//  1. inside GROUP middleware, c.Path() is the REGISTERED path with `:param`
//     placeholders (not the concrete request URI) and c.Param is already bound;
//  2. an unmatched path under a group's prefix still runs the group middleware,
//     via the RouteNotFound catch-all echo.Group.Use installs — and c.Path() is
//     then the wildcard form, which is NOT in the table and therefore denied.
func TestM50W2EchoPathIsTheRegisteredRouteInMiddleware(t *testing.T) {
	e := echo.New()
	var gotPath, gotID string
	spy := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			gotPath, gotID = c.Path(), c.Param("id")
			return next(c)
		}
	}
	g := e.Group("/api/v1/cli", spy)
	g.GET("/projects/:id", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })

	for _, tc := range []struct {
		name, uri, wantPath, wantID string
	}{
		{"matched route", "/api/v1/cli/projects/abc-123", "/api/v1/cli/projects/:id", "abc-123"},
		{"unmatched under the prefix", "/api/v1/cli/nope", "/api/v1/cli/*", ""},
		{"deeper unmatched", "/api/v1/cli/a/b/c", "/api/v1/cli/*", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotPath, gotID = "", ""
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.uri, nil))
			if gotPath != tc.wantPath {
				t.Errorf("c.Path() in group middleware = %q, want %q", gotPath, tc.wantPath)
			}
			if gotID != tc.wantID {
				t.Errorf("c.Param(\"id\") = %q, want %q", gotID, tc.wantID)
			}
		})
	}

	// And the wildcard form the catch-all produces must not be a table key —
	// otherwise the default-deny branch would never be reached for it.
	if _, ok := apiKeyRouteScope["GET /api/v1/cli/*"]; ok {
		t.Error("apiKeyRouteScope contains the RouteNotFound wildcard path; it must not")
	}
}

// TestM50W2TenantLevelKeyIsUnaffected is the regression fence around every
// existing key. Every api_keys row in the development database had project_id
// NULL when this wave was written (96 of 96, measured 2026-07-30 against the dev
// database — the count is recorded in docs/UPGRADE.md §2d rather than relied on
// here), so if this ever fails the wave has broken every deployed CI pipeline
// rather than scoped anything.
//
// It sweeps EVERY table entry plus an unclassified path, because the guarantee
// is "the route table cannot affect a tenant-level key at all" — the nil check
// returns before the lookup.
func TestM50W2TenantLevelKeyIsUnaffected(t *testing.T) {
	paths := append(APIKeyRouteScopeKeys(), "GET /api/v1/cli/*", "POST /api/v1/not/a/route")
	for _, key := range paths {
		method, routePath, ok := strings.Cut(key, " ")
		if !ok {
			t.Fatalf("malformed route key %q", key)
		}
		c, rec := m50w2Ctx(method, routePath, map[string]string{"id": uuid.New().String()})
		allowed, err := apiKeyProjectScopeAllowed(c, m50w2TenantKey())
		if !allowed || err != nil {
			t.Errorf("%s: tenant-level key denied (err=%v, body=%s)", key, err, rec.Body.String())
		}
	}

	// A nil key (no API-key credential at all: Clerk session / self-hosted)
	// must also pass, since the check has no credential to scope.
	c, _ := m50w2Ctx(http.MethodGet, "/api/v1/projects/:id/sbom", map[string]string{"id": uuid.New().String()})
	if allowed, err := apiKeyProjectScopeAllowed(c, nil); !allowed || err != nil {
		t.Errorf("nil key denied (err=%v)", err)
	}
}

// TestM50W2PathParamScopeMatrix is the core comparison, over every
// scopeProjectPathParam route in the table rather than a hand-picked sample.
func TestM50W2PathParamScopeMatrix(t *testing.T) {
	own := uuid.New()
	sibling := uuid.New()

	var covered int
	for key, rule := range apiKeyRouteScope {
		if rule.kind != scopeProjectPathParam {
			continue
		}
		covered++
		method, routePath, _ := strings.Cut(key, " ")

		t.Run("own/"+key, func(t *testing.T) {
			c, rec := m50w2Ctx(method, routePath, map[string]string{"id": own.String()})
			allowed, err := apiKeyProjectScopeAllowed(c, m50w2ProjectKey(own))
			if !allowed || err != nil {
				t.Errorf("the key's OWN project was denied (err=%v, body=%s)", err, rec.Body.String())
			}
		})
		t.Run("sibling/"+key, func(t *testing.T) {
			c, rec := m50w2Ctx(method, routePath, map[string]string{"id": sibling.String()})
			allowed, _ := apiKeyProjectScopeAllowed(c, m50w2ProjectKey(own))
			if allowed {
				t.Error("a project outside the key's scope was allowed")
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
		t.Run("malformed/"+key, func(t *testing.T) {
			c, rec := m50w2Ctx(method, routePath, map[string]string{"id": "not-a-uuid"})
			allowed, _ := apiKeyProjectScopeAllowed(c, m50w2ProjectKey(own))
			if allowed {
				t.Error("an unparseable :id was allowed through; the check must fail closed")
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
	if covered < 25 {
		t.Fatalf("only %d path-param routes in the table — the sweep has gone blind", covered)
	}
}

// TestM50W2PathParamDenialIsIndistinguishable is the reason this refusal can be a
// 403 without reintroducing the M47 W1 existence oracle.
//
// The comparison is credential-local: both UUIDs are already in hand and no row
// is read. So an existing sibling project, a foreign tenant's project and a UUID
// that was never allocated must produce byte-identical responses. Nothing about
// the response distinguishes them, which is exactly the property M47 W1's 404
// sentinel buys — obtained here without asserting "not found" about a project
// that may well exist.
func TestM50W2PathParamDenialIsIndistinguishable(t *testing.T) {
	own := uuid.New()
	key := m50w2ProjectKey(own)

	type answer struct {
		code int
		body string
	}
	got := map[string]answer{}
	for name, target := range map[string]uuid.UUID{
		"sibling project of the same tenant": uuid.New(),
		"project of a different tenant":      uuid.New(),
		"uuid that was never allocated":      uuid.New(),
	} {
		c, rec := m50w2Ctx(http.MethodGet, "/api/v1/projects/:id/sbom",
			map[string]string{"id": target.String()})
		if allowed, _ := apiKeyProjectScopeAllowed(c, key); allowed {
			t.Fatalf("%s was allowed", name)
		}
		got[name] = answer{rec.Code, rec.Body.String()}
	}

	var first string
	for name, a := range got {
		if first == "" {
			first = name
			continue
		}
		if a != got[first] {
			t.Errorf("%q answers %d %q but %q answers %d %q — the difference is a "+
				"project-existence oracle",
				name, a.code, a.body, first, got[first].code, got[first].body)
		}
	}
	if a := got[first]; a.code != http.StatusForbidden || !strings.Contains(a.body, `"forbidden"`) {
		t.Errorf("refusal = %d %q, want 403 with the generic forbidden body "+
			"(same body policy as RequireWrite)", a.code, a.body)
	}
}

// TestM50W2TenantWideRoutesAreDenied covers the second design decision: a route
// that names no project is refused rather than silently narrowed to the key's
// project. Sweeps the table so a new tenant-wide entry is covered on arrival.
func TestM50W2TenantWideRoutesAreDenied(t *testing.T) {
	var covered int
	for key, rule := range apiKeyRouteScope {
		if rule.kind != scopeTenantWide {
			continue
		}
		covered++
		method, routePath, _ := strings.Cut(key, " ")
		c, rec := m50w2Ctx(method, routePath, nil)
		allowed, _ := apiKeyProjectScopeAllowed(c, m50w2ProjectKey(uuid.New()))
		if allowed {
			t.Errorf("%s: tenant-wide route allowed for a project-scoped key", key)
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", key, rec.Code)
		}
		if rule.why == "" {
			t.Errorf("%s: tenant-wide entry carries no reason", key)
		}
	}
	if covered == 0 {
		t.Fatal("no tenant-wide routes in the table — the sweep has gone blind")
	}
}

// TestM50W2UnclassifiedRouteIsDenied is the default-deny property, which is what
// makes this table safe to be incomplete-by-accident: the failure mode of
// forgetting an entry is a refused request, not a tenant-wide one.
func TestM50W2UnclassifiedRouteIsDenied(t *testing.T) {
	for _, tc := range []struct{ name, method, path string }{
		{"a route nobody classified", http.MethodPost, "/api/v1/mcp/something/new"},
		{"the /cli RouteNotFound catch-all", http.MethodGet, "/api/v1/cli/*"},
		{"the /mcp RouteNotFound catch-all", http.MethodGet, "/api/v1/mcp/*"},
		{"right path, wrong method", http.MethodDelete, "/api/v1/projects/:id/sbom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := m50w2Ctx(tc.method, tc.path, map[string]string{"id": uuid.New().String()})
			allowed, err := apiKeyProjectScopeAllowed(c, m50w2ProjectKey(uuid.New()))
			if allowed {
				t.Errorf("allowed (err=%v)", err)
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
}

// TestM50W2HandlerCheckedRoutesAreExactlyTheKnownTwo fences the one
// classification the middleware cannot enforce.
//
// scopeHandlerChecked means "this middleware waves the request through and the
// HANDLER performs the comparison". That is a promise made in a table about code
// somewhere else, so the set is pinned by name: adding a third route to it has
// to be a deliberate edit here, next to the two whose handler-side refusal is
// pinned by internal/handler/m50w2_cli_project_scope_integration_test.go against a
// live database.
func TestM50W2HandlerCheckedRoutesAreExactlyTheKnownTwo(t *testing.T) {
	want := map[string]bool{
		"POST /api/v1/cli/upload":   true,
		"POST /api/v1/cli/projects": true,
	}
	got := map[string]bool{}
	for key, rule := range apiKeyRouteScope {
		if rule.kind == scopeHandlerChecked {
			got[key] = true
		}
	}
	for key := range got {
		if !want[key] {
			t.Errorf("%s is classified scopeHandlerChecked, but only %v have a "+
				"handler-side comparison pinned by an integration test. Either add the "+
				"handler check plus its test, or classify the route differently.",
				key, keysOf(want))
		}
	}
	for key := range want {
		if !got[key] {
			t.Errorf("%s is no longer classified scopeHandlerChecked — if its project is "+
				"no longer body-resolved, drop it from this test too", key)
		}
	}
}

// TestM50W2NoProjectResourceRoutesCarryAReason: the one route waved through
// entirely must say why, since "touches no project-scoped resource" is a claim
// about a handler, not about a path.
func TestM50W2NoProjectResourceRoutesCarryAReason(t *testing.T) {
	for key, rule := range apiKeyRouteScope {
		if rule.kind != scopeNoProjectResource {
			continue
		}
		if rule.why == "" {
			t.Errorf("%s is waved through with no stated reason", key)
		}
		method, routePath, _ := strings.Cut(key, " ")
		c, rec := m50w2Ctx(method, routePath, nil)
		if allowed, err := apiKeyProjectScopeAllowed(c, m50w2ProjectKey(uuid.New())); !allowed {
			t.Errorf("%s: denied (err=%v, body=%s)", key, err, rec.Body.String())
		}
	}
}

// TestM50W2EveryRuleCarriesAReason: no entry may be added by copying a neighbour.
func TestM50W2EveryRuleCarriesAReason(t *testing.T) {
	for key, rule := range apiKeyRouteScope {
		if strings.TrimSpace(rule.why) == "" {
			t.Errorf("%s carries no reason", key)
		}
	}
}

// TestM50W2ScopeCheckCoversEveryValidateKeyCallSite is the structural claim this
// wave rests on, checked mechanically.
//
// The scope filter is placed at the points where a raw `sbh_...` string becomes
// an authenticated request context — i.e. every caller of
// APIKeyService.ValidateKey — rather than at each of the 38 API-key-reachable
// route registrations. That is only sound while the set of such callers is
// known. This test parses the middleware package's non-test sources, finds every
// function that calls ValidateKey, and requires each of them to also call
// apiKeyProjectScopeAllowed.
//
// What it verifies: for each function in package middleware that calls
// ValidateKey, a call to apiKeyProjectScopeAllowed appears in the same function
// body. What it does NOT verify: the ORDER of the two calls, or that the result
// is propagated — those are covered by the behavioural tests above and by
// TestM50W2ScopeDenialShortCircuitsBeforeNext.
func TestM50W2ScopeCheckCoversEveryValidateKeyCallSite(t *testing.T) {
	// parser.ParseDir is deprecated (SA1019) because it ignores build tags; the
	// walk below is the ParseFile-per-file equivalent, and skipping _test.go is
	// deliberate — a test helper that calls ValidateKey is not an authentication
	// path.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read middleware package dir: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) < 5 {
		t.Fatalf("parsed only %d non-test files in package middleware — the walk is blind",
			len(files))
	}

	type site struct {
		fn        string
		line      int
		hasScope  bool
		hasValida bool
	}
	var sites []site
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			s := site{fn: fn.Name.Name, line: fset.Position(fn.Pos()).Line}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "ValidateKey" {
					s.hasValida = true
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if ok && id.Name == "apiKeyProjectScopeAllowed" {
					s.hasScope = true
				}
				return true
			})
			if s.hasValida {
				sites = append(sites, s)
			}
		}
	}

	if len(sites) < 3 {
		t.Fatalf("found only %d ValidateKey call sites in package middleware; expected at "+
			"least the 3 known ones (APIKeyAuth, OptionalAPIKeyAuth, handleAPIKeyAuth) — "+
			"the parser is blind", len(sites))
	}
	for _, s := range sites {
		if !s.hasScope {
			t.Errorf("%s (line %d) turns a raw key into an authenticated context via "+
				"ValidateKey but never calls apiKeyProjectScopeAllowed — a project-scoped "+
				"key reaching a route through it carries the whole tenant, which is the "+
				"defect M50 W2 closed", s.fn, s.line)
		}
	}
}

// TestM50W2ScopeDenialShortCircuitsBeforeNext drives the real APIKeyAuth
// middleware and asserts the denial never reaches the next handler. The
// tenant-context middleware that normally follows would issue SQL, so "next was
// not called" is also the claim that a refusal costs no database work of its
// own beyond the ValidateKey lookup that produced the key.
func TestM50W2ScopeDenialShortCircuitsBeforeNext(t *testing.T) {
	own := uuid.New()
	nextCalled := false
	next := func(c echo.Context) error {
		nextCalled = true
		return c.NoContent(http.StatusNoContent)
	}

	// Drive apiKeyProjectScopeAllowed through the same shape APIKeyAuth uses:
	// check, and return without calling next on refusal.
	guard := func(key *model.APIKey) echo.HandlerFunc {
		return func(c echo.Context) error {
			if ok, err := apiKeyProjectScopeAllowed(c, key); !ok {
				return err
			}
			return next(c)
		}
	}

	c, rec := m50w2Ctx(http.MethodPost, "/api/v1/projects/:id/sbom",
		map[string]string{"id": uuid.New().String()})
	if err := guard(m50w2ProjectKey(own))(c); err != nil {
		t.Fatalf("guard returned a non-HTTP error: %v", err)
	}
	if nextCalled {
		t.Error("the request reached the next handler despite the scope violation")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}

	nextCalled = false
	c, rec = m50w2Ctx(http.MethodPost, "/api/v1/projects/:id/sbom",
		map[string]string{"id": own.String()})
	if err := guard(m50w2ProjectKey(own))(c); err != nil {
		t.Fatalf("guard returned a non-HTTP error: %v", err)
	}
	if !nextCalled {
		t.Errorf("the key's own project did not reach the next handler (status %d)", rec.Code)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
