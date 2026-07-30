package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
)

// ---------------------------------------------------------------------------
// M50 W3 — the doc comment that justifies the conditional narrowing must match
// main.go.
//
// Why a test for a COMMENT. handler.listProjectsForCredential narrows the
// project list only when the request carries a project-scoped API key, and the
// comment above it explains why the condition cannot be dropped: the same
// handler also serves a Clerk-fronted route that no API key can reach and that
// must keep listing the whole tenant. Someone deciding whether that condition is
// still needed will read the comment, not main.go.
//
// The first version of that justification was prose and said "registered three
// times" when main.go registers it twice (Codex R1). The replacement for the
// prose is a machine-readable block, and this file re-derives the same facts
// from main.go's AST and compares them. A count alone would have been a weak
// gate — it says nothing about WHICH routes or which of them accept an API key
// (Codex R2) — so the block carries `<AUDIENCE> <METHOD> <path>` per route and
// all three fields are checked.
// ---------------------------------------------------------------------------

// m50w3DocRoute is one line of the machine-readable block in
// internal/handler/project.go's listProjectsForCredential comment.
type m50w3DocRoute struct {
	audience string // "APIKEY" or "CLERK"
	key      string // "<METHOD> <path>"
}

// m50w3DocBlockRE matches those lines. gofmt keeps a tab-indented block inside a
// doc comment preformatted, so the `//\t` prefix and the spacing are stable.
var m50w3DocBlockRE = regexp.MustCompile(`(?m)^//\t(APIKEY|CLERK)\s+([A-Z]+)\s+(/\S*)\s*$`)

// m50w3AppmwAuthRE matches a literal `appmw.Auth(` that is not the tail of a
// longer package identifier such as `fakeappmw.Auth(`.
var m50w3AppmwAuthRE = regexp.MustCompile(`(^|[^\w.])appmw\.Auth\(`)

// m50w3RegistrationsOf returns the sites at which main.go registers the given
// handler expression, derived from the AST rather than from a text search, so
// that a handler mentioned in a comment is not counted.
func m50w3RegistrationsOf(t *testing.T, handler string) []routeReg {
	t.Helper()
	routes, _ := parseRoutes(t)
	if len(routes) < 100 {
		t.Fatalf("parsed only %d routes from main.go — the parser is blind, not the router",
			len(routes))
	}
	var out []routeReg
	for _, r := range routes {
		if strings.TrimSpace(r.handler) == handler {
			out = append(out, r)
		}
	}
	return out
}

// TestM50W3ProjectHandlerListRegistrationsMatchTheDoc is the gate.
func TestM50W3ProjectHandlerListRegistrationsMatchTheDoc(t *testing.T) {
	got := m50w3RegistrationsOf(t, "projectHandler.List")
	if len(got) == 0 {
		t.Fatal("main.go registers projectHandler.List nowhere; either the handler was " +
			"renamed or the AST resolver is blind. Both invalidate the comment this test " +
			"checks, so update internal/handler/project.go alongside.")
	}
	reachable := apiKeyReachableRoutes(t)
	clerkFronted := m50w3ClerkFrontedRoutes(t)

	// Scoped to listProjectsForCredential's OWN doc comment, not to the file:
	// a file-wide search would stay green if the block were moved into an
	// unrelated comment, or duplicated (Codex R3, Low).
	doc := m50w3DocCommentOf(t, "../../internal/handler/project.go", "listProjectsForCredential")
	matches := m50w3DocBlockRE.FindAllStringSubmatch(doc, -1)
	if len(matches) == 0 {
		t.Fatalf("listProjectsForCredential's doc comment in internal/handler/project.go no "+
			"longer contains the `<AUDIENCE> <METHOD> <path>` block that documents where "+
			"ProjectHandler.List is mounted, which is what justifies narrowing on the "+
			"CREDENTIAL rather than on the route. If the justification was rewritten, rewrite "+
			"this test with it. (main.go currently registers it at %s.)", m50w3RouteList(got))
	}

	documented := map[string]m50w3DocRoute{}
	for _, m := range matches {
		r := m50w3DocRoute{audience: m[1], key: m[2] + " " + m[3]}
		if prev, dup := documented[r.key]; dup {
			t.Errorf("the doc block lists %q twice (%s and %s)", r.key, prev.audience, r.audience)
		}
		documented[r.key] = r
	}

	actual := map[string]m50w3DocRoute{}
	for _, r := range got {
		key := r.method + " " + r.fullPath
		// APIKEY and CLERK are each derived POSITIVELY, from the route's own
		// middleware chain. An earlier version derived CLERK as "anything not
		// API-key-reachable", which would have kept labelling the route CLERK
		// after it was moved to some third, non-Clerk chain (Codex R3, Low).
		_, isAPIKey := reachable[key]
		_, isClerk := clerkFronted[key]
		var audience string
		switch {
		case isAPIKey && isClerk:
			t.Errorf("%s sits behind BOTH an API-key middleware and appmw.Auth; the doc block's "+
				"two-way split cannot describe it. Decide which one the route is.", key)
			continue
		case isAPIKey:
			audience = "APIKEY"
		case isClerk:
			audience = "CLERK"
		default:
			t.Errorf("%s is behind neither an API-key middleware nor appmw.Auth. The doc block "+
				"in internal/handler/project.go describes ProjectHandler.List's mounts as one "+
				"or the other, so a third kind of chain needs a decision (and probably a "+
				"decision about whether it should narrow) rather than a new label.", key)
			continue
		}
		actual[key] = m50w3DocRoute{audience: audience, key: key}
	}

	for key, want := range actual {
		doc, ok := documented[key]
		switch {
		case !ok:
			t.Errorf("main.go registers ProjectHandler.List at %q (%s) but the doc block in "+
				"internal/handler/project.go does not list it. Every mount has to be accounted "+
				"for there, because the comment's argument is about the set of mounts.",
				key, want.audience)
		case doc.audience != want.audience:
			t.Errorf("the doc block calls %q %s, but main.go mounts it %s. If a Clerk-only "+
				"route became API-key-reachable, the web project list will now narrow for "+
				"API-key callers — decide that deliberately.", key, doc.audience, want.audience)
		}
	}
	for key := range documented {
		if _, ok := actual[key]; !ok {
			t.Errorf("the doc block in internal/handler/project.go lists %q as a mount of "+
				"ProjectHandler.List, but main.go has no such registration. Stale or "+
				"mistyped: main.go currently registers it at %s.", key, m50w3RouteList(got))
		}
	}
}

// m50w3DocCommentOf returns the text of the doc comment attached to the
// top-level function `fn` in `path`, so a gate on that comment cannot be
// satisfied by text elsewhere in the file.
func m50w3DocCommentOf(t *testing.T, path, fn string) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		decl, ok := decl.(*ast.FuncDecl)
		if !ok || decl.Name.Name != fn || decl.Recv != nil {
			continue
		}
		if decl.Doc == nil {
			t.Fatalf("%s in %s has no doc comment", fn, path)
		}
		// Re-emit with the `//\t` prefixes intact: m50w3DocBlockRE is anchored
		// on them, and decl.Doc.Text() strips the markers.
		var b strings.Builder
		for _, c := range decl.Doc.List {
			b.WriteString(c.Text)
			b.WriteString("\n")
		}
		return b.String()
	}
	t.Fatalf("no top-level func %s in %s — if it was renamed, this gate and the comment it "+
		"checks both need updating", fn, path)
	return ""
}

// m50w3ClerkFrontedRoutes returns the "<METHOD> <full path>" routes whose
// effective middleware chain includes appmw.Auth (directly or through a local
// variable such as main.go's `authMiddleware := appmw.Auth(...)`).
//
// It mirrors apiKeyReachableRoutes, for the other authenticator.
func m50w3ClerkFrontedRoutes(t *testing.T) map[string]routeReg {
	t.Helper()
	routes, _ := parseRoutes(t)

	// Resolve `<name> := appmw.Auth(...)` aliases.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	aliases := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		lhs, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		// Package-QUALIFIED: `appmw.Auth`, not any selector named Auth.
		// Substring matching credited `thirdparty.Auth(...)` too (Codex R4, Low).
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Auth" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "appmw" {
			aliases[lhs.Name] = true
		}
		return true
	})
	if len(aliases) == 0 {
		t.Fatal("resolved no appmw.Auth alias from main.go; it declares " +
			"`authMiddleware := appmw.Auth(...)`, so zero means the resolver is blind")
	}

	out := map[string]routeReg{}
	for _, r := range routes {
		for _, m := range r.chain {
			// Either a resolved `x := appmw.Auth(...)` alias, or the
			// constructor written out at the registration site. The literal
			// form is matched with a boundary so `fakeappmw.Auth(` does not
			// count (Codex R4/R5, Low); earlier versions matched the substring
			// "Auth(" minus two exclusions, and then "appmw.Auth(" unanchored.
			//
			// Not covered, and deliberately: an import renamed away from
			// `appmw`, or the middleware reached through a `var` declaration
			// rather than `:=`. Both would make a genuine Clerk route
			// unclassified, which this test reports as a failure (the "behind
			// neither" branch above) rather than silently mislabelling it.
			if aliases[strings.TrimSpace(m)] || m50w3AppmwAuthRE.MatchString(m) {
				out[r.method+" "+r.fullPath] = r
				break
			}
		}
	}
	return out
}

// TestM50W3ExactlyOneProjectListRouteIsAPIKeyReachablePerHandler pins the
// substance behind the count: of ProjectHandler.List's registrations, exactly
// one accepts a Bearer API key (the MCP mount) and the rest do not.
//
// That asymmetry is the whole reason listProjectsForCredential branches on
// middleware.APIKeyProjectID instead of on the route. If a second API-key-fronted
// mount appeared, the narrowing would still be correct — but if the Clerk-fronted
// one ever became API-key-reachable, the web UI's project list would start
// narrowing for API-key callers without anyone having decided that.
func TestM50W3ExactlyOneProjectListRouteIsAPIKeyReachablePerHandler(t *testing.T) {
	for _, tc := range []struct {
		handler         string
		wantReachable   []string
		wantUnreachable []string
	}{
		{
			handler:         "projectHandler.List",
			wantReachable:   []string{"GET /api/v1/mcp/projects"},
			wantUnreachable: []string{"GET /api/v1/projects"},
		},
		{
			handler:         "cliHandler.ListProjects",
			wantReachable:   []string{"GET /api/v1/cli/projects"},
			wantUnreachable: nil,
		},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			reachable := apiKeyReachableRoutes(t)
			var gotReachable, gotUnreachable []string
			for _, r := range m50w3RegistrationsOf(t, tc.handler) {
				key := r.method + " " + r.fullPath
				if _, ok := reachable[key]; ok {
					gotReachable = append(gotReachable, key)
				} else {
					gotUnreachable = append(gotUnreachable, key)
				}
			}
			sort.Strings(gotReachable)
			sort.Strings(gotUnreachable)
			if strings.Join(gotReachable, ", ") != strings.Join(tc.wantReachable, ", ") {
				t.Errorf("%s: API-key-reachable registrations = %v, want %v. A new one has to "+
					"be classified in middleware.apiKeyRouteScope and covered by the handler "+
					"narrowing tests before this list is updated.",
					tc.handler, gotReachable, tc.wantReachable)
			}
			if strings.Join(gotUnreachable, ", ") != strings.Join(tc.wantUnreachable, ", ") {
				t.Errorf("%s: registrations NOT reachable with an API key = %v, want %v. If a "+
					"route left this set it is now behind an API-key chain and a project-scoped "+
					"key will have its answer narrowed there.",
					tc.handler, gotUnreachable, tc.wantUnreachable)
			}
		})
	}
}

// TestM50W3EveryNarrowedRouteHandlerCallsTheSharedDecision is the CI-runnable
// half of the scopeProjectListNarrowed obligation (Codex R2, Medium).
//
// The middleware ADMITS every route classified scopeProjectListNarrowed and
// relies on that route's handler to narrow. Nothing inside internal/middleware
// can check that. Its own pin compares the table against a literal list, so
// adding a route to both keeps it green; and the live-database cross-check in
// internal/handler is behind `//go:build integration`, which no CI workflow runs
// for that package.
//
// This test does the check from main.go, in the default unit suite: for every
// route the table promises to narrow, resolve the handler it is registered with
// and require that handler's body to call listProjectsForCredential — the one
// function that consults middleware.APIKeyProjectID. A route classified narrowed
// whose handler still calls the tenant-wide lookup fails here.
//
// It is a syntactic check: it proves the decision function is CALLED, not that
// its result is used correctly. That part is
// TestM50W3ListProjectsForCredentialPicksTheRightLookup (unit) and the live
// handler suite (integration).
func TestM50W3EveryNarrowedRouteHandlerCallsTheSharedDecision(t *testing.T) {
	promised := appmw.APIKeyProjectListNarrowedRoutes()
	if len(promised) == 0 {
		t.Fatal("middleware classifies no route scopeProjectListNarrowed — either the " +
			"classification was removed (delete this test with it) or the accessor is blind")
	}

	routes, _ := parseRoutes(t)
	byKey := map[string]routeReg{}
	for _, r := range routes {
		byKey[r.method+" "+r.fullPath] = r
	}

	callers := m50w3HandlerFuncsCalling(t, "listProjectsForCredential")
	if len(callers) == 0 {
		t.Fatal("no function in internal/handler calls listProjectsForCredential; the " +
			"narrowing decision is wired to nothing")
	}

	for _, key := range promised {
		route, ok := byKey[key]
		if !ok {
			t.Errorf("middleware classifies %q scopeProjectListNarrowed, but main.go registers "+
				"no such route. TestM50W2APIKeyReachableRoutesAreAllClassified should have "+
				"caught this; if it did not, the table and the router have diverged.", key)
			continue
		}
		// `projectHandler.List` -> receiver type `ProjectHandler`, method `List`.
		// Matching on the method name alone would credit an unrelated
		// `FooHandler.List` with ProjectHandler.List's narrowing (Codex R3,
		// Medium), so the receiver is resolved through main.go's constructor
		// call before the lookup.
		handler := strings.TrimSpace(route.handler)
		qualified, err := m50w3QualifyHandler(t, handler)
		if err != nil {
			t.Errorf("%q is classified scopeProjectListNarrowed but its handler %q could not "+
				"be resolved to a `handler.<Type>` method (%v). Unresolvable means unchecked, "+
				"which for this classification means a route that may not narrow at all.",
				key, handler, err)
			continue
		}
		if !callers[qualified] {
			t.Errorf("%q is classified scopeProjectListNarrowed — the middleware admits it "+
				"unconditionally and expects its handler to narrow — but %s does not call "+
				"listProjectsForCredential. Methods that do: %v. Either route it through the "+
				"shared decision or classify the route differently.",
				key, qualified, m50w3SortedKeys(callers))
		}
	}
}

// m50w3QualifyHandler turns main.go's `projectHandler.List` into
// `ProjectHandler.List` by resolving the receiver VARIABLE to the handler type
// its constructor returns.
//
// main.go builds every handler as `<var> := handler.New<Type>(...)`, so the type
// is read off the constructor name. That is a convention, not a guarantee, which
// is why an unresolvable handler is reported as a failure by the caller rather
// than skipped: for this classification "unchecked" and "not narrowing" have the
// same consequence.
func m50w3QualifyHandler(t *testing.T, expr string) (string, error) {
	t.Helper()
	varName, method, ok := strings.Cut(expr, ".")
	if !ok {
		return "", fmt.Errorf("%q is not of the form <var>.<Method>", expr)
	}
	if strings.Contains(method, ".") {
		return "", fmt.Errorf("%q has more than one selector", expr)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	var typeName string
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		lhs, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || lhs.Name != varName {
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
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "handler" {
			return true
		}
		if ctor := sel.Sel.Name; strings.HasPrefix(ctor, "New") {
			typeName = strings.TrimPrefix(ctor, "New")
		}
		return true
	})
	if typeName == "" {
		return "", fmt.Errorf("no `%s := handler.New<Type>(...)` assignment in main.go", varName)
	}
	return typeName + "." + method, nil
}

// m50w3HandlerFuncsCalling returns the "<ReceiverType>.<Method>" names in
// package internal/handler whose body contains a direct call to `fn`.
//
// Receiver-QUALIFIED. An earlier version keyed on the method name alone, which
// meant any `FooHandler.List` was credited with `ProjectHandler.List`'s
// narrowing (Codex R3, Medium). Plain functions are recorded unqualified so the
// map is still usable for them; route handlers always have a receiver.
func m50w3HandlerFuncsCalling(t *testing.T, fn string) map[string]bool {
	t.Helper()
	const dir = "../../internal/handler"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	out := map[string]bool{}
	var files int
	for _, e := range entries {
		name := e.Name()
		// Non-test .go files only. parser.ParseDir would do the walking but is
		// deprecated (it ignores build tags when grouping files into packages);
		// walking here keeps the set explicit.
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files++
		for _, decl := range f.Decls {
			decl, ok := decl.(*ast.FuncDecl)
			if !ok || decl.Body == nil {
				continue
			}
			name := decl.Name.Name
			if decl.Recv != nil && len(decl.Recv.List) == 1 {
				typ := decl.Recv.List[0].Type
				if star, ok := typ.(*ast.StarExpr); ok {
					typ = star.X
				}
				if ident, ok := typ.(*ast.Ident); ok {
					name = ident.Name + "." + name
				}
			}
			ast.Inspect(decl.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == fn {
					out[name] = true
				}
				return true
			})
		}
	}
	if files < 5 {
		t.Fatalf("parsed only %d non-test files from %s — the walk is blind", files, dir)
	}
	return out
}

func m50w3SortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func m50w3RouteList(routes []routeReg) string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, fmt.Sprintf("%s %s (main.go:%d)", r.method, r.fullPath, r.line))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
