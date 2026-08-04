package middleware

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// M52 — the AST half of the tenant-binding gate.
//
// This file derives, from cmd/server/main.go, the set of routes whose
// effective middleware chain contains no appmw.TenantTx, and compares it
// against noTenantTxRouteBinding in both directions. That comparison is what
// makes the table an ENUMERATION rather than a claim.
//
// # Why a source-level test, and why it lives HERE
//
// Echo exposes no way to enumerate a route's middleware after registration
// (e.Routes() returns method / path / handler-name only), so the registration
// site is the only place the wiring is observable. cmd/server already has two
// source-level sweeps built on the same idea (m47r_route_role_gate_test.go,
// m50w2_apikey_project_scope_test.go). This one parses main.go by PATH from
// the middleware package instead of reusing their parser, because the table it
// checks lives here and a test in package `main` cannot be imported from
// anywhere. The cost is a second route parser; the benefit is that the table
// and the thing that keeps the table honest sit in one package.
//
// # Scan unit — stated exactly, because "complete" is a claim
//
// One file: apps/api/cmd/server/main.go, parsed with go/parser into a single
// *ast.File. Within it:
//
//	ROOT        the identifier bound by `<name> := echo.New()`, resolved from
//	            the source rather than assumed to be `e`, with an empty prefix
//	            and an empty middleware list.
//	GROUPS      every `<name> := <recv>.Group("<prefix>", mw...)` assignment
//	            whose <recv> is an identifier already known to be a group.
//	            Prefix and middleware are inherited from the parent, so a
//	            nested group's chain is fully resolved. Source order guarantees
//	            a parent is registered before its children.
//	GLOBAL      every `<root>.Use(<mw>)` argument, prepended to EVERY route's
//	            chain (that is what echo.Echo.Use means).
//	ROUTES      every *ast.CallExpr whose Fun is a SelectorExpr with Sel in
//	            {GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, Any}, whose
//	            receiver is an identifier known to be a group, with >= 2
//	            arguments and a string-literal first argument.
//	CHAIN       global `e.Use` args ++ the group's inherited middleware ++ the
//	            registration's own args[2:], each rendered with go/printer.
//	TenantTx?   any chain entry whose rendered text contains "TenantTx(",
//	            after expanding local `x := <expr>` aliases up to 8 levels.
//
// Three guards keep that unit honest rather than merely stated:
// TestM52RouteScanUnitCoversEveryRegistrationForm (no route is registered
// through a method or a receiver shape this parser does not read),
// TestM52MainGoIsTheOnlyRouter (no other non-test file holds a router), and
// TestM52RouteCountsArePinned (the parser did not go blind, and the count of
// unbound routes is what it was).
//
// # What the scan unit still cannot see
//
// A middleware that binds the tenant under a name other than TenantTx is read
// as "no TenantTx" and therefore DEMANDS a classification. That direction is
// deliberate: it produces a request for a written reason, never a silent pass.
// The opposite direction — a chain entry whose text contains "TenantTx(" but
// which does not bind — would pass silently; nothing in main.go has that
// shape today, and appmw.TenantTx is a single function.
// ---------------------------------------------------------------------------

// mainGoPath is the router this gate reads. Relative to the middleware package
// directory, which is where `go test` runs.
const mainGoPath = "../../cmd/server/main.go"

// apiRootPath is the module root (apps/api), relative to this package.
const apiRootPath = "../.."

// echoImportPath is the router library. A non-test file that does not import
// it cannot hold an *echo.Echo or an *echo.Group, and therefore cannot
// register a route — which is what makes TestM52MainGoIsTheOnlyRouter cheap
// and precise.
const echoImportPath = "github.com/labstack/echo/v4"

// m52RouteVerbs are the echo.Group / echo.Echo methods that register a route.
var m52RouteVerbs = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true, "Any": true,
}

// m52NonRoutingGroupMethods are the other methods main.go is allowed to call
// on the Echo instance or on a group. Anything outside these two sets is a
// registration form this parser does not read — see
// TestM52RouteScanUnitCoversEveryRegistrationForm.
var m52NonRoutingGroupMethods = map[string]bool{
	"Group": true, // sub-group declaration: parsed
	"Use":   true, // middleware: parsed (global) / inherited (group)
	"Start": true, // e.Start(addr): not a registration
}

type m52Route struct {
	method   string
	fullPath string
	handler  string
	chain    []string
	line     int
}

type m52Group struct {
	prefix string
	mw     []string
}

// m52ParseMainGo returns every route registration in main.go with its
// effective middleware chain resolved, plus the alias map used to expand
// chain entries.
func m52ParseMainGo(t *testing.T) (routes []m52Route, groups map[string]m52Group, aliases map[string]string) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGoPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", mainGoPath, err)
	}
	render := func(n ast.Node) string {
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, n); err != nil {
			t.Fatalf("render node: %v", err)
		}
		return buf.String()
	}

	// Pass 1 — local aliases. `x := <expr>` for any single-assignment
	// statement. Chain entries that are bare identifiers are expanded through
	// this map so a middleware held in a variable is not mistaken for
	// something else.
	aliases = map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		aliases[name.Name] = render(assign.Rhs[0])
		return true
	})

	// Pass 2 — groups, in source order so a parent is always known first.
	//
	// The root is whatever `<name> := echo.New()` binds rather than a
	// hardcoded `e`: renaming the Echo instance would otherwise silently
	// empty every set this file computes.
	root := m52EchoInstanceName(t, file)
	groups = map[string]m52Group{root: {}}
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
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		parent, known := groups[recv.Name]
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
		groups[name.Name] = m52Group{prefix: parent.prefix + prefix, mw: mw}
		return true
	})
	if len(groups) < 5 {
		t.Fatalf("resolved only %d route groups from %s — the parser is blind, not the router",
			len(groups), mainGoPath)
	}

	// Pass 3 — global middleware installed with e.Use(...). echo.Echo.Use
	// applies to every route, including the ones registered directly on `e`,
	// so it belongs in front of every chain. Nothing global binds a tenant
	// today; collecting it means a future `e.Use(appmw.TenantTx(db))` would
	// not make all 181 routes look unbound at once.
	var global []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Use" {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != root {
			return true
		}
		for _, a := range call.Args {
			global = append(global, render(a))
		}
		return true
	})

	// Pass 4 — the registrations themselves.
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !m52RouteVerbs[sel.Sel.Name] {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		grp, known := groups[recv.Name]
		if !known || len(call.Args) < 2 {
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
		chain := append([]string{}, global...)
		chain = append(chain, grp.mw...)
		for _, a := range call.Args[2:] {
			chain = append(chain, render(a))
		}
		routes = append(routes, m52Route{
			method:   sel.Sel.Name,
			fullPath: grp.prefix + path,
			handler:  m52Normalise(render(call.Args[1])),
			chain:    chain,
			line:     fset.Position(call.Pos()).Line,
		})
		return true
	})
	sort.Slice(routes, func(i, j int) bool { return routes[i].line < routes[j].line })
	return routes, groups, aliases
}

// m52EchoInstanceName returns the identifier bound by `<name> := echo.New()`.
//
// Deriving it removes the last hardcoded assumption about main.go's shape: a
// rename would otherwise leave `groups` seeded with a name nothing matches,
// every route unresolved, and the sweep passing on an empty set. It fails
// rather than defaulting, because a default is what would hide the rename.
func m52EchoInstanceName(t *testing.T, file *ast.File) string {
	t.Helper()
	echoPkg := m52EchoPackageName(file)
	found := ""
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		if !m52IsEchoSelectorCall(assign.Rhs[0], echoPkg, "New") {
			return true
		}
		if found != "" && found != name.Name {
			t.Fatalf("main.go binds %s.New() to both %q and %q; this gate assumes a single "+
				"Echo instance and would resolve routes against only one of them",
				echoPkg, found, name.Name)
		}
		found = name.Name
		return true
	})
	if found == "" {
		t.Fatalf("found no `<name> := %s.New()` in %s. Every set this file computes is "+
			"seeded from that instance, so without it the sweep would pass on an empty "+
			"route set.", echoPkg, mainGoPath)
	}
	return found
}

// m52EchoPackageName returns the local name the file uses for the echo
// package ("echo" unless the import is aliased).
func m52EchoPackageName(file *ast.File) string {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != echoImportPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return "echo"
	}
	return ""
}

// m52IsEchoSelectorCall reports whether expr is `<echoPkg>.<sel>(...)`.
func m52IsEchoSelectorCall(expr ast.Expr, echoPkg, selName string) bool {
	if echoPkg == "" {
		return false
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != selName {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == echoPkg
}

// m52Normalise collapses runs of whitespace so a rendered handler expression
// compares stably against the table's single-line form.
func m52Normalise(s string) string { return strings.Join(strings.Fields(s), " ") }

// m52Expand resolves a chain entry through the alias map until it stops
// changing (bounded), so `authMiddleware` is compared as what it was assigned.
func m52Expand(entry string, aliases map[string]string) string {
	cur := strings.TrimSpace(entry)
	for i := 0; i < 8; i++ {
		next, ok := aliases[cur]
		if !ok {
			break
		}
		cur = strings.TrimSpace(next)
	}
	return cur
}

// m52HasTenantTx reports whether an effective chain carries appmw.TenantTx.
func m52HasTenantTx(chain []string, aliases map[string]string) bool {
	for _, entry := range chain {
		if strings.Contains(m52Expand(entry, aliases), "TenantTx(") {
			return true
		}
	}
	return false
}

// m52NoTenantTxRoutes returns the derived "<METHOD> <path>" → route map.
func m52NoTenantTxRoutes(t *testing.T) map[string]m52Route {
	t.Helper()
	routes, _, aliases := m52ParseMainGo(t)
	if len(routes) < 100 {
		t.Fatalf("parsed only %d routes from %s — the parser is blind, not the router",
			len(routes), mainGoPath)
	}
	out := map[string]m52Route{}
	for _, r := range routes {
		if m52HasTenantTx(r.chain, aliases) {
			continue
		}
		out[r.method+" "+r.fullPath] = r
	}
	return out
}

// TestM52NoTenantTxRoutesAreAllClassified is the sweep.
//
// Both directions matter. A MISSING entry is the /reanalyse defect arriving
// again: a route that touches the database with nothing binding the tenant and
// nobody having written down why that is safe. A STALE entry is worse than
// useless: it silently pre-approves a future route that happens to reuse the
// same method and path.
func TestM52NoTenantTxRoutesAreAllClassified(t *testing.T) {
	derived := m52NoTenantTxRoutes(t)
	if len(derived) == 0 {
		t.Fatal("found no TenantTx-less routes in main.go — the sweep is blind (main.go " +
			"has always had at least the two provider webhooks and /health)")
	}

	classified := noTenantTxRouteBinding

	var missing []string
	for key, r := range derived {
		if _, ok := classified[key]; !ok {
			missing = append(missing, key+"  (main.go:"+strconv.Itoa(r.line)+", "+r.handler+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s is registered with NO appmw.TenantTx in its effective chain and is not "+
			"classified in middleware.noTenantTxRouteBinding.\n"+
			"Nothing binds app.current_tenant_id for this route, so any read or write of an "+
			"RLS-protected table on it lands on a pooled connection where the policy "+
			"predicate is either NULL (zero rows — a false 404 even for your own data) or "+
			"''::UUID (22P02 — a 500 for every input). That is the defect this table exists "+
			"for; see the file header.\n"+
			"Add an entry: TenantBindingBindsItself (name BindsVia and a ProvedBy test that "+
			"drives it on a poisoned connection) or TenantBindingTouchesNoRLSTable (name "+
			"every table the path touches; each is checked against live pg_class).", m)
	}

	var stale []string
	for key := range classified {
		if _, ok := derived[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("middleware.noTenantTxRouteBinding classifies %q, which main.go no longer "+
			"registers without TenantTx — either the route is gone, or it now carries "+
			"TenantTx and the middleware binds it. Drop the entry: a stale rule silently "+
			"pre-approves a future route that reuses the path.", s)
	}
}

// TestM52ClassifiedRoutesStillHaveTheHandlerTheyWereClassifiedFor closes the
// gap the route set alone leaves open.
//
// A classification is a statement about CODE, not about a URL. Re-pointing
// `GET /api/v1/health` at a handler that queries the database changes nothing
// this file's route sweep can see — same method, same path, still no TenantTx
// — while making the recorded reason false. Comparing the rendered handler
// argument costs one string per route and fails with the new text in the
// message.
//
// Whitespace is normalised, so gofmt churn inside an inline closure does not
// trip it; a changed identifier or a changed literal does.
func TestM52ClassifiedRoutesStillHaveTheHandlerTheyWereClassifiedFor(t *testing.T) {
	derived := m52NoTenantTxRoutes(t)
	for _, key := range NoTenantTxRouteKeys() {
		rule := noTenantTxRouteBinding[key]
		r, ok := derived[key]
		if !ok {
			continue // reported by the sweep above
		}
		if r.handler != rule.Handler {
			t.Errorf("%s is served by a different handler than the one it was classified for.\n"+
				"  classified for: %s\n"+
				"  main.go:%d now: %s\n"+
				"The classification (%s) and its reason were written about the old handler. "+
				"Re-read the new one, confirm the reason still holds, then update the Handler "+
				"field.", key, rule.Handler, r.line, r.handler, rule.Kind)
		}
	}
}

// TestM52EveryRuleCarriesItsEvidence enforces the shape of the table itself:
// a classification with no reason, or a BindsItself with nothing naming the
// binding or driving it, is a comment pretending to be a gate.
func TestM52EveryRuleCarriesItsEvidence(t *testing.T) {
	for _, key := range NoTenantTxRouteKeys() {
		rule := noTenantTxRouteBinding[key]
		if strings.TrimSpace(rule.Why) == "" {
			t.Errorf("%s has no Why. The reason is a field precisely so a route cannot be "+
				"classified by copying its neighbour.", key)
		}
		if strings.TrimSpace(rule.Handler) == "" {
			t.Errorf("%s has no Handler, so nothing pins which code the classification is "+
				"about.", key)
		}
		switch rule.Kind {
		case TenantBindingBindsItself:
			if len(rule.BindsVia) == 0 {
				t.Errorf("%s is BindsItself but names no BindsVia function.", key)
			}
			if strings.TrimSpace(rule.ProvedBy) == "" {
				t.Errorf("%s is BindsItself but names no ProvedBy test. BindsItself is a "+
					"promise about code in another package; unmeasured, it is exactly the "+
					"comment that was already in main.go when /reanalyse shipped broken.", key)
			}
			if len(rule.RLSExemptTables) != 0 {
				t.Errorf("%s is BindsItself but also lists RLSExemptTables. The exempt-table "+
					"list is only checked for TouchesNoRLSTable rules, so listing it here "+
					"would read as verified evidence while nothing verifies it.", key)
			}
		case TenantBindingTouchesNoRLSTable:
			if rule.ProvedBy != "" || len(rule.BindsVia) != 0 {
				t.Errorf("%s is TouchesNoRLSTable but names BindsVia/ProvedBy. If it really "+
					"binds something, classify it BindsItself so the binding gets driven.", key)
			}
		default:
			t.Errorf("%s has an unknown Kind %q. Add a case here and decide what evidence it "+
				"must carry before the table accepts it.", key, rule.Kind)
		}
	}
}

// TestM52EveryBindsItselfRuleNamesAnExistingTest resolves each ProvedBy name
// against the test sources, so a typo or a deleted test is caught here rather
// than by nobody.
//
// It checks EXISTENCE of a `func <name>(t *testing.T)` declaration, not what
// the function does. What the drives actually assert is pinned by
// TestM52EveryBindsItselfRouteIsDriven in internal/handler, which iterates
// this same table against a live database.
func TestM52EveryBindsItselfRuleNamesAnExistingTest(t *testing.T) {
	declared := m52TestFuncNames(t)
	for _, key := range NoTenantTxRouteKeys() {
		rule := noTenantTxRouteBinding[key]
		if rule.Kind != TenantBindingBindsItself {
			continue
		}
		if file, ok := declared[rule.ProvedBy]; !ok {
			t.Errorf("%s names ProvedBy %q, which no test function in apps/api declares.",
				key, rule.ProvedBy)
		} else if testing.Verbose() {
			t.Logf("%s → %s (%s)", key, rule.ProvedBy, file)
		}
	}
}

// m52SkipDir reports whether a directory is outside the source tree these
// walks care about.
func m52SkipDir(name string) bool {
	return name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".")
}

// m52TestFuncNames returns every `func TestXxx(t *testing.T)` declared under
// apps/api, mapped to the file that declares it. Build tags are irrelevant
// here: go/parser reads the declaration regardless, which is what makes the
// integration-tagged drives visible to this untagged test.
func m52TestFuncNames(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(apiRootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// path == apiRootPath is the walk root itself ("../.."), whose
			// base name starts with a dot; skipping it would make the walk
			// silently empty.
			if path != apiRootPath && m52SkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // a file that does not parse is not this gate's business
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			out[fn.Name.Name] = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", apiRootPath, err)
	}
	if len(out) < 100 {
		t.Fatalf("found only %d test functions under %s — the walk is blind", len(out), apiRootPath)
	}
	return out
}

// TestM52RouteScanUnitCoversEveryRegistrationForm is the completeness guard
// for the stated scan unit.
//
// The parser reads eight verb methods. Echo also offers Add, Match, Static,
// File, RouteNotFound and Host, none of which main.go uses — and if one were
// used, its routes would be INVISIBLE to the sweep above, which would then
// report "all classified" while a new unbound route existed. Rather than
// teach the parser six more shapes speculatively, this asserts that no group
// receiver is called with anything outside the two known sets.
func TestM52RouteScanUnitCoversEveryRegistrationForm(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGoPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", mainGoPath, err)
	}
	_, groups, _ := m52ParseMainGo(t)

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		recv, isIdent := sel.X.(*ast.Ident)
		if isIdent {
			if _, isGroup := groups[recv.Name]; !isGroup {
				// Some other receiver entirely — but if it is being called
				// with a verb name it may still be a router this parser has
				// not resolved (a group passed in as a parameter, say).
				if m52RouteVerbs[name] {
					t.Errorf("main.go:%d calls %s.%s(...) on a receiver this gate did not "+
						"resolve to a route group. If %s is a router, the routes registered "+
						"on it are invisible to TestM52NoTenantTxRoutesAreAllClassified.",
						fset.Position(call.Pos()).Line, recv.Name, name, recv.Name)
				}
				return true
			}
			if m52RouteVerbs[name] || m52NonRoutingGroupMethods[name] {
				return true
			}
			t.Errorf("main.go:%d calls %s.%s(...), which this gate's parser does not read. "+
				"If it registers a route, the route is invisible to "+
				"TestM52NoTenantTxRoutesAreAllClassified and could be unbound without anyone "+
				"being told. Teach m52ParseMainGo the shape, or add %q to "+
				"m52NonRoutingGroupMethods if it registers nothing.",
				fset.Position(call.Pos()).Line, recv.Name, name, name)
			return true
		}
		// A non-identifier receiver: `e.Group("/x", mw).GET(...)` chains the
		// registration onto a group that was never assigned to a variable, so
		// pass 2 never saw it and the route is invisible. main.go assigns
		// every group today; this fires if that stops being true.
		if m52RouteVerbs[name] {
			t.Errorf("main.go:%d registers %s(...) on an unnamed receiver (%s). This gate "+
				"resolves middleware chains through group VARIABLES, so a chained "+
				"registration is invisible to it. Assign the group to a variable first.",
				fset.Position(call.Pos()).Line, name, m52Normalise(renderNode(fset, sel.X)))
		}
		return true
	})
}

// renderNode prints an AST node with go/printer, for error messages.
func renderNode(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, n); err != nil {
		return "<unprintable>"
	}
	return buf.String()
}

// TestM52MainGoIsTheOnlyRouter underwrites "one file is the whole scan unit".
//
// If a second non-test file held an Echo instance or a group, the routes
// registered on it would never be seen by the sweep. The allowlist is empty on
// purpose: today exactly one non-test file does.
//
// # Why the signal is the echo package and not a text pattern
//
// The first version of this test looked for the literal `.Group("`, which
// `slog.Group("k", ...)` — a perfectly ordinary logging call — would have
// matched. Reddening CI on a log statement is exactly the kind of false
// positive that gets a gate switched off.
//
// A router object can only enter a file two ways: it is constructed there
// (`echo.New()`), or it arrives as a value of type `*echo.Echo` / `*echo.Group`
// — and both spellings are package-qualified, so the check is: does this file
// import github.com/labstack/echo/v4, and if so does it mention that package's
// New / Echo / Group identifiers? A file that does not import echo at all is
// skipped without reading further.
func TestM52MainGoIsTheOnlyRouter(t *testing.T) {
	// Files exempted from the check, with the reason. Empty today.
	allowed := map[string]string{}

	mainAbs, err := filepath.Abs(mainGoPath)
	if err != nil {
		t.Fatalf("abs %s: %v", mainGoPath, err)
	}

	// The echo identifiers that can only mean "a router lives here".
	// `echo.Context`, `echo.HandlerFunc`, `echo.MiddlewareFunc`,
	// `echo.NewHTTPError` and friends are what handler and middleware files
	// legitimately use, and none of them can register a route.
	routerIdents := map[string]bool{"New": true, "Echo": true, "Group": true}

	fset := token.NewFileSet()
	var offenders []string
	err = filepath.WalkDir(apiRootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != apiRootPath && m52SkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		abs, aerr := filepath.Abs(path)
		if aerr == nil && abs == mainAbs {
			return nil
		}
		if _, ok := allowed[filepath.ToSlash(path)]; ok {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v — this walk cannot judge a file it cannot read, and a "+
				"silent skip is how a second router would hide", path, perr)
			return nil
		}
		echoPkg := m52EchoPackageName(file)
		if echoPkg == "" {
			return nil // does not import echo: cannot hold a router
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !routerIdents[sel.Sel.Name] {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != echoPkg {
				return true
			}
			offenders = append(offenders, filepath.ToSlash(path)+" ("+echoPkg+"."+sel.Sel.Name+
				" at line "+strconv.Itoa(fset.Position(sel.Pos()).Line)+")")
			return false
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", apiRootPath, err)
	}
	sort.Strings(offenders)
	for _, f := range offenders {
		t.Errorf("%s constructs an Echo instance or a route group outside cmd/server/main.go. "+
			"The M52 tenant-binding sweep reads main.go only, so any route registered there "+
			"is unclassified AND invisible. Either move the registration into main.go, or "+
			"widen the scan unit and record the file in this test's `allowed` map with a "+
			"reason.", f)
	}
}

// TestM52RouteCountsArePinned pins the size of the surface THIS gate owns,
// and only that.
//
// The exact number pinned is the count of routes with no TenantTx — 9 as of
// 2026-08-05. It changes only when somebody adds or removes an unbound route,
// which is precisely the event a reviewer should be told about, and which
// already requires a deliberate edit to the table next door.
//
// The TOTAL registration count is deliberately NOT pinned to an exact value.
// 181 routes exist today, but adding a 182nd on a TenantTx chain is correct
// code that this gate has no business reddening; an exact pin would make every
// unrelated route addition fail a tenant-binding test, and a gate that cries
// on correct changes is a gate somebody deletes. The lower bound is kept
// because a parser that suddenly resolves 4 routes IS this gate failing
// silently.
func TestM52RouteCountsArePinned(t *testing.T) {
	const (
		minTotal       = 100
		wantNoTenantTx = 9
		minGroups      = 5
	)
	routes, groups, aliases := m52ParseMainGo(t)
	if len(routes) < minTotal {
		t.Errorf("resolved %d routes from main.go, want at least %d — the parser is blind, "+
			"not the router", len(routes), minTotal)
	}
	n := 0
	for _, r := range routes {
		if !m52HasTenantTx(r.chain, aliases) {
			n++
		}
	}
	if n != wantNoTenantTx {
		t.Errorf("%d routes carry no TenantTx, pinned at %d. Every one of them is a route "+
			"where nothing binds app.current_tenant_id for the handler; if the change is "+
			"intended, classify the new route in noTenantTxRouteBinding and update this "+
			"number in the same commit.", n, wantNoTenantTx)
	}
	if len(groups) < minGroups {
		t.Errorf("resolved %d route groups, want at least %d — a group that fails to resolve "+
			"takes its whole middleware chain with it, and every route on it would then read "+
			"as unbound", len(groups), minGroups)
	}
}
