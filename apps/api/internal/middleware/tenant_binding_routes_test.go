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
//	            the source rather than assumed to be `e`.
//	GLOBAL      every `<root>.Use(...)` and `<root>.Pre(...)` argument.
//	            echo.Echo applies these at request time to every route
//	            regardless of registration order, so they are collected
//	            order-INSENSITIVELY and prepended to every chain.
//	GROUPS      every binding — `x := ...`, `x = ...` or `var x = ...` — whose
//	            value is `<knownGroup>.Group("<prefix>", mw...)`. The child
//	            copies the parent's prefix and its middleware AS OF THAT POINT,
//	            which is what echo.Group.Group does.
//	GROUP Use   `<knownGroup>.Use(mw...)` appends to that group's middleware
//	            for every registration that FOLLOWS it, which is what
//	            echo.Group.Add reads. This one IS order-sensitive, so the walk
//	            below is a single ordered pass rather than separate passes.
//	ROUTES      every *ast.CallExpr whose Fun is a SelectorExpr with Sel in
//	            m52RouteVerbs (echo's nine HTTP-verb methods plus Any — every
//	            method with the `(path, handler, mw...)` shape), whose receiver
//	            is an identifier known to be a group, with >= 2 arguments and a
//	            string-literal first argument.
//	CHAIN       GLOBAL ++ the group's middleware at that point ++ the
//	            registration's own args[2:], each rendered with go/printer.
//	TenantTx?   any chain entry whose rendered text contains "TenantTx(", after
//	            expanding identifiers that main.go binds EXACTLY ONCE.
//
// Four guards keep that unit honest rather than merely stated:
// TestM52RouteScanUnitCoversEveryRegistrationForm (nothing is registered
// through a form this parser does not read), TestM52MainGoIsTheOnlyRouter (no
// other non-test file constructs a router or registers a route),
// TestM52MainGoDoesNotAliasTheRouterTypes (no `type X = echo.Group`, which
// would let another file hold a router without importing echo), and
// TestM52ParserIsNotBlind (the walk resolved a plausible amount of main.go).
//
// # What the scan unit still cannot see, and which way it errs
//
// The rule for every gap is the same: an unresolved thing must read as "no
// TenantTx", so it DEMANDS a written classification rather than passing
// silently.
//
//   - An identifier main.go binds more than once is not expanded at all
//     (m52Expand), because this walk has no flow analysis and the last write
//     is not necessarily the one Echo captured. A middleware held in a
//     reassigned variable therefore reads as unbound.
//   - A middleware that binds the tenant under a name other than TenantTx
//     reads as unbound.
//   - A chain entry whose text contains "TenantTx(" but which does not bind
//     WOULD pass silently. appmw.TenantTx is a single function and nothing in
//     main.go has that shape; this is the one direction the walk trusts.
//
// ---------------------------------------------------------------------------

// mainGoPath is the router this gate reads. Relative to the middleware package
// directory, which is where `go test` runs.
const mainGoPath = "../../cmd/server/main.go"

// apiRootPath is the module root (apps/api), relative to this package.
const apiRootPath = "../.."

// echoImportPath is the router library, used to resolve the local name main.go
// gives the package (it could be aliased).
const echoImportPath = "github.com/labstack/echo/v4"

// m52RouteVerbs are the echo.Group / echo.Echo methods that register a route
// with the signature this parser reads: (path string, h HandlerFunc,
// m ...MiddlewareFunc).
//
// This is echo v4's full set of that shape — the nine HTTP verbs plus Any.
// CONNECT and TRACE are here for completeness rather than because main.go uses
// them; the alternative (leaving them out) would have routed them through
// TestM52RouteScanUnitCoversEveryRegistrationForm's "unknown method" branch,
// which is loud but demands a code change to accept a perfectly ordinary
// registration. Echo's OTHER registration methods — Add, Match, Static, File,
// Host, RouteNotFound — take a different shape and are deliberately NOT read;
// that test is what makes their absence audible instead of silent.
var m52RouteVerbs = map[string]bool{
	"CONNECT": true, "DELETE": true, "GET": true, "HEAD": true,
	"OPTIONS": true, "PATCH": true, "POST": true, "PUT": true,
	"TRACE": true, "Any": true,
}

// m52UnreadRegistrationMethods are echo's OTHER route-registering methods —
// the ones whose signature this parser does not read. A call to any of them on
// a resolved group registers a route that the sweep cannot see.
//
// This is a denylist rather than an allowlist of everything-else on purpose.
// The first version allowlisted {verbs, Group, Use, Start} and errored on
// anything else, which would have reddened CI for `e.Shutdown(ctx)` or
// `len(e.Routes())` — correct code that registers nothing. Naming the
// registering APIs instead costs one thing: if a future echo release adds a
// tenth way to register a route, this list goes stale and the new form is a
// MISS rather than a false alarm. That is the right direction to be wrong in.
//
// Taken from echo v4.13.4's echo.go / group.go / echo_fs.go / group_fs.go.
var m52UnreadRegistrationMethods = map[string]bool{
	"Add":            true, // (method, path, h, mw...) — method is arg 0
	"Match":          true, // ([]string, path, h, mw...)
	"Static":         true, // (prefix, root)
	"StaticFS":       true, // (pathPrefix, fs)
	"File":           true, // (path, file, mw...)
	"FileFS":         true, // (path, file, fs, mw...)
	"Host":           true, // returns a per-host router
	"RouteNotFound":  true, // (path, h, mw...) — a real route in echo v4
	"AddRoute":       true, // (Routable)
	"AddRouteToHost": true, // (host, Routable)
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
// effective middleware chain resolved, plus the alias map used to expand chain
// entries.
//
// The group/route walk is a SINGLE ordered pass, which matters: echo.Group.Use
// appends to a group's middleware for registrations that follow it, and
// echo.Group.Group snapshots the parent's middleware at the moment the child
// is created. Two independent passes would get both wrong.
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

	// Aliases: identifiers main.go binds EXACTLY ONCE, mapped to the rendered
	// value. Chain entries that are bare identifiers are expanded through this
	// so a middleware held in a variable is compared as what it was assigned.
	//
	// The once-only rule is the whole of the flow analysis here. A reassigned
	// identifier has no single answer this walk can defend — the last write is
	// not necessarily the one Echo captured — so it is left unexpanded, which
	// makes its route read as unbound and demand a classification. That is the
	// safe direction; guessing would be the other one.
	bindingCount := map[string]int{}
	bindingText := map[string]string{}
	m52EachBinding(file, func(name string, rhs ast.Expr) {
		bindingCount[name]++
		bindingText[name] = render(rhs)
	})
	aliases = map[string]string{}
	for name, n := range bindingCount {
		if n == 1 {
			aliases[name] = bindingText[name]
		}
	}

	root := m52EchoInstanceName(t, file)

	// Global middleware: `<root>.Use(...)` and `<root>.Pre(...)`. echo.Echo
	// applies both at request time to every route however it was registered,
	// so this pass is order-insensitive and its result prefixes every chain.
	var global []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Use" && sel.Sel.Name != "Pre") {
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

	// The ordered walk. ast.Inspect visits a single file in source order, and
	// main.go's router setup is one linear function body, so source order is
	// execution order.
	groups = map[string]m52Group{root: {}}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt, *ast.ValueSpec:
			m52VisitBindingNode(node, func(name string, rhs ast.Expr) {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					return
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Group" || len(call.Args) == 0 {
					return
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok {
					return
				}
				parent, known := groups[recv.Name]
				if !known {
					return
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return
				}
				prefix, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return
				}
				// echo.Group.Group copies the parent's middleware as it stands
				// NOW; a later parent Use does not reach this child.
				mw := append([]string{}, parent.mw...)
				for _, a := range call.Args[1:] {
					mw = append(mw, render(a))
				}
				groups[name] = m52Group{prefix: parent.prefix + prefix, mw: mw}
			})
			return true

		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
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

			// `<group>.Use(mw...)`: appends for every registration that
			// FOLLOWS, which is what echo.Group.Add reads. The root's Use was
			// already handled above and is global rather than positional.
			if sel.Sel.Name == "Use" {
				if recv.Name == root {
					return true
				}
				mw := append([]string{}, grp.mw...)
				for _, a := range node.Args {
					mw = append(mw, render(a))
				}
				groups[recv.Name] = m52Group{prefix: grp.prefix, mw: mw}
				return true
			}

			if !m52RouteVerbs[sel.Sel.Name] || len(node.Args) < 2 {
				return true
			}
			lit, ok := node.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			path, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			chain := append([]string{}, global...)
			chain = append(chain, grp.mw...)
			for _, a := range node.Args[2:] {
				chain = append(chain, render(a))
			}
			routes = append(routes, m52Route{
				method:   sel.Sel.Name,
				fullPath: grp.prefix + path,
				handler:  m52Normalise(render(node.Args[1])),
				chain:    chain,
				line:     fset.Position(node.Pos()).Line,
			})
			return true
		}
		return true
	})

	if len(groups) < 5 {
		t.Fatalf("resolved only %d route groups from %s — the parser is blind, not the router",
			len(groups), mainGoPath)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].line < routes[j].line })
	return routes, groups, aliases
}

// m52EachBinding visits every single-value binding of a plain identifier in
// source order, in both spellings Go offers: the short form `x := <expr>` and
// the declaration `var x = <expr>` (including inside a grouped `var (...)`).
//
// Handling only the short form was a blind spot rather than a simplification:
// a group declared `var api = e.Group("/api/v1")` would have been unknown to
// pass 2, its routes would have had an unresolved receiver, and their
// middleware chains — including any TenantTx — would never have been read.
// TestM52RouteScanUnitCoversEveryRegistrationForm would have caught it, but
// as "unknown receiver" noise on a perfectly ordinary declaration.
func m52EachBinding(file *ast.File, visit func(name string, rhs ast.Expr)) {
	ast.Inspect(file, func(n ast.Node) bool {
		m52VisitBindingNode(n, visit)
		return true
	})
}

// m52VisitBindingNode is m52EachBinding for one already-visited node, so the
// ordered walk in m52ParseMainGo can share the same notion of "a binding".
func m52VisitBindingNode(n ast.Node, visit func(name string, rhs ast.Expr)) {
	switch d := n.(type) {
	case *ast.AssignStmt:
		if len(d.Lhs) != 1 || len(d.Rhs) != 1 {
			return
		}
		if name, ok := d.Lhs[0].(*ast.Ident); ok {
			visit(name.Name, d.Rhs[0])
		}
	case *ast.ValueSpec:
		if len(d.Names) != 1 || len(d.Values) != 1 {
			return
		}
		visit(d.Names[0].Name, d.Values[0])
	}
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
	m52EachBinding(file, func(name string, rhs ast.Expr) {
		if !m52IsEchoSelectorCall(rhs, echoPkg, "New") {
			return
		}
		if found != "" && found != name {
			t.Fatalf("main.go binds %s.New() to both %q and %q; this gate assumes a single "+
				"Echo instance and would resolve routes against only one of them",
				echoPkg, found, name)
		}
		found = name
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

// m52Expand resolves a chain entry through the alias map, so `authMiddleware`
// is compared as what it was assigned.
//
// The map holds only identifiers main.go binds exactly once (see
// m52ParseMainGo), so there is no last-write-wins guess here. The loop follows
// a chain of such bindings and stops when the text is no longer a name it
// knows; `seen` is a cycle guard, not a depth limit — an unresolvable name
// simply stays as written and reads as "no TenantTx".
func m52Expand(entry string, aliases map[string]string) string {
	cur := strings.TrimSpace(entry)
	seen := map[string]bool{}
	for {
		next, ok := aliases[cur]
		if !ok || seen[cur] {
			return cur
		}
		seen[cur] = true
		cur = strings.TrimSpace(next)
	}
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
//
// # The cost, stated rather than discovered
//
// This compares TEXT, not identity, so renaming the handler variable in
// main.go — `lsWebhookHandler` → `lsHandler`, same object, same method — also
// fails it. That is a false alarm on correct code, accepted deliberately
// because the alternative loses the check: comparing only the method name
// (`.Handle`) would pass `someOtherHandler.Handle`, which is the swap worth
// noticing. The failure message below says which of the two happened, and the
// fix for a rename is one string.
func TestM52ClassifiedRoutesStillHaveTheHandlerTheyWereClassifiedFor(t *testing.T) {
	derived := m52NoTenantTxRoutes(t)
	for _, key := range NoTenantTxRouteKeys() {
		rule := noTenantTxRouteBinding[key]
		r, ok := derived[key]
		if !ok {
			continue // reported by the sweep above
		}
		if r.handler != rule.Handler {
			t.Errorf("%s is served by a different handler EXPRESSION than the one it was "+
				"classified for.\n"+
				"  classified for: %s\n"+
				"  main.go:%d now: %s\n"+
				"If this is only a rename of the same handler object, the classification (%s) "+
				"still holds — update the Handler field and move on. If it is a different "+
				"handler, its reason was written about other code: re-read it, confirm the "+
				"classification, and update both.", key, rule.Handler, r.line, r.handler, rule.Kind)
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
// for the stated scan unit: nothing in main.go registers a route through a
// form m52ParseMainGo does not read.
//
// It flags four shapes, and nothing else. Every one of them is a REGISTRATION
// the parser skips; ordinary calls on the Echo instance (`e.Shutdown(ctx)`,
// `len(e.Routes())`, `e.Pre(...)`) are none of this test's business, and an
// earlier version that errored on them would have reddened CI for correct
// code.
func TestM52RouteScanUnitCoversEveryRegistrationForm(t *testing.T) {
	// Receivers that carry a route-verb method name but are NOT routers, with
	// the reason. Empty today: main.go calls GET/POST/... on nothing else.
	notARouter := map[string]string{}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGoPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", mainGoPath, err)
	}
	_, groups, _ := m52ParseMainGo(t)
	at := func(n ast.Node) int { return fset.Position(n.Pos()).Line }

	// (1) A bound method value: `post := e.POST` detaches the registration
	// from any selector call the walkers can see.
	m52EachBinding(file, func(name string, rhs ast.Expr) {
		sel, ok := rhs.(*ast.SelectorExpr)
		if !ok || !m52RouteVerbs[sel.Sel.Name] {
			return
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return
		}
		if _, isGroup := groups[recv.Name]; !isGroup {
			return
		}
		t.Errorf("main.go:%d binds %s = %s.%s — a route registered through that value has "+
			"no selector-shaped call for this gate to read, so it would be invisible to "+
			"TestM52NoTenantTxRoutesAreAllClassified. Call the method directly.",
			at(rhs), name, recv.Name, sel.Sel.Name)
	})

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

		// (2) A chained registration: `e.Group("/x", mw).GET(...)` never binds
		// the group to a variable, so its chain was never resolved.
		//
		// Only ROUTE VERBS are flagged here, not m52UnreadRegistrationMethods.
		// A non-identifier receiver plus `Add` is `time.Now().Add(time.Hour)`
		// far more often than it is a chained echo registration, and reddening
		// CI for a duration calculation is exactly the false alarm that gets a
		// gate switched off. The cost is that a chained
		// `.Group("/x").Static(...)` would go unnoticed; nothing in echo makes
		// that shape natural, and guard (4) still covers the same methods on a
		// named group.
		if !isIdent {
			if m52RouteVerbs[name] {
				t.Errorf("main.go:%d registers %s(...) on an unnamed receiver (%s). This gate "+
					"resolves middleware chains through group VARIABLES, so a chained "+
					"registration is invisible to it. Assign the group to a variable first.",
					at(call), name, m52Normalise(renderNode(fset, sel.X)))
			}
			return true
		}

		if _, isGroup := groups[recv.Name]; !isGroup {
			// (3) A verb call on a receiver this gate did not resolve to a
			// group — most plausibly a group that arrived as a function
			// parameter, which would make its routes invisible.
			if m52RouteVerbs[name] {
				if why, exempt := notARouter[recv.Name]; exempt {
					t.Logf("main.go:%d %s.%s(...) exempt: %s", at(call), recv.Name, name, why)
					return true
				}
				t.Errorf("main.go:%d calls %s.%s(...) on a receiver this gate did not resolve "+
					"to a route group. If %s is a router, the routes registered on it are "+
					"invisible to TestM52NoTenantTxRoutesAreAllClassified — resolve it here. "+
					"If it is not a router at all, add it to this test's `notARouter` map "+
					"with the reason.",
					at(call), recv.Name, name, recv.Name)
			}
			return true
		}

		// (4) A registration on a KNOWN group in a form the parser skips:
		// echo's other registration APIs, or a verb whose path argument is not
		// a string literal (a loop variable, a const, a fmt.Sprintf). Either
		// one is a live route with a live middleware chain that the sweep
		// never sees — the shape that would let an unbound route arrive with
		// every set and every count unchanged.
		if m52UnreadRegistrationMethods[name] {
			t.Errorf("main.go:%d calls %s.%s(...), an echo registration method this gate's "+
				"parser does not read. Any route it registers is invisible to "+
				"TestM52NoTenantTxRoutesAreAllClassified. Teach m52ParseMainGo the shape, or "+
				"register the route through one of the verb methods.",
				at(call), recv.Name, name)
			return true
		}
		if !m52RouteVerbs[name] {
			return true
		}
		if len(call.Args) < 2 {
			t.Errorf("main.go:%d %s.%s(...) has fewer than two arguments; this gate reads "+
				"(path, handler, mw...) and skipped it.", at(call), recv.Name, name)
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
			t.Errorf("main.go:%d %s.%s(%s, ...) registers a route whose path is not a string "+
				"literal. This gate keys its table by the registered path, so it SKIPS this "+
				"registration entirely — the route exists, carries whatever chain it "+
				"carries, and is invisible to TestM52NoTenantTxRoutesAreAllClassified. Write "+
				"the path as a literal, or teach m52ParseMainGo to resolve it.",
				at(call), recv.Name, name, m52Normalise(renderNode(fset, call.Args[0])))
		}
		return true
	})
}

// TestM52MainGoDoesNotAliasTheRouterTypes closes the one way another file can
// hold a router without importing echo.
//
// TestM52MainGoIsTheOnlyRouter recognises a router by the echo package
// qualifier. `type routeGroup = echo.Group` in main.go would let
// routes_extra.go take a `*routeGroup` and register on it with no echo import
// at all — invisible to that walk and to this parser both. A named type
// (`type routeGroup echo.Group`, no `=`) cannot receive echo's methods, so
// only the ALIAS form is refused.
func TestM52MainGoDoesNotAliasTheRouterTypes(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGoPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", mainGoPath, err)
	}
	echoPkg := m52EchoPackageName(file)
	if echoPkg == "" {
		t.Fatalf("%s does not import %s", mainGoPath, echoImportPath)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || !spec.Assign.IsValid() {
			return true // not an alias
		}
		sel, ok := spec.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != echoPkg {
			return true
		}
		if sel.Sel.Name != "Echo" && sel.Sel.Name != "Group" {
			return true
		}
		t.Errorf("main.go:%d declares `type %s = %s.%s`. An alias lets another file hold a "+
			"router without importing echo, which is the signal "+
			"TestM52MainGoIsTheOnlyRouter recognises — the routes registered there would be "+
			"invisible to this gate. Use the echo type directly.",
			fset.Position(spec.Pos()).Line, spec.Name.Name, echoPkg, sel.Sel.Name)
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
// If a second non-test file held a router, the routes registered on it would
// never be seen by the sweep. The allowlist is empty on purpose: today exactly
// one non-test file does.
//
// # What counts as evidence of a router, and what does not
//
// Two signals, either of which is enough:
//
//	CONSTRUCTION   a call to `<echo>.New()`.
//	REGISTRATION   a call shaped like one: `X.<verb>("<literal>", <arg>, ...)`
//	               with a route-verb method name.
//
// Nothing else. Earlier versions were looser twice over and both were false
// positives waiting to happen: matching the literal `.Group("` would have
// reddened for `slog.Group("k", …)`, and matching any mention of
// `echo.Echo` / `echo.Group` would have reddened for `var _ *echo.Echo` or for
// a helper that takes a `*echo.Group` and only reads from it. Neither
// registers anything.
//
// The REGISTRATION signal is also what covers a file that holds a router
// WITHOUT importing echo — reachable through a type alias, which is why
// TestM52MainGoDoesNotAliasTheRouterTypes refuses the alias in main.go and why
// this walk does not gate on the import. Measured 2026-08-05: zero
// registration-shaped calls exist outside main.go, so the check costs nothing
// today.
func TestM52MainGoIsTheOnlyRouter(t *testing.T) {
	// Files exempted from the check, with the reason. Empty today.
	allowed := map[string]string{}

	mainAbs, err := filepath.Abs(mainGoPath)
	if err != nil {
		t.Fatalf("abs %s: %v", mainGoPath, err)
	}

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
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			what := ""
			switch {
			case echoPkg != "" && m52IsEchoSelectorCall(call, echoPkg, "New"):
				what = "constructs an Echo instance (" + echoPkg + ".New)"
			case m52RouteVerbs[sel.Sel.Name] && len(call.Args) >= 2:
				lit, isLit := call.Args[0].(*ast.BasicLit)
				if !isLit || lit.Kind != token.STRING {
					return true
				}
				what = "registers a route (" + m52Normalise(renderNode(fset, sel.X)) + "." +
					sel.Sel.Name + "(" + lit.Value + ", …))"
			default:
				return true
			}
			offenders = append(offenders, filepath.ToSlash(path)+":"+
				strconv.Itoa(fset.Position(call.Pos()).Line)+" "+what)
			return false
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", apiRootPath, err)
	}
	sort.Strings(offenders)
	for _, f := range offenders {
		t.Errorf("%s — outside cmd/server/main.go. The M52 tenant-binding sweep reads "+
			"main.go only, so a route registered here is unclassified AND invisible. "+
			"Either move the registration into main.go, or widen the scan unit and record "+
			"the file in this test's `allowed` map with a reason.", f)
	}
}

// TestM52ParserIsNotBlind is the blindness guard, and deliberately NOT a pin.
//
// Every other assertion in this file is a comparison against a set the parser
// produced. A parser that resolved nothing would make all of them vacuous, so
// the floors below have to hold. What is NOT here is an exact count of
// anything:
//
//   - the total registration count was pinned at 181 in the first version.
//     Adding a 182nd route on a TenantTx chain is correct code, and a
//     tenant-binding gate has no business reddening for it.
//   - the count of TenantTx-less routes was pinned at 9 in the second. Adding
//     a tenth WITH a complete classification — reason, BindsVia, a ProvedBy
//     test that drives it on a poisoned connection — is a correct change that
//     satisfies every other test here, and failing it on the count alone is a
//     second red build for the same, already-reviewed edit.
//
// Both were tripwires for "somebody should look", and both cost a false alarm
// on a change that had already been looked at. The bidirectional sweep in
// TestM52NoTenantTxRoutesAreAllClassified owns that surface exactly: it fails
// for an unclassified route and for a stale entry, and passes only when the
// table and main.go agree.
//
// For the record rather than as an assertion, measured 2026-08-05: 181
// registrations, 10 groups (the Echo instance plus nine declared), 9 routes
// with no TenantTx.
func TestM52ParserIsNotBlind(t *testing.T) {
	const (
		minRoutes = 100
		minGroups = 5
	)
	routes, groups, aliases := m52ParseMainGo(t)
	if len(routes) < minRoutes {
		t.Errorf("resolved %d routes from main.go, want at least %d — the parser is blind, "+
			"not the router", len(routes), minRoutes)
	}
	if len(groups) < minGroups {
		t.Errorf("resolved %d route groups, want at least %d — a group that fails to resolve "+
			"takes its whole middleware chain with it, and every route on it would then read "+
			"as unbound", len(groups), minGroups)
	}
	// Both sides of the TenantTx question must be non-empty. All-bound would
	// mean the sweep compares an empty set against a nine-entry table (caught,
	// loudly, as nine stale entries); all-unbound would mean m52HasTenantTx
	// never matches, which no amount of table editing would reveal as a bug.
	bound, unbound := 0, 0
	for _, r := range routes {
		if m52HasTenantTx(r.chain, aliases) {
			bound++
		} else {
			unbound++
		}
	}
	if bound == 0 {
		t.Errorf("not one of the %d resolved routes carries TenantTx. main.go has three "+
			"TenantTx-carrying groups and a dozen explicit chains, so this means "+
			"m52HasTenantTx or the chain resolution stopped working, not that the "+
			"middleware was removed.", len(routes))
	}
	if unbound == 0 {
		t.Errorf("every one of the %d resolved routes carries TenantTx. main.go has always "+
			"had at least the two provider webhooks and /health without it.", len(routes))
	}
}
