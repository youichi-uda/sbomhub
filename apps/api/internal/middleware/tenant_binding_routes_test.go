package middleware

import (
	"bytes"
	"go/ast"
	"go/build"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
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
//	            m52RouteVerbs (echo's nine HTTP-verb methods plus Any), whose
//	            receiver is an identifier known to be a group, with >= 2
//	            arguments and a string-literal first argument.
//
// All of it inside ONE function: the one that calls echo.New(). Resolving
// group names file-wide meant a helper's `api *echo.Group` parameter picked up
// main()'s `api`, which is wrong in both directions — and silently bound in the
// worse one.
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
// # Three narrow contracts this gate imposes on main.go
//
// Stated up front because each one CAN fail a change that is correct in
// itself. They are the price of a parser that reads a fixed set of shapes, and
// each is a one-line fix with an explicit message:
//
//  1. Routes are registered through the verb methods. A correctly bound
//     `e.Add(http.MethodPost, path, h, appmw.TenantTx(db))` is refused, because
//     this parser does not read Add's signature and would otherwise not see
//     the route at all.
//  2. `type routeGroup = echo.Group` is refused even when it is used only
//     inside main.go, because the alias is what would let another file hold a
//     router with no echo import.
//  3. The floors in TestM52ParserIsNotBlind (>= 100 routes, >= 5 groups) treat
//     a large reduction as a blind parser. Genuinely shrinking the API below
//     them is correct code that fails until the numbers are revisited.
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
//   - Echo registers an implicit RouteNotFound pair per PREFIX whenever a
//     group takes middleware, so `e.Routes()` at runtime is a superset of what
//     this walk enumerates. Those catch-alls carry the last-declared group's
//     chain, which cmd/server/m47r_route_role_gate_test.go already pins; this
//     gate does not classify them and does not claim to.
//
// ---------------------------------------------------------------------------

// mainGoPath is the router this gate reads, and apiRootPath is the module root
// (apps/api). Both are located at package-init time, and NEITHER is a fixed
// relative literal.
//
// # Two ways this went wrong before
//
//  1. The literals "../../cmd/server/main.go" and "../.." are correct only
//     when the process runs in the package directory. `go test` arranges that,
//     but a binary built with `go test -c` does not carry it: run from /tmp,
//     `../..` resolved to another tree, the walk climbed toward `/` and died
//     on `../../data/lost+found: permission denied`, and main.go itself was
//     reported as "a router outside main.go".
//  2. Deriving them from runtime.Caller(0) alone fixes that — but only without
//     `-trimpath`. Under it, the compiler records
//     `github.com/sbomhub/sbomhub/internal/middleware/...`, which is not a
//     filesystem path, and every parse fails.
//
// Both are correct builds failing a REQUIRED check, so the resolution tries
// several origins in order and takes the first where `cmd/server/main.go`
// actually exists. Measured 2026-08-05: this resolves under plain `go test`,
// under `go test -trimpath`, from a compiled binary run in /tmp, / and $HOME,
// and from a `-trimpath` binary run in the package directory.
var mainGoPath, apiRootPath = m52LocateRouter()

// m52LocateRouter returns (path to cmd/server/main.go, module root).
//
// It falls back to the relative literal rather than panicking when nothing
// resolves: package-init panics take out every unrelated test in the package,
// and a path that does not exist already fails loudly, and accurately, at the
// first parse.
func m52LocateRouter() (string, string) {
	var roots []string

	// (a) This file's compiled-in location. Correct unless -trimpath.
	if _, thisFile, _, ok := runtime.Caller(0); ok && filepath.IsAbs(thisFile) {
		pkgDir := filepath.Dir(thisFile)
		roots = append(roots, filepath.Dir(filepath.Dir(pkgDir)))
	}
	// (b) The working directory, which `go test` sets to the package dir...
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, filepath.Join(wd, "..", ".."))
		// (c) ...and, failing that, any ancestor of it. This is what carries
		// `-trimpath` runs, where (a) is not a filesystem path.
		for d := wd; ; {
			roots = append(roots, d)
			parent := filepath.Dir(d)
			if parent == d {
				break
			}
			d = parent
		}
	}

	for _, root := range roots {
		candidate := filepath.Join(root, "cmd", "server", "main.go")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, root
		}
	}
	// Nothing resolved. One shape does that: a `-trimpath` binary run outside
	// the source tree, where there is neither a compiled-in path nor a working
	// directory to anchor to. The gate cannot inspect a router it cannot find
	// and must not RED for it, because the build was correct and the router is
	// fine. m52RequireRouter turns this into a skip.
	return "", ""
}

// m52RequireRouter skips when the gate cannot locate cmd/server/main.go.
//
// That is not a finding about the router — it is the gate not knowing where to
// look, which happens only for a `-trimpath` binary run outside the checkout.
// Failing there would be a correct build reddening a required check; a skip
// says exactly what happened.
func m52RequireRouter(t *testing.T) {
	t.Helper()
	if mainGoPath == "" {
		t.Skip("this gate could not LOCATE cmd/server/main.go — not a finding about the " +
			"router. `-trimpath` removes the compiled-in source path, so a binary built " +
			"with it and run outside the checkout has no anchor. Run " +
			"`go test ./internal/middleware/` from apps/api, or run the binary from " +
			"inside the checkout.")
	}
}

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

// m52AliasResolver answers "what was `name` bound to, as of this position?".
type m52AliasResolver func(name string, at token.Pos) (string, bool)

type m52Route struct {
	method   string
	fullPath string
	handler  string
	chain    []string
	// chainAt is the source position the chain was collected at; alias
	// expansion resolves names as of this point, not as of end-of-file.
	chainAt token.Pos
	line    int
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
func m52ParseMainGo(t *testing.T) (routes []m52Route, groups map[string]m52Group, aliasAt m52AliasResolver) {
	t.Helper()
	m52RequireRouter(t)

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
	root, rootFn := m52EchoInstanceName(t, file)

	// Every binding, WITH its source position. Resolution is "the last binding
	// of this name before the use", which is what straight-line Go means and
	// what a map keyed by name alone could not express.
	//
	// The previous rule was "expand only names bound exactly once". It was
	// meant to avoid guessing but guessed the other way: a middleware assigned
	// twice whose final value IS appmw.TenantTx(db) went unexpanded and its
	// routes read as unbound, and an unrelated variable that merely SHADOWED a
	// handler name pushed the real one's count to two and failed the handler
	// pins of routes nobody had touched. Both redden correct code.
	type m52Binding struct {
		pos  token.Pos
		text string
		expr ast.Expr
	}
	bindings := map[string][]m52Binding{}
	collect := func(name string, rhs ast.Expr) {
		bindings[name] = append(bindings[name], m52Binding{pos: rhs.Pos(), text: render(rhs), expr: rhs})
	}
	// Only the router function's own bindings, plus package-level ones. A
	// file-wide map conflated distinct lexical bindings that happen to share a
	// spelling: an unrelated local named `publicLinkHandler` in some helper
	// would have pushed the real one's count to two, dropped it out of the
	// alias map, and failed the handler pins of routes nobody had touched.
	m52EachBindingIn(rootFn, collect)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			m52VisitBindingNode(spec, collect)
		}
	}
	resolveAt := func(name string, at token.Pos) (m52Binding, bool) {
		best, found := m52Binding{}, false
		for _, b := range bindings[name] {
			if b.pos < at && (!found || b.pos > best.pos) {
				best, found = b, true
			}
		}
		return best, found
	}
	aliasAt = func(name string, at token.Pos) (string, bool) {
		b, ok := resolveAt(name, at)
		if !ok {
			return "", false
		}
		return b.text, true
	}
	exprAt := func(name string, at token.Pos) (ast.Expr, bool) {
		b, ok := resolveAt(name, at)
		if !ok {
			return nil, false
		}
		return b.expr, true
	}

	// Global middleware: `<root>.Use(...)` and `<root>.Pre(...)`. echo.Echo
	// applies both at request time to every route however it was registered,
	// so this pass is order-insensitive and its result prefixes every chain.
	var global []string
	ast.Inspect(rootFn, func(n ast.Node) bool {
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

	// The ordered walk, over the ONE function that constructs the Echo
	// instance. ast.Inspect visits it in source order, and main.go's router
	// setup is one linear body, so source order is execution order.
	//
	// Confining it to that function is what keeps group names meaning what
	// they say. Resolving `api` file-wide would have mis-read
	//
	//	func mount(api *echo.Group, h echo.HandlerFunc) { api.GET("/x", h) }
	//	...
	//	mount(auth, statsHandler.Get)      // the TenantTx-bearing group
	//
	// as the unbound `api` group declared in main() — and the same shape with
	// the names the other way round would have reported a genuinely unbound
	// route as bound, which is a silent miss rather than a loud one. A verb
	// call outside this function now resolves to no group at all, which
	// TestM52RouteScanUnitCoversEveryRegistrationForm reports.
	groups = map[string]m52Group{root: {}}
	ast.Inspect(rootFn, func(n ast.Node) bool {
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
				chainAt:  node.Pos(),
				fullPath: grp.prefix + path,
				handler:  m52HandlerIdentity(node.Args[1], node.Pos(), exprAt, render),
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
	return routes, groups, aliasAt
}

// m52EachBindingIn visits every single-value binding of a plain identifier
// under `root`, in source order, in both spellings Go offers: the short form
// `x := <expr>` and the declaration `var x = <expr>` (including inside a
// grouped `var (...)`).
//
// Handling only the short form was a blind spot rather than a simplification:
// a group declared `var api = e.Group("/api/v1")` would have been unknown to
// pass 2, its routes would have had an unresolved receiver, and their
// middleware chains — including any TenantTx — would never have been read.
// TestM52RouteScanUnitCoversEveryRegistrationForm would have caught it, but
// as "unknown receiver" noise on a perfectly ordinary declaration.
func m52EachBindingIn(root ast.Node, visit func(name string, rhs ast.Expr)) {
	ast.Inspect(root, func(n ast.Node) bool {
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
func m52EchoInstanceName(t *testing.T, file *ast.File) (string, *ast.FuncDecl) {
	t.Helper()
	echoPkg := m52EchoPackageName(file)
	found := ""
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || d.Body == nil {
			continue
		}
		ast.Inspect(d, func(n ast.Node) bool {
			m52VisitBindingNode(n, func(name string, rhs ast.Expr) {
				if !m52IsEchoSelectorCall(rhs, echoPkg, "New") {
					return
				}
				if found != "" && (found != name || fn != d) {
					t.Fatalf("main.go binds %s.New() more than once (%q and %q); this gate "+
						"assumes a single Echo instance built in a single function and would "+
						"resolve routes against only one of them", echoPkg, found, name)
				}
				found, fn = name, d
			})
			return true
		})
	}
	if found == "" {
		t.Fatalf("found no `<name> := %s.New()` in %s. Every set this file computes is "+
			"seeded from that instance, so without it the sweep would pass on an empty "+
			"route set.", echoPkg, mainGoPath)
	}
	return found, fn
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

// m52HandlerIdentity renders a registration's handler argument as something
// stable enough to pin a classification to.
//
// For the usual shape — `lsWebhookHandler.Handle`, where the receiver is bound
// exactly once to a constructor call — it returns
// `handler.NewLemonSqueezyWebhookHandler#Handle`: the CONSTRUCTOR plus the
// method. That is the identity a classification is about. Comparing the raw
// text instead meant that renaming the variable, which changes nothing at
// runtime, failed the gate — a false alarm on correct code, and the kind that
// teaches people to stop trusting it.
//
// Everything else — an inline function literal, a receiver bound to something
// that is not a constructor call, a receiver bound more than once — falls back
// to the whitespace-normalised expression. For an inline handler that is the
// right answer anyway: the body IS the code the classification was written
// about, so a change to it should demand a re-read.
func m52HandlerIdentity(arg ast.Expr, at token.Pos, exprAt func(string, token.Pos) (ast.Expr, bool), render func(ast.Node) string) string {
	sel, ok := arg.(*ast.SelectorExpr)
	if !ok {
		return m52Normalise(render(arg))
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return m52Normalise(render(arg))
	}
	bound, ok := exprAt(recv.Name, at)
	if !ok {
		return m52Normalise(render(arg))
	}
	call, ok := bound.(*ast.CallExpr)
	if !ok {
		return m52Normalise(render(arg))
	}
	switch call.Fun.(type) {
	case *ast.SelectorExpr, *ast.Ident:
		return m52Normalise(render(call.Fun)) + "#" + sel.Sel.Name
	default:
		return m52Normalise(render(arg))
	}
}

// m52Expand resolves a chain entry through the alias map, so `authMiddleware`
// is compared as what it was assigned.
//
// The map holds only identifiers main.go binds exactly once (see
// m52ParseMainGo), so there is no last-write-wins guess here.
//
// Substitution is by WHOLE IDENTIFIER anywhere in the text, not only when the
// entry is exactly an alias name. The narrower version reported
//
//	tenantTx := appmw.TenantTx(db)
//	chain := []echo.MiddlewareFunc{tenantTx}
//	e.POST(path, handler, chain...)
//
// as unbound: `chain...` is not an alias key, so nothing was expanded and
// "TenantTx(" never appeared. That is correct code reddening CI, which is the
// failure mode this gate cannot afford. Substituting inside the text handles
// it, and the direction of any over-substitution is toward reading a route as
// BOUND — so the guards that demand a classification stay conservative in the
// other direction.
//
// `seen` is a cycle guard and the iteration cap bounds pathological chains;
// neither is a semantic limit. Anything still unresolved stays as written and
// reads as "no TenantTx".
func m52Expand(entry string, at token.Pos, aliasAt m52AliasResolver) string {
	// A chain of bindings that each mention two others grows exponentially.
	// main.go's are shallow (the whole middleware package's suite runs in
	// ~0.1s), but a cap keeps a pathological one from turning this test into a
	// hang — and stopping early only ever leaves text unexpanded, which reads
	// as "no TenantTx" and demands a classification.
	const maxLen = 1 << 16
	cur := strings.TrimSpace(entry)
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		if seen[cur] || len(cur) > maxLen {
			return cur
		}
		seen[cur] = true
		next := m52SubstituteIdents(cur, at, aliasAt)
		if next == cur {
			return cur
		}
		cur = next
	}
	return cur
}

// m52SubstituteIdents replaces every whole-identifier occurrence of an alias
// name in `text` with its bound expression, once.
func m52SubstituteIdents(text string, at token.Pos, aliasAt m52AliasResolver) string {
	var b strings.Builder
	i := 0
	for i < len(text) {
		if !m52IsIdentStart(text[i]) {
			b.WriteByte(text[i])
			i++
			continue
		}
		j := i + 1
		for j < len(text) && m52IsIdentPart(text[j]) {
			j++
		}
		word := text[i:j]
		// `pkg.Name` — only the leading identifier of a selector is a local
		// binding, and a name preceded by '.' is a field or method.
		precededByDot := i > 0 && text[i-1] == '.'
		repl, ok := aliasAt(word, at)
		if ok && !precededByDot {
			b.WriteString(repl)
		} else {
			b.WriteString(word)
		}
		i = j
	}
	return b.String()
}

func m52IsIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func m52IsIdentPart(c byte) bool {
	return m52IsIdentStart(c) || (c >= '0' && c <= '9')
}

// m52HasTenantTx reports whether an effective chain carries appmw.TenantTx.
func m52HasTenantTx(chain []string, at token.Pos, aliasAt m52AliasResolver) bool {
	for _, entry := range chain {
		if strings.Contains(m52Expand(entry, at, aliasAt), "TenantTx(") {
			return true
		}
	}
	return false
}

// m52NoTenantTxRoutes returns the derived "<METHOD> <path>" → route map.
func m52NoTenantTxRoutes(t *testing.T) map[string]m52Route {
	t.Helper()
	routes, _, aliasAt := m52ParseMainGo(t)
	if len(routes) < 100 {
		t.Fatalf("parsed only %d routes from %s — the parser is blind, not the router",
			len(routes), mainGoPath)
	}
	// Echo REPLACES the handler when the same method+path is registered twice
	// (echo.Router.add overwrites), so the last registration is the one that
	// serves. Collapsing by key first, then filtering, is what makes a later
	// bound registration remove an earlier unbound one — the previous version
	// only ever ADDED unbound routes, so an unbound registration followed by
	// the real, TenantTx-carrying one left the route reported as unbound.
	last := map[string]m52Route{}
	for _, r := range routes {
		key := r.method + " " + r.fullPath
		if prev, seen := last[key]; !seen || r.line >= prev.line {
			last[key] = r
		}
	}
	out := map[string]m52Route{}
	for key, r := range last {
		if m52HasTenantTx(r.chain, r.chainAt, aliasAt) {
			continue
		}
		out[key] = r
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
// — while making the recorded reason false.
//
// What is compared is m52HandlerIdentity's rendering, not the source text:
// `<constructor>#<method>` when the receiver is bound exactly once, so
// renaming `lsWebhookHandler` to `lsHandler` does NOT fail this, while
// pointing the route at `clerkWebhookHandler.Handle` does. An inline handler
// falls back to its whitespace-normalised expression, which is the right
// answer there — for an inline handler the body IS the classified code, so a
// change to it should demand a re-read.
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

// m52InDefaultBuild reports whether the go tool would compile this file for
// the current build configuration.
func m52InDefaultBuild(path string) (bool, error) {
	ctx := build.Default
	ctx.UseAllFiles = false
	return ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
}

// m52SkipDir reports whether a directory is outside the source tree these
// walks care about.
func m52SkipDir(name string) bool {
	// `testdata` is excluded by the go tool from the build, and this repo uses
	// it for exactly what it is for: analyzer fixtures under
	// internal/nullscan/testdata (some deliberately unparsable) and sample
	// programs under internal/service/reachability/testdata. A fixture that
	// happens to contain an Echo server is not a second production router, and
	// reddening the gate for one would be a false alarm on correct code.
	return name == "vendor" || name == "node_modules" || name == "testdata" ||
		strings.HasPrefix(name, ".")
}

// m52TestFuncNames returns every `func TestXxx(t *testing.T)` declared under
// apps/api, mapped to the file that declares it. Build tags are irrelevant
// here: go/parser reads the declaration regardless, which is what makes the
// integration-tagged drives visible to this untagged test.
func m52TestFuncNames(t *testing.T) map[string]string {
	t.Helper()
	m52RequireRouter(t)
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
			// The SIGNATURE too, not just the name: `func TestHelper(x int)`
			// is not a runnable test, and accepting it would let ProvedBy
			// resolve to something `go test` never calls.
			if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
				continue
			}
			star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			sel, ok := star.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "T" {
				continue
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "testing" {
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
	m52RequireRouter(t)
	// Receivers that carry a route-verb method name but are NOT routers, with
	// the reason. Empty today: main.go calls GET/POST/... on nothing else.
	notARouter := map[string]string{}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGoPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", mainGoPath, err)
	}
	_, groups, _ := m52ParseMainGo(t)
	rootName, rootFn := m52EchoInstanceName(t, file)
	at := func(n ast.Node) int { return fset.Position(n.Pos()).Line }

	// (0b) A registration or a Use call inside a CLOSURE. The ordered walk
	// visits a FuncLit's body where it is WRITTEN, but Go runs it where it is
	// CALLED, so the middleware a group carries at registration time can
	// differ from what the walk computed — in both directions:
	//
	//	mount := func() { g.GET("/r", h) }
	//	g.Use(appmw.TenantTx(db))
	//	mount()                            // bound at runtime; walk says unbound
	//
	//	addTx := func() { g.Use(appmw.TenantTx(db)) }
	//	g.GET("/r", h)
	//	addTx()                            // unbound at runtime; walk says bound
	//
	// The second is a silent miss, which is why this is refused rather than
	// modelled. Note that a handler passed AS AN ARGUMENT — /health's inline
	// closure — is not affected: the registration call is not itself inside a
	// FuncLit body.
	ast.Inspect(rootFn, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(lit.Body, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, isGroup := groups[recv.Name]; !isGroup {
				return true
			}
			if !m52RouteVerbs[sel.Sel.Name] && sel.Sel.Name != "Use" &&
				!m52UnreadRegistrationMethods[sel.Sel.Name] {
				return true
			}
			t.Errorf("main.go:%d calls %s.%s(...) inside a closure. This gate orders group "+
				"middleware by SOURCE position, and a closure runs where it is called, not "+
				"where it is written — so the chain it computes for this can be wrong in "+
				"either direction, including reporting an unbound route as bound. Move the "+
				"call out of the closure.", at(call), recv.Name, sel.Sel.Name)
			return true
		})
		return false
	})

	// (0a) A registration in ANOTHER function of main.go. m52ParseMainGo reads
	// only the function that builds the Echo instance, so a helper like
	//
	//	func mount(api *echo.Group, h echo.HandlerFunc) { api.GET("/x", h) }
	//
	// registers a live route the sweep never sees — and because `api` happens
	// to be a group name in main(), nothing downstream notices either. Scoping
	// the parser to one function is what stopped it attributing the WRONG
	// chain to such a route; this is what stops it being silent about it.
	echoPkgMain := m52EchoPackageName(file)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn == rootFn {
			continue
		}
		// Only a function that RECEIVES a router can register on one. Without
		// this, a perfectly ordinary helper — `func probe(c *httpClient) {
		// c.GET("/status", nil) }` — matched the registration shape and
		// reddened the gate, which is the false alarm that gets a gate
		// switched off. The parameter type is the discriminator, and it is the
		// same one TestM52MainGoIsTheOnlyRouter uses for other files.
		if !m52TakesARouter(fn, echoPkgMain) {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			// Only VERBS are decisive here: `Add` on some receiver in a helper
			// is `wg.Add(1)` far more often than an echo registration, and
			// reddening for a WaitGroup is the false alarm that gets a gate
			// switched off. The same reasoning demands the REGISTRATION SHAPE
			// (a string-literal path and a handler) and the notARouter hatch:
			// `client.GET(url)` on an HTTP client is not this gate's business.
			if !ok || !m52RouteVerbs[sel.Sel.Name] || len(call.Args) < 2 {
				return true
			}
			if lit, isLit := call.Args[0].(*ast.BasicLit); !isLit || lit.Kind != token.STRING {
				return true
			}
			if recv, isIdent := sel.X.(*ast.Ident); isIdent {
				if why, exempt := notARouter[recv.Name]; exempt {
					t.Logf("main.go:%d %s.%s(...) in func %s exempt: %s",
						at(call), recv.Name, sel.Sel.Name, fn.Name.Name, why)
					return true
				}
			}
			t.Errorf("main.go:%d registers %s(...) inside func %s, not inside the function "+
				"that builds the Echo instance (func %s). This gate reads route "+
				"registrations from that one function, so anything registered here is "+
				"invisible to TestM52NoTenantTxRoutesAreAllClassified — including its "+
				"middleware chain. Register the route alongside the others, or teach "+
				"m52ParseMainGo to follow the helper. If the receiver is not a router at "+
				"all, add it to this test's `notARouter` map with the reason.",
				at(call), sel.Sel.Name, fn.Name.Name, rootFn.Name.Name)
			return true
		})
	}

	// (1) A bound method value: `post := e.POST` detaches the registration
	// from any selector call the walkers can see.
	m52EachBindingIn(rootFn, func(name string, rhs ast.Expr) {
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

	ast.Inspect(rootFn, func(n ast.Node) bool {
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

		// (0) `e.Router()` hands out the raw router, whose Add() registers
		// routes that neither walker here can attribute to a group. It is
		// flagged by name because it is unambiguous — nothing else in this
		// codebase is called Router() on the Echo instance — where flagging
		// `<something>.Add(...)` generally would redden for `wg.Add(1)`.
		if isIdent && recv.Name == rootName && (name == "Router" || name == "Routers") {
			t.Errorf("main.go:%d calls %s.%s(). Routes added through a raw router — including "+
				"`%s.Routers()[\"\"].Add(...)` — are invisible to this gate: it resolves "+
				"chains through group variables, and a router object belongs to no group. "+
				"Register through the Echo instance or a group instead.",
				at(call), recv.Name, name, recv.Name)
			return true
		}

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

// TestM52ProductionWiresTheBindingsTheDrivesMeasure closes the gap between the
// drives and the server.
//
// The handler-package drives construct their own runners and pass
// `triage.NewDBTxManager(appDB)` explicitly, then prove — with a negative
// control — that removing it breaks the route. What they cannot show is that
// PRODUCTION passes one. `RunnerConfig.TxManager` is OPTIONAL: leave the field
// out and triage.NewRunner / cra.NewRunner silently fall back to
// PassthroughTxManager, which binds nothing. So deleting one line from main.go
// would put all four F19 routes back to answering 500 in production while
// every live-database drive stayed green and every route in the census kept
// its handler expression.
//
// This asserts the line is there, syntactically, at the registration site the
// rest of this file already parses. Same idea for PublicLinkService, whose
// runWithTenantTx refuses outright when its *sql.DB is nil.
//
// The check is textual on purpose — it looks for `NewDBTxManager(` in the
// value after alias expansion — so swapping in a DIFFERENT real TxManager
// implementation reddens it. That is a demand for review rather than a false
// alarm: the whole gate rests on what that field holds.
func TestM52ProductionWiresTheBindingsTheDrivesMeasure(t *testing.T) {
	// Every non-test file of package main, not just main.go. Wiring is
	// routinely extracted into a sibling (llm_resolver.go already holds
	// newTenantLLMProviderResolver), and refusing that would fail a refactor
	// that changes nothing.
	fset := token.NewFileSet()
	files := m52CmdServerFiles(t, fset)
	render := func(n ast.Node) string { return m52Normalise(renderNode(fset, n)) }

	// Aliases from EVERY file of package main, not just main.go. Moving the
	// runner construction into a sibling is a plausible refactor — the package
	// already keeps newTenantLLMProviderResolver in llm_resolver.go — and
	// taking aliases from main.go alone rejected a `txManager :=
	// triage.NewDBTxManager(db)` declared beside the literal it feeds.
	pkgAlias := map[string]string{}
	for _, f := range files {
		m52EachBindingIn(f, func(name string, rhs ast.Expr) {
			pkgAlias[name] = render(rhs)
		})
	}
	aliasAt := m52AliasResolver(func(name string, _ token.Pos) (string, bool) {
		v, ok := pkgAlias[name]
		return v, ok
	})

	// Names of functions in the package whose body constructs a real
	// DBTxManager, so `TxManager: newTenantTxManager(db)` resolves as well as
	// the direct call does. One level is enough for the shapes this codebase
	// uses; anything deeper falls through to the message below, which asks for
	// a human rather than guessing.
	txFactories := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if strings.Contains(render(fn.Body), "NewDBTxManager(") {
				txFactories[fn.Name.Name] = true
			}
		}
	}
	bindsTenant := func(value string) bool {
		expanded := m52Expand(value, token.NoPos, aliasAt)
		if strings.Contains(expanded, "NewDBTxManager(") {
			return true
		}
		for name := range txFactories {
			if strings.Contains(expanded, name+"(") {
				return true
			}
		}
		return false
	}

	// (a) Both runner configs must set TxManager to something that binds.
	wantConfigs := map[string]bool{"triage.RunnerConfig": false, "cra.RunnerConfig": false}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || lit.Type == nil {
				return true
			}
			typeName := render(lit.Type)
			if _, want := wantConfigs[typeName]; !want {
				return true
			}
			wantConfigs[typeName] = true
			value := ""
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "TxManager" {
					value = render(kv.Value)
				}
			}
			line := fset.Position(lit.Pos()).Line
			file := filepath.Base(fset.Position(lit.Pos()).Filename)
			if value == "" {
				t.Errorf("%s:%d builds a %s with NO TxManager field. Both runners default to "+
					"PassthroughTxManager, which binds nothing — every F19 route would run "+
					"unbound in production while the M52 drives, which inject their own "+
					"manager, stayed green.", file, line, typeName)
				return true
			}
			if !bindsTenant(value) {
				t.Errorf("%s:%d sets %s.TxManager = %s, and this gate cannot resolve that to a "+
					"triage.NewDBTxManager(...) — directly, through a single-binding local, or "+
					"through a function in this package whose body constructs one.\n"+
					"That field is what binds app.current_tenant_id for every stage of the F19 "+
					"routes, and the live drives inject their OWN manager, so nothing else "+
					"here would notice its loss. If the replacement really does bind, extend "+
					"this check to recognise it.", file, line, typeName, value)
			}
			return true
		})
	}
	for typeName, seen := range wantConfigs {
		if !seen {
			t.Errorf("found no %s literal anywhere in cmd/server — either the runner moved out "+
				"of package main or this check went blind; either way it is asserting "+
				"nothing.", typeName)
		}
	}

	// (b) PublicLinkService must receive a live *sql.DB: runWithTenantTx
	// returns "db handle is nil" rather than binding when it does not.
	found := false
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewPublicLinkService" || len(call.Args) == 0 {
				return true
			}
			found = true
			if arg := m52ResolvesToNil(call.Args[0], call.Pos(), f, render); arg != "" {
				t.Errorf("%s:%d constructs the public-link service with a nil *sql.DB (%s). "+
					"PublicLinkService.runWithTenantTx is the only thing binding the tenant on "+
					"the two anonymous share routes, and it refuses outright without a handle.",
					filepath.Base(fset.Position(call.Pos()).Filename),
					fset.Position(call.Pos()).Line,
					m52ResolvesToNil(call.Args[0], call.Pos(), f, render))
			}
			return true
		})
	}
	if !found {
		t.Error("found no NewPublicLinkService(...) call in cmd/server — the two share-link " +
			"rules name its runWithTenantTx as their binding, so this check must resolve it.")
	}
}

// m52TakesARouter reports whether fn declares a parameter of type *echo.Echo
// or *echo.Group — i.e. whether it can register a route at all.
func m52TakesARouter(fn *ast.FuncDecl, echoPkg string) bool {
	if echoPkg == "" || fn.Type.Params == nil {
		return false
	}
	for _, param := range fn.Type.Params.List {
		star, ok := param.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != echoPkg {
			continue
		}
		if sel.Sel.Name == "Echo" || sel.Sel.Name == "Group" {
			return true
		}
	}
	return false
}

// m52ResolvesToNil reports how `arg` is nil, or "" when it is not.
//
// Comparing the rendered text against "nil" was this guard's own hole: a
// deployment that passed `var publicLinkDB *sql.DB` or `(*sql.DB)(nil)` would
// have satisfied it while PublicLinkService.runWithTenantTx refused every
// anonymous share request for want of a handle. Three shapes are recognised —
// the literal, a conversion of one, and an identifier declared in this file
// with a pointer type and no initialiser. Anything else is treated as
// non-nil, which is the direction that does not redden correct code.
func m52ResolvesToNil(arg ast.Expr, at token.Pos, file *ast.File, render func(ast.Node) string) string {
	switch a := arg.(type) {
	case *ast.Ident:
		if a.Name == "nil" {
			return "the literal nil"
		}
		// `var x *T` with no value — but only the LAST such declaration
		// before the call, and only if no later initialised binding of the
		// same name intervenes. Searching the whole file by name alone made a
		// live `db := liveDB()` in main() read as nil because some unrelated
		// helper elsewhere declared `var db *sql.DB`.
		empty, bestPos := "", token.NoPos
		ast.Inspect(file, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.ValueSpec:
				if d.Pos() >= at {
					return true
				}
				initialised := len(d.Values) != 0
				for _, nm := range d.Names {
					if nm.Name != a.Name || d.Pos() < bestPos {
						continue
					}
					if initialised || d.Type == nil {
						empty, bestPos = "", d.Pos()
						continue
					}
					if _, isPtr := d.Type.(*ast.StarExpr); isPtr {
						empty = "`var " + a.Name + " " + render(d.Type) + "` is declared with no value"
						bestPos = d.Pos()
					} else {
						empty, bestPos = "", d.Pos()
					}
				}
			case *ast.AssignStmt:
				// ANY assignment that names the identifier clears the
				// "declared without a value" state, including a multi-value
				// one. `db, err := database.Connect(...)` is how this codebase
				// actually obtains the handle, and skipping it left an
				// unrelated helper's `var db *sql.DB` as the last thing seen.
				if d.Pos() >= at || d.Pos() < bestPos {
					return true
				}
				for _, lhs := range d.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == a.Name {
						empty, bestPos = "", d.Pos()
					}
				}
			}
			return true
		})
		return empty
	case *ast.CallExpr:
		// `(*sql.DB)(nil)` and friends.
		if len(a.Args) == 1 {
			if id, ok := a.Args[0].(*ast.Ident); ok && id.Name == "nil" {
				return "a conversion of the literal nil: " + render(a)
			}
		}
	case *ast.ParenExpr:
		return m52ResolvesToNil(a.X, at, file, render)
	}
	return ""
}

// m52CmdServerFiles parses every non-test .go file of package main.
func m52CmdServerFiles(t *testing.T, fset *token.FileSet) []*ast.File {
	t.Helper()
	m52RequireRouter(t)
	dir := filepath.Dir(mainGoPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		out = append(out, f)
	}
	if len(out) < 2 {
		t.Fatalf("parsed only %d non-test files in %s — the walk is blind", len(out), dir)
	}
	return out
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
	m52RequireRouter(t)
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
	m52RequireRouter(t)
	// Files exempted from the check, with the reason. Empty today.
	allowed := map[string]string{}

	// Receivers that carry a route-verb method name but are not routers, with
	// the reason. `client.GET("/status", req)` on an HTTP client would match
	// the registration SHAPE without being one; this is the escape hatch that
	// keeps such a file from reddening the gate. Empty today: measured
	// 2026-08-05, no non-test file outside main.go contains a call of that
	// shape at all.
	notARouter := map[string]string{}

	mainInfo, err := os.Stat(mainGoPath)
	if err != nil {
		t.Fatalf("stat %s: %v", mainGoPath, err)
	}
	// Identity by inode, not by path spelling. Comparing rendered paths made
	// this walk report main.go as "a router outside main.go" whenever the two
	// spellings diverged — through a symlink, a bind mount, or a different
	// working directory.
	isMainGo := func(path string) bool {
		info, serr := os.Stat(path)
		return serr == nil && os.SameFile(info, mainInfo)
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
		if isMainGo(path) {
			return nil
		}
		if _, ok := allowed[filepath.ToSlash(path)]; ok {
			return nil
		}
		// A file the default build excludes (`//go:build ignore`, a foreign
		// GOOS/GOARCH, a tag this build does not set) is not part of the
		// running server, so a router in it is not a second router. Judging it
		// as production source reddened the gate for a build-excluded helper.
		if included, berr := m52InDefaultBuild(path); berr == nil && !included {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// Reported, not failed. A file the Go compiler would reject is not
			// a running router, and `testdata` — where deliberately unparsable
			// fixtures live — is already skipped above.
			t.Logf("NOTE: %s does not parse (%v); this walk skipped it. If it is real "+
				"production source, the build is broken and that will be said elsewhere.",
				path, perr)
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
				recv := m52Normalise(renderNode(fset, sel.X))
				if why, exempt := notARouter[recv]; exempt {
					t.Logf("%s: %s.%s(...) exempt: %s", path, recv, sel.Sel.Name, why)
					return true
				}
				what = "registers a route (" + recv + "." + sel.Sel.Name + "(" + lit.Value + ", …))"
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
	// A function elsewhere that TAKES a router is a mounter whether or not its
	// paths are literals: `func mount(g *echo.Group) { g.GET(reportsPath, h) }`
	// registers real routes that neither walker above can see, because the
	// path is an identifier and the file need not construct anything. The
	// parameter TYPE is the signal — precise, and nothing else in this
	// codebase has it.
	err = filepath.WalkDir(apiRootPath, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
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
		if isMainGo(path) {
			return nil
		}
		if _, ok := allowed[filepath.ToSlash(path)]; ok {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // already reported above
		}
		echoPkg := m52EchoPackageName(file)
		if echoPkg == "" {
			return nil
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !m52TakesARouter(fn, echoPkg) {
				continue
			}
			// Taking a router is not registering on one. A function that only
			// READS from it — logging len(e.Routes()), say — is correct code,
			// and the earlier version rejected it. Require an actual
			// registration-shaped call in the body.
			registers := ""
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || registers != "" {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if !m52RouteVerbs[sel.Sel.Name] && !m52UnreadRegistrationMethods[sel.Sel.Name] {
					return true
				}
				if len(call.Args) < 2 {
					return true
				}
				registers = m52Normalise(renderNode(fset, sel.X)) + "." + sel.Sel.Name
				return false
			})
			if registers == "" {
				continue
			}
			offenders = append(offenders, filepath.ToSlash(path)+":"+
				strconv.Itoa(fset.Position(fn.Pos()).Line)+" declares func "+fn.Name.Name+
				", which takes a router and calls "+registers+"(...) on one")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s for router mounters: %v", apiRootPath, err)
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
	routes, groups, aliasAt := m52ParseMainGo(t)
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
		if m52HasTenantTx(r.chain, r.chainAt, aliasAt) {
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
