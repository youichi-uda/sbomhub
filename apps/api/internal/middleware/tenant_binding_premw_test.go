package middleware

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// M52P — the AST half of the pre-TenantTx middleware gate.
//
// It derives, from cmd/server/main.go, the set of middlewares that run with
// nothing having bound `app.current_tenant_id`, and compares it against
// preTenantTxMiddleware in both directions. See that table's doc comment for
// what the classification means and why the question is worth asking; this
// file is only the mechanism.
//
// # Scan unit — the same one, sliced differently
//
// Nothing new is parsed. m52ParseMainGo already resolves every route's
// EFFECTIVE chain (global `e.Use` / `e.Pre` ++ inherited group middleware ++
// the registration's own arguments), and m52Expand already resolves an entry
// held in a variable. Group and per-route entries are in source order, which
// is the order echo runs them in; the globals are not ordered against each
// other, which does not matter here and cannot start mattering silently — see
// preTenantTxMiddleware's "does NOT cover" list for why. So the derivation is
// one line of set logic over that chain:
//
//	for each route, take the chain entries BEFORE the first one that expands
//	to contain "TenantTx(" — the whole chain when there is none.
//
// Everything the route parser cannot see, this cannot see either, and every
// gap errs the same way it does there: an unresolved thing reads as "not
// TenantTx", so the entries around it stay in the unbound prefix and DEMAND a
// classification rather than dropping out of it. Deliberately reusing that
// parser rather than writing a second one is the point — a hand-written
// resolver for a language whose scoping rules are not ours is what this whole
// family of gates exists to avoid.
//
// # The key, and the one way it is deliberately lossy
//
// m52pMiddlewareIdentity renders the constructor and DROPS the arguments, so
//
//	appmw.RateLimitByAPIKey(rdb, appmw.BudgetPoll)
//	appmw.RateLimitByAPIKey(rdb, appmw.BudgetStandard)
//
// are one entry. That is the right loss: the question is "does this middleware
// read an RLS-protected table with no tenant bound", which is a property of the
// FUNCTION. Keying by the rendered call instead would have split that one
// answer across two rules differing only in a budget constant — and made the
// key change every time an argument was renamed, which is the churn that gets a
// table rubber-stamped.
//
// What it does NOT drop is the package qualifier: `appmw.Auth` and `mw.Auth`
// are different keys. An import alias rename therefore costs one line here.
// That is the price of a key that is stable against everything else, and it
// fails loudly with the new spelling in the message.
//
// # Which way it errs
//
// An entry this file cannot reduce to a constructor — an unparsable rendering,
// a composite literal, a bare identifier main.go never bound — keeps its
// normalised text as the key, matches nothing in the table, and fails. Loud on
// a shape nobody writes today, rather than silent on one somebody might.
// ---------------------------------------------------------------------------

// m52pMiddlewareIdentity reduces one rendered (and already alias-expanded)
// chain entry to the key preTenantTxMiddleware is written against.
//
// Re-parsing the rendered text rather than carrying ast.Expr through the group
// walk is deliberate: alias expansion happens on TEXT (m52Expand substitutes
// into the rendering), so the expression an entry finally denotes only exists
// as a string. Parsing that string is the one place both halves agree.
func m52pMiddlewareIdentity(entry string) string {
	text := strings.TrimSpace(entry)
	expr, err := parser.ParseExpr(text)
	if err != nil {
		// Not an expression this can reduce. Returning the text unchanged makes
		// it an unclassified key, which fails the sweep with the text in the
		// message — the loud direction.
		return m52Normalise(text)
	}
	fset := token.NewFileSet()
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			break
		}
		expr = p.X
	}
	if call, ok := expr.(*ast.CallExpr); ok {
		return m52Normalise(renderNode(fset, call.Fun))
	}
	// A middleware VALUE rather than a call: `var mw echo.MiddlewareFunc = ...`
	// passed straight through, or an identifier main.go never bound. Its own
	// text is the key, so it is classified explicitly or it fails.
	return m52Normalise(renderNode(fset, expr))
}

// m52pUnboundMiddleware returns middleware identity → the route keys it runs
// unbound on, sorted, plus how many routes carried TenantTx at all.
func m52pUnboundMiddleware(t *testing.T) (map[string][]string, int) {
	t.Helper()
	routes, _, aliasAt := m52ParseMainGo(t)

	out := map[string]map[string]bool{}
	withTx := 0
	for key, r := range m52LastRegistrationPerKey(routes) {
		cut := len(r.chain)
		for i, entry := range r.chain {
			if strings.Contains(m52Expand(entry, r.chainAt, aliasAt), "TenantTx(") {
				cut = i
				break
			}
		}
		if cut < len(r.chain) {
			withTx++
		}
		for _, entry := range r.chain[:cut] {
			id := m52pMiddlewareIdentity(m52Expand(entry, r.chainAt, aliasAt))
			if out[id] == nil {
				out[id] = map[string]bool{}
			}
			out[id][key] = true
		}
	}

	flat := make(map[string][]string, len(out))
	for id, keys := range out {
		list := make([]string, 0, len(keys))
		for k := range keys {
			list = append(list, k)
		}
		sort.Strings(list)
		flat[id] = list
	}
	return flat, withTx
}

// m52pSample renders up to n route keys for an error message, with a count of
// the rest. A middleware on 137 routes must not print 137 lines.
func m52pSample(keys []string, n int) string {
	if len(keys) <= n {
		return strings.Join(keys, ", ")
	}
	return strings.Join(keys[:n], ", ") + " (+" + strconv.Itoa(len(keys)-n) + " more)"
}

// TestM52PPreTenantTxMiddlewareIsClassified is the sweep.
//
// Both directions, for the same reasons the route sweep gives. A MISSING entry
// is a middleware doing database work on a connection where the RLS predicate
// is NULL or the empty string cast to UUID, with nobody having written down
// whether that is safe. A STALE entry pre-approves a middleware that gets
// re-wired ahead of TenantTx later without anyone re-reading it.
func TestM52PPreTenantTxMiddlewareIsClassified(t *testing.T) {
	derived, withTx := m52pUnboundMiddleware(t)
	if len(derived) == 0 {
		t.Fatal("found no middleware running ahead of TenantTx in main.go — the derivation " +
			"is blind. main.go has always had at least four global `e.Use` middlewares, " +
			"and echo applies those to every route.")
	}
	if withTx == 0 {
		t.Fatal("not one route in main.go carries TenantTx, so every chain was taken whole " +
			"and this test is measuring something other than what it says. Either the " +
			"middleware was removed from the server or m52HasTenantTx stopped matching.")
	}

	var missing []string
	for id, routes := range derived {
		if _, ok := preTenantTxMiddleware[id]; !ok {
			missing = append(missing, id+"  ("+strconv.Itoa(len(routes))+" routes: "+
				m52pSample(routes, 3)+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s runs with NOTHING having bound app.current_tenant_id and is not "+
			"classified in middleware.preTenantTxMiddleware.\n"+
			"Every statement it issues lands on a pooled connection where the RLS policy "+
			"predicate is either NULL (zero rows — a false 404 even for your own data) or "+
			"''::UUID (22P02 — a 500 for every input); see that table's doc comment.\n"+
			"Add an entry. PreTenantTxNamesNoTable if it issues no statement naming a "+
			"table (say in Why what it does instead — Redis, the echo context, nothing at "+
			"all); PreTenantTxRLSExemptTablesOnly and name every table, each of which is "+
			"checked against live pg_class; PreTenantTxBindsWhatItReaches if it reaches an "+
			"RLS-protected table and binds first, naming BindsVia and a ProvedBy test that "+
			"drives it on a poisoned connection.\n"+
			"If the key above is not a constructor expression — a bare identifier, a "+
			"composite literal — this gate could not reduce the chain entry, which is "+
			"itself worth a look before classifying it.", m)
	}

	var stale []string
	for id := range preTenantTxMiddleware {
		if _, ok := derived[id]; !ok {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("middleware.preTenantTxMiddleware classifies %q, which no longer runs ahead "+
			"of TenantTx on any route in main.go — either it is gone, or every chain that "+
			"carried it now binds the tenant first. Drop the entry: a stale rule silently "+
			"pre-approves the middleware if it is wired back in front of TenantTx later.", s)
	}
}

// TestM52PEveryPreTenantTxRuleCarriesItsEvidence enforces the shape of the
// table: a classification with no reason, or a binding claim with nothing
// naming or driving it, is a comment pretending to be a gate.
func TestM52PEveryPreTenantTxRuleCarriesItsEvidence(t *testing.T) {
	for _, key := range PreTenantTxMiddlewareKeys() {
		rule := preTenantTxMiddleware[key]
		if strings.TrimSpace(rule.Why) == "" {
			t.Errorf("%s has no Why. For PreTenantTxNamesNoTable the reason is the WHOLE of "+
				"the evidence — nothing about that class is checked against a database.", key)
		}
		switch rule.Kind {
		case PreTenantTxNamesNoTable:
			if len(rule.RLSExemptTables) != 0 || len(rule.BoundRLSTables) != 0 {
				t.Errorf("%s is NamesNoTable but names tables. If it names one, it is not this "+
					"class — re-classify so the name gets checked against live pg_class.", key)
			}
			if len(rule.BindsVia) != 0 || strings.TrimSpace(rule.ProvedBy) != "" {
				t.Errorf("%s is NamesNoTable but claims a binding. A middleware that touches no "+
					"table has nothing to bind FOR, and the claim would read as verified "+
					"evidence while nothing verifies it.", key)
			}
		case PreTenantTxRLSExemptTablesOnly:
			if len(rule.RLSExemptTables) == 0 {
				t.Errorf("%s is RLSExemptTablesOnly and names no table. The table list is the "+
					"entire assertion; empty, it asserts nothing. If it really touches none, "+
					"classify it PreTenantTxNamesNoTable.", key)
			}
			if len(rule.BoundRLSTables) != 0 || len(rule.BindsVia) != 0 ||
				strings.TrimSpace(rule.ProvedBy) != "" {
				t.Errorf("%s is RLSExemptTablesOnly but also claims a binding. If it binds "+
					"something, classify it PreTenantTxBindsWhatItReaches so the binding gets "+
					"driven.", key)
			}
		case PreTenantTxBindsWhatItReaches:
			if len(rule.BoundRLSTables) == 0 {
				t.Errorf("%s is BindsWhatItReaches but names no BoundRLSTables. Which protected "+
					"table forced the classification is the load-bearing fact; without it "+
					"nothing can check the rule has not gone stale.", key)
			}
			if len(rule.BindsVia) == 0 {
				t.Errorf("%s is BindsWhatItReaches but names no BindsVia function.", key)
			}
			if strings.TrimSpace(rule.ProvedBy) == "" {
				t.Errorf("%s is BindsWhatItReaches but names no ProvedBy test. This is a promise "+
					"about code in another package; unmeasured, it is exactly the comment that "+
					"was already in main.go when /reanalyse shipped broken.", key)
			}
		default:
			t.Errorf("%s has an unknown Kind %q. Add a case here and decide what evidence it "+
				"must carry before the table accepts it.", key, rule.Kind)
		}
	}
}

// TestM52PSetCurrentTenantIsNotAcceptedAsABinding refuses the one wrong answer
// a reader is most likely to reach for.
//
// TenantRepository.SetCurrentTenant looks exactly like a binding — it issues
// `SELECT set_config('app.current_tenant_id', $1, true)` — and three of the
// middlewares in this table call it. It binds nothing for them. With no
// ambient transaction the statement runs in its own implicit one and
// `is_local = true` discards the value at commit; measured on the migrated
// schema (2026-08-05) the next statement on that connection reads the
// placeholder as the EMPTY STRING, which is the state that turns an unbound
// read into a 500 rather than a false 404.
//
// So a rule naming it in BindsVia would be claiming the opposite of what the
// call does, and would do it in the field a reviewer reads first.
func TestM52PSetCurrentTenantIsNotAcceptedAsABinding(t *testing.T) {
	for _, key := range PreTenantTxMiddlewareKeys() {
		for _, via := range preTenantTxMiddleware[key].BindsVia {
			if !strings.Contains(via, "SetCurrentTenant") {
				continue
			}
			t.Errorf("%s names %q in BindsVia. SetCurrentTenant does not bind anything for a "+
				"middleware that runs outside a transaction: `is_local = true` discards the "+
				"value when the implicit single-statement transaction commits, one statement "+
				"later. A real binding OPENS a transaction and issues the set_config inside "+
				"it — repository.TenantRepository.Create and triage.DBTxManager are the two "+
				"in this codebase that do.", key, via)
		}
	}
}

// TestM52PEveryBindingRuleNamesAnExistingTest resolves each ProvedBy name
// against the test sources, so a typo or a deleted drive is caught here.
//
// Existence only, like its route-table counterpart. What the drive asserts is
// its own business; what this stops is a rule pointing at nothing.
func TestM52PEveryBindingRuleNamesAnExistingTest(t *testing.T) {
	declared := m52TestFuncNames(t)
	for _, key := range PreTenantTxMiddlewareKeys() {
		rule := preTenantTxMiddleware[key]
		if rule.Kind != PreTenantTxBindsWhatItReaches {
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

// TestM52PMiddlewareIdentityReducesTheShapesMainGoUses pins the one piece of
// logic this file adds that is not already exercised by the sweep.
//
// The sweep proves an UNKNOWN key fails. What it cannot show is that a key is
// derived the way the table is written — that dropping arguments really does
// collapse two call sites onto one rule, and that a shape the reduction cannot
// handle keeps its text rather than silently becoming some other rule's key.
func TestM52PMiddlewareIdentityReducesTheShapesMainGoUses(t *testing.T) {
	cases := []struct{ in, want, why string }{
		{"appmw.RequireWrite()", "appmw.RequireWrite",
			"the no-argument case"},
		{"appmw.RateLimitByAPIKey(rdb, appmw.BudgetPoll)", "appmw.RateLimitByAPIKey",
			"arguments dropped, so this and the BudgetStandard call site are ONE rule"},
		{"appmw.RateLimitByAPIKey(rdb, appmw.BudgetStandard)", "appmw.RateLimitByAPIKey",
			"the other half of the same pair"},
		{"appmw.Auth(config.Load(), repository.NewTenantRepository(db), repository.NewUserRepository(db))",
			"appmw.Auth", "nested constructor calls in the arguments are dropped with them"},
		{"appmw.NewTriageConcurrencyLimiterFromEnv().Middleware()",
			"appmw.NewTriageConcurrencyLimiterFromEnv().Middleware",
			"a method on a constructed value keeps the whole selector"},
		{"( appmw.RequireAdmin() )", "appmw.RequireAdmin",
			"parenthesised"},
		{"appmw.SomeMiddlewareValue", "appmw.SomeMiddlewareValue",
			"a value rather than a call is its own key, so it is classified explicitly"},
		{"[]echo.MiddlewareFunc{a, b}", "[]echo.MiddlewareFunc{a, b}",
			"a shape the reduction does not model keeps its text and fails the sweep loudly"},
		{"appmw.Broken(", "appmw.Broken(",
			"unparsable text is returned as-is rather than dropped"},
		{"middleware.BodyLimit(\"10M\")", "middleware.BodyLimit",
			"a literal argument is dropped like any other"},
	}
	for _, c := range cases {
		if got := m52pMiddlewareIdentity(c.in); got != c.want {
			t.Errorf("m52pMiddlewareIdentity(%q) = %q, want %q (%s)", c.in, got, c.want, c.why)
		}
	}
}

// TestM52PUnboundPrefixAgreesWithTheRouteSweep ties the two gates together.
//
// This file computes "the entries before TenantTx, or the whole chain when
// there is none". The route sweep computes "the routes with no TenantTx". They
// are two readings of one predicate, and if they ever disagree then one of the
// two tables is being checked against a route set the other does not recognise
// — silently, because each passes on its own terms.
//
// So the identity is asserted rather than assumed: a route contributes its
// WHOLE chain here exactly when the route sweep calls it unbound.
func TestM52PUnboundPrefixAgreesWithTheRouteSweep(t *testing.T) {
	routes, _, aliasAt := m52ParseMainGo(t)
	wholeChain := map[string]bool{}
	for key, r := range m52LastRegistrationPerKey(routes) {
		if !m52HasTenantTx(r.chain, r.chainAt, aliasAt) {
			wholeChain[key] = true
		}
	}
	sweep := m52NoTenantTxRoutes(t)

	for key := range wholeChain {
		if _, ok := sweep[key]; !ok {
			t.Errorf("%s has no TenantTx by this file's reading, so its whole chain is "+
				"examined here — but the route sweep does not list it as unbound. The two "+
				"gates are reading different route sets.", key)
		}
	}
	for key := range sweep {
		if !wholeChain[key] {
			t.Errorf("%s is listed as unbound by the route sweep, but this file found a "+
				"TenantTx in its chain and examined only a prefix. The two gates are reading "+
				"different route sets.", key)
		}
	}
	if len(wholeChain) == 0 {
		t.Error("no route was found without TenantTx, so this comparison compared two empty " +
			"sets. main.go has always had at least the two provider webhooks and /health.")
	}
}

// TestM52PDerivationIsNotBlind is the blindness guard, and — like
// TestM52ParserIsNotBlind — deliberately not a pin.
//
// The floors are far below the measured values so that adding or removing a
// middleware, which is correct code, does not redden a required check twice
// (the sweep above already owns that surface). What they catch is the
// derivation resolving nothing, which would make every assertion here vacuous.
//
// For the record rather than as an assertion, measured 2026-08-05: 181 route
// registrations resolving to 181 distinct method+path keys, 172 of them
// carrying TenantTx, and 14 distinct middlewares running unbound — four of
// them echo's globals, on all 181.
func TestM52PDerivationIsNotBlind(t *testing.T) {
	const (
		minMiddleware = 4  // echo's global e.Use set alone
		minTenantTx   = 20 // main.go has had three TenantTx groups for a long time
	)
	derived, withTx := m52pUnboundMiddleware(t)
	if len(derived) < minMiddleware {
		t.Errorf("resolved only %d distinct middlewares running ahead of TenantTx, want at "+
			"least %d — main.go's global `e.Use` set alone is that many, and echo applies "+
			"it to every route", len(derived), minMiddleware)
	}
	if withTx < minTenantTx {
		t.Errorf("only %d routes were seen to carry TenantTx, want at least %d. Below that "+
			"the prefix this gate examines is being taken from chains it failed to "+
			"resolve, not from the router.", withTx, minTenantTx)
	}
	// Both sides of the reduction must work. If m52pMiddlewareIdentity fell
	// back to raw text for everything, the sweep would fail loudly — but if it
	// fell back for a MINORITY the sweep failure would look like an ordinary
	// unclassified middleware, so name the shape here instead.
	unreduced := 0
	for id := range derived {
		if strings.ContainsAny(id, "{}\"") || strings.HasSuffix(id, ")") {
			unreduced++
			t.Logf("NOTE: %q did not reduce to a plain constructor expression. That is not a "+
				"failure by itself — it is classified or it is not — but it is the shape a "+
				"broken reduction produces, so check it is really written that way in "+
				"main.go.", id)
		}
	}
	if unreduced == len(derived) {
		t.Errorf("not one of the %d derived keys reduced to a constructor expression — "+
			"m52pMiddlewareIdentity is failing on everything, and the sweep's failures "+
			"are about the reduction rather than about the router.", len(derived))
	}
}
