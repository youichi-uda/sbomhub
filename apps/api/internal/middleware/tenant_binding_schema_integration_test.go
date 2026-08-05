//go:build integration

// Package middleware — M52: the TouchesNoRLSTable half of the tenant-binding
// gate, checked against the live schema.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M52' ./internal/middleware
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// # Why pg_class and not grep
//
// A route classified TouchesNoRLSTable is safe only for as long as the runtime
// role can still reach every relation it names with no tenant bound. In
// practice today that means none of them has Row-Level Security. Deciding that from the migrations by
// grepping for `ENABLE ROW LEVEL SECURITY` gets it wrong in the one direction
// that matters: four of this project's migrations (028 / 029 / 030 / 031)
// exist specifically to DISABLE RLS on a table an earlier migration enabled it
// on, and a later one could just as easily re-enable it. The grep would report
// the first statement it finds and call the table protected — or, run the other
// way, call it exempt because the ENABLE lives in a file it did not read.
//
// `pg_class.relrowsecurity` on the migrated database is the authority: it is
// the state the policy engine actually consults, after every migration in the
// directory has had its say.
//
// Measured on the migrated schema, 2026-08-05: 61 ordinary tables in schema
// `public`, 35 with RLS on and 26 with it off. No partitioned tables, no
// application views, no non-`public` application schema.
package middleware

import (
	"database/sql"
	"os"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

func m52SchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = os.Getenv("MIGRATE_DATABASE_URL")
	}
	if url == "" {
		t.Skip("M52 schema check requires DATABASE_URL or MIGRATE_DATABASE_URL. Start " +
			"postgres, apply migrations, source the .env values, then re-run with " +
			"-tags=integration.")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open DB: %v", err)
		return nil
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping DB: %v (the URL is set, so this is a broken environment, not an "+
			"absent one)", err)
		return nil
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// m52TableRLS is what the catalog says about one table's row security.
type m52TableRLS struct {
	// Enabled is pg_class.relrowsecurity. When false, stored policies are
	// ignored entirely and the table is a hazard to nobody — that much the
	// catalog decides on its own.
	Enabled bool
	// Kind is pg_class.relkind: 'r' ordinary, 'p' partitioned, 'm'
	// materialised view. The last one is exempt by construction and is
	// reported rather than assessed.
	Kind string
}

// m52LiveRLS returns relation name → row-security state for every relation in
// the public schema a route could name: ordinary ('r'), partitioned ('p'),
// materialised views ('m'), ordinary views ('v') and foreign tables ('f').
//
// All five are included because a rule may legitimately name any of them, and
// "does not exist" is the wrong answer for a relation that is simply not an
// ordinary table:
//
//	'm'  reads return the STORED result; the underlying query runs at REFRESH.
//	'v'  policies are evaluated as the view's OWNER unless it is
//	     security_invoker, so telling the author to list base tables instead
//	     would test the wrong identity. The view itself is probed.
//	'f'  foreign tables carry no local RLS at all (there is no
//	     ALTER FOREIGN TABLE ... ENABLE ROW LEVEL SECURITY).
func m52LiveRLS(t *testing.T) map[string]m52TableRLS {
	t.Helper()
	db := m52SchemaDB(t)
	rows, err := db.Query(`
		SELECT c.relname, c.relrowsecurity, c.relkind::text
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm', 'v', 'f')`)
	if err != nil {
		t.Fatalf("read pg_class: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]m52TableRLS{}
	for rows.Next() {
		var name string
		var st m52TableRLS
		if err := rows.Scan(&name, &st.Enabled, &st.Kind); err != nil {
			t.Fatalf("scan pg_class row: %v", err)
		}
		out[name] = st
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate pg_class: %v", err)
	}
	if len(out) < 30 {
		t.Fatalf("found only %d relations in the public schema — the database this test is "+
			"pointed at is not the migrated SBOMHub schema, so every assertion below "+
			"would be vacuous", len(out))
	}
	return out
}

// m52ReadVerdict is what actually happened when the runtime role read one
// table with no tenant bound.
type m52ReadVerdict struct {
	// ProbeErr is the error a real `SELECT 1 FROM <t> LIMIT 1` raised on the
	// poisoned connection, or nil. This is the ONLY failing signal.
	ProbeErr error
	// Rows is how many rows that read returned (0 or 1). A read that returned
	// a row is positive proof the role can see into the table; a read that
	// returned none proves nothing, because the table may simply be empty.
	Rows int
	// Policies and Context are diagnostic only — they go into messages, never
	// into the pass/fail decision. See the doc comment below for why.
	Policies int
	Context  string
}

// m52UnboundReadVerdict reads one RLS-enabled table as the runtime role with
// no tenant bound, and reports what happened.
//
// # Why the policy catalogue is diagnostic and not decisive
//
// Three earlier versions tried to DECIDE from the catalogue: "RLS is enabled",
// then "some policy mentions the GUC", then "every permissive SELECT policy
// applicable to this role mentions the GUC". Each was a model of a question
// PostgreSQL answers itself, and each was wrong at an edge that reddens CI on
// a correct schema. The last one failed this, which is a policy that
// deliberately ADMITS the unbound state:
//
//	CREATE POLICY p ON t FOR SELECT TO sbomhub_app
//	  USING (NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL);
//
// It mentions `app.current_tenant_id`, so the text model called it
// tenant-gated and reported the table denied — while the live read returned
// rows. Visibility is the BOOLEAN RESULT of an expression over a row, not a
// property of its deparsed text, and reproducing that in Go means
// reimplementing PostgreSQL's policy evaluation: exactly the hand-written
// analysis this whole gate exists to avoid.
//
// So the only thing that fails is the statement itself failing. The catalogue
// is still read, and still reported, because "RLS is on and there are N
// policies" is what a human needs in order to go and look.
func m52UnboundReadVerdict(t *testing.T, table string) m52ReadVerdict {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("this check needs DATABASE_URL (the sbomhub_app role): the migrator OWNS " +
			"these tables, and what the RUNTIME role can read is the whole question")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open app DB: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	v := m52ReadVerdict{}
	if err := db.QueryRow(`
		SELECT count(*)
		FROM pg_policy p
		JOIN pg_class c ON c.oid = p.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relname = $1`, table).Scan(&v.Policies); err != nil {
		t.Fatalf("read pg_policy for %q: %v", table, err)
	}

	// Put the single connection into the state a running server's pool is in:
	// `SET LOCAL` outside a transaction leaves the placeholder at the empty
	// string for the next statement.
	if _, err := db.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`,
		"00000000-0000-0000-0000-000000000000"); err != nil {
		t.Fatalf("poison the probe connection: %v", err)
	}
	var isNull bool
	var val sql.NullString
	if err := db.QueryRow(
		`SELECT current_setting('app.current_tenant_id', true) IS NULL,
		        current_setting('app.current_tenant_id', true)`).Scan(&isNull, &val); err != nil {
		t.Fatalf("read GUC state: %v", err)
	}
	if isNull || val.String != "" {
		t.Fatalf("probe precondition not met: app.current_tenant_id is (null=%v, value=%q), "+
			"want a non-NULL empty string", isNull, val.String)
	}

	// The identifier comes from the classification table in this repository,
	// and has already been resolved against pg_class by the caller.
	rows, perr := db.Query(`SELECT 1 FROM "` + table + `" LIMIT 1`)
	if perr != nil {
		v.ProbeErr = perr
		return v
	}
	for rows.Next() {
		v.Rows++
	}
	if cerr := rows.Err(); cerr != nil {
		v.ProbeErr = cerr
	}
	_ = rows.Close()
	if v.Rows > 0 {
		v.Context = "the read returned a row, so the role can see into the table"
	} else {
		v.Context = "the read returned no rows, which proves nothing: the table may be " +
			"empty, or a policy may be excluding everything"
	}
	return v
}

// TestM52TouchesNoRLSTableRulesNameOnlyRLSExemptTables is the check that keeps
// a TouchesNoRLSTable classification true after the migration that would
// falsify it.
//
// Three of the tables named by the Lemon Squeezy rule are RLS-free BECAUSE of
// that route (migrations 029 / 031 / 060). Nothing stops a future migration
// from adding a policy back — `subscriptions` is an obvious candidate the day
// somebody notices it carries tenant_id and no policy. On that day this test
// goes red and the route gets re-classified, instead of quietly becoming the
// next /reanalyse.
func TestM52TouchesNoRLSTableRulesNameOnlyRLSExemptTables(t *testing.T) {
	live := m52LiveRLS(t)

	checked := 0
	for _, key := range NoTenantTxRouteKeys() {
		rule := noTenantTxRouteBinding[key]
		if rule.Kind != TenantBindingTouchesNoRLSTable {
			continue
		}
		tables := append([]string{}, rule.RLSExemptTables...)
		sort.Strings(tables)
		for _, table := range tables {
			st, exists := live[table]
			if !exists {
				t.Errorf("%s names %q, which is not an ordinary or partitioned table in "+
					"schema `public`. A name that resolves to nothing is checked by "+
					"nothing, so correct the list: if the object was renamed or dropped, "+
					"re-read the route; if it is a VIEW, list the underlying tables instead "+
					"— a view has no meaningful relrowsecurity of its own, the policies that "+
					"decide the answer belong to what it selects from.", key, table)
				continue
			}
			checked++
			switch {
			case (st.Kind == "r" || st.Kind == "p") && !st.Enabled:
				// Decisive on its own: with relrowsecurity false, PostgreSQL
				// ignores every stored policy.
				continue
			case st.Kind == "f":
				// A foreign table. PostgreSQL has no way to put row security
				// on one — there is no ALTER FOREIGN TABLE ... ENABLE ROW
				// LEVEL SECURITY — so there is nothing here to check, and
				// probing it would reach the remote server: a wrapper that is
				// unreachable, misconfigured or slow would fail this gate for
				// a reason that has nothing to do with tenant binding.
				// Measured 2026-08-05: a foreign table on a handler-less
				// wrapper made the probe raise, which is exactly that false
				// alarm.
				t.Logf("NOTE: %s names %q, a FOREIGN TABLE. It cannot carry local row "+
					"security, so it is exempt by construction and is not probed — whatever "+
					"the remote enforces is outside this gate.", key, table)
				continue
			}
			if ack, ok := rule.RLSEnabledButReachable[table]; ok {
				t.Logf("NOTE: %s names %q, which carries row security, and the rule declares "+
					"it reachable anyway: %s", key, table, ack)
				continue
			}
			v := m52UnboundReadVerdict(t, table)
			if v.ProbeErr != nil {
				t.Errorf("%s names %q (relkind %q), and a plain `SELECT 1 FROM %s LIMIT 1` as "+
					"the runtime role, with no tenant bound, FAILS: %v\n"+
					"That is the connection state this route's statements run in — it carries "+
					"no TenantTx. (%d policies on the relation.)\n"+
					"Move the route onto a TenantTx chain, or re-classify it "+
					"TenantBindingBindsItself with a binding and a drive. If instead the READ "+
					"is not what this route does — it only INSERTs, or it reads through a view "+
					"whose owner can see what the runtime role cannot — say so in the rule's "+
					"RLSEnabledButReachable entry for %q and this passes.\n"+
					"Reason recorded for the old classification: %s",
					key, table, st.Kind, table, v.ProbeErr, v.Policies, table, rule.Why)
				continue
			}
			// No error. Record what that does and does not establish rather
			// than implying more — see m52UnboundReadVerdict's doc comment for
			// why the policy catalogue is not consulted for a verdict.
			if st.Enabled || st.Kind != "r" {
				t.Logf("NOTE: %s names %q (relkind %q, rls=%v, %d policies). An unbound read "+
					"of it as the runtime role raised nothing, so this is not failing — %s. "+
					"Only SELECT was exercised; if the route also INSERTs or UPDATEs, read "+
					"those policies yourself.", key, table, st.Kind, st.Enabled, v.Policies, v.Context)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no TouchesNoRLSTable rule named a table that exists — this test asserted " +
			"nothing. /health names none by design, so at least the Lemon Squeezy rule's " +
			"five should have been checked.")
	}
}

// TestM52PPreTenantTxRulesNameOnlyReachableTables is the same check for the
// pre-TenantTx middleware table.
//
// It matters for the same reason and rather more widely: `api_keys` is
// RLS-free BECAUSE migration 028 removed it so an API-key lookup could run
// before any tenant is known, and `appmw.Auth` reads three RLS-free tables on
// most routes of the API. Any migration that gives one of those a policy turns
// a middleware that runs on 137 chains into a 500, and it does so on a
// connection where nothing has bound the tenant. On that day this goes red.
//
// The verdict machinery is shared with the route check above, deliberately: it
// took three attempts to get "can the runtime role read this with no tenant
// bound" right, and the answer is not one to reimplement.
func TestM52PPreTenantTxRulesNameOnlyReachableTables(t *testing.T) {
	live := m52LiveRLS(t)

	checked := 0
	for _, key := range PreTenantTxMiddlewareKeys() {
		rule := PreTenantTxMiddlewareRules()[key]

		tables := append([]string{}, rule.RLSExemptTables...)
		sort.Strings(tables)
		for _, table := range tables {
			st, exists := live[table]
			if !exists {
				t.Errorf("%s names %q in RLSExemptTables, which is not a relation in schema "+
					"`public`. A name that resolves to nothing is checked by nothing: if the "+
					"table was renamed or dropped, re-read the middleware and correct the list.",
					key, table)
				continue
			}
			checked++
			switch {
			case (st.Kind == "r" || st.Kind == "p") && !st.Enabled:
				continue // relrowsecurity false — every stored policy is ignored
			case st.Kind == "f":
				t.Logf("NOTE: %s names %q, a FOREIGN TABLE. It cannot carry local row security, "+
					"so it is exempt by construction and is not probed.", key, table)
				continue
			}
			if ack, ok := rule.RLSEnabledButReachable[table]; ok {
				t.Logf("NOTE: %s names %q, which carries row security, and the rule declares it "+
					"reachable anyway: %s", key, table, ack)
				continue
			}
			v := m52UnboundReadVerdict(t, table)
			if v.ProbeErr != nil {
				t.Errorf("%s names %q (relkind %q), and a plain `SELECT 1 FROM %s LIMIT 1` as the "+
					"runtime role, with no tenant bound, FAILS: %v\n"+
					"That is the connection state this middleware runs in on every route it is "+
					"registered on — it sits AHEAD of TenantTx, so nothing has bound the tenant "+
					"when it issues its statements. (%d policies on the relation.)\n"+
					"Either give the middleware a transaction of its own that binds before it "+
					"reads — and re-classify it PreTenantTxBindsWhatItReaches with a BindsVia "+
					"and a ProvedBy drive — or, if the READ is not what it does here (an "+
					"INSERT-only path, a view read as its owner, a foreign table), record that "+
					"in the rule's RLSEnabledButReachable entry for %q.\n"+
					"Reason recorded for the current classification: %s",
					key, table, st.Kind, table, v.ProbeErr, v.Policies, table, rule.Why)
				continue
			}
			if st.Enabled || st.Kind != "r" {
				t.Logf("NOTE: %s names %q (relkind %q, rls=%v, %d policies). An unbound read of "+
					"it as the runtime role raised nothing, so this is not failing — %s. Only "+
					"SELECT was exercised; if the middleware also INSERTs or UPDATEs, read those "+
					"policies yourself.", key, table, st.Kind, st.Enabled, v.Policies, v.Context)
			}
		}

		// BoundRLSTables is checked in ONE direction only, and the asymmetry is
		// the point. A name that resolves to nothing is a stale rule and fails.
		// A name whose row security has been REMOVED makes the rule
		// over-cautious rather than wrong — the middleware still binds, the
		// binding is simply no longer needed — so that is logged. Failing there
		// would redden a correct middleware for a migration that made its life
		// easier, which is the false alarm that gets a gate switched off.
		bound := append([]string{}, rule.BoundRLSTables...)
		sort.Strings(bound)
		for _, table := range bound {
			st, exists := live[table]
			if !exists {
				t.Errorf("%s names %q in BoundRLSTables, which is not a relation in schema "+
					"`public`. That name is the load-bearing fact of a "+
					"PreTenantTxBindsWhatItReaches rule — the protected table that forced the "+
					"classification — so a rule pointing at nothing is asserting nothing. "+
					"Re-read the middleware and correct the list.", key, table)
				continue
			}
			checked++
			if !st.Enabled {
				t.Logf("NOTE: %s names %q in BoundRLSTables, but relrowsecurity is now FALSE on "+
					"it (relkind %q). The rule is not wrong — %s still binds — but the binding "+
					"is no longer what makes the middleware safe, so the rule may be "+
					"simplifiable to PreTenantTxRLSExemptTablesOnly. Not failing: a migration "+
					"that removes a policy has not broken anything here.",
					key, table, st.Kind, strings.Join(rule.BindsVia, " / "))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no pre-TenantTx rule named a table that exists — this test asserted nothing. " +
			"The authenticators name five between them (api_keys, tenants, tenant_users, " +
			"users, scan_settings), so those should have been checked.")
	}
}

// TestM52NoExemptTableNameIsAmbiguous underwrites the unqualified table names
// the classification table uses.
//
// m52LiveRLS keys by bare `relname` inside schema `public`. If a relation with
// the SAME NAME sat EARLIER in the runtime search_path, an unqualified query in
// the route would resolve to that one while this gate kept checking the
// `public` one — the wrong object, and a miss nothing would reveal.
//
// # Two things it deliberately does not do
//
// It does not flag a same-named relation in a schema that is NOT in the
// effective search_path, because PostgreSQL never resolves to it: an
// `observability.audit_logs` under the default `"$user", public` path cannot
// shadow anything, and failing for it would redden a correct deployment.
//
// It does not restrict the shadowing relation's kind. A view, a materialised
// view or a foreign table earlier in the path shadows `public.<name>` exactly
// as an ordinary table does, so all of them count here even though m52LiveRLS
// itself only enumerates the kinds a route can carry RLS on.
func TestM52NoExemptTableNameIsAmbiguous(t *testing.T) {
	named := map[string]bool{}
	for _, key := range NoTenantTxRouteKeys() {
		for _, table := range noTenantTxRouteBinding[key].RLSExemptTables {
			named[table] = true
		}
	}
	// The pre-TenantTx middleware table names tables the same way and is
	// resolved by the same unqualified lookup, so it inherits the same hazard.
	// Both of its lists are included: a BoundRLSTables name that resolves to a
	// shadowing relation would make the binding check assert something about a
	// different object just as readily.
	for _, key := range PreTenantTxMiddlewareKeys() {
		rule := PreTenantTxMiddlewareRules()[key]
		for _, table := range rule.RLSExemptTables {
			named[table] = true
		}
		for _, table := range rule.BoundRLSTables {
			named[table] = true
		}
	}
	if len(named) == 0 {
		t.Skip("no rule names an exempt table, so there is no name to disambiguate")
	}
	names := make([]string, 0, len(named))
	for n := range named {
		names = append(names, n)
	}
	sort.Strings(names)

	// The runtime role, not the migrator: this test reads current_schemas(),
	// which is a property of the CONNECTING role. Resolving it as the migrator
	// would judge name ambiguity against a search_path the route never has —
	// and a migrator-only schema ahead of `public` would fail a deployment in
	// which sbomhub_app resolves correctly.
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("name-ambiguity resolution is a property of the RUNTIME role's search_path, " +
			"so this check needs DATABASE_URL (sbomhub_app) rather than the migrator fallback")
	}
	db := m52SchemaDB(t)

	// The effective search_path of the connecting role, with "$user" and
	// implicit pg_catalog resolved. Only schemas listed BEFORE public can
	// shadow a public relation.
	var path []byte
	if err := db.QueryRow(
		`SELECT array_to_string(current_schemas(true), ',')`).Scan(&path); err != nil {
		t.Fatalf("read current_schemas: %v", err)
	}
	schemas := strings.Split(string(path), ",")
	ahead := map[string]bool{}
	for _, sch := range schemas {
		if sch == "public" {
			break
		}
		ahead[sch] = true
	}
	if len(ahead) == 0 {
		t.Logf("search_path is %q — nothing precedes `public`, so no relation can shadow "+
			"one of the named tables on this connection", string(path))
	}

	for _, name := range names {
		rows, err := db.Query(`
			SELECT n.nspname, c.relkind
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relname = $1 AND n.nspname <> 'public'
			ORDER BY n.nspname`, name)
		if err != nil {
			t.Fatalf("look up %q outside public: %v", name, err)
		}
		for rows.Next() {
			var schema, kind string
			if err := rows.Scan(&schema, &kind); err != nil {
				_ = rows.Close()
				t.Fatalf("scan: %v", err)
			}
			if !ahead[schema] {
				continue
			}
			t.Errorf("a relation named %q (relkind %q) exists in schema %q, which precedes "+
				"`public` in the search_path (%s). middleware.noTenantTxRouteBinding names "+
				"it UNQUALIFIED, so the route's own unqualified statements resolve to THAT "+
				"relation while this gate keeps checking the `public` one. Qualify the name "+
				"in the rule and widen m52LiveRLS, or take the schema out of the path.",
				name, kind, schema, string(path))
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			t.Fatalf("iterate: %v", err)
		}
		_ = rows.Close()
	}
}

// TestM52LiveSchemaHasRLSAtAll is the blindness guard for the test above.
//
// Every assertion there is "this table's flag is false". A database where the
// flag is false everywhere — a half-applied migration set, or a schema built
// by something other than cmd/migrate — would pass it while proving nothing.
func TestM52LiveSchemaHasRLSAtAll(t *testing.T) {
	live := m52LiveRLS(t)
	on := 0
	for _, st := range live {
		if st.Enabled {
			on++
		}
	}
	// 35 as of 2026-08-05. The bar is deliberately far below that: this is a
	// "the migrations ran" check, not a second inventory to keep in sync.
	const min = 20
	if on < min {
		t.Fatalf("only %d of %d public tables have RLS enabled (want at least %d). The "+
			"database this test is pointed at has not had the RLS migrations applied, so "+
			"TestM52TouchesNoRLSTableRulesNameOnlyRLSExemptTables would pass on a schema "+
			"where nothing is protected.", on, len(live), min)
	}
}
