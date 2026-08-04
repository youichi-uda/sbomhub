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
// A route classified TouchesNoRLSTable is safe only for as long as none of the
// tables it names has Row-Level Security. Deciding that from the migrations by
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

// m52LiveRLS returns table name → row-security state for every relation in the
// public schema that a route could read: ordinary ('r'), partitioned ('p') and
// materialised ('m') views.
//
// Materialised views are included because a route that reads one reads its
// STORED result — the underlying query is executed at REFRESH time, not at
// read time — so naming one in RLSExemptTables is a legitimate thing to do and
// must resolve to something rather than to "does not exist". They carry no row
// security of their own, which is what relrowsecurity reports for them.
func m52LiveRLS(t *testing.T) map[string]m52TableRLS {
	t.Helper()
	db := m52SchemaDB(t)
	rows, err := db.Query(`
		SELECT c.relname, c.relrowsecurity, c.relkind::text
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm')`)
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

// m52ReadVerdict is what an unbound SELECT of one table would do, as decided
// by the server rather than by a model written here.
type m52ReadVerdict struct {
	// SelectDenied is true when PostgreSQL's permissive-OR semantics leave no
	// way for the runtime role to SELECT a row without app.current_tenant_id.
	SelectDenied bool
	// Why records the reason, for the failure message.
	Why string
	// ProbeErr is the error a real `SELECT 1 FROM <t> LIMIT 1` raised on the
	// poisoned connection, or nil.
	ProbeErr error
}

// m52UnboundReadVerdict decides, for one RLS-enabled table, whether the
// runtime role can read it with no tenant bound.
//
// # Why this shape
//
// The first version of this check asked only whether RLS was enabled; the
// second asked whether ANY policy mentioned the tenant GUC. Both were models
// of a question PostgreSQL answers itself, and both were wrong at the edges: a
// table with `FOR SELECT TO sbomhub_app USING (true)` beside a tenant-gated
// `FOR INSERT` is read perfectly well by an unbound route, and the second
// model failed it.
//
// So this asks two narrower questions, both about SELECT only:
//
//  1. The catalog, with PostgreSQL's actual applicability rules — command
//     (`polcmd IN ('*','r')`), role (`polroles` is PUBLIC or includes one the
//     current role has), and composition (PERMISSIVE policies are ORed, so one
//     GUC-free permissive policy is enough to admit the read; RESTRICTIVE ones
//     are ANDed, so one tenant-gated restrictive policy denies it).
//  2. An actual `SELECT 1 FROM <t> LIMIT 1` on a connection in the poisoned
//     state, which catches the 22P02 the empty-string placeholder raises when
//     a row IS scanned.
//
// Neither is complete on its own — (1) models only SELECT, and (2) evaluates
// nothing when the table happens to be empty — and the caller reports what
// each did and did not establish rather than implying more.
func m52UnboundReadVerdict(t *testing.T, table string) m52ReadVerdict {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("this check needs DATABASE_URL (the sbomhub_app role): the migrator OWNS " +
			"these tables, and role applicability is half the question")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open app DB: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	var permissive, permissiveGUCFree, restrictiveGUCGated int
	if err := db.QueryRow(`
		SELECT
		  count(*) FILTER (WHERE p.polpermissive),
		  count(*) FILTER (WHERE p.polpermissive
		                     AND coalesce(pg_get_expr(p.polqual, p.polrelid), '')
		                           NOT LIKE '%app.current_tenant_id%'),
		  count(*) FILTER (WHERE NOT p.polpermissive
		                     AND coalesce(pg_get_expr(p.polqual, p.polrelid), '')
		                           LIKE '%app.current_tenant_id%')
		FROM pg_policy p
		JOIN pg_class c ON c.oid = p.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		  AND c.relname = $1
		  AND p.polcmd IN ('*', 'r')
		  AND (p.polroles = '{0}'::oid[]
		       OR EXISTS (SELECT 1 FROM unnest(p.polroles) rr
		                  WHERE pg_has_role(current_user, rr, 'USAGE')))`,
		table).Scan(&permissive, &permissiveGUCFree, &restrictiveGUCGated); err != nil {
		t.Fatalf("read pg_policy for %q: %v", table, err)
	}

	v := m52ReadVerdict{}
	switch {
	case permissive == 0:
		v.SelectDenied, v.Why = true, "RLS is enabled and no PERMISSIVE policy applies to "+
			"SELECT for this role, which under RLS is default-deny"
	case permissiveGUCFree == 0:
		v.SelectDenied, v.Why = true, "every PERMISSIVE SELECT policy that applies to this "+
			"role is gated on app.current_tenant_id"
	case restrictiveGUCGated > 0:
		v.SelectDenied, v.Why = true, "a RESTRICTIVE SELECT policy gated on "+
			"app.current_tenant_id applies, and restrictive policies are ANDed"
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
	_, v.ProbeErr = db.Exec(`SELECT 1 FROM "` + table + `" LIMIT 1`)
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
			if st.Kind == "m" {
				// A materialised view. Reading one returns its STORED result —
				// the underlying query runs at REFRESH time — so no row
				// security applies to the route's read and relrowsecurity is
				// false for it by construction. Naming one here is legitimate;
				// it is logged rather than silently accepted so that the day
				// this project starts using matviews, the fact is visible in
				// the run rather than inferred from this comment.
				t.Logf("NOTE: %s names %q, which is a MATERIALISED VIEW. Its reads return "+
					"stored rows and carry no row security, so it is exempt by construction "+
					"— but if the route also REFRESHes it, the refresh executes the "+
					"underlying query and every RLS table in it applies. Check that "+
					"separately.", key, table)
				continue
			}
			if !st.Enabled {
				// Decisive on its own: with relrowsecurity false, PostgreSQL
				// ignores every stored policy.
				continue
			}
			v := m52UnboundReadVerdict(t, table)
			switch {
			case v.SelectDenied:
				t.Errorf("%s is classified TenantBindingTouchesNoRLSTable, but %q now has ROW "+
					"LEVEL SECURITY enabled and an unbound SELECT of it is denied: %s.\n"+
					"This route carries no TenantTx, so that is the state its statements run "+
					"in. Move the route onto a TenantTx chain, or re-classify it "+
					"TenantBindingBindsItself and give it a binding plus a drive.\n"+
					"Reason recorded for the old classification: %s", key, table, v.Why, rule.Why)
			case v.ProbeErr != nil:
				t.Errorf("%s is classified TenantBindingTouchesNoRLSTable, but a plain "+
					"`SELECT 1 FROM %s LIMIT 1` as the runtime role, with no tenant bound, "+
					"FAILS: %v\nThat is the state this route's statements run in. Move the "+
					"route onto a TenantTx chain, or re-classify it TenantBindingBindsItself "+
					"and give it a binding plus a drive.\n"+
					"Reason recorded for the old classification: %s",
					key, table, v.ProbeErr, rule.Why)
			default:
				// Neither signal says the read is broken. Record what that
				// does NOT establish rather than implying more.
				t.Logf("NOTE: %s names %q, which now has ROW LEVEL SECURITY enabled. A "+
					"permissive SELECT policy admits the runtime role without the tenant "+
					"GUC and a live unbound read raised nothing, so this is not failing — "+
					"but only SELECT was examined. If the route also INSERTs or UPDATEs "+
					"this table, re-read the policies for those commands.", key, table)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no TouchesNoRLSTable rule named a table that exists — this test asserted " +
			"nothing. /health names none by design, so at least the Lemon Squeezy rule's " +
			"five should have been checked.")
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
	if len(named) == 0 {
		t.Skip("no rule names an exempt table, so there is no name to disambiguate")
	}
	names := make([]string, 0, len(named))
	for n := range named {
		names = append(names, n)
	}
	sort.Strings(names)

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
