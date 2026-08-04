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
	// ignored entirely and the table is a hazard to nobody.
	Enabled bool
	// Policies is how many policies the table carries. Zero WITH Enabled is
	// default-deny: every statement matches nothing.
	Policies int
	// TenantGated is how many of them mention `app.current_tenant_id` in
	// their USING or WITH CHECK expression. This is what distinguishes "RLS
	// is on and it is the tenant GUC that decides" from "RLS is on for some
	// other reason" — the enable bit alone does not say.
	TenantGated int
}

// m52LiveRLS returns table name → row-security state for every ordinary or
// partitioned table in the public schema of the migrated database.
func m52LiveRLS(t *testing.T) map[string]m52TableRLS {
	t.Helper()
	db := m52SchemaDB(t)
	// relkind 'r' is an ordinary table and 'p' a PARTITIONED one. Both carry
	// relrowsecurity; the schema has no partitioned table today, but filtering
	// them out would make a future one read as "does not exist" and fail a
	// classification that is in fact correct — a false positive on correct
	// code, which is the failure mode that gets a gate deleted. Views ('v'),
	// materialised views ('m') and foreign tables ('f') are excluded because
	// RLS is a property of the underlying table, not of them.
	rows, err := db.Query(`
		SELECT c.relname,
		       c.relrowsecurity,
		       count(p.oid)                                             AS policies,
		       count(*) FILTER (WHERE pg_get_expr(p.polqual, p.polrelid)
		                                LIKE '%app.current_tenant_id%'
		                           OR pg_get_expr(p.polwithcheck, p.polrelid)
		                                LIKE '%app.current_tenant_id%') AS tenant_gated
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_policy p ON p.polrelid = c.oid
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
		GROUP BY c.relname, c.relrowsecurity`)
	if err != nil {
		t.Fatalf("read pg_class: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]m52TableRLS{}
	for rows.Next() {
		var name string
		var st m52TableRLS
		if err := rows.Scan(&name, &st.Enabled, &st.Policies, &st.TenantGated); err != nil {
			t.Fatalf("scan pg_class row: %v", err)
		}
		out[name] = st
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate pg_class: %v", err)
	}
	if len(out) < 30 {
		t.Fatalf("found only %d tables in the public schema — the database this test is "+
			"pointed at is not the migrated SBOMHub schema, so every assertion below "+
			"would be vacuous", len(out))
	}
	return out
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
			if !st.Enabled {
				continue
			}
			// RLS is on. Whether that BREAKS this route depends on what the
			// policies say, not on the enable bit: a table could carry
			// `FOR SELECT TO sbomhub_app USING (true)` and remain perfectly
			// readable with no GUC. Only two states are decided here, and the
			// third is handed back to a human rather than guessed at.
			switch {
			case st.Policies == 0:
				t.Errorf("%s is classified TenantBindingTouchesNoRLSTable, but %q now has ROW "+
					"LEVEL SECURITY enabled and NO policies — under RLS that is default-deny, "+
					"so every statement this route issues against it matches nothing. Move "+
					"the route onto a TenantTx chain, or re-classify it "+
					"TenantBindingBindsItself with a binding and a drive.\n"+
					"Reason recorded for the old classification: %s", key, table, rule.Why)
			case st.TenantGated > 0:
				t.Errorf("%s is classified TenantBindingTouchesNoRLSTable, but %q now has ROW "+
					"LEVEL SECURITY enabled with %d of its %d policies gated on "+
					"app.current_tenant_id.\n"+
					"This route carries no TenantTx, so its statements against %q run on a "+
					"pooled connection where that setting is NULL on a fresh backend (the "+
					"predicate is NULL, zero rows) or the empty string on a reused one "+
					"(''::UUID, 22P02, a 500). Move the route onto a TenantTx chain, or "+
					"re-classify it TenantBindingBindsItself and give it a binding plus a "+
					"drive.\nReason recorded for the old classification: %s",
					key, table, st.TenantGated, st.Policies, table, rule.Why)
			default:
				// RLS on, policies present, none of them mentioning the tenant
				// GUC. Whether those policies admit what this route does is a
				// question about their expressions, their commands and their
				// roles — this check does not read any of that, and guessing
				// would mean reddening CI for a table that is in fact fine.
				// Recorded as a limitation, loudly, rather than asserted.
				t.Logf("NOTE: %s names %q, which now has ROW LEVEL SECURITY enabled with %d "+
					"policies, none of them referencing app.current_tenant_id. This gate "+
					"cannot tell whether they admit what the route does, so it is NOT "+
					"failing — re-read the policies and, if they do gate on anything the "+
					"route cannot supply, re-classify the route.", key, table, st.Policies)
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
// m52LiveRLS keys by bare `relname` inside schema `public`. If a table with the
// SAME NAME also existed in another schema, a rule naming it would silently be
// checked against the `public` one — the wrong object, and a miss nothing would
// reveal.
//
// The check is scoped to the names the table actually uses, not to schemas in
// general. An earlier version asserted that no non-system schema held any table
// at all, which would have reddened for `CREATE SCHEMA observability` or for
// any extension that installs its own tables — correct deployments that have
// nothing to do with this gate.
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
	for _, name := range names {
		rows, err := db.Query(`
			SELECT n.nspname
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'p')
			  AND c.relname = $1
			  AND n.nspname <> 'public'
			ORDER BY n.nspname`, name)
		if err != nil {
			t.Fatalf("look up %q outside public: %v", name, err)
		}
		for rows.Next() {
			var schema string
			if err := rows.Scan(&schema); err != nil {
				_ = rows.Close()
				t.Fatalf("scan: %v", err)
			}
			t.Errorf("a table named %q also exists in schema %q. "+
				"middleware.noTenantTxRouteBinding names it UNQUALIFIED and this gate "+
				"resolves it against `public`, so whichever one the route actually uses, "+
				"the check may be reading the other. Qualify the name in the rule and widen "+
				"m52LiveRLS before letting the two coexist.", name, schema)
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
