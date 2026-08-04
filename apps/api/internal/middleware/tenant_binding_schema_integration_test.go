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

// m52LiveRLS returns table name → relrowsecurity for every ordinary or
// partitioned table in the public schema of the migrated database.
func m52LiveRLS(t *testing.T) map[string]bool {
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
		SELECT c.relname, c.relrowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')`)
	if err != nil {
		t.Fatalf("read pg_class: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]bool{}
	for rows.Next() {
		var name string
		var rls bool
		if err := rows.Scan(&name, &rls); err != nil {
			t.Fatalf("scan pg_class row: %v", err)
		}
		out[name] = rls
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
			rls, exists := live[table]
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
			if rls {
				t.Errorf("%s is classified TenantBindingTouchesNoRLSTable, but %q now has "+
					"ROW LEVEL SECURITY enabled.\n"+
					"This route carries no TenantTx, so its statements against %q run on a "+
					"pooled connection with no app.current_tenant_id bound: the policy "+
					"predicate is NULL on a fresh backend (zero rows) or ''::UUID on a "+
					"reused one (22P02, a 500).\n"+
					"Three ways out, in order of preference: move the route onto a TenantTx "+
					"chain; re-classify it TenantBindingBindsItself and give it a binding "+
					"plus a drive; or — if the new policy is PERMISSIVE for what this route "+
					"reads (slo_targets' `tenant_id IS NULL OR ...` is the shape) — say so in "+
					"a BindsItself rule with a drive, because RLSExemptTables can no longer "+
					"be the evidence. Note that even a permissive policy of that shape still "+
					"raises 22P02 on the poisoned connection for any row whose tenant_id is "+
					"NOT null, so 'permissive' is rarely the whole answer.\n"+
					"Reason recorded for the old classification: %s", key, table, table, rule.Why)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no TouchesNoRLSTable rule named a table that exists — this test asserted " +
			"nothing. /health names none by design, so at least the Lemon Squeezy rule's " +
			"five should have been checked.")
	}
}

// TestM52PublicIsTheOnlyApplicationSchema underwrites the unqualified table
// names the table uses.
//
// m52LiveRLS keys by bare `relname` inside schema `public`. If the application
// ever put a table in a second schema, a rule naming it would either report
// "does not exist" (loud, tolerable) or — worse — silently match a same-named
// `public` table and check the WRONG object's RLS flag. That second outcome is
// a miss, not a false positive, and it would be invisible. This asserts the
// precondition instead of assuming it.
func TestM52PublicIsTheOnlyApplicationSchema(t *testing.T) {
	db := m52SchemaDB(t)
	rows, err := db.Query(`
		SELECT n.nspname, count(*)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p')
		  AND n.nspname <> 'public'
		  AND n.nspname NOT LIKE 'pg\_%'
		  AND n.nspname <> 'information_schema'
		GROUP BY n.nspname
		ORDER BY n.nspname`)
	if err != nil {
		t.Fatalf("read pg_namespace: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var schema string
		var n int
		if err := rows.Scan(&schema, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		t.Errorf("schema %q holds %d table(s). middleware.noTenantTxRouteBinding's "+
			"RLSExemptTables entries are UNQUALIFIED names resolved against `public` "+
			"only, so a table here is either invisible to the check or — if `public` "+
			"has one of the same name — silently substituted for it. Qualify the names "+
			"and widen m52LiveRLS before adding a second application schema.", schema, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate pg_namespace: %v", err)
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
	for _, rls := range live {
		if rls {
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
