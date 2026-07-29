//go:build integration

// Package repository — M48: `vulnerabilities` must carry no tenant column.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M48_VulnerabilitiesTenantIDDropped' ./internal/repository
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Prerequisites (skipped otherwise): postgres up and MIGRATE_DATABASE_URL set
// to a sbomhub_migrator connection string, schema migrated through 063.
//
// What this test pins down:
//
// `vulnerabilities` is the GLOBAL CVE catalogue — every tenant reads the same
// rows, it has no RLS policy, and it is a recorded structural exemption in
// tools/lint-migration-rls. Migration 007 nonetheless gave it a `tenant_id`
// column (plus an index and an FK to tenants) in the same sweep that promoted
// the genuinely tenant-scoped tables. Nothing ever read that column and only
// two E2E fixtures ever wrote it; on the 2026-07-30 dev DB 0 of 10,899 rows
// held a non-NULL value. Migration 063 dropped it.
//
// This is a schema-shape assertion, and the reason it is worth a test rather
// than being left to the migration alone is the failure mode it guards. In
// this schema a `tenant_id` column is the strongest available signal that a
// table is tenant-scoped, and this codebase has already shipped cross-tenant
// bugs founded on exactly that inference — migration 062 exists because a
// per-(tenant, project) SSVC decision was stamped onto these same shared rows.
// Re-adding the column would re-arm that misreading with no RLS backstop to
// catch it, because this table has none by design.
//
// SCOPE. This asserts on the DDL only: the column, its index and its FK. It
// does NOT assert that no Go code references a tenant column on this table
// (the compiler and the integration suite cover that — a query naming a
// dropped column fails at the database), and it does not speak to any other
// table's tenant_id, all of which are load-bearing.
package repository

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// openVulnSchemaProbeDB opens the migrator handle used by the schema probes
// below. The migrator role is used rather than the app role because
// information_schema / pg_catalog visibility is what is being read, not table
// data — no tenant GUC is involved and no rows are created, so this test
// seeds nothing and has no cleanup obligations under the C27 regime.
func openVulnSchemaProbeDB(t *testing.T) *sql.DB {
	t.Helper()
	migURL := os.Getenv("MIGRATE_DATABASE_URL")
	if migURL == "" {
		t.Skip("M48 vulnerabilities schema probe requires MIGRATE_DATABASE_URL " +
			"(sbomhub_migrator). Run `docker compose up -d postgres`, source the .env " +
			"values, then re-run with -tags=integration.")
	}
	return openIntegrationDB(t, migURL)
}

// TestM48_VulnerabilitiesTenantIDDropped_NoColumn is the primary assertion:
// the column itself is gone.
//
// When the column IS present the failure reports how many rows carry a
// non-NULL value, because that number decides the remediation. Zero means a
// re-add slipped in structurally (re-run 063). Non-zero means something is
// actively writing a tenant id onto rows every other tenant also reads, which
// is the cross-tenant defect itself and not merely a schema drift.
func TestM48_VulnerabilitiesTenantIDDropped_NoColumn(t *testing.T) {
	migDB := openVulnSchemaProbeDB(t)

	var n int
	if err := migDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'vulnerabilities'
		  AND column_name = 'tenant_id'`).Scan(&n); err != nil {
		t.Fatalf("probe vulnerabilities.tenant_id: %v", err)
	}
	if n == 0 {
		return
	}

	var nonNull int
	if err := migDB.QueryRow(`SELECT COUNT(tenant_id) FROM vulnerabilities`).Scan(&nonNull); err != nil {
		t.Fatalf("vulnerabilities carries a tenant_id column again (migration 063 dropped it); "+
			"counting non-NULL values failed: %v", err)
	}
	t.Fatalf("vulnerabilities carries a tenant_id column again and %d row(s) hold a non-NULL value "+
		"(migration 063 dropped it). This table is the GLOBAL CVE catalogue read by every tenant and "+
		"has no RLS policy, so a tenant column here is not an isolation boundary — it only invites a "+
		"`WHERE tenant_id = $1` that appears scoped and is not (see migration 062 for the same "+
		"mistake made with ssvc_decision)", nonNull)
}

// TestM48_VulnerabilitiesTenantIDDropped_NoIndexOrFK asserts the broader
// invariant: `vulnerabilities` carries no tenant-shaped object at all, not
// just no tenant_id column.
//
// It is NOT the case that this test catches something the column probe above
// misses via the column being restored on its own — that probe detects the
// column through information_schema and fails either way (Codex round 1 #4),
// and an index or FK cannot exist without the column in the first place:
// PostgreSQL rejects `CREATE INDEX … (tenant_id)` and the FK clause with
// `column "tenant_id" does not exist`, and DROP COLUMN removes both dependents
// atomically (Codex round 2 #4 — round 1 replaced one wrong rationale with
// another, inventing a "reverse asymmetry" that the database makes
// unreachable).
//
// What it does buy: it catches a same-named index built over a DIFFERENT
// column, or any other vulnerabilities → tenants foreign key introduced later
// under a different column name — neither of which the column probe sees — and
// it names which object is present instead of leaving that to be inferred from
// a column-level diagnostic.
func TestM48_VulnerabilitiesTenantIDDropped_NoIndexOrFK(t *testing.T) {
	migDB := openVulnSchemaProbeDB(t)

	var idx int
	if err := migDB.QueryRow(`
		SELECT COUNT(*) FROM pg_indexes
		WHERE schemaname = 'public'
		  AND tablename = 'vulnerabilities'
		  AND indexname = 'idx_vulnerabilities_tenant_id'`).Scan(&idx); err != nil {
		t.Fatalf("probe idx_vulnerabilities_tenant_id: %v", err)
	}
	if idx != 0 {
		t.Errorf("idx_vulnerabilities_tenant_id still exists — migration 063 drops it together with "+
			"the column it indexes (found %d)", idx)
	}

	// Any FK from vulnerabilities to tenants, not just the 007 name: a
	// re-add under a different constraint name is the same defect.
	var fks int
	if err := migDB.QueryRow(`
		SELECT COUNT(*) FROM pg_constraint
		WHERE conrelid = 'vulnerabilities'::regclass
		  AND confrelid = 'tenants'::regclass`).Scan(&fks); err != nil {
		t.Fatalf("probe vulnerabilities -> tenants FKs: %v", err)
	}
	if fks != 0 {
		t.Errorf("vulnerabilities still has %d foreign key(s) to tenants — the global CVE catalogue "+
			"must not reference a tenant at all (migration 063)", fks)
	}
}
