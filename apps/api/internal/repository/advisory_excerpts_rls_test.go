//go:build integration

// Package repository - advisory_excerpts tenant-isolation integration
// test (M1 Wave M1-2 / issue #23, migration 033).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestAdvisoryExcerpts ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 033_advisory_excerpts.
//
// What this test pins down:
//
//  1. The advisory_excerpts INSERT goes through the FORCE RLS WITH
//     CHECK policy installed in migration 033. A session that has not
//     set app.current_tenant_id, or that has set it to a different
//     tenant, must NOT be able to insert a row with a third tenant's
//     id.
//
//  2. A read from tenant B's session must NOT surface rows that
//     tenant A inserted. Cross-tenant advisory-excerpt leakage would
//     defeat the per-tenant parser-tuning model the design doc
//     assumes.
//
//  3. The CHECK constraint on `source` still rejects unknown values
//     even from the privileged migrator role -- caught by attempting
//     an INSERT with source='osv' (not in the allow-list).
package repository

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func advisoryExcerptsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // reuse env helper from llm_calls_rls_test.go
}

// schemaReadyAdvisoryExcerpts checks that advisory_excerpts exists AND
// that RLS is still ENABLE + FORCE on it (migration 033 state). If
// RLS has been removed by a future migration without updating this
// test, we skip loudly rather than silently mis-test the policy.
func schemaReadyAdvisoryExcerpts(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'advisory_excerpts'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("advisory_excerpts existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("advisory_excerpts table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.advisory_excerpts'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("advisory_excerpts RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("advisory_excerpts RLS not in expected state (enabled=%v, force=%v); "+
			"migration 033 may have been reverted -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

func seedTenantForAdvisoryExcerpts(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "advex-test-"+label+"-"+id.String(),
		"AdvEx Test "+label,
		"advex-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func openOrSkipAdvisoryExcerpts(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open: %v -- skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("db unreachable: %v -- skipping", err)
	}
	return db
}

// TestAdvisoryExcerpts_TenantIsolation_RLS verifies the load-bearing
// security property of migration 033: under the sbomhub_app
// (NOBYPASSRLS) role, a row written by tenant A is invisible to
// tenant B, and tenant B cannot forge a row claiming to belong to
// tenant A (the WITH CHECK clause rejects the INSERT).
func TestAdvisoryExcerpts_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := advisoryExcerptsTestEnv(t)

	migDB := openOrSkipAdvisoryExcerpts(t, migURL)
	defer migDB.Close()
	if !schemaReadyAdvisoryExcerpts(t, migDB) {
		return
	}
	appDB := openOrSkipAdvisoryExcerpts(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForAdvisoryExcerpts(t, migDB, "A")
	tenantB := seedTenantForAdvisoryExcerpts(t, migDB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// --- Step 1: as app role under tenant A, insert one excerpt.
	rowA := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source,
			vuln_funcs, affected_paths, required_config, required_env,
			raw_excerpt, fetched_at
		) VALUES ($1, $2, 'CVE-2025-A1', 'nvd',
			'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
			'tenantA private excerpt', NOW())
	`, rowA, tenantA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, count tenant A's row. RLS
	// should make it invisible -> count must be 0.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}
	var seen int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM advisory_excerpts WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak: tenantB saw %d row(s) for tenantA's advisory_excerpts.id=%s; expected 0", seen, rowA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it.
	rowForged := uuid.New()
	_, forgeErr := txB.Exec(`
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source,
			vuln_funcs, affected_paths, required_config, required_env
		) VALUES ($1, $2, 'CVE-2025-FORGE', 'ghsa',
			'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb)
	`, rowForged, tenantA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken: tenantB session was able to insert a row "+
			"with tenant_id=%s (tenantA). This is the cross-tenant write primitive "+
			"the policy is supposed to prevent.", tenantA)
	}

	// --- Step 4: as tenant A again, confirm the original row is still
	// visible to its owner (the policy must not over-reject).
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM advisory_excerpts WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own advisory_excerpts rows for id=%s; expected 1 -- RLS policy may be over-restrictive", seen, rowA)
	}
}

// TestAdvisoryExcerpts_SourceCheckConstraint verifies the CHECK
// constraint on `source` rejects unknown values even from the
// privileged migrator role. Catches the regression class where a
// future migration replaces the constraint with a stricter / looser
// one that accidentally permits free-form strings.
func TestAdvisoryExcerpts_SourceCheckConstraint(t *testing.T) {
	_, migURL := advisoryExcerptsTestEnv(t)
	migDB := openOrSkipAdvisoryExcerpts(t, migURL)
	defer migDB.Close()
	if !schemaReadyAdvisoryExcerpts(t, migDB) {
		return
	}
	tenant := seedTenantForAdvisoryExcerpts(t, migDB, "CK")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// M9 F158: migration 023+ puts advisory_excerpts under FORCE RLS, so
	// the negative-path INSERT must run inside a tx with the tenant GUC
	// set; otherwise the row is rejected by the RLS policy before the
	// CHECK constraint fires.
	// M43 F467: migration 056 extended the allow-list to include 'osv'
	// (Go vulndb structured symbols), so the rejection probe uses a value
	// outside the 4-entry registry and 'osv' is asserted as accepted.
	err := execAsTenant(t, migDB, tenant, `
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source
		) VALUES ($1, $2, 'CVE-2025-CK', 'redhat')
	`, uuid.New(), tenant)
	if err == nil {
		t.Fatalf("CHECK constraint allowed source='redhat'; the allow-list is meant to be nvd|ghsa|jvn|osv only")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation, got: %v", err)
	}

	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source
		) VALUES ($1, $2, 'CVE-2025-CK', 'osv')
	`, uuid.New(), tenant); err != nil {
		t.Fatalf("CHECK constraint rejected source='osv'; migration 056 is meant to allow it: %v", err)
	}
}
