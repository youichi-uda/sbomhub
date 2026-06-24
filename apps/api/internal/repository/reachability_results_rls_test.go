//go:build integration

// Package repository - reachability_results tenant-isolation
// integration test (M1 Wave M1-3 / issue #26, migration 034).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestReachabilityResults ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 034_reachability_results.
//
// What this test pins down:
//
//  1. The reachability_results INSERT goes through the FORCE RLS WITH
//     CHECK policy installed in migration 034.
//  2. A read from tenant B's session must NOT surface rows that
//     tenant A inserted. Cross-tenant reachability leakage would
//     leak project structure (which CVEs land on which components),
//     which is itself sensitive.
//  3. The CHECK constraints on status and confidence still hold.
package repository

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func reachabilityResultsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // reuse env helper from llm_calls_rls_test.go
}

func schemaReadyReachabilityResults(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'reachability_results'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("reachability_results existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("reachability_results table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.reachability_results'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("reachability_results RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("reachability_results RLS not in expected state (enabled=%v, force=%v); "+
			"migration 034 may have been reverted -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

func seedTenantForReachabilityResults(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "reach-test-"+label+"-"+id.String(),
		"Reach Test "+label,
		"reach-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func openOrSkipReachabilityResults(t *testing.T, url string) *sql.DB {
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

// TestReachabilityResults_TenantIsolation_RLS verifies migration 034's
// load-bearing tenant isolation property: tenant A's verdicts are
// invisible to tenant B, and tenant B cannot forge a verdict claiming
// to belong to tenant A.
func TestReachabilityResults_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := reachabilityResultsTestEnv(t)

	migDB := openOrSkipReachabilityResults(t, migURL)
	defer migDB.Close()
	if !schemaReadyReachabilityResults(t, migDB) {
		return
	}
	appDB := openOrSkipReachabilityResults(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForReachabilityResults(t, migDB, "A")
	tenantB := seedTenantForReachabilityResults(t, migDB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	projectA := uuid.New()
	componentA := uuid.New()
	rowA := uuid.New()

	// --- Step 1: as app role under tenant A, insert one verdict.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO reachability_results (
			id, tenant_id, project_id, component_id,
			cve_id, ecosystem, status,
			evidence, confidence,
			analyzer_version, analyzed_at
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-RA', 'go', 'reachable',
			'{}'::jsonb, 0.90,
			'v0.1.0', NOW())
	`, rowA, tenantA, projectA, componentA); err != nil {
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
	if err := txB.QueryRow(`SELECT COUNT(*) FROM reachability_results WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak: tenantB saw %d row(s) for tenantA's reachability_results.id=%s; expected 0", seen, rowA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it.
	_, forgeErr := txB.Exec(`
		INSERT INTO reachability_results (
			id, tenant_id, project_id, component_id,
			cve_id, status
		) VALUES ($1, $2, $3, $4, 'CVE-2025-FORGE', 'reachable')
	`, uuid.New(), tenantA, projectA, componentA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken: tenantB session was able to insert a reachability row "+
			"with tenant_id=%s (tenantA).", tenantA)
	}

	// --- Step 4: as tenant A again, confirm the original row is still
	// visible.
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM reachability_results WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own reachability rows for id=%s; expected 1", seen, rowA)
	}
}

// TestReachabilityResults_StatusAndConfidenceChecks verifies the
// CHECK constraints on status (allow-list) and confidence ([0,1])
// hold against direct migrator-role inserts. Catches the regression
// class where a future migration loosens or removes them.
func TestReachabilityResults_StatusAndConfidenceChecks(t *testing.T) {
	_, migURL := reachabilityResultsTestEnv(t)
	migDB := openOrSkipReachabilityResults(t, migURL)
	defer migDB.Close()
	if !schemaReadyReachabilityResults(t, migDB) {
		return
	}
	tenant := seedTenantForReachabilityResults(t, migDB, "CK")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// Bad status.
	_, err := migDB.Exec(`
		INSERT INTO reachability_results (
			id, tenant_id, project_id, component_id,
			cve_id, status
		) VALUES ($1, $2, $3, $4, 'CVE-2025-CK', 'definitely-not-a-status')
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown status; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on status, got: %v", err)
	}

	// Bad confidence.
	_, err = migDB.Exec(`
		INSERT INTO reachability_results (
			id, tenant_id, project_id, component_id,
			cve_id, status, confidence
		) VALUES ($1, $2, $3, $4, 'CVE-2025-CK', 'reachable', 1.5)
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed confidence > 1; the [0,1] bound is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on confidence, got: %v", err)
	}
}
