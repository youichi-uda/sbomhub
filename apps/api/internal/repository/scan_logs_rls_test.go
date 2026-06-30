//go:build integration

// Package repository — scan_logs tenant-isolation integration test
// (M13 Phase D round 2 / F185, migration 048).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestScanLogs ./internal/repository
//
// Prerequisites: same as scan_settings_rls_test.go (DATABASE_URL +
// MIGRATE_DATABASE_URL, schema migrated through 048).
//
// What this test pins down:
//
//  1. scan_logs INSERT goes through the FORCE RLS WITH CHECK policy.
//     Pre-F185 the scheduler inserted scan_logs rows on j.db without any
//     tenant context, which would silently succeed on a non-RLS table
//     but is now rejected — the companion vulnerability_scan.go refactor
//     wraps the insert in runWithTenantTx.
//
//  2. Cross-tenant SELECT on scan_logs returns zero rows. The API
//     handler /api/v1/settings/scan/logs is the obvious leak surface
//     pre-F185 (a misrouted request could surface another tenant's
//     scan history); RLS closes it as defense in depth on top of the
//     app-layer `WHERE tenant_id = $1` filter.
//
//  3. The owner tenant still sees its own scan_logs rows.
//
// Mirrors tenant_llm_config_rls_test.go in shape. See its header for
// the rationale behind the duplicated helpers.
package repository

import (
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func scanLogsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("scan_logs integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

func schemaReadyScanLogs(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'scan_logs'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("scan_logs existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("scan_logs table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.scan_logs'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("scan_logs RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Fatalf("scan_logs RLS not in expected state "+
			"(enabled=%v, force=%v). Migration 048 either not applied or "+
			"reverted -- this is the F185 regression. Run `go run ./cmd/migrate up`.",
			rlsEnabled, rlsForce)
		return false
	}
	var policyCount int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM pg_policies
		WHERE schemaname = 'public'
		  AND tablename  = 'scan_logs'
		  AND policyname = 'tenant_isolation_scan_logs'
	`).Scan(&policyCount); err != nil {
		t.Skipf("pg_policies lookup failed: %v -- skipping", err)
		return false
	}
	if policyCount != 1 {
		t.Fatalf("scan_logs policy tenant_isolation_scan_logs not "+
			"found (count=%d). Migration 048 either not applied or reverted -- "+
			"this is the F185 regression.", policyCount)
		return false
	}
	return true
}

func seedTenantForScanLogs(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "scan-logs-test-"+label+"-"+id.String(),
		"ScanLogs Test "+label,
		"scan-logs-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func openOrSkipScanLogs(t *testing.T, url string) *sql.DB {
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

// TestScanLogs_TenantIsolation_RLS verifies the load-bearing security
// property of migration 048 (F185) on scan_logs: under the sbomhub_app
// (NOBYPASSRLS) role, a scan_logs row written by tenant A is invisible
// to tenant B, and tenant B cannot forge a row claiming to belong to
// tenant A.
func TestScanLogs_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := scanLogsTestEnv(t)

	migDB := openOrSkipScanLogs(t, migURL)
	defer migDB.Close()
	if !schemaReadyScanLogs(t, migDB) {
		return
	}
	appDB := openOrSkipScanLogs(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForScanLogs(t, migDB, "A")
	tenantB := seedTenantForScanLogs(t, migDB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// --- Step 1: as app role under tenant A, insert a scan_logs row
	// (this mirrors what the post-F185 scheduler does inside
	// runWithTenantTx).
	logAID := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO scan_logs (id, tenant_id, started_at, status, projects_scanned, new_vulnerabilities)
		VALUES ($1, $2, NOW(), 'running', 0, 0)
	`, logAID, tenantA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, attempt to read tenantA's
	// scan_logs row. RLS must make it invisible.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}
	var seen int
	if err := txB.QueryRow(
		`SELECT COUNT(*) FROM scan_logs WHERE tenant_id = $1`, tenantA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (F185 regression): tenantB saw %d scan_logs row(s) for "+
			"tenantA; expected 0. This is the cross-tenant scan-history disclosure "+
			"primitive F185 closed.", seen)
	}

	// --- Step 2b: also exercise the API handler shape — SELECT … FROM
	// scan_logs WHERE tenant_id = $1 ORDER BY created_at DESC — to
	// confirm the leak path through GetLogs is also closed.
	rows, err := txB.Query(`
		SELECT id FROM scan_logs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 20
	`, tenantA)
	if err != nil {
		t.Fatalf("tenantB SELECT scan_logs: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		var id uuid.UUID
		_ = rows.Scan(&id)
		t.Fatalf("RLS leak (F185 regression): tenantB API-shaped SELECT surfaced a "+
			"scan_logs row for tenantA (id=%s).", id)
	}

	// --- Step 3: tenantB tries to INSERT a scan_logs row claiming
	// tenant_id = tenantA. WITH CHECK should reject it. We expect an
	// error.
	forgedID := uuid.New()
	_, forgeErr := txB.Exec(`
		INSERT INTO scan_logs (id, tenant_id, started_at, status)
		VALUES ($1, $2, NOW(), 'failed')
	`, forgedID, tenantA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken (F185 regression): tenantB session was able "+
			"to write a scan_logs row with tenant_id=%s (tenantA). This is the "+
			"cross-tenant audit-trail injection primitive the policy is supposed to "+
			"prevent.", tenantA)
	}

	// --- Step 4: as tenant A again, confirm the original row is still
	// visible to its owner (policy must not over-reject).
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	if err := txA2.QueryRow(
		`SELECT COUNT(*) FROM scan_logs WHERE tenant_id = $1`, tenantA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own scan_logs rows; "+
			"expected 1 -- RLS policy may be over-restrictive", seen)
	}
}
