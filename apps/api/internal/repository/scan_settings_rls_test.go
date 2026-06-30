//go:build integration

// Package repository — scan_settings tenant-isolation integration test
// (M13 Phase D round 2 / F185, migration 048).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestScanSettings ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 048_legacy_scan_settings_logs_rls (the api
//     server's auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. The scan_settings INSERT goes through the FORCE RLS WITH CHECK
//     policy installed in migration 048. A session under tenant B must
//     NOT be able to insert a row with tenant A's id (cross-tenant
//     write primitive).
//
//  2. A read from tenant B's session must NOT surface a row tenant A
//     inserted. Pre-F185 the scheduler relied on a cross-tenant read
//     here to enumerate eligible tenants — exactly the gap defense in
//     depth is supposed to close.
//
//  3. tenant A still sees its own row (policy must not over-reject).
//
// This file mirrors tenant_llm_config_rls_test.go (migration 037). See
// its header for the rationale behind the duplicated helpers (we keep
// each RLS test file self-contained for readability).
package repository

import (
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func scanSettingsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("scan_settings integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// schemaReadyScanSettings checks that scan_settings exists AND that RLS is
// ENABLE + FORCE on it (migration 048 state). If a future migration
// reverts RLS without updating this test, we fail loudly rather than
// silently mis-test the policy — the whole point of F185 is to keep this
// state.
func schemaReadyScanSettings(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'scan_settings'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("scan_settings existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("scan_settings table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.scan_settings'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("scan_settings RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		// Regression-test failure mode: table exists but RLS not in the
		// post-048 state. F185 says this is the gap we just closed, so
		// fail (not skip) when the schema is ready enough to have the
		// table but missing the policy.
		t.Fatalf("scan_settings RLS not in expected state "+
			"(enabled=%v, force=%v). Migration 048 either not applied or "+
			"reverted -- this is the F185 regression. Run `go run ./cmd/migrate up`.",
			rlsEnabled, rlsForce)
		return false
	}
	var policyCount int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM pg_policies
		WHERE schemaname = 'public'
		  AND tablename  = 'scan_settings'
		  AND policyname = 'tenant_isolation_scan_settings'
	`).Scan(&policyCount); err != nil {
		t.Skipf("pg_policies lookup failed: %v -- skipping", err)
		return false
	}
	if policyCount != 1 {
		t.Fatalf("scan_settings policy tenant_isolation_scan_settings not "+
			"found (count=%d). Migration 048 either not applied or reverted -- "+
			"this is the F185 regression.", policyCount)
		return false
	}
	return true
}

func seedTenantForScanSettings(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "scan-settings-test-"+label+"-"+id.String(),
		"ScanSettings Test "+label,
		"scan-settings-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// openOrSkipScanSettings is a local wrapper around sql.Open that skips the
// test (rather than failing) when the database is unreachable -- so CI
// without Postgres just skips this file.
func openOrSkipScanSettings(t *testing.T, url string) *sql.DB {
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

// TestScanSettings_TenantIsolation_RLS verifies the load-bearing security
// property of migration 048 (F185): under the sbomhub_app (NOBYPASSRLS)
// role, a scan_settings row written by tenant A is invisible to tenant
// B, and tenant B cannot forge a row claiming to belong to tenant A.
// scan_settings holds scheduled-scan configuration (one row per tenant);
// a cross-tenant write could disable another tenant's scans, the read
// gap was the exact failure mode the scheduler relied on pre-F185.
func TestScanSettings_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := scanSettingsTestEnv(t)

	migDB := openOrSkipScanSettings(t, migURL)
	defer migDB.Close()
	if !schemaReadyScanSettings(t, migDB) {
		return
	}
	appDB := openOrSkipScanSettings(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForScanSettings(t, migDB, "A")
	tenantB := seedTenantForScanSettings(t, migDB, "B")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the scan_settings rows.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// --- Step 1: as app role under tenant A, insert one scan_settings row.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	settingsAID := uuid.New()
	if _, err := txA.Exec(`
		INSERT INTO scan_settings (
			id, tenant_id, enabled, schedule_type, schedule_hour
		) VALUES ($1, $2, true, 'daily', 6)
	`, settingsAID, tenantA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, attempt to read tenant A's
	// row by tenant_id. RLS must make it invisible -> COUNT == 0.
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
		`SELECT COUNT(*) FROM scan_settings WHERE tenant_id = $1`, tenantA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (F185 regression): tenantB saw %d row(s) for tenantA's "+
			"scan_settings; expected 0. This is the cross-tenant scheduler-config "+
			"read primitive F185 closed.", seen)
	}

	// --- Step 2b: also verify the wildcard scan_settings SELECT (the
	// pattern the legacy scheduler used) returns nothing for tenantA's
	// row from tenantB's session.
	rows, err := txB.Query(`SELECT tenant_id FROM scan_settings`)
	if err != nil {
		t.Fatalf("tenantB SELECT scan_settings: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tid uuid.UUID
		if err := rows.Scan(&tid); err != nil {
			continue
		}
		if tid == tenantA {
			t.Fatalf("RLS leak (F185 regression): tenantB unscoped SELECT surfaced "+
				"tenantA's row (tenant_id=%s). The legacy scheduler used this exact "+
				"shape — confirming the gap is closed.", tenantA)
		}
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it. We expect an error here.
	// We use a fresh UUID for the row id so any failure is from the
	// WITH CHECK clause and not from the UNIQUE(tenant_id) constraint
	// — the row CLAIMS tenant_id = tenantA which collides with the
	// row Step 1 inserted, but RLS rejects the write before the
	// unique-constraint check.
	forgedID := uuid.New()
	_, forgeErr := txB.Exec(`
		INSERT INTO scan_settings (
			id, tenant_id, enabled, schedule_type, schedule_hour
		) VALUES ($1, $2, false, 'daily', 12)
		ON CONFLICT (tenant_id) DO UPDATE
		SET enabled = EXCLUDED.enabled
	`, forgedID, tenantA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken (F185 regression): tenantB session was able "+
			"to write a scan_settings row with tenant_id=%s (tenantA). This is the "+
			"cross-tenant scheduler-disable primitive the policy is supposed to prevent.",
			tenantA)
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
		`SELECT COUNT(*) FROM scan_settings WHERE tenant_id = $1`, tenantA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own scan_settings rows; "+
			"expected 1 -- RLS policy may be over-restrictive", seen)
	}
}
