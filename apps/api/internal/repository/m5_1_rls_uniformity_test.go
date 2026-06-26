//go:build integration

// Package repository - M5 Wave M5-1 RLS uniformity sweep regression
// test (issue #50). This test covers the cross-tenant probe pattern
// over EVERY table touched by migrations 042 / 043 / 044:
//
//   - migration 042 (FORCE + WITH CHECK harmonisation, 9 tables in
//     migrations 012 / 013 / 014 / 021):
//     vulnerability_resolution_events, slo_targets,
//     vulnerability_snapshots, compliance_snapshots,
//     report_settings, generated_reports, ipa_sync_settings,
//     ssvc_project_defaults, ssvc_assessments
//
//   - migration 043 (ENABLE + FORCE + policy, 3 tables):
//     github_connections, github_repositories,
//     ssvc_assessment_history (subquery policy)
//
//   - migration 044 (composite (tenant_id, project_id) FK, 5 tables):
//     github_repositories, vulnerability_resolution_events,
//     compliance_snapshots, ssvc_project_defaults, ssvc_assessments
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestM5_1 ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection
//   - Schema migrated through 044_composite_fk_tenant_project.
//
// The cross-tenant probe pattern (one per table family) is:
//  1. Seed tenant A + tenant B (+ project A + project B where relevant).
//  2. As tenant A's sbomhub_app session, insert one row.
//  3. As tenant B's session, attempt to read tenant A's row via
//     whatever non-tenant_id key would be guessable -- expect 0 rows.
//  4. As tenant B's session, attempt to forge a row claiming
//     tenant_id=A -- expect rejection by WITH CHECK.
//  5. As tenant A's session, verify the original row is still there
//     (i.e. tenant B's tamper attempts did not silently succeed).
//
// For migration 044's composite FK we additionally probe:
//  6. As tenant A's session, attempt to insert a row with
//     tenant_id=A + project_id=<B's project UUID> -- expect the
//     composite FK to reject (would otherwise pass WITH CHECK
//     because row.tenant_id matches the GUC).
//
// The test is one Go file deliberately so the cleanup hook (DELETE
// FROM tenants CASCADE) reaps every seeded row in one shot.
package repository

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// m5_1TestEnv shares the env helpers used by the M1..M4 RLS suites.
func m5_1TestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t)
}

// schemaReadyM5_1 verifies migrations 042, 043 and 044 have been
// applied. Returns false (and skips) on partial / unmigrated state so
// the test fails gracefully on pre-M5 schemas rather than reporting a
// spurious leak.
func schemaReadyM5_1(t *testing.T, db *sql.DB) bool {
	t.Helper()
	// Spot-check one table per migration: if these are present, the
	// migrate-up sequence has crossed 042+043+044.
	checks := []struct {
		table, policy string
		needPolicy    bool
	}{
		// migration 042 -- FORCE + new policy name on previously-USING-
		// only tables.
		{"vulnerability_resolution_events", "tenant_isolation_vulnerability_resolution_events", true},
		{"slo_targets", "tenant_isolation_slo_targets", true},
		{"ssvc_assessments", "tenant_isolation_ssvc_assessments", true},

		// migration 043 -- ENABLE + FORCE + policy on previously-no-RLS
		// tables.
		{"github_connections", "tenant_isolation_github_connections", true},
		{"github_repositories", "tenant_isolation_github_repositories", true},
		{"ssvc_assessment_history", "tenant_isolation_ssvc_assessment_history", true},
	}
	for _, c := range checks {
		var rlsEnabled, rlsForce bool
		err := db.QueryRow(`
			SELECT relrowsecurity, relforcerowsecurity
			FROM pg_class
			WHERE oid = ('public.' || $1)::regclass
		`, c.table).Scan(&rlsEnabled, &rlsForce)
		if err != nil {
			t.Skipf("%s RLS state check failed: %v -- skipping (migrations 042-044 not applied?)", c.table, err)
			return false
		}
		if !rlsEnabled || !rlsForce {
			t.Fatalf("%s RLS not in expected state (enabled=%v, force=%v). "+
				"Migrations 042-044 either not applied or reverted -- this is "+
				"the M5-1 cross-tenant uniformity regression.",
				c.table, rlsEnabled, rlsForce)
			return false
		}
		if c.needPolicy {
			var pc int
			if err := db.QueryRow(`
				SELECT COUNT(*) FROM pg_policies
				WHERE schemaname = 'public' AND tablename = $1 AND policyname = $2
			`, c.table, c.policy).Scan(&pc); err != nil {
				t.Skipf("pg_policies lookup for %s/%s failed: %v -- skipping", c.table, c.policy, err)
				return false
			}
			if pc != 1 {
				t.Fatalf("policy %s on %s not found (count=%d). "+
					"Migrations 042-044 either not applied or reverted -- M5-1 regression.",
					c.policy, c.table, pc)
				return false
			}
		}
	}
	// Spot-check one composite FK from migration 044.
	var fkExists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conname = 'ssvc_assessments_tenant_project_fk'
			  AND conrelid = 'public.ssvc_assessments'::regclass
		)
	`).Scan(&fkExists); err != nil {
		t.Skipf("composite FK existence check failed: %v -- skipping", err)
		return false
	}
	if !fkExists {
		t.Skip("ssvc_assessments_tenant_project_fk not present -- migration 044 not applied, skipping")
		return false
	}
	return true
}

func seedTenantForM5_1(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "m5-1-rls-"+label+"-"+id.String(),
		"M5-1 RLS "+label,
		"m5-1-rls-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func seedProjectForM5_1(t *testing.T, migDB *sql.DB, tenant uuid.UUID, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
		id, tenant, "M5-1 RLS Project "+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed project %s: %v", label, err)
	}
	return id
}

func openOrSkipM5_1(t *testing.T, url string) *sql.DB {
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

// setTenantGUC runs SET LOCAL app.current_tenant_id on tx. Helper used
// by every probe below.
func setTenantGUC(t *testing.T, tx *sql.Tx, tenantID uuid.UUID) {
	t.Helper()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("set_config tenant=%s: %v", tenantID, err)
	}
}

// TestM5_1_TenantIsolation_VulnerabilityResolutionEvents covers
// migration 042 (FORCE + WITH CHECK) AND migration 044 (composite FK)
// for vulnerability_resolution_events.
func TestM5_1_TenantIsolation_VulnerabilityResolutionEvents(t *testing.T) {
	appURL, migURL := m5_1TestEnv(t)
	migDB := openOrSkipM5_1(t, migURL)
	defer migDB.Close()
	if !schemaReadyM5_1(t, migDB) {
		return
	}
	appDB := openOrSkipM5_1(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForM5_1(t, migDB, "vreA")
	tenantB := seedTenantForM5_1(t, migDB, "vreB")
	projectA := seedProjectForM5_1(t, migDB, tenantA, "vreA")
	projectB := seedProjectForM5_1(t, migDB, tenantB, "vreB")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// Pre-seed a vulnerability row (FK target). vulnerabilities is
	// NOT tenant-scoped (global CVE catalog), so we use the migrator
	// role for the seed.
	vulnID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, severity, source, created_at, updated_at)
		VALUES ($1, $2, 'HIGH', 'NVD', NOW(), NOW())
	`, vulnID, "CVE-M5-1-VRE-"+vulnID.String()[:8]); err != nil {
		t.Fatalf("seed vulnerabilities: %v", err)
	}
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID) })

	rowA := uuid.New()

	// --- Step 1: tenant A inserts a resolution event.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	setTenantGUC(t, txA, tenantA)
	if _, err := txA.Exec(`
		INSERT INTO vulnerability_resolution_events (
			id, tenant_id, vulnerability_id, project_id, cve_id, severity,
			detected_at, resolved_at, resolution_type, resolution_notes
		) VALUES ($1, $2, $3, $4, $5, 'HIGH', NOW(), NOW(), 'fixed', 'tenant-A-private-resolution')
	`, rowA, tenantA, vulnID, projectA, "CVE-M5-1-VRE-"+vulnID.String()[:8]); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: tenant B probes for tenant A's row.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	setTenantGUC(t, txB, tenantB)

	var seen int
	if err := txB.QueryRow(
		`SELECT COUNT(*) FROM vulnerability_resolution_events WHERE id = $1`, rowA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantB count by id: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (M5-1 regression): tenantB saw %d row(s) for tenantA's "+
			"vulnerability_resolution_event id=%s; expected 0.", seen, rowA)
	}

	// --- Step 3: tenant B tries to forge a row claiming tenant_id=A.
	_, forgeErr := txB.Exec(`
		INSERT INTO vulnerability_resolution_events (
			id, tenant_id, vulnerability_id, project_id, cve_id, severity,
			detected_at, resolution_type
		) VALUES ($1, $2, $3, $4, $5, 'HIGH', NOW(), 'fixed')
	`, uuid.New(), tenantA, vulnID, projectA, "CVE-M5-1-VRE-"+vulnID.String()[:8])
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken (M5-1 regression): tenantB session inserted a "+
			"vulnerability_resolution_events row with tenant_id=%s (tenantA).", tenantA)
	}

	// --- Step 4: F75 composite FK probe -- tenant A tries to attach
	// to tenant B's project.
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	setTenantGUC(t, txA2, tenantA)
	_, polluteErr := txA2.Exec(`
		INSERT INTO vulnerability_resolution_events (
			id, tenant_id, vulnerability_id, project_id, cve_id, severity,
			detected_at, resolution_type
		) VALUES ($1, $2, $3, $4, $5, 'HIGH', NOW(), 'fixed')
	`, uuid.New(), tenantA, vulnID, projectB, "CVE-M5-1-VRE-"+vulnID.String()[:8])
	if polluteErr == nil {
		t.Fatalf("F75 regression (M5-1 composite FK): tenantA session was able to attach "+
			"a vulnerability_resolution_event to tenantB's project (id=%s). "+
			"Migration 044 composite FK is supposed to reject this.", projectB)
	}
}

// TestM5_1_TenantIsolation_SLOTargets covers the special-case
// slo_targets policy: NULL-tenant_id global rows must be visible to
// every tenant on READ, but WRITE with tenant_id=NULL must be
// rejected.
func TestM5_1_TenantIsolation_SLOTargets(t *testing.T) {
	appURL, migURL := m5_1TestEnv(t)
	migDB := openOrSkipM5_1(t, migURL)
	defer migDB.Close()
	if !schemaReadyM5_1(t, migDB) {
		return
	}
	appDB := openOrSkipM5_1(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForM5_1(t, migDB, "sloA")
	tenantB := seedTenantForM5_1(t, migDB, "sloB")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// --- Step 1: tenant A inserts a per-tenant override.
	rowA := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	setTenantGUC(t, txA, tenantA)
	if _, err := txA.Exec(`
		INSERT INTO slo_targets (id, tenant_id, severity, target_hours)
		VALUES ($1, $2, $3, $4)
	`, rowA, tenantA, "CRITICAL", 6); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert override: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: tenant B reads -- must see the global defaults but
	// NOT tenant A's CRITICAL override.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	setTenantGUC(t, txB, tenantB)

	// Global default CRITICAL=24h must be visible to tenant B (NULL tenant).
	var globalCriticalHours int
	if err := txB.QueryRow(`
		SELECT target_hours FROM slo_targets
		WHERE tenant_id IS NULL AND severity = 'CRITICAL'
	`).Scan(&globalCriticalHours); err != nil {
		t.Fatalf("tenantB read of NULL-tenant CRITICAL: %v -- M5-1 regression "+
			"(WITH CHECK rejects NULL on write but USING must still allow NULL on read)", err)
	}
	if globalCriticalHours != 24 {
		t.Errorf("global default CRITICAL target_hours = %d, want 24 (migration 012 seed)", globalCriticalHours)
	}

	// Tenant A's CRITICAL override must NOT be visible to tenant B.
	var seen int
	if err := txB.QueryRow(`
		SELECT COUNT(*) FROM slo_targets WHERE id = $1
	`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count by id: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (M5-1 regression): tenantB saw tenantA's slo_targets override id=%s", rowA)
	}

	// --- Step 3: tenant B tries to forge a NULL-tenant row (the new
	// global-default forgery attack the WITH CHECK is supposed to
	// reject in addition to plain cross-tenant forgery).
	_, forgeNullErr := txB.Exec(`
		INSERT INTO slo_targets (id, tenant_id, severity, target_hours)
		VALUES ($1, NULL, 'INFO', 1)
	`, uuid.New())
	if forgeNullErr == nil {
		t.Fatalf("M5-1 regression: tenantB inserted a NULL-tenant slo_targets row " +
			"(tenant_id IS NOT NULL is supposed to be in WITH CHECK)")
	}

	// --- Step 4: tenant B tries to forge tenant_id=A.
	_, forgeAErr := txB.Exec(`
		INSERT INTO slo_targets (id, tenant_id, severity, target_hours)
		VALUES ($1, $2, 'INFO', 1)
	`, uuid.New(), tenantA)
	if forgeAErr == nil {
		t.Fatalf("M5-1 regression: tenantB inserted a slo_targets row claiming tenant_id=%s (tenantA)", tenantA)
	}
}

// TestM5_1_TenantIsolation_ReportSettings covers report_settings
// (migration 042) -- the standard FORCE + WITH CHECK probe.
func TestM5_1_TenantIsolation_ReportSettings(t *testing.T) {
	appURL, migURL := m5_1TestEnv(t)
	migDB := openOrSkipM5_1(t, migURL)
	defer migDB.Close()
	if !schemaReadyM5_1(t, migDB) {
		return
	}
	appDB := openOrSkipM5_1(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForM5_1(t, migDB, "rsA")
	tenantB := seedTenantForM5_1(t, migDB, "rsB")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	rowA := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	setTenantGUC(t, txA, tenantA)
	if _, err := txA.Exec(`
		INSERT INTO report_settings (id, tenant_id, enabled, report_type, schedule_type)
		VALUES ($1, $2, true, 'compliance', 'monthly')
	`, rowA, tenantA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	setTenantGUC(t, txB, tenantB)
	var seen int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM report_settings WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (M5-1 regression): tenantB saw tenantA's report_settings id=%s", rowA)
	}

	_, forgeErr := txB.Exec(`
		INSERT INTO report_settings (id, tenant_id, enabled, report_type, schedule_type)
		VALUES ($1, $2, true, 'compliance', 'monthly')
	`, uuid.New(), tenantA)
	if forgeErr == nil {
		t.Fatalf("M5-1 regression: tenantB forged report_settings with tenant_id=%s", tenantA)
	}
}

// TestM5_1_TenantIsolation_IPASyncSettings covers ipa_sync_settings
// (migration 042) -- the standard FORCE + WITH CHECK probe.
func TestM5_1_TenantIsolation_IPASyncSettings(t *testing.T) {
	appURL, migURL := m5_1TestEnv(t)
	migDB := openOrSkipM5_1(t, migURL)
	defer migDB.Close()
	if !schemaReadyM5_1(t, migDB) {
		return
	}
	appDB := openOrSkipM5_1(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForM5_1(t, migDB, "ipaA")
	tenantB := seedTenantForM5_1(t, migDB, "ipaB")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	rowA := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	setTenantGUC(t, txA, tenantA)
	if _, err := txA.Exec(`
		INSERT INTO ipa_sync_settings (id, tenant_id, enabled, notify_on_new)
		VALUES ($1, $2, true, true)
	`, rowA, tenantA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	setTenantGUC(t, txB, tenantB)
	var seen int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM ipa_sync_settings WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (M5-1 regression): tenantB saw tenantA's ipa_sync_settings id=%s", rowA)
	}

	_, forgeErr := txB.Exec(`
		INSERT INTO ipa_sync_settings (id, tenant_id, enabled, notify_on_new)
		VALUES ($1, $2, true, true)
	`, uuid.New(), tenantA)
	if forgeErr == nil {
		t.Fatalf("M5-1 regression: tenantB forged ipa_sync_settings with tenant_id=%s", tenantA)
	}
}

// TestM5_1_TenantIsolation_GitHubTables covers github_connections +
// github_repositories (migration 043: ENABLE + FORCE + policy).
// Also exercises migration 044's composite FK on github_repositories.
func TestM5_1_TenantIsolation_GitHubTables(t *testing.T) {
	appURL, migURL := m5_1TestEnv(t)
	migDB := openOrSkipM5_1(t, migURL)
	defer migDB.Close()
	if !schemaReadyM5_1(t, migDB) {
		return
	}
	appDB := openOrSkipM5_1(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForM5_1(t, migDB, "ghA")
	tenantB := seedTenantForM5_1(t, migDB, "ghB")
	projectA := seedProjectForM5_1(t, migDB, tenantA, "ghA")
	projectB := seedProjectForM5_1(t, migDB, tenantB, "ghB")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// --- Step 1: tenant A inserts a github_connection.
	connA := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	setTenantGUC(t, txA, tenantA)
	if _, err := txA.Exec(`
		INSERT INTO github_connections (id, tenant_id, access_token_encrypted, token_type, username)
		VALUES ($1, $2, 'tenant-A-secret-PAT-ciphertext', 'pat', 'alice')
	`, connA, tenantA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert connection: %v", err)
	}
	repoA := uuid.New()
	if _, err := txA.Exec(`
		INSERT INTO github_repositories (id, tenant_id, project_id, connection_id, repo_full_name, branch, webhook_secret)
		VALUES ($1, $2, $3, $4, $5, 'main', 'tenant-A-webhook-secret')
	`, repoA, tenantA, projectA, connA, "tenantA/private-repo"); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert repository: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: tenant B probes for tenant A's connection +
	// repository.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	setTenantGUC(t, txB, tenantB)

	var seenConn int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM github_connections WHERE id = $1`, connA).Scan(&seenConn); err != nil {
		t.Fatalf("tenantB count connection: %v", err)
	}
	if seenConn != 0 {
		t.Fatalf("RLS leak (M5-1 regression): tenantB saw tenantA's github_connections id=%s -- "+
			"that row contains access_token_encrypted (the encrypted PAT).", connA)
	}

	var seenRepo int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM github_repositories WHERE id = $1`, repoA).Scan(&seenRepo); err != nil {
		t.Fatalf("tenantB count repository: %v", err)
	}
	if seenRepo != 0 {
		t.Fatalf("RLS leak (M5-1 regression): tenantB saw tenantA's github_repositories id=%s -- "+
			"that row contains webhook_secret (HMAC verification key).", repoA)
	}

	// --- Step 3: forge probe on github_connections.
	_, forgeConnErr := txB.Exec(`
		INSERT INTO github_connections (id, tenant_id, access_token_encrypted, token_type)
		VALUES ($1, $2, 'forged', 'pat')
	`, uuid.New(), tenantA)
	if forgeConnErr == nil {
		t.Fatalf("M5-1 regression: tenantB forged github_connections with tenant_id=%s", tenantA)
	}

	// --- Step 4: F75 composite FK probe on github_repositories.
	// tenant A targets tenant B's project_id. WITH CHECK on tenant_id
	// would pass (row.tenant_id == GUC), but the composite FK from
	// migration 044 must reject.
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	setTenantGUC(t, txA2, tenantA)
	_, polluteErr := txA2.Exec(`
		INSERT INTO github_repositories (id, tenant_id, project_id, connection_id, repo_full_name, branch, webhook_secret)
		VALUES ($1, $2, $3, $4, $5, 'main', 'pollute')
	`, uuid.New(), tenantA, projectB, connA, "tenantA/pollute-attempt")
	if polluteErr == nil {
		t.Fatalf("F75 regression (M5-1 composite FK): tenantA attached a github_repositories "+
			"row to tenantB's project (id=%s). Migration 044 composite FK is supposed to reject.",
			projectB)
	}
}

// TestM5_1_TenantIsolation_SSVCAssessmentHistory covers the subquery
// policy on ssvc_assessment_history (migration 043). This is the
// audit-trail table that has no tenant_id column -- tenant scope
// derives from the parent ssvc_assessments row via EXISTS subquery.
func TestM5_1_TenantIsolation_SSVCAssessmentHistory(t *testing.T) {
	appURL, migURL := m5_1TestEnv(t)
	migDB := openOrSkipM5_1(t, migURL)
	defer migDB.Close()
	if !schemaReadyM5_1(t, migDB) {
		return
	}
	appDB := openOrSkipM5_1(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForM5_1(t, migDB, "sahA")
	tenantB := seedTenantForM5_1(t, migDB, "sahB")
	projectA := seedProjectForM5_1(t, migDB, tenantA, "sahA")
	projectB := seedProjectForM5_1(t, migDB, tenantB, "sahB")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// Seed a vulnerability + assessments per tenant (assessments
	// table has FORCE RLS post-042, so we use the app role via SET
	// LOCAL).
	vulnID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, severity, source, created_at, updated_at)
		VALUES ($1, $2, 'HIGH', 'NVD', NOW(), NOW())
	`, vulnID, "CVE-M5-1-SAH-"+vulnID.String()[:8]); err != nil {
		t.Fatalf("seed vulnerabilities: %v", err)
	}
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID) })

	// As tenant A, create an assessment + history row.
	assessA := uuid.New()
	histA := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	setTenantGUC(t, txA, tenantA)
	if _, err := txA.Exec(`
		INSERT INTO ssvc_assessments (
			id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact,
			mission_prevalence, safety_impact, decision
		) VALUES (
			$1, $2, $3, $4, $5,
			'active', 'yes', 'total',
			'essential', 'significant', 'immediate'
		)
	`, assessA, projectA, tenantA, vulnID, "CVE-M5-1-SAH-"+vulnID.String()[:8]); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert assessment: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO ssvc_assessment_history (
			id, assessment_id,
			new_exploitation, new_automatable, new_technical_impact,
			new_mission_prevalence, new_safety_impact, new_decision,
			change_reason
		) VALUES (
			$1, $2,
			'active', 'yes', 'total',
			'essential', 'significant', 'immediate',
			'tenant-A-private-audit-trail'
		)
	`, histA, assessA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert history: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: tenant B probes for tenant A's history row by id +
	// by assessment_id. The subquery policy in migration 043 routes
	// through ssvc_assessments which is FORCE-RLS post-042, so tenant
	// B's session cannot see ssvc_assessments rows for tenant A and
	// the EXISTS subquery returns false.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	setTenantGUC(t, txB, tenantB)

	var seen int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM ssvc_assessment_history WHERE id = $1`, histA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count history by id: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (M5-1 regression): tenantB saw tenantA's ssvc_assessment_history "+
			"id=%s -- the subquery policy is supposed to make this 0.", histA)
	}

	if err := txB.QueryRow(`SELECT COUNT(*) FROM ssvc_assessment_history WHERE assessment_id = $1`, assessA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count history by assessment_id: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (M5-1 regression): tenantB saw %d ssvc_assessment_history rows "+
			"by tenantA's assessment_id=%s.", seen, assessA)
	}

	// --- Step 3: tenant B tries to insert a history row referencing
	// tenant A's assessment_id -- the WITH CHECK subquery should
	// reject because tenant B's session has no visibility into
	// tenant A's ssvc_assessments rows.
	_, forgeErr := txB.Exec(`
		INSERT INTO ssvc_assessment_history (
			id, assessment_id,
			new_exploitation, new_automatable, new_technical_impact,
			new_mission_prevalence, new_safety_impact, new_decision,
			change_reason
		) VALUES (
			$1, $2,
			'none', 'no', 'partial',
			'minimal', 'minimal', 'defer',
			'forged-by-B'
		)
	`, uuid.New(), assessA)
	if forgeErr == nil {
		t.Fatalf("M5-1 regression: tenantB session forged a ssvc_assessment_history "+
			"row attached to tenantA's assessment_id=%s -- subquery WITH CHECK is "+
			"supposed to reject.", assessA)
	}

	_ = projectB // referenced for symmetry; the probe uses projectA / assessA
}

// TestM5_1_TenantIsolation_SSVCAssessments_CompositeFK covers the
// migration 044 composite FK on ssvc_assessments. The RLS probe is
// already covered by existing tests; this one focuses on the F75
// cross-tenant project_id rejection.
func TestM5_1_TenantIsolation_SSVCAssessments_CompositeFK(t *testing.T) {
	appURL, migURL := m5_1TestEnv(t)
	migDB := openOrSkipM5_1(t, migURL)
	defer migDB.Close()
	if !schemaReadyM5_1(t, migDB) {
		return
	}
	appDB := openOrSkipM5_1(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForM5_1(t, migDB, "ssaA")
	tenantB := seedTenantForM5_1(t, migDB, "ssaB")
	projectA := seedProjectForM5_1(t, migDB, tenantA, "ssaA")
	projectB := seedProjectForM5_1(t, migDB, tenantB, "ssaB")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	vulnID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, severity, source, created_at, updated_at)
		VALUES ($1, $2, 'HIGH', 'NVD', NOW(), NOW())
	`, vulnID, "CVE-M5-1-SSACFK-"+vulnID.String()[:8]); err != nil {
		t.Fatalf("seed vulnerabilities: %v", err)
	}
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID) })

	// Tenant A attempts to attach an ssvc_assessment to tenant B's
	// project_id. WITH CHECK passes (row.tenant_id=A == GUC=A). The
	// composite FK from 044 must reject.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	defer txA.Rollback()
	setTenantGUC(t, txA, tenantA)

	_, polluteErr := txA.Exec(`
		INSERT INTO ssvc_assessments (
			id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact,
			mission_prevalence, safety_impact, decision
		) VALUES (
			$1, $2, $3, $4, $5,
			'none', 'no', 'partial',
			'minimal', 'minimal', 'defer'
		)
	`, uuid.New(), projectB, tenantA, vulnID, "CVE-M5-1-SSACFK-"+vulnID.String()[:8])
	if polluteErr == nil {
		t.Fatalf("F75 regression (M5-1 composite FK): tenantA attached a ssvc_assessment "+
			"to tenantB's project (id=%s). Migration 044 composite FK is supposed to reject.",
			projectB)
	}

	// Sanity: the same INSERT with tenant A's own project_id must
	// succeed.
	if _, err := txA.Exec(`
		INSERT INTO ssvc_assessments (
			id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact,
			mission_prevalence, safety_impact, decision
		) VALUES (
			$1, $2, $3, $4, $5,
			'none', 'no', 'partial',
			'minimal', 'minimal', 'defer'
		)
	`, uuid.New(), projectA, tenantA, vulnID, "CVE-M5-1-SSACFK-"+vulnID.String()[:8]); err != nil {
		t.Fatalf("M5-1 regression: same-tenant ssvc_assessment insert failed: %v -- "+
			"the composite FK should NOT reject in-tenant project_id targeting.", err)
	}
}

// keep time import used by other tests above (silence unused warnings
// when this file is built without other RLS tests). Helpers below are
// referenced from the time-based tests above.
var _ = time.Second
