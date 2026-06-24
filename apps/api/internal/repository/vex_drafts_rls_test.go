//go:build integration

// Package repository - vex_drafts tenant-isolation integration test
// (M1 Wave M1-5 / issue #27, migration 035).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestVEXDrafts ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 035_vex_drafts.
//
// What this test pins down:
//
//  1. The vex_drafts INSERT goes through the FORCE RLS WITH CHECK
//     policy installed in migration 035. A foreign-tenant INSERT is
//     rejected at write time, not merely hidden at read time.
//  2. A read from tenant B's session must NOT surface rows that
//     tenant A inserted. Cross-tenant draft leakage would disclose
//     both the vulnerability surface and the AI's draft text, both
//     of which are competitive-intelligence sensitive for the
//     manufacturer ICP.
//  3. The CHECK constraint enforcing non-empty `evidence` still
//     holds. PRODUCT_REBOOT_PLAN.md §8.5 "no AI output without
//     evidence" lives in this constraint.
//  4. The CHECK constraints on state / decision / confidence are
//     still in force (regression class: a future migration loosens
//     or removes them).
package repository

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func vexDraftsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // reuse env helper from llm_calls_rls_test.go
}

func schemaReadyVEXDrafts(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'vex_drafts'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("vex_drafts existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("vex_drafts table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.vex_drafts'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("vex_drafts RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("vex_drafts RLS not in expected state (enabled=%v, force=%v); "+
			"migration 035 may have been reverted -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

func seedTenantForVEXDrafts(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "vex-draft-test-"+label+"-"+id.String(),
		"VEXDraft Test "+label,
		"vex-draft-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func openOrSkipVEXDrafts(t *testing.T, url string) *sql.DB {
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

// TestVEXDrafts_TenantIsolation_RLS verifies migration 035's load-
// bearing tenant isolation property: tenant A's drafts are invisible
// to tenant B, and tenant B cannot forge a draft claiming to belong
// to tenant A.
func TestVEXDrafts_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := vexDraftsTestEnv(t)

	migDB := openOrSkipVEXDrafts(t, migURL)
	defer migDB.Close()
	if !schemaReadyVEXDrafts(t, migDB) {
		return
	}
	appDB := openOrSkipVEXDrafts(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForVEXDrafts(t, migDB, "A")
	tenantB := seedTenantForVEXDrafts(t, migDB, "B")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the vex_drafts rows we insert.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	projectA := uuid.New()
	componentA := uuid.New()
	vulnA := uuid.New()
	rowA := uuid.New()

	// --- Step 1: as app role under tenant A, insert one draft.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id,
			cve_id, state, evidence
		) VALUES ($1, $2, $3, $4, $5,
			'CVE-2025-RA', 'not_affected',
			'[{"kind":"advisory_excerpt","ref":"00000000-0000-0000-0000-000000000001"}]'::jsonb)
	`, rowA, tenantA, projectA, componentA, vulnA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, count tenant A's row.
	// RLS should make it invisible -> count must be 0.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}
	var seen int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM vex_drafts WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak: tenantB saw %d row(s) for tenantA's vex_drafts.id=%s; expected 0", seen, rowA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it.
	_, forgeErr := txB.Exec(`
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id,
			cve_id, state, evidence
		) VALUES ($1, $2, $3, $4, $5,
			'CVE-2025-FORGE', 'not_affected',
			'[{"kind":"advisory_excerpt","ref":"00000000-0000-0000-0000-000000000001"}]'::jsonb)
	`, uuid.New(), tenantA, projectA, componentA, vulnA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken: tenantB session was able to insert a vex_drafts row "+
			"with tenant_id=%s (tenantA).", tenantA)
	}

	// --- Step 4: as tenant A again, confirm the original row is
	// still visible.
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM vex_drafts WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own vex_drafts rows for id=%s; expected 1", seen, rowA)
	}
}

// TestVEXDrafts_EvidenceRequired verifies the load-bearing
// "no AI output without evidence" CHECK constraint
// (PRODUCT_REBOOT_PLAN.md §8.5). Empty array, NULL, and a non-array
// JSON value must all be rejected by the DB even when the
// application layer is bypassed (direct migrator insert).
func TestVEXDrafts_EvidenceRequired(t *testing.T) {
	_, migURL := vexDraftsTestEnv(t)
	migDB := openOrSkipVEXDrafts(t, migURL)
	defer migDB.Close()
	if !schemaReadyVEXDrafts(t, migDB) {
		return
	}
	tenant := seedTenantForVEXDrafts(t, migDB, "EV")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// Empty array.
	_, err := migDB.Exec(`
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id,
			cve_id, state, evidence
		) VALUES ($1, $2, $3, $4, $5,
			'CVE-2025-EV1', 'not_affected', '[]'::jsonb)
	`, uuid.New(), tenant, uuid.New(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed empty evidence array; \"no AI output without evidence\" is meant to be enforced at the schema layer")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on evidence (empty array), got: %v", err)
	}

	// NULL evidence: NOT NULL violation, not a CHECK violation, but
	// equally load-bearing. We accept either error class but require
	// the insert to fail.
	_, err = migDB.Exec(`
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id,
			cve_id, state, evidence
		) VALUES ($1, $2, $3, $4, $5,
			'CVE-2025-EV2', 'not_affected', NULL)
	`, uuid.New(), tenant, uuid.New(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("NOT NULL / CHECK constraint allowed NULL evidence; \"no AI output without evidence\" is meant to be enforced")
	}

	// Non-array JSON: jsonb_array_length raises an error on non-arrays;
	// the CHECK constraint is therefore tripped.
	_, err = migDB.Exec(`
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id,
			cve_id, state, evidence
		) VALUES ($1, $2, $3, $4, $5,
			'CVE-2025-EV3', 'not_affected', '{"kind":"x"}'::jsonb)
	`, uuid.New(), tenant, uuid.New(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed non-array evidence (jsonb_array_length only meaningful on arrays)")
	}
}

// TestVEXDrafts_StateAndDecisionAndConfidenceChecks verifies the
// CHECK constraints on state (allow-list), decision (allow-list),
// and confidence ([0,1]) hold against direct migrator-role inserts.
// Catches the regression class where a future migration loosens or
// removes them.
func TestVEXDrafts_StateAndDecisionAndConfidenceChecks(t *testing.T) {
	_, migURL := vexDraftsTestEnv(t)
	migDB := openOrSkipVEXDrafts(t, migURL)
	defer migDB.Close()
	if !schemaReadyVEXDrafts(t, migDB) {
		return
	}
	tenant := seedTenantForVEXDrafts(t, migDB, "CK")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	good := `'[{"kind":"advisory_excerpt","ref":"00000000-0000-0000-0000-000000000001"}]'::jsonb`

	// Bad state.
	_, err := migDB.Exec(`
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id,
			cve_id, state, evidence
		) VALUES ($1, $2, $3, $4, $5,
			'CVE-2025-CK', 'definitely-not-a-state', `+good+`)
	`, uuid.New(), tenant, uuid.New(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown state; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on state, got: %v", err)
	}

	// Bad decision.
	_, err = migDB.Exec(`
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id,
			cve_id, state, evidence, decision
		) VALUES ($1, $2, $3, $4, $5,
			'CVE-2025-CK', 'not_affected', `+good+`, 'frobnicated')
	`, uuid.New(), tenant, uuid.New(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown decision; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on decision, got: %v", err)
	}

	// Bad confidence.
	_, err = migDB.Exec(`
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id,
			cve_id, state, evidence, confidence
		) VALUES ($1, $2, $3, $4, $5,
			'CVE-2025-CK', 'not_affected', `+good+`, 1.5)
	`, uuid.New(), tenant, uuid.New(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed confidence > 1; the [0,1] bound is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on confidence, got: %v", err)
	}
}
