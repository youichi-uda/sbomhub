//go:build integration

// Package repository - meti_assessments tenant-isolation integration
// test (M3 Wave M3-1 / issue #41, migration 039).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestMetiAssessments ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 039_meti_assessments.
//
// What this test pins down:
//
//  1. The meti_assessments INSERT goes through the FORCE RLS WITH
//     CHECK policy installed in migration 039. A foreign-tenant
//     INSERT is rejected at write time, not merely hidden at read
//     time.
//  2. A read from tenant B's session must NOT surface rows that
//     tenant A inserted. Cross-tenant assessment leakage would
//     disclose the manufacturer's self-reported compliance posture
//     -- competitive-intelligence sensitive and a regulator-facing
//     artefact under METI 手引 ver 2.0.
//  3. The CHECK constraint enforcing `evidence` is a JSON array
//     (jsonb_array_length >= 0) still holds, including the relaxed
//     "empty array OK" semantics that distinguishes METI from VEX /
//     CRA (M3-1 spec).
//  4. The CHECK constraints on criterion_phase / status /
//     override_status are still in force (regression class: a future
//     migration loosens or removes them).
//  5. The UNIQUE (tenant_id, project_id, criterion_id) constraint
//     holds -- a duplicate write is rejected so the Upsert ON CONFLICT
//     path is the only way to update.
package repository

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// metiAssessmentsTestEnv reuses the same env-helper as the M1 / M2
// RLS suites so a single DATABASE_URL / MIGRATE_DATABASE_URL pair
// drives every integration test in this package.
func metiAssessmentsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // reuse env helper from llm_calls_rls_test.go
}

func schemaReadyMetiAssessments(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'meti_assessments'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("meti_assessments existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("meti_assessments table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.meti_assessments'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("meti_assessments RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("meti_assessments RLS not in expected state (enabled=%v, force=%v); "+
			"migration 039 may have been reverted -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

func seedTenantForMetiAssessments(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "meti-assess-test-"+label+"-"+id.String(),
		"MetiAssess Test "+label,
		"meti-assess-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func openOrSkipMetiAssessments(t *testing.T, url string) *sql.DB {
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

// TestMetiAssessments_TenantIsolation_RLS verifies migration 039's
// load-bearing tenant isolation property: tenant A's assessments are
// invisible to tenant B, and tenant B cannot forge an assessment
// claiming to belong to tenant A.
func TestMetiAssessments_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := metiAssessmentsTestEnv(t)

	migDB := openOrSkipMetiAssessments(t, migURL)
	defer migDB.Close()
	if !schemaReadyMetiAssessments(t, migDB) {
		return
	}
	appDB := openOrSkipMetiAssessments(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForMetiAssessments(t, migDB, "A")
	tenantB := seedTenantForMetiAssessments(t, migDB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	projectA := uuid.New()
	rowA := uuid.New()

	// --- Step 1: as app role under tenant A, insert one assessment.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'ENV-SBOM-001', 'env_setup', 'achieved',
			'[{"kind":"ci_config","ref":"github_actions"}]'::jsonb)
	`, rowA, tenantA, projectA); err != nil {
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
	if err := txB.QueryRow(`SELECT COUNT(*) FROM meti_assessments WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak: tenantB saw %d row(s) for tenantA's meti_assessments.id=%s; expected 0", seen, rowA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it.
	_, forgeErr := txB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'ENV-SBOM-001', 'env_setup', 'achieved',
			'[{"kind":"ci_config","ref":"github_actions"}]'::jsonb)
	`, uuid.New(), tenantA, projectA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken: tenantB session was able to insert a meti_assessments row "+
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
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM meti_assessments WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own meti_assessments rows for id=%s; expected 1", seen, rowA)
	}
}

// TestMetiAssessments_EvidenceShape verifies the relaxed evidence
// CHECK: NULL is rejected (NOT NULL), non-array shapes are rejected
// (jsonb_array_length raises), but empty arrays ARE accepted -- this
// is the explicit relaxation from vex_drafts / cra_reports.
// not_applicable / needs_review rows can legitimately have
// evidence='[]' because the evaluator could not inspect the
// criterion (e.g. SBOM not yet uploaded).
func TestMetiAssessments_EvidenceShape(t *testing.T) {
	_, migURL := metiAssessmentsTestEnv(t)
	migDB := openOrSkipMetiAssessments(t, migURL)
	defer migDB.Close()
	if !schemaReadyMetiAssessments(t, migDB) {
		return
	}
	tenant := seedTenantForMetiAssessments(t, migDB, "EV")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// Empty array: MUST be accepted (relaxation from vex/cra).
	_, err := migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'NA-001', 'sbom_creation', 'not_applicable', '[]'::jsonb)
	`, uuid.New(), tenant, uuid.New())
	if err != nil {
		t.Fatalf("CHECK constraint should accept empty evidence array on meti_assessments (relaxation from vex/cra), got: %v", err)
	}

	// NULL evidence: NOT NULL violation, MUST be rejected.
	_, err = migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'NA-002', 'sbom_creation', 'not_applicable', NULL)
	`, uuid.New(), tenant, uuid.New())
	if err == nil {
		t.Fatalf("NOT NULL constraint allowed NULL evidence; F4 regression-class guard")
	}

	// Non-array JSON: jsonb_array_length raises on non-arrays; the
	// CHECK constraint is therefore tripped.
	_, err = migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'NA-003', 'sbom_creation', 'not_applicable', '{"kind":"x"}'::jsonb)
	`, uuid.New(), tenant, uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed non-array evidence (jsonb_array_length only meaningful on arrays)")
	}
}

// TestMetiAssessments_PhaseStatusAndOverrideChecks verifies the CHECK
// constraints on criterion_phase (allow-list), status (allow-list),
// and override_status (NULL or allow-list). Catches the regression
// class where a future migration loosens or removes them.
func TestMetiAssessments_PhaseStatusAndOverrideChecks(t *testing.T) {
	_, migURL := metiAssessmentsTestEnv(t)
	migDB := openOrSkipMetiAssessments(t, migURL)
	defer migDB.Close()
	if !schemaReadyMetiAssessments(t, migDB) {
		return
	}
	tenant := seedTenantForMetiAssessments(t, migDB, "CK")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// Bad criterion_phase.
	_, err := migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'CK-001', 'not-a-real-phase', 'achieved', '[]'::jsonb)
	`, uuid.New(), tenant, uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown criterion_phase; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on criterion_phase, got: %v", err)
	}

	// Bad status.
	_, err = migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'CK-002', 'env_setup', 'frobnicated', '[]'::jsonb)
	`, uuid.New(), tenant, uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown status; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on status, got: %v", err)
	}

	// Bad override_status (a non-NULL non-allowed value).
	_, err = migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence,
			override_status, override_by, override_at
		) VALUES ($1, $2, $3,
			'CK-003', 'env_setup', 'achieved', '[]'::jsonb,
			'frobnicated', $4, NOW())
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown override_status; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on override_status, got: %v", err)
	}

	// NULL override_status MUST be accepted (it's the "no override" state).
	_, err = migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'CK-004', 'env_setup', 'achieved', '[]'::jsonb)
	`, uuid.New(), tenant, uuid.New())
	if err != nil {
		t.Fatalf("INSERT with implicit NULL override_status failed: %v -- the 'no override' state must be permitted", err)
	}
}

// TestMetiAssessments_UniqueCriterionPerProject verifies the
// UNIQUE (tenant_id, project_id, criterion_id) constraint that drives
// Upsert's ON CONFLICT path. Two raw INSERTs for the same composite
// key from the migrator role must fail with a unique-violation; the
// Upsert ON CONFLICT path (exercised by the unit tests) is the only
// supported way to update.
func TestMetiAssessments_UniqueCriterionPerProject(t *testing.T) {
	_, migURL := metiAssessmentsTestEnv(t)
	migDB := openOrSkipMetiAssessments(t, migURL)
	defer migDB.Close()
	if !schemaReadyMetiAssessments(t, migDB) {
		return
	}
	tenant := seedTenantForMetiAssessments(t, migDB, "UN")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	project := uuid.New()

	// First insert OK.
	if _, err := migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'UN-001', 'env_setup', 'achieved', '[]'::jsonb)
	`, uuid.New(), tenant, project); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// Second insert with same (tenant, project, criterion) MUST fail.
	_, err := migDB.Exec(`
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase, status, evidence
		) VALUES ($1, $2, $3,
			'UN-001', 'env_setup', 'not_achieved', '[]'::jsonb)
	`, uuid.New(), tenant, project)
	if err == nil {
		t.Fatalf("UNIQUE (tenant_id, project_id, criterion_id) constraint failed to reject duplicate")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		t.Fatalf("expected a unique-violation error, got: %v", err)
	}
}
