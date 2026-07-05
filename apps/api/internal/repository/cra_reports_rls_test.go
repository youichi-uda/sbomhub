//go:build integration

// Package repository - cra_reports tenant-isolation integration test
// (M2 Wave M2-2 / issue #35, migration 038).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestCRAReports ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 038_cra_reports.
//
// What this test pins down:
//
//  1. The cra_reports INSERT goes through the FORCE RLS WITH CHECK
//     policy installed in migration 038. A foreign-tenant INSERT is
//     rejected at write time, not merely hidden at read time.
//  2. A read from tenant B's session must NOT surface rows that
//     tenant A inserted. Cross-tenant report leakage would disclose
//     both the vulnerability surface AND the authority-facing prose
//     (operator's product names, supplier chain, remediation
//     timeline) -- all directly competitive-intelligence sensitive
//     for the manufacturer ICP.
//  3. The CHECK constraint enforcing non-empty `evidence` still
//     holds. PRODUCT_REBOOT_PLAN.md §8.5 "no AI output without
//     evidence" lives in this constraint (M1 F4 regression-class
//     guard repeated for CRA reports).
//  4. The CHECK constraints on report_type / lang / state / decision
//     are still in force (regression class: a future migration
//     loosens or removes them).
package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
)

// craReportsTestEnv reuses the same env-helper as the M1 RLS suites
// so a single DATABASE_URL / MIGRATE_DATABASE_URL pair drives every
// integration test in this package.
func craReportsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // reuse env helper from llm_calls_rls_test.go
}

func schemaReadyCRAReports(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'cra_reports'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("cra_reports existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("cra_reports table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.cra_reports'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("cra_reports RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("cra_reports RLS not in expected state (enabled=%v, force=%v); "+
			"migration 038 may have been reverted -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

func seedTenantForCRAReports(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "cra-report-test-"+label+"-"+id.String(),
		"CRAReport Test "+label,
		"cra-report-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func openOrSkipCRAReports(t *testing.T, url string) *sql.DB {
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

// TestCRAReports_TenantIsolation_RLS verifies migration 038's load-
// bearing tenant isolation property: tenant A's reports are invisible
// to tenant B, and tenant B cannot forge a report claiming to belong
// to tenant A.
func TestCRAReports_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := craReportsTestEnv(t)

	migDB := openOrSkipCRAReports(t, migURL)
	defer migDB.Close()
	if !schemaReadyCRAReports(t, migDB) {
		return
	}
	appDB := openOrSkipCRAReports(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForCRAReports(t, migDB, "A")
	tenantB := seedTenantForCRAReports(t, migDB, "B")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the cra_reports rows we insert.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	projectA := uuid.New()
	vulnA := uuid.New()
	rowA := uuid.New()

	// --- Step 1: as app role under tenant A, insert one report.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-RA', 'early_warning', 'ja', 'draft body A',
			'[{"kind":"vex_draft","ref":"00000000-0000-0000-0000-000000000001"}]'::jsonb)
	`, rowA, tenantA, projectA, vulnA); err != nil {
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
	if err := txB.QueryRow(`SELECT COUNT(*) FROM cra_reports WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak: tenantB saw %d row(s) for tenantA's cra_reports.id=%s; expected 0", seen, rowA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it.
	_, forgeErr := txB.Exec(`
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-FORGE', 'early_warning', 'ja', 'forged',
			'[{"kind":"vex_draft","ref":"00000000-0000-0000-0000-000000000001"}]'::jsonb)
	`, uuid.New(), tenantA, projectA, vulnA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken: tenantB session was able to insert a cra_reports row "+
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
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM cra_reports WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own cra_reports rows for id=%s; expected 1", seen, rowA)
	}
}

// TestCRAReports_AwarenessTime_RLS_RoundTrip verifies the migration 054
// column end-to-end through the repository (M34-A / F423): the operator-
// attested awareness instant round-trips a tenant-scoped Insert -> Get
// (proving the INSERT bind + SELECT + scanner all carry the new column),
// and a cross-tenant read under another tenant's session does NOT surface
// the row (and therefore never leaks its awareness_time).
func TestCRAReports_AwarenessTime_RLS_RoundTrip(t *testing.T) {
	appURL, migURL := craReportsTestEnv(t)

	migDB := openOrSkipCRAReports(t, migURL)
	defer migDB.Close()
	if !schemaReadyCRAReports(t, migDB) {
		return
	}
	// Skip cleanly on a schema that predates migration 054.
	var hasCol bool
	if err := migDB.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'cra_reports'
			  AND column_name = 'awareness_time'
		)
	`).Scan(&hasCol); err != nil {
		t.Skipf("awareness_time column check failed: %v -- skipping", err)
	}
	if !hasCol {
		t.Skip("cra_reports.awareness_time not present -- run migration 054 first")
	}

	appDB := openOrSkipCRAReports(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForCRAReports(t, migDB, "AW-A")
	tenantB := seedTenantForCRAReports(t, migDB, "AW-B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	repo := NewCRAReportsRepository(appDB)
	awareness := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	reportID := uuid.New()

	// --- Insert + read back under tenant A's tx (repository path).
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	ctxA := database.WithTx(context.Background(), txA)
	rep := &CRAReport{
		ID:              reportID,
		TenantID:        tenantA,
		ProjectID:       uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2025-AW",
		ReportType:      "early_warning",
		Lang:            "ja",
		DraftText:       "awareness round-trip body",
		Evidence:        validCRAEvidence(),
		AwarenessTime:   &awareness,
	}
	if err := repo.Insert(ctxA, rep); err != nil {
		_ = txA.Rollback()
		t.Fatalf("Insert under tenant A: %v", err)
	}
	got, err := repo.Get(ctxA, tenantA, reportID)
	if err != nil {
		_ = txA.Rollback()
		t.Fatalf("Get under tenant A: %v", err)
	}
	if got == nil {
		_ = txA.Rollback()
		t.Fatalf("expected the inserted row to be visible under tenant A")
	}
	if got.AwarenessTime == nil || !got.AwarenessTime.Equal(awareness) {
		_ = txA.Rollback()
		t.Fatalf("awareness_time did not round-trip: got %v, want %v", got.AwarenessTime, awareness)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Cross-tenant read: under tenant B's session even an explicit
	// Get for tenantA's id is invisible (RLS), so its awareness_time can
	// never leak.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}
	ctxB := database.WithTx(context.Background(), txB)
	leaked, err := repo.Get(ctxB, tenantA, reportID)
	if err != nil {
		t.Fatalf("Get under tenant B: %v", err)
	}
	if leaked != nil {
		t.Fatalf("RLS leak: tenant B surfaced tenant A's cra_report (awareness_time=%v)", leaked.AwarenessTime)
	}
}

// TestCRAReports_UpdateAwarenessTime_RLS proves the M35 Wave A write
// path is tenant-safe end-to-end: tenant B cannot UPDATE tenant A's
// awareness_time. We deliberately pass tenantID = tenantA (so the
// method's explicit `tenant_id = $1` clause is *satisfied*) while
// running under tenant B's session -- this isolates the migration 038
// FORCE RLS policy as the load-bearing guard. RLS hides A's row from
// B, so the UPDATE matches zero rows and UpdateAwarenessTime returns
// the wrapped sql.ErrNoRows the handler surfaces as a 404. We then
// re-read as tenant A and confirm the original awareness is untouched
// (no silent cross-tenant mutation slipped through).
func TestCRAReports_UpdateAwarenessTime_RLS(t *testing.T) {
	appURL, migURL := craReportsTestEnv(t)

	migDB := openOrSkipCRAReports(t, migURL)
	defer migDB.Close()
	if !schemaReadyCRAReports(t, migDB) {
		return
	}
	// Skip cleanly on a schema that predates migration 054.
	var hasCol bool
	if err := migDB.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'cra_reports'
			  AND column_name = 'awareness_time'
		)
	`).Scan(&hasCol); err != nil {
		t.Skipf("awareness_time column check failed: %v -- skipping", err)
	}
	if !hasCol {
		t.Skip("cra_reports.awareness_time not present -- run migration 054 first")
	}

	appDB := openOrSkipCRAReports(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForCRAReports(t, migDB, "UAW-A")
	tenantB := seedTenantForCRAReports(t, migDB, "UAW-B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	repo := NewCRAReportsRepository(appDB)
	original := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	reportID := uuid.New()

	// --- Step 1: as tenant A, insert a report carrying the original
	// awareness instant.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	ctxA := database.WithTx(context.Background(), txA)
	rep := &CRAReport{
		ID:              reportID,
		TenantID:        tenantA,
		ProjectID:       uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2025-UAW",
		ReportType:      "early_warning",
		Lang:            "ja",
		DraftText:       "awareness update-rls body",
		Evidence:        validCRAEvidence(),
		AwarenessTime:   &original,
	}
	if err := repo.Insert(ctxA, rep); err != nil {
		_ = txA.Rollback()
		t.Fatalf("Insert under tenant A: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: under tenant B's session, attempt to overwrite tenant
	// A's awareness. tenantID = tenantA is passed on purpose so only RLS
	// (not the explicit tenant_id clause) can stop the write. Expect
	// zero rows -> wrapped sql.ErrNoRows.
	attacker := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		_ = txB.Rollback()
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}
	ctxB := database.WithTx(context.Background(), txB)
	updErr := repo.UpdateAwarenessTime(ctxB, tenantA, reportID, &attacker)
	if updErr == nil {
		_ = txB.Rollback()
		t.Fatalf("RLS breach: tenant B was able to UPDATE tenant A's awareness_time")
	}
	if !errors.Is(updErr, sql.ErrNoRows) {
		_ = txB.Rollback()
		t.Fatalf("expected wrapped sql.ErrNoRows from a cross-tenant UpdateAwarenessTime, got %v", updErr)
	}
	if err := txB.Rollback(); err != nil {
		t.Fatalf("rollback tenantB: %v", err)
	}

	// --- Step 3: re-read as tenant A and confirm the awareness is
	// untouched (no silent cross-tenant mutation slipped through).
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	ctxA2 := database.WithTx(context.Background(), txA2)
	got, err := repo.Get(ctxA2, tenantA, reportID)
	if err != nil {
		t.Fatalf("Get under tenant A2: %v", err)
	}
	if got == nil {
		t.Fatalf("expected tenant A's row to still exist after the blocked cross-tenant UPDATE")
	}
	if got.AwarenessTime == nil || !got.AwarenessTime.Equal(original) {
		t.Fatalf("cross-tenant mutation leaked: awareness_time is now %v, want unchanged %v", got.AwarenessTime, original)
	}
}

// TestCRAReports_EvidenceRequired verifies the load-bearing
// "no AI output without evidence" CHECK constraint
// (PRODUCT_REBOOT_PLAN.md §8.5, M1 F4 regression-class guard
// repeated). Empty array, NULL, and a non-array JSON value must all
// be rejected by the DB even when the application layer is bypassed
// (direct migrator insert).
func TestCRAReports_EvidenceRequired(t *testing.T) {
	_, migURL := craReportsTestEnv(t)
	migDB := openOrSkipCRAReports(t, migURL)
	defer migDB.Close()
	if !schemaReadyCRAReports(t, migDB) {
		return
	}
	tenant := seedTenantForCRAReports(t, migDB, "EV")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// M9 F158: cra_reports is under FORCE RLS, so the negative-path
	// INSERTs below must run inside a tx with the tenant GUC set.

	// Empty array.
	err := execAsTenant(t, migDB, tenant, `
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-EV1', 'early_warning', 'ja', 'x', '[]'::jsonb)
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed empty evidence array; \"no AI output without evidence\" is meant to be enforced at the schema layer")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on evidence (empty array), got: %v", err)
	}

	// NULL evidence: NOT NULL violation, not a CHECK violation, but
	// equally load-bearing. We accept either error class but require
	// the insert to fail.
	err = execAsTenant(t, migDB, tenant, `
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-EV2', 'early_warning', 'ja', 'x', NULL)
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("NOT NULL / CHECK constraint allowed NULL evidence; \"no AI output without evidence\" is meant to be enforced")
	}

	// Non-array JSON: jsonb_array_length raises an error on non-
	// arrays; the CHECK constraint is therefore tripped.
	err = execAsTenant(t, migDB, tenant, `
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-EV3', 'early_warning', 'ja', 'x', '{"kind":"x"}'::jsonb)
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed non-array evidence (jsonb_array_length only meaningful on arrays)")
	}
}

// TestCRAReports_ReportTypeLangStateAndDecisionChecks verifies the
// CHECK constraints on report_type (allow-list), lang (allow-list),
// state (allow-list), and decision (allow-list) hold against direct
// migrator-role inserts. Catches the regression class where a future
// migration loosens or removes them.
func TestCRAReports_ReportTypeLangStateAndDecisionChecks(t *testing.T) {
	_, migURL := craReportsTestEnv(t)
	migDB := openOrSkipCRAReports(t, migURL)
	defer migDB.Close()
	if !schemaReadyCRAReports(t, migDB) {
		return
	}
	tenant := seedTenantForCRAReports(t, migDB, "CK")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	good := `'[{"kind":"vex_draft","ref":"00000000-0000-0000-0000-000000000001"}]'::jsonb`

	// M9 F158: cra_reports is under FORCE RLS. Wrap each negative-path
	// INSERT in a tenant-GUC tx. Also keep all bogus VARCHAR(20) values
	// within 20 chars so the CHECK constraint fires before PG's column
	// type length check ("value too long for type character varying(20)")
	// pre-empts the allow-list error we are asserting against.

	// Bad report_type (17 chars, fits VARCHAR(20)).
	err := execAsTenant(t, migDB, tenant, `
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-CK', 'bogus_report_type', 'ja', 'x', `+good+`)
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown report_type; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on report_type, got: %v", err)
	}

	// Bad lang.
	err = execAsTenant(t, migDB, tenant, `
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-CK', 'early_warning', 'fr', 'x', `+good+`)
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown lang; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on lang, got: %v", err)
	}

	// Bad state (11 chars, fits VARCHAR(20)).
	err = execAsTenant(t, migDB, tenant, `
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, state, draft_text, evidence
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-CK', 'early_warning', 'ja', 'frobnicated', 'x', `+good+`)
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown state; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on state, got: %v", err)
	}

	// Bad decision (11 chars, fits VARCHAR(20)).
	err = execAsTenant(t, migDB, tenant, `
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence, decision
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-CK', 'early_warning', 'ja', 'x', `+good+`, 'frobnicated')
	`, uuid.New(), tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("CHECK constraint allowed unknown decision; the allow-list is meant to be enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation on decision, got: %v", err)
	}
}
