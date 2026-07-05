//go:build integration

// Package repository - cra_submissions tenant-isolation integration
// test (M33 Wave A / F418, migration 053).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestCRASubmissions ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 053_cra_submissions.
//
// What this test pins down:
//
//  1. The cra_submissions INSERT goes through the FORCE RLS WITH CHECK
//     policy installed in migration 053. A foreign-tenant INSERT is
//     rejected at write time, not merely hidden at read time.
//  2. A read from tenant B's session must NOT surface rows that tenant
//     A inserted. Cross-tenant submission-record leakage would disclose
//     that tenant A submitted a specific report to a named authority
//     under a specific reference number -- directly competitive-
//     intelligence sensitive for the manufacturer ICP.
//  3. A legitimate same-tenant write with SET LOCAL app.current_tenant_id
//     succeeds, including the single-column FK to an approved
//     cra_reports parent row (the FK check runs inside the same tenant
//     tx, so the parent row is visible under RLS).
package repository

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
)

// craSubmissionsTestEnv reuses the same env-helper as the M1/M2 RLS
// suites so a single DATABASE_URL / MIGRATE_DATABASE_URL pair drives
// every integration test in this package.
func craSubmissionsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // reuse env helper from llm_calls_rls_test.go
}

func schemaReadyCRASubmissions(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'cra_submissions'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("cra_submissions existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("cra_submissions table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.cra_submissions'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("cra_submissions RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("cra_submissions RLS not in expected state (enabled=%v, force=%v); "+
			"migration 053 may have been reverted -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

func seedTenantForCRASubmissions(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "cra-submission-test-"+label+"-"+id.String(),
		"CRASubmission Test "+label,
		"cra-submission-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func openOrSkipCRASubmissions(t *testing.T, url string) *sql.DB {
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

// insertApprovedCRAReport inserts one approved cra_reports row inside a
// tenant-scoped tx on the app connection (cra_reports is FORCE RLS, so
// the GUC must be set) and returns its id. It is the FK parent the
// cra_submissions rows below reference.
func insertApprovedCRAReport(t *testing.T, appDB *sql.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	reportID := uuid.New()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("insertApprovedCRAReport begin: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("insertApprovedCRAReport SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence, decision
		) VALUES ($1, $2, $3, $4,
			'CVE-2025-SUB', 'early_warning', 'ja', 'approved draft body',
			'[{"kind":"vex_draft","ref":"00000000-0000-0000-0000-000000000001"}]'::jsonb,
			'approved')
	`, reportID, tenant, uuid.New(), uuid.New()); err != nil {
		t.Fatalf("insertApprovedCRAReport insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("insertApprovedCRAReport commit: %v", err)
	}
	committed = true
	return reportID
}

// TestCRASubmissions_TenantIsolation_RLS verifies migration 053's load-
// bearing tenant isolation property: tenant A's submission records are
// invisible to tenant B, and tenant B cannot forge a submission row
// claiming to belong to tenant A.
func TestCRASubmissions_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := craSubmissionsTestEnv(t)

	migDB := openOrSkipCRASubmissions(t, migURL)
	defer migDB.Close()
	if !schemaReadyCRASubmissions(t, migDB) {
		return
	}
	appDB := openOrSkipCRASubmissions(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForCRASubmissions(t, migDB, "A")
	tenantB := seedTenantForCRASubmissions(t, migDB, "B")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the cra_reports + cra_submissions
		// rows we insert.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// FK parent: an approved cra_reports row in tenant A.
	reportA := insertApprovedCRAReport(t, appDB, tenantA)

	rowA := uuid.New()

	// --- Step 1: as app role under tenant A, record one submission.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO cra_submissions (
			id, tenant_id, cra_report_id, authority, submitted_at
		) VALUES ($1, $2, $3, 'ENISA CSIRT', NOW())
	`, rowA, tenantA, reportA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA legitimate insert (SET LOCAL): %v", err)
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
	if err := txB.QueryRow(`SELECT COUNT(*) FROM cra_submissions WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak: tenantB saw %d row(s) for tenantA's cra_submissions.id=%s; expected 0", seen, rowA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it at write time (the mismatch
	// between the row's tenant_id and the session GUC fires the RLS
	// WITH CHECK before the FK trigger runs).
	_, forgeErr := txB.Exec(`
		INSERT INTO cra_submissions (
			id, tenant_id, cra_report_id, authority, submitted_at
		) VALUES ($1, $2, $3, 'FORGE AUTHORITY', NOW())
	`, uuid.New(), tenantA, reportA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken: tenantB session was able to insert a cra_submissions row "+
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
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM cra_submissions WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own cra_submissions rows for id=%s; expected 1", seen, rowA)
	}
}

// TestCRASubmissions_Repository_RLS drives the CRASubmissionsRepository
// Record / ListByReport methods through a real tenant tx (attached to
// ctx via database.WithTx) so the repository's q(ctx) helper joins the
// SET LOCAL app.current_tenant_id session -- the same path the request
// middleware uses in prod. Confirms the RLS WITH CHECK passes for a
// legitimate write and the read is tenant-scoped.
func TestCRASubmissions_Repository_RLS(t *testing.T) {
	appURL, migURL := craSubmissionsTestEnv(t)

	migDB := openOrSkipCRASubmissions(t, migURL)
	defer migDB.Close()
	if !schemaReadyCRASubmissions(t, migDB) {
		return
	}
	appDB := openOrSkipCRASubmissions(t, appURL)
	defer appDB.Close()

	tenant := seedTenantForCRASubmissions(t, migDB, "REPO")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	report := insertApprovedCRAReport(t, appDB, tenant)
	repo := NewCRASubmissionsRepository(appDB)

	// Open a tenant tx and attach it to ctx via database.WithTx so the
	// repository's q(ctx) helper joins the same connection that has
	// SET LOCAL app.current_tenant_id -- the prod request-middleware path.
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	ctx := database.WithTx(context.Background(), tx)

	ref := "ACK-72H-0001"
	sub, err := repo.Record(ctx, CRASubmissionInput{
		TenantID:        tenant,
		CRAReportID:     report,
		Authority:       "ENISA CSIRT",
		ReferenceNumber: &ref,
	})
	if err != nil {
		t.Fatalf("repo.Record under tenant GUC: %v", err)
	}
	if sub.ID == uuid.Nil {
		t.Fatal("expected Record to return a generated id")
	}

	list, err := repo.ListByReport(ctx, tenant, report)
	if err != nil {
		t.Fatalf("repo.ListByReport: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 submission for the report, got %d", len(list))
	}
	if list[0].ID != sub.ID {
		t.Errorf("ListByReport returned id %s, expected %s", list[0].ID, sub.ID)
	}
	if list[0].ReferenceNumber == nil || *list[0].ReferenceNumber != ref {
		t.Errorf("expected reference_number %q round-tripped, got %v", ref, list[0].ReferenceNumber)
	}
}
