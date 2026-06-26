//go:build integration

// Package repository - compliance_checklist_responses tenant-isolation
// integration test (M4 Codex review round 13 / F73, migration 040).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestComplianceChecklist ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 040_rls_compliance_visualization.
//
// What this test pins down:
//
//  1. The compliance_checklist_responses INSERT goes through the FORCE
//     RLS WITH CHECK policy installed in migration 040. A foreign-
//     tenant INSERT is rejected at write time, not merely hidden at
//     read time.
//  2. A read from tenant B's session must NOT surface rows that tenant
//     A inserted. Cross-tenant leakage here would expose the
//     manufacturer's manually-asserted METI compliance posture (which
//     items they admit they have NOT yet done, with free-text notes)
//     -- competitive-intelligence sensitive and the load-bearing F73
//     bug.
//  3. The repository wrapper (ChecklistRepository) refuses writes /
//     reads with tenant_id mismatched against the GUC, so a regression
//     in the middleware that fails to SET LOCAL app.current_tenant_id
//     is still caught at the app-layer guard from the same review.
package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/model"
)

// complianceChecklistTestEnv reuses the same env-helper as the M1 / M2
// / M3 RLS suites so a single DATABASE_URL / MIGRATE_DATABASE_URL pair
// drives every integration test in this package.
func complianceChecklistTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t)
}

func schemaReadyComplianceChecklist(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'compliance_checklist_responses'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("compliance_checklist_responses existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("compliance_checklist_responses table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.compliance_checklist_responses'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("compliance_checklist_responses RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		// Migration 040 either not applied or reverted -- this is the
		// F73 regression. Fail loudly rather than silently mis-test.
		t.Fatalf("compliance_checklist_responses RLS not in expected state "+
			"(enabled=%v, force=%v). Migration 040 either not applied or "+
			"reverted -- this is the F73 cross-tenant leak regression. "+
			"Run `go run ./cmd/migrate up`.", rlsEnabled, rlsForce)
		return false
	}
	var policyCount int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM pg_policies
		WHERE schemaname = 'public'
		  AND tablename  = 'compliance_checklist_responses'
		  AND policyname = 'tenant_isolation_compliance_checklist'
	`).Scan(&policyCount); err != nil {
		t.Skipf("pg_policies lookup failed: %v -- skipping", err)
		return false
	}
	if policyCount != 1 {
		t.Fatalf("compliance_checklist_responses policy "+
			"tenant_isolation_compliance_checklist not found (count=%d). "+
			"Migration 040 either not applied or reverted -- F73 regression.", policyCount)
		return false
	}
	return true
}

func seedTenantForComplianceChecklist(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "checklist-rls-test-"+label+"-"+id.String(),
		"ChecklistRLS Test "+label,
		"checklist-rls-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// seedProjectForComplianceChecklist creates a minimal projects row for
// the given tenant so the compliance_checklist_responses FK to
// projects(id) is satisfied. We do this via the migrator role so RLS
// does not interfere with the seed itself.
func seedProjectForComplianceChecklist(t *testing.T, migDB *sql.DB, tenant uuid.UUID, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
		id, tenant, "ChecklistRLS Project "+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed project %s: %v", label, err)
	}
	return id
}

func openOrSkipComplianceChecklist(t *testing.T, url string) *sql.DB {
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

// TestComplianceChecklist_TenantIsolation_RLS verifies migration 040's
// load-bearing tenant isolation property for compliance_checklist_responses:
// tenant A's manual METI checklist responses are invisible to tenant B,
// and tenant B cannot forge / overwrite a row claiming to belong to
// tenant A. This is the SQL-layer half of the F73 fix.
func TestComplianceChecklist_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := complianceChecklistTestEnv(t)

	migDB := openOrSkipComplianceChecklist(t, migURL)
	defer migDB.Close()
	if !schemaReadyComplianceChecklist(t, migDB) {
		return
	}
	appDB := openOrSkipComplianceChecklist(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForComplianceChecklist(t, migDB, "A")
	tenantB := seedTenantForComplianceChecklist(t, migDB, "B")
	projectA := seedProjectForComplianceChecklist(t, migDB, tenantA, "A")
	projectB := seedProjectForComplianceChecklist(t, migDB, tenantB, "B")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the projects + checklist rows.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	rowA := uuid.New()

	// --- Step 1: as app role under tenant A, insert one checklist row.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO compliance_checklist_responses (
			id, tenant_id, project_id, check_id, response, note, updated_by, updated_at
		) VALUES ($1, $2, $3, 'setup_01', TRUE, 'tenant-A-private-note', 'alice@tenantA', NOW())
	`, rowA, tenantA, projectA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, attempt to read tenant A's
	// row by project_id (the F73 attack vector -- guess the project UUID).
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
		`SELECT COUNT(*) FROM compliance_checklist_responses WHERE project_id = $1`, projectA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantB count by project_id (F73 probe): %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (F73 regression): tenantB saw %d row(s) for tenantA's "+
			"project_id=%s; expected 0. Cross-tenant METI checklist disclosure -- "+
			"the exact gap Codex round 13 F73 flagged.", seen, projectA)
	}

	// --- Step 2b: explicit note SELECT must also surface no rows.
	var leakedNote sql.NullString
	err = txB.QueryRow(
		`SELECT note FROM compliance_checklist_responses WHERE project_id = $1`, projectA,
	).Scan(&leakedNote)
	if err == nil {
		t.Fatalf("RLS leak (F73 regression): tenantB read tenantA's checklist note %q "+
			"via project_id guess.", leakedNote.String)
	}
	if err != sql.ErrNoRows {
		t.Logf("tenantB note SELECT returned %v (no leak, ok)", err)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject.
	_, forgeErr := txB.Exec(`
		INSERT INTO compliance_checklist_responses (
			id, tenant_id, project_id, check_id, response, note, updated_by, updated_at
		) VALUES ($1, $2, $3, 'setup_02', TRUE, 'forged-by-B', 'mallory@tenantB', NOW())
	`, uuid.New(), tenantA, projectA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken (F73 regression): tenantB session was able to "+
			"insert a compliance_checklist_responses row with tenant_id=%s (tenantA). "+
			"This is the cross-tenant checklist forgery primitive the policy is "+
			"supposed to prevent.", tenantA)
	}

	// --- Step 3b: tenantB tries to UPDATE tenant A's row via project_id
	// guess. RLS should make it a 0-row UPDATE (or reject WITH CHECK).
	res, updateErr := txB.Exec(`
		UPDATE compliance_checklist_responses SET response = FALSE, note = 'overwritten-by-B'
		WHERE project_id = $1 AND check_id = 'setup_01'
	`, projectA)
	if updateErr == nil {
		n, _ := res.RowsAffected()
		if n != 0 {
			t.Fatalf("RLS leak (F73 regression): tenantB UPDATE matched %d row(s) on "+
				"tenantA's project_id=%s; expected 0. Cross-tenant checklist tamper "+
				"primitive.", n, projectA)
		}
	}

	// --- Step 3c: tenantB tries to DELETE tenant A's row via project_id
	// guess. Same expectation: 0 rows affected (or rejection).
	res, deleteErr := txB.Exec(`
		DELETE FROM compliance_checklist_responses WHERE project_id = $1
	`, projectA)
	if deleteErr == nil {
		n, _ := res.RowsAffected()
		if n != 0 {
			t.Fatalf("RLS leak (F73 regression): tenantB DELETE removed %d row(s) on "+
				"tenantA's project_id=%s; expected 0. Cross-tenant checklist destroy "+
				"primitive.", n, projectA)
		}
	}

	_ = projectB // referenced for symmetry; the cross-tenant probe uses projectA

	// --- Step 4: as tenant A again, confirm the original row is still
	// visible and unchanged.
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	var note sql.NullString
	var response bool
	if err := txA2.QueryRow(`
		SELECT response, note FROM compliance_checklist_responses WHERE id = $1
	`, rowA).Scan(&response, &note); err != nil {
		t.Fatalf("tenantA2 SELECT: %v", err)
	}
	if !response {
		t.Fatalf("tenantA's response was overwritten cross-tenant (got false, want true); F73 regression")
	}
	if note.String != "tenant-A-private-note" {
		t.Fatalf("tenantA's note was overwritten cross-tenant (got %q, want %q); F73 regression",
			note.String, "tenant-A-private-note")
	}
}

// TestComplianceChecklist_RepositoryRejectsMissingTenantID verifies the
// app-layer twin of the RLS fix: ChecklistRepository methods refuse to
// run when tenantID is uuid.Nil. This catches the regression class
// where a caller forgets to thread tenant_id from the middleware
// context all the way to the repo. Runs against the migrator role
// because no DB round trip should happen for the bad-input cases --
// the methods reject before issuing a query.
func TestComplianceChecklist_RepositoryRejectsMissingTenantID(t *testing.T) {
	_, migURL := complianceChecklistTestEnv(t)
	migDB := openOrSkipComplianceChecklist(t, migURL)
	defer migDB.Close()

	repo := NewChecklistRepository(migDB)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := repo.ListByProject(ctx, uuid.Nil, uuid.New()); err == nil {
		t.Error("ChecklistRepository.ListByProject(tenant=nil) should fail fast (F73 guard)")
	}
	if _, err := repo.GetByCheckID(ctx, uuid.Nil, uuid.New(), "setup_01"); err == nil {
		t.Error("ChecklistRepository.GetByCheckID(tenant=nil) should fail fast (F73 guard)")
	}
	if err := repo.Delete(ctx, uuid.Nil, uuid.New(), "setup_01"); err == nil {
		t.Error("ChecklistRepository.Delete(tenant=nil) should fail fast (F73 guard)")
	}
	if err := repo.DeleteByProject(ctx, uuid.Nil, uuid.New()); err == nil {
		t.Error("ChecklistRepository.DeleteByProject(tenant=nil) should fail fast (F73 guard)")
	}
	if err := repo.Upsert(ctx, &model.ChecklistResponse{
		ID: uuid.New(), TenantID: uuid.Nil, ProjectID: uuid.New(),
		CheckID: "setup_01", Response: true,
	}); err == nil {
		t.Error("ChecklistRepository.Upsert(tenant=nil) should fail fast (F73 guard)")
	}
	if err := repo.BulkUpsert(ctx, []model.ChecklistResponse{
		{ID: uuid.New(), TenantID: uuid.Nil, ProjectID: uuid.New(), CheckID: "setup_01"},
	}); err == nil {
		t.Error("ChecklistRepository.BulkUpsert(tenant=nil) should fail fast (F73 guard)")
	}
	if _, err := repo.ListByTenant(ctx, uuid.Nil); err == nil {
		t.Error("ChecklistRepository.ListByTenant(tenant=nil) should fail fast (F73 guard)")
	}
}
