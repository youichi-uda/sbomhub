//go:build integration

// Package repository - RLS / tenant isolation integration test.
//
// Run with:
//
//	cd apps/api && go test -tags=integration ./internal/repository -run TestRLS
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema already migrated (the server's auto-migrate also handles this)
//
// The test deliberately uses raw sql.DB (not testcontainers) to keep the
// dependency surface small. We only need a real postgres because RLS is
// enforced server-side and cannot be exercised against sqlmock.
package repository

import (
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// rlsTestEnv returns the (app, migrator) URLs or skips the test.
func rlsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("RLS integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env.example values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// openOrSkip returns a *sql.DB or skips if the DB is unreachable. This is
// intentionally non-fatal so CI without postgres just skips the test.
func openOrSkip(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open failed (%v) — skipping RLS test", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("DB unreachable (%v) — skipping RLS test", err)
	}
	return db
}

// schemaReady returns true if the multi-tenant tables we need exist.
func schemaReady(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var ok bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'tenants'
		) AND EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'projects'
		) AND EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'sboms'
		)
	`).Scan(&ok)
	if err != nil {
		t.Skipf("schema check failed: %v — skipping RLS test", err)
	}
	return ok
}

// TestRLS_AppRoleNotBypassRLS asserts that the app role used at runtime does
// not have the BYPASSRLS attribute. This is the security invariant of P0 #2.
func TestRLS_AppRoleNotBypassRLS(t *testing.T) {
	appURL, _ := rlsTestEnv(t)
	db := openOrSkip(t, appURL)
	defer db.Close()

	var role string
	var bypass bool
	if err := db.QueryRow(
		`SELECT current_user, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&role, &bypass); err != nil {
		t.Fatalf("query rolbypassrls: %v", err)
	}
	if bypass {
		t.Fatalf("app role %q has rolbypassrls=true; expected NOBYPASSRLS. "+
			"Switch DATABASE_URL to the sbomhub_app role.", role)
	}
	t.Logf("app role %q has rolbypassrls=false (OK)", role)
}

// TestRLS_TenantIsolation_Sboms verifies that, when connected as the app
// role, a session scoped to tenant B cannot see rows that tenant A inserted
// — even when both rows live in the same table.
func TestRLS_TenantIsolation_Sboms(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)

	migDB := openOrSkip(t, migURL)
	defer migDB.Close()
	if !schemaReady(t, migDB) {
		t.Skip("schema not migrated yet — run the api server (or migrate up) first")
	}

	appDB := openOrSkip(t, appURL)
	defer appDB.Close()

	// Provision two test tenants + one project each as the migrator. The
	// projects/sboms inserts here run as migrator (table owner with default
	// FORCE RLS — but FORCE RLS still applies, so we set the tenant GUC).
	tenantA := uuid.New()
	tenantB := uuid.New()
	projectA := uuid.New()
	projectB := uuid.New()

	cleanup := func() {
		// Use migrator role; tenants table has no RLS, ON DELETE CASCADE
		// removes projects/sboms.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	}
	t.Cleanup(cleanup)
	cleanup()

	mustExec := func(db *sql.DB, q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}

	// Seed tenants (no RLS on tenants table).
	mustExec(migDB,
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES
		   ($1, $2, $3, $4),
		   ($5, $6, $7, $8)`,
		tenantA, "rls-test-A-"+tenantA.String(), "RLS Test A", "rls-test-a-"+tenantA.String()[:8],
		tenantB, "rls-test-B-"+tenantB.String(), "RLS Test B", "rls-test-b-"+tenantB.String()[:8],
	)

	// Seed projects as migrator under each tenant's GUC. Wrap in tx so we
	// can SET LOCAL.
	seedProject := func(tenantID, projectID uuid.UUID, name string) {
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
			_ = tx.Rollback()
			t.Fatalf("SET LOCAL: %v", err)
		}
		if _, err := tx.Exec(
			`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
			projectID, tenantID, name,
		); err != nil {
			_ = tx.Rollback()
			t.Fatalf("insert project: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit project: %v", err)
		}
	}
	seedProject(tenantA, projectA, "RLS Project A")
	seedProject(tenantB, projectB, "RLS Project B")

	// As the app role (NOBYPASSRLS), tenant A inserts one sbom.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(
		`INSERT INTO sboms (id, project_id, tenant_id, format, version, raw_data)
		 VALUES ($1, $2, $3, 'cyclonedx', '1.4', '{}'::jsonb)`,
		uuid.New(), projectA, tenantA,
	); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert sbom: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// Tenant B (still on the app role) must see zero sbom rows for tenant
	// A's project. RLS enforcement is what makes this hold.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}

	var count int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM sboms WHERE project_id = $1`, projectA).Scan(&count); err != nil {
		t.Fatalf("tenantB count sboms: %v", err)
	}
	if count != 0 {
		t.Fatalf("RLS leak: tenantB session saw %d sbom rows belonging to tenantA; expected 0", count)
	}

	// Sanity: tenant A still sees its own row in a fresh tx.
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM sboms WHERE project_id = $1`, projectA).Scan(&count); err != nil {
		t.Fatalf("tenantA2 count sboms: %v", err)
	}
	if count == 0 {
		t.Fatalf("tenantA session sees 0 of its own sbom rows — RLS policy may be over-restrictive")
	}
}
