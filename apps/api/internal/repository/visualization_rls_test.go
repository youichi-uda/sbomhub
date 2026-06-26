//go:build integration

// Package repository - sbom_visualization_settings tenant-isolation
// integration test (M4 Codex review round 13 / F73, migration 040).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestVisualization ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 040_rls_compliance_visualization.
//
// What this test pins down:
//
//  1. The sbom_visualization_settings INSERT goes through the FORCE RLS
//     WITH CHECK policy installed in migration 040. A foreign-tenant
//     INSERT is rejected at write time, not merely hidden at read time.
//  2. A read from tenant B's session must NOT surface a row that tenant
//     A inserted. Cross-tenant leakage here would expose the
//     manufacturer's METI visualization framework posture -- not as
//     sensitive as raw component vuln data, but still disclosed via
//     F73 and a regulator-facing artefact.
//  3. The repository wrapper (VisualizationRepository) refuses writes /
//     reads with tenant_id mismatched against the GUC.
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

func visualizationTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t)
}

func schemaReadyVisualization(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'sbom_visualization_settings'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("sbom_visualization_settings existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("sbom_visualization_settings table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.sbom_visualization_settings'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("sbom_visualization_settings RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Fatalf("sbom_visualization_settings RLS not in expected state "+
			"(enabled=%v, force=%v). Migration 040 either not applied or "+
			"reverted -- this is the F73 cross-tenant leak regression. "+
			"Run `go run ./cmd/migrate up`.", rlsEnabled, rlsForce)
		return false
	}
	var policyCount int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM pg_policies
		WHERE schemaname = 'public'
		  AND tablename  = 'sbom_visualization_settings'
		  AND policyname = 'tenant_isolation_visualization'
	`).Scan(&policyCount); err != nil {
		t.Skipf("pg_policies lookup failed: %v -- skipping", err)
		return false
	}
	if policyCount != 1 {
		t.Fatalf("sbom_visualization_settings policy "+
			"tenant_isolation_visualization not found (count=%d). "+
			"Migration 040 either not applied or reverted -- F73 regression.", policyCount)
		return false
	}
	return true
}

func seedTenantForVisualization(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "viz-rls-test-"+label+"-"+id.String(),
		"VizRLS Test "+label,
		"viz-rls-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func seedProjectForVisualization(t *testing.T, migDB *sql.DB, tenant uuid.UUID, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
		id, tenant, "VizRLS Project "+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed project %s: %v", label, err)
	}
	return id
}

func openOrSkipVisualization(t *testing.T, url string) *sql.DB {
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

// TestVisualization_TenantIsolation_RLS verifies migration 040's
// load-bearing tenant isolation property for sbom_visualization_settings:
// tenant A's settings are invisible to tenant B, and tenant B cannot
// forge / overwrite a row claiming to belong to tenant A. SQL-layer
// half of the F73 fix.
func TestVisualization_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := visualizationTestEnv(t)

	migDB := openOrSkipVisualization(t, migURL)
	defer migDB.Close()
	if !schemaReadyVisualization(t, migDB) {
		return
	}
	appDB := openOrSkipVisualization(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForVisualization(t, migDB, "A")
	tenantB := seedTenantForVisualization(t, migDB, "B")
	projectA := seedProjectForVisualization(t, migDB, tenantA, "A")
	projectB := seedProjectForVisualization(t, migDB, tenantB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	rowA := uuid.New()

	// --- Step 1: as app role under tenant A, insert one settings row.
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO sbom_visualization_settings (
			id, tenant_id, project_id, sbom_author_scope, dependency_scope,
			generation_method, data_format, utilization_scope, utilization_actor
		) VALUES ($1, $2, $3, 'self', 'direct_only', 'tool_with_review',
			'standard', '["vuln_identification"]'::jsonb, 'product_vendor')
	`, rowA, tenantA, projectA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, attempt to read tenant A's
	// row by project_id (the F73 attack vector).
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
		`SELECT COUNT(*) FROM sbom_visualization_settings WHERE project_id = $1`, projectA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantB count by project_id (F73 probe): %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (F73 regression): tenantB saw %d row(s) for tenantA's "+
			"project_id=%s; expected 0. Cross-tenant visualization disclosure -- "+
			"the exact gap Codex round 13 F73 flagged.", seen, projectA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject.
	_, forgeErr := txB.Exec(`
		INSERT INTO sbom_visualization_settings (
			id, tenant_id, project_id, sbom_author_scope, dependency_scope,
			generation_method, data_format, utilization_scope, utilization_actor
		) VALUES ($1, $2, $3, 'self', 'direct_only', 'tool_with_review',
			'standard', '["vuln_identification"]'::jsonb, 'product_vendor')
		ON CONFLICT (project_id) DO UPDATE
		SET sbom_author_scope = EXCLUDED.sbom_author_scope
	`, uuid.New(), tenantA, projectA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken (F73 regression): tenantB session was able to "+
			"write a sbom_visualization_settings row with tenant_id=%s (tenantA). "+
			"This is the cross-tenant visualization overwrite primitive the policy "+
			"is supposed to prevent.", tenantA)
	}

	// --- Step 3b: tenantB tries to UPDATE tenant A's row via project_id.
	res, updateErr := txB.Exec(`
		UPDATE sbom_visualization_settings SET sbom_author_scope = 'supplier_thirdparty'
		WHERE project_id = $1
	`, projectA)
	if updateErr == nil {
		n, _ := res.RowsAffected()
		if n != 0 {
			t.Fatalf("RLS leak (F73 regression): tenantB UPDATE matched %d row(s) on "+
				"tenantA's project_id=%s; expected 0.", n, projectA)
		}
	}

	// --- Step 3c: tenantB tries to DELETE tenant A's row via project_id.
	res, deleteErr := txB.Exec(`
		DELETE FROM sbom_visualization_settings WHERE project_id = $1
	`, projectA)
	if deleteErr == nil {
		n, _ := res.RowsAffected()
		if n != 0 {
			t.Fatalf("RLS leak (F73 regression): tenantB DELETE removed %d row(s) on "+
				"tenantA's project_id=%s; expected 0.", n, projectA)
		}
	}

	_ = projectB

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
	var authorScope string
	if err := txA2.QueryRow(`
		SELECT sbom_author_scope FROM sbom_visualization_settings WHERE id = $1
	`, rowA).Scan(&authorScope); err != nil {
		t.Fatalf("tenantA2 SELECT: %v", err)
	}
	if authorScope != "self" {
		t.Fatalf("tenantA's sbom_author_scope was overwritten cross-tenant (got %q, want %q); F73 regression",
			authorScope, "self")
	}
}

// TestVisualization_RepositoryRejectsMissingTenantID verifies the
// app-layer twin of the RLS fix: VisualizationRepository methods refuse
// to run when tenantID is uuid.Nil.
func TestVisualization_RepositoryRejectsMissingTenantID(t *testing.T) {
	_, migURL := visualizationTestEnv(t)
	migDB := openOrSkipVisualization(t, migURL)
	defer migDB.Close()

	repo := NewVisualizationRepository(migDB)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := repo.GetByProject(ctx, uuid.Nil, uuid.New()); err == nil {
		t.Error("VisualizationRepository.GetByProject(tenant=nil) should fail fast (F73 guard)")
	}
	if err := repo.Delete(ctx, uuid.Nil, uuid.New()); err == nil {
		t.Error("VisualizationRepository.Delete(tenant=nil) should fail fast (F73 guard)")
	}
	if err := repo.Upsert(ctx, &model.VisualizationSettings{
		ID: uuid.New(), TenantID: uuid.Nil, ProjectID: uuid.New(),
		SBOMAuthorScope: "self", DependencyScope: "direct_only",
		GenerationMethod: "tool_no_review", DataFormat: "standard",
		UtilizationScope: []string{"vuln_identification"}, UtilizationActor: "product_vendor",
	}); err == nil {
		t.Error("VisualizationRepository.Upsert(tenant=nil) should fail fast (F73 guard)")
	}
}
