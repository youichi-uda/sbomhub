//go:build integration

// Package service — cross-project transitive dependency-path (blast-radius ×
// reachability) integration test (M30-A / F402, issue #138).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestCVEPaths ./internal/service
//
// -count=1 is load-bearing: this test asserts against live DB rows +
// FORCE ROW LEVEL SECURITY behaviour under a NOBYPASSRLS app role, neither of
// which is an input to go's test cache.
//
// Prerequisites (skipped otherwise — same env contract as the M28 impact
// integration test, whose seed/env helpers this file reuses):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through the canonical apps/api sequence.
//
// What this pins (M30 kickoff Wave A real-PG list):
//
//  1. Cross-project aggregation WITHIN a tenant: a CVE affecting projects A
//     (transitive path) and B (direct path) yields BOTH with the correct
//     per-project entry chain, computed against each project's latest SBOM.
//  2. Tenant isolation: a foreign tenant's project affected by the SAME CVE
//     (same purl) NEVER appears in the caller's result; total_project_count
//     counts only the caller's projects. RLS (authoritative) + the query's
//     explicit tenant_id predicate (belt).
//  3. GUC load-bearing: querying the SAME CVE under tenant T's GUC vs tenant
//     F's GUC returns DISJOINT project sets — mutating app.current_tenant_id
//     changes the result, proving tenant separation is not incidental.
//  4. 200/404 boundary: a known CVE reaching zero of the tenant's projects →
//     non-nil empty (200); an unknown CVE → nil (handler answers 404).
//
// The seed/env helpers (seedTenantVS, seedProjectVS, seedComponentVS,
// seedVulnVS, linkCompVulnVS, openOrSkipVS, schemaReadyVS, vexSuggestionsTestEnv,
// withTenantTxVS) live in vex_suggestions_integration_test.go — same package,
// same build tag — and the CycloneDX fixture builders (mkCDX/cdxComp/cdxDep)
// live in cve_paths_test.go (same package, no build tag). Both are reused here.
package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// seedSbomRawCP inserts a SBOM carrying real CycloneDX raw_data (the default
// seedSbomVS writes an empty `{}` graph, which yields no paths). The bytes are
// stored in the raw_data jsonb column exactly as the ingest path would.
func seedSbomRawCP(t *testing.T, migDB *sql.DB, tenantID, projectID uuid.UUID, format string, raw []byte) uuid.UUID {
	t.Helper()
	id := uuid.New()
	withTenantTxVS(t, migDB, tenantID, func(tx *sql.Tx) {
		if _, err := tx.Exec(
			`INSERT INTO sboms (id, project_id, tenant_id, format, version, raw_data)
			 VALUES ($1,$2,$3,$4,'1.6',$5::jsonb)`,
			id, projectID, tenantID, format, string(raw)); err != nil {
			t.Fatalf("seed sbom raw: %v", err)
		}
	})
	return id
}

// runCVEPaths drives the real CVEPathsService.GetCVEPaths for (tenant, cve)
// through an app-role tx that has SET LOCAL app.current_tenant_id, so RLS is
// active exactly as on a live request.
func runCVEPaths(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, cveID string) *model.CVEPathsResponse {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL %s: %v", tenantID, err)
	}
	svc := NewCVEPathsService(repository.NewSearchRepository(appDB), repository.NewSbomRepository(appDB))
	ctx := database.WithTx(context.Background(), tx)
	got, err := svc.GetCVEPaths(ctx, tenantID, cveID)
	if err != nil {
		t.Fatalf("GetCVEPaths(%s): %v", cveID, err)
	}
	return got
}

func joinPathIDs(chain []model.PathNode) string {
	ids := make([]string, 0, len(chain))
	for _, n := range chain {
		ids = append(ids, n.ID)
	}
	return strings.Join(ids, " -> ")
}

func TestCVEPaths_CrossProjectAndTenantIsolation(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyVS(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "PATHS-T")
	tenantF := seedTenantVS(t, migDB, "PATHS-F")

	sfx := strings.ToUpper(uuid.New().String()[:8])
	cve := func(n string) string { return fmt.Sprintf("CVE-2026-%s-%s", n, sfx) }
	vHit := seedVulnVS(t, migDB, cve("HIT"))   // affects T's A + B and foreign F
	vZero := seedVulnVS(t, migDB, cve("ZERO")) // known, affects nothing in T

	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenantT, tenantF)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id IN ($1,$2)`, vHit, vZero)
	})

	// --- Tenant T, project A: app-a → express → qs (qs TRANSITIVE) ---
	projA := uuid.New()
	seedProjectVS(t, migDB, tenantT, projA, "app-a")
	rawA := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "app-a", Version: "1.0.0", Purl: "pkg:generic/app-a@1.0.0"},
		[]cdxComp{
			{BOMRef: "express", Type: "library", Name: "express", Version: "4.18.0", Purl: "pkg:generic/express@4.18.0"},
			{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:generic/qs@6.2.0"},
		},
		[]cdxDep{
			{Ref: "root", DependsOn: []string{"express"}},
			{Ref: "express", DependsOn: []string{"qs"}},
		},
	)
	sbomA := seedSbomRawCP(t, migDB, tenantT, projA, "cyclonedx", rawA)
	compA := seedComponentVS(t, migDB, tenantT, sbomA, "qs", "6.2.0", "pkg:generic/qs@6.2.0")
	linkCompVulnVS(t, migDB, compA, vHit)

	// --- Tenant T, project B: app-b → qs (qs DIRECT) ---
	projB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projB, "app-b")
	rawB := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "app-b", Version: "2.0.0", Purl: "pkg:generic/app-b@2.0.0"},
		[]cdxComp{
			{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:generic/qs@6.2.0"},
		},
		[]cdxDep{{Ref: "root", DependsOn: []string{"qs"}}},
	)
	sbomB := seedSbomRawCP(t, migDB, tenantT, projB, "cyclonedx", rawB)
	compB := seedComponentVS(t, migDB, tenantT, sbomB, "qs", "6.2.0", "pkg:generic/qs@6.2.0")
	linkCompVulnVS(t, migDB, compB, vHit)

	// --- Tenant T, project C: unaffected (counts toward total only) ---
	projC := uuid.New()
	seedProjectVS(t, migDB, tenantT, projC, "app-c")
	sbomC := seedSbomVS(t, migDB, tenantT, projC)
	_ = seedComponentVS(t, migDB, tenantT, sbomC, "libsafe", "9.9", "pkg:generic/libsafe@9.9")

	// --- Foreign tenant F: SAME CVE, SAME purl — strongest leak candidate ---
	projF := uuid.New()
	seedProjectVS(t, migDB, tenantF, projF, "foreign-app")
	rawF := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "foreign", Version: "1.0.0", Purl: "pkg:generic/foreign@1.0.0"},
		[]cdxComp{{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:generic/qs@6.2.0"}},
		[]cdxDep{{Ref: "root", DependsOn: []string{"qs"}}},
	)
	sbomF := seedSbomRawCP(t, migDB, tenantF, projF, "cyclonedx", rawF)
	compF := seedComponentVS(t, migDB, tenantF, sbomF, "qs", "6.2.0", "pkg:generic/qs@6.2.0")
	linkCompVulnVS(t, migDB, compF, vHit)

	// ---- Query vHit as tenant T ----
	got := runCVEPaths(t, appDB, tenantT, cve("HIT"))
	if got == nil {
		t.Fatalf("expected non-nil paths result for known CVE %s", cve("HIT"))
	}

	// Case 1: exactly A and B; C (unaffected) and F (foreign) never appear.
	if got.AffectedProjectCount != 2 || len(got.AffectedProjects) != 2 {
		t.Fatalf("affected_project_count = %d (len %d), want 2: %+v", got.AffectedProjectCount, len(got.AffectedProjects), got.AffectedProjects)
	}
	byID := map[uuid.UUID]model.AffectedProjectPaths{}
	for _, p := range got.AffectedProjects {
		if p.ProjectID == projF {
			t.Fatalf("TENANT LEAK: foreign project %s surfaced in tenant T's paths", projF)
		}
		if p.ProjectID == projC {
			t.Fatalf("unaffected project C %s surfaced", projC)
		}
		byID[p.ProjectID] = p
	}

	// Case 1 detail: project A transitive path app-a → express → qs.
	pa, okA := byID[projA]
	if !okA {
		t.Fatalf("project A missing from result")
	}
	if pa.SbomID != sbomA || pa.Degraded {
		t.Errorf("projA sbom_id=%s degraded=%v, want %s/false", pa.SbomID, pa.Degraded, sbomA)
	}
	if len(pa.AffectedComponents) != 1 {
		t.Fatalf("projA affected_components = %d, want 1", len(pa.AffectedComponents))
	}
	ca := pa.AffectedComponents[0]
	if !ca.InGraph || ca.IsDirect {
		t.Errorf("projA qs in_graph=%v is_direct=%v, want true/false (transitive)", ca.InGraph, ca.IsDirect)
	}
	if ca.PathCount != 1 || joinPathIDs(ca.Paths[0]) != "pkg:generic/app-a -> pkg:generic/express -> pkg:generic/qs" {
		t.Errorf("projA qs path = %v, want [app-a -> express -> qs]", ca.Paths)
	}

	// Case 1 detail: project B direct path app-b → qs.
	pb, okB := byID[projB]
	if !okB {
		t.Fatalf("project B missing from result")
	}
	cb := pb.AffectedComponents[0]
	if !cb.InGraph || !cb.IsDirect {
		t.Errorf("projB qs in_graph=%v is_direct=%v, want true/true (direct)", cb.InGraph, cb.IsDirect)
	}
	if cb.PathCount != 1 || joinPathIDs(cb.Paths[0]) != "pkg:generic/app-b -> pkg:generic/qs" {
		t.Errorf("projB qs path = %v, want [app-b -> qs]", cb.Paths)
	}

	// Case 2: total_project_count is tenant T's project total (A,B,C = 3).
	if got.TotalProjectCount != 3 {
		t.Fatalf("total_project_count = %d, want 3 (T has A,B,C; F excluded)", got.TotalProjectCount)
	}

	// Case 4a: known CVE affecting zero of T's projects → 200 empty.
	zero := runCVEPaths(t, appDB, tenantT, cve("ZERO"))
	if zero == nil {
		t.Fatalf("known-but-unaffecting CVE %s must return non-nil (200 empty)", cve("ZERO"))
	}
	if zero.AffectedProjectCount != 0 || len(zero.AffectedProjects) != 0 {
		t.Errorf("zero-affected: count=%d len=%d, want 0/0", zero.AffectedProjectCount, len(zero.AffectedProjects))
	}

	// Case 4b: unknown CVE → nil (handler → 404).
	unknown := runCVEPaths(t, appDB, tenantT, fmt.Sprintf("CVE-2099-NOPE-%s", sfx))
	if unknown != nil {
		t.Errorf("unknown CVE must return nil (→404), got %+v", unknown)
	}
}

// TestCVEPaths_TenantGUCLoadBearing proves the tenant separation is
// load-bearing, not incidental: the SAME CVE, with the SAME component purl in
// BOTH tenants' projects, returns DISJOINT project sets depending solely on
// which tenant's GUC (app.current_tenant_id) the query runs under. Under a
// NOBYPASSRLS app role RLS is authoritative; the query's explicit tenant_id
// predicate is the defence-in-depth belt. If either boundary were absent, both
// queries would absorb the other tenant's project — this test would then see
// the foreign project leak.
func TestCVEPaths_TenantGUCLoadBearing(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyVS(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	var bypass bool
	_ = appDB.QueryRow(`SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass)
	t.Logf("app role bypasses RLS = %v (false → RLS authoritative; true → explicit tenant_id predicate is sole guard)", bypass)

	tenantT := seedTenantVS(t, migDB, "GUC-T")
	tenantF := seedTenantVS(t, migDB, "GUC-F")
	sfx := strings.ToUpper(uuid.New().String()[:8])
	cveID := fmt.Sprintf("CVE-2026-GUC-%s", sfx)
	vX := seedVulnVS(t, migDB, cveID)
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenantT, tenantF)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vX)
	})

	// Tenant T: projT with qs behind app-t.
	projT := uuid.New()
	seedProjectVS(t, migDB, tenantT, projT, "T-app")
	rawT := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "app-t", Version: "1.0.0", Purl: "pkg:generic/app-t@1.0.0"},
		[]cdxComp{{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:generic/qs@6.2.0"}},
		[]cdxDep{{Ref: "root", DependsOn: []string{"qs"}}},
	)
	sbomT := seedSbomRawCP(t, migDB, tenantT, projT, "cyclonedx", rawT)
	compT := seedComponentVS(t, migDB, tenantT, sbomT, "qs", "6.2.0", "pkg:generic/qs@6.2.0")
	linkCompVulnVS(t, migDB, compT, vX)

	// Tenant F: projF with the SAME qs purl behind app-f.
	projF := uuid.New()
	seedProjectVS(t, migDB, tenantF, projF, "F-app")
	rawF := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "app-f", Version: "1.0.0", Purl: "pkg:generic/app-f@1.0.0"},
		[]cdxComp{{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:generic/qs@6.2.0"}},
		[]cdxDep{{Ref: "root", DependsOn: []string{"qs"}}},
	)
	sbomF := seedSbomRawCP(t, migDB, tenantF, projF, "cyclonedx", rawF)
	compF := seedComponentVS(t, migDB, tenantF, sbomF, "qs", "6.2.0", "pkg:generic/qs@6.2.0")
	linkCompVulnVS(t, migDB, compF, vX)

	// Under T's GUC: only projT, its path is app-t → qs.
	underT := runCVEPaths(t, appDB, tenantT, cveID)
	if underT.AffectedProjectCount != 1 || underT.AffectedProjects[0].ProjectID != projT {
		t.Fatalf("under T GUC: want exactly projT, got %+v", underT.AffectedProjects)
	}
	if joinPathIDs(underT.AffectedProjects[0].AffectedComponents[0].Paths[0]) != "pkg:generic/app-t -> pkg:generic/qs" {
		t.Errorf("under T GUC path = %v, want [app-t -> qs]", underT.AffectedProjects[0].AffectedComponents[0].Paths)
	}
	for _, p := range underT.AffectedProjects {
		if p.ProjectID == projF {
			t.Fatalf("TENANT LEAK under T GUC: foreign projF surfaced")
		}
	}

	// Mutate the GUC to F: result CHANGES to only projF, its path app-f → qs.
	underF := runCVEPaths(t, appDB, tenantF, cveID)
	if underF.AffectedProjectCount != 1 || underF.AffectedProjects[0].ProjectID != projF {
		t.Fatalf("under F GUC: want exactly projF, got %+v", underF.AffectedProjects)
	}
	if joinPathIDs(underF.AffectedProjects[0].AffectedComponents[0].Paths[0]) != "pkg:generic/app-f -> pkg:generic/qs" {
		t.Errorf("under F GUC path = %v, want [app-f -> qs]", underF.AffectedProjects[0].AffectedComponents[0].Paths)
	}
	for _, p := range underF.AffectedProjects {
		if p.ProjectID == projT {
			t.Fatalf("TENANT LEAK under F GUC: T's projT surfaced")
		}
	}

	// The two GUCs produced DISJOINT project sets — the boundary is load-bearing.
	if underT.AffectedProjects[0].ProjectID == underF.AffectedProjects[0].ProjectID {
		t.Fatalf("GUC not load-bearing: both tenants resolved the same project")
	}
}
