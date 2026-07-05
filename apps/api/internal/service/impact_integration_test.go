//go:build integration

// Package service — cross-project vulnerability impact (blast radius)
// integration test (M28-A / F388, issue #134).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestCVEImpact ./internal/service
//
// -count=1 is load-bearing: this test asserts against live DB rows +
// FORCE ROW LEVEL SECURITY behaviour, neither of which is an input to go's
// test cache. Re-running after re-seeding with an unchanged binary would
// otherwise return the previous cached verdict.
//
// Prerequisites (skipped otherwise — same env contract as the VEX suggestions
// integration test, whose seed helpers this file reuses):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through the canonical apps/api sequence (the api
//     server's auto-migrate covers this).
//
// What this test pins down (kickoff cases 1-5):
//
//  1. Blast radius across the SAME tenant's projects: a CVE affecting projects
//     A and B (but not C) yields affected_project_count == 2, the exact
//     affected components + component_count per project, and never lists the
//     unaffected project C.
//  2. Tenant isolation — a foreign tenant's project affected by the SAME CVE
//     (same purl) NEVER appears, and total_project_count counts only the
//     querying tenant's projects. Guarded twice: RLS (authoritative) + the
//     query's explicit tenant_id predicate (defence in depth). This is the
//     assertion the tenant-predicate mutation is expected to break.
//  3. A known CVE affecting zero of the tenant's projects returns a non-nil
//     result with count 0 and an empty list (200, not 404); an unknown CVE
//     returns nil (the handler answers 404).
//  4. severity / CVSS / KEV / EPSS rollup matches the vulnerability metadata.
//  5. total_project_count equals the tenant's project total, excluding the
//     foreign tenant's projects.
//
// The seed/env helpers (seedTenantVS, seedProjectVS, seedSbomVS,
// seedComponentVS, seedVulnVS, linkCompVulnVS, openOrSkipVS, schemaReadyVS,
// vexSuggestionsTestEnv) are defined in vex_suggestions_integration_test.go —
// same package, same build tag — and are reused verbatim here.
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

// setVulnKEVEPSS marks a seeded global vulnerability as KEV-listed. The
// vulnerabilities table is global (no RLS), so the migrator pool updates it
// directly. epss_score is intentionally left alone: this seed never syncs an
// EPSS score, so the row's epss_score stays NULL and the impact view's
// COALESCE(epss_score, 0) (M36-A / F432) surfaces EPSS as 0 (mirroring
// SearchByCVE / GetTopRisksByTenant) — see repository/impact.go.
func setVulnKEVEPSS(t *testing.T, migDB *sql.DB, vulnID uuid.UUID, inKEV bool) {
	t.Helper()
	if _, err := migDB.Exec(`UPDATE vulnerabilities SET in_kev = $1 WHERE id = $2`, inKEV, vulnID); err != nil {
		t.Fatalf("set kev on vuln %s: %v", vulnID, err)
	}
}

// runImpact drives the real ImpactService.GetCVEImpact for (tenant, cve)
// through an app-role tx that has SET LOCAL app.current_tenant_id, so RLS is
// active exactly as on a live request.
func runImpact(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, cveID string) *model.CVEImpact {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL %s: %v", tenantID, err)
	}
	svc := NewImpactService(repository.NewSearchRepository(appDB))
	ctx := database.WithTx(context.Background(), tx)
	got, err := svc.GetCVEImpact(ctx, tenantID, cveID)
	if err != nil {
		t.Fatalf("GetCVEImpact(%s): %v", cveID, err)
	}
	return got
}

func TestCVEImpact_BlastRadius(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	// Close via t.Cleanup (LIFO → runs AFTER the data-deletion cleanup below),
	// not defer, so the DELETEs don't fire against a closed pool.
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyVS(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "IMP-T")
	tenantF := seedTenantVS(t, migDB, "IMP-F")

	// Uppercase the hex suffix: GetCVEImpact normalises the input cve_id with
	// strings.ToUpper (correct for real CVE-YYYY-NNNNN ids), so the seeded
	// cve_id must already be uppercase to round-trip.
	sfx := strings.ToUpper(uuid.New().String()[:8])
	cve := func(n string) string { return fmt.Sprintf("CVE-2026-%s-%s", n, sfx) }
	vHit := seedVulnVS(t, migDB, cve("HIT"))   // affects A + B (and foreign F)
	vZero := seedVulnVS(t, migDB, cve("ZERO")) // known but affects nothing in T
	setVulnKEVEPSS(t, migDB, vHit, true)       // KEV-listed → in_kev rollup = true

	t.Cleanup(func() {
		// tenants CASCADE reaps projects → sboms → components →
		// component_vulnerabilities. Global vulnerabilities are not
		// tenant-scoped, so remove them explicitly.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenantT, tenantF)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id IN ($1,$2)`, vHit, vZero)
	})

	// --- Tenant T: project A (2 affected components), B (1), C (unaffected) ---
	projA := uuid.New()
	seedProjectVS(t, migDB, tenantT, projA, "app-a")
	sbomA := seedSbomVS(t, migDB, tenantT, projA)
	compA1 := seedComponentVS(t, migDB, tenantT, sbomA, "libx", "1.0", "pkg:generic/libx@1.0")
	compA2 := seedComponentVS(t, migDB, tenantT, sbomA, "liby", "2.0", "pkg:generic/liby@2.0")
	linkCompVulnVS(t, migDB, compA1, vHit)
	linkCompVulnVS(t, migDB, compA2, vHit)

	projB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projB, "app-b")
	sbomB := seedSbomVS(t, migDB, tenantT, projB)
	compB1 := seedComponentVS(t, migDB, tenantT, sbomB, "libx", "1.0", "pkg:generic/libx@1.0")
	linkCompVulnVS(t, migDB, compB1, vHit)

	projC := uuid.New() // affected by nothing
	seedProjectVS(t, migDB, tenantT, projC, "app-c")
	sbomC := seedSbomVS(t, migDB, tenantT, projC)
	_ = seedComponentVS(t, migDB, tenantT, sbomC, "libsafe", "9.9", "pkg:generic/libsafe@9.9")

	// --- Foreign tenant F: SAME CVE, SAME purl — strongest leak candidate ---
	projF := uuid.New()
	seedProjectVS(t, migDB, tenantF, projF, "foreign-app")
	sbomF := seedSbomVS(t, migDB, tenantF, projF)
	compF := seedComponentVS(t, migDB, tenantF, sbomF, "libx", "1.0", "pkg:generic/libx@1.0")
	linkCompVulnVS(t, migDB, compF, vHit)

	// ---- Case 1 + 2 + 4 + 5: blast radius for vHit, queried as tenant T ----
	got := runImpact(t, appDB, tenantT, cve("HIT"))
	if got == nil {
		t.Fatalf("expected a non-nil impact for known CVE %s", cve("HIT"))
	}

	// Case 4: metadata rollup matches the seeded vulnerability (seedVulnVS uses
	// severity=HIGH, cvss=7.5; setVulnKEVEPSS set in_kev=true; no EPSS is synced
	// for this seed row, so its epss_score stays NULL and COALESCEs to 0).
	if got.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", got.Severity)
	}
	if got.CVSSScore != 7.5 {
		t.Errorf("cvss_score = %v, want 7.5", got.CVSSScore)
	}
	if !got.InKEV {
		t.Errorf("in_kev = false, want true (KEV rollup)")
	}
	if got.EPSSScore != 0 {
		t.Errorf("epss_score = %v, want 0 (no EPSS synced for this seed row)", got.EPSSScore)
	}

	// Case 1: exactly A and B affected; C never appears.
	if got.AffectedProjectCount != 2 {
		t.Fatalf("affected_project_count = %d, want 2: %+v", got.AffectedProjectCount, got.AffectedProjects)
	}
	if len(got.AffectedProjects) != 2 {
		t.Fatalf("len(affected_projects) = %d, want 2", len(got.AffectedProjects))
	}

	// Case 2 (tenant isolation) — highest priority: the foreign project must
	// NOT appear.
	byID := map[uuid.UUID]model.ImpactProject{}
	for _, p := range got.AffectedProjects {
		if p.ProjectID == projF {
			t.Fatalf("TENANT LEAK: foreign tenant's project %s surfaced in tenant T's impact", projF)
		}
		if p.ProjectID == projC {
			t.Fatalf("unaffected project C %s surfaced in impact", projC)
		}
		byID[p.ProjectID] = p
	}

	// Case 1 detail: component_count per project.
	pa, okA := byID[projA]
	pb, okB := byID[projB]
	if !okA || !okB {
		t.Fatalf("expected both projA and projB in impact, got %+v", got.AffectedProjects)
	}
	if pa.ComponentCount != 2 || len(pa.AffectedComponents) != 2 {
		t.Errorf("projA component_count = %d (len %d), want 2", pa.ComponentCount, len(pa.AffectedComponents))
	}
	if pb.ComponentCount != 1 || len(pb.AffectedComponents) != 1 {
		t.Errorf("projB component_count = %d (len %d), want 1", pb.ComponentCount, len(pb.AffectedComponents))
	}
	// purl carried through on projB's single affected component.
	if pb.AffectedComponents[0].Purl != "pkg:generic/libx@1.0" {
		t.Errorf("projB component purl = %q, want pkg:generic/libx@1.0", pb.AffectedComponents[0].Purl)
	}

	// Case 5: total_project_count is tenant T's project total (A, B, C = 3),
	// excluding the foreign tenant's project.
	if got.TotalProjectCount != 3 {
		t.Fatalf("total_project_count = %d, want 3 (T has A,B,C; foreign F excluded)", got.TotalProjectCount)
	}

	// ---- Case 3a: known CVE affecting zero of T's projects → 200 empty ----
	zero := runImpact(t, appDB, tenantT, cve("ZERO"))
	if zero == nil {
		t.Fatalf("known-but-unaffecting CVE %s must return non-nil (200 empty), got nil (would be 404)", cve("ZERO"))
	}
	if zero.AffectedProjectCount != 0 || len(zero.AffectedProjects) != 0 {
		t.Errorf("zero-affected impact: count=%d len=%d, want 0/0", zero.AffectedProjectCount, len(zero.AffectedProjects))
	}
	if zero.TotalProjectCount != 3 {
		t.Errorf("zero-affected total_project_count = %d, want 3", zero.TotalProjectCount)
	}

	// ---- Case 3b: unknown CVE → nil (handler → 404) ----
	unknown := runImpact(t, appDB, tenantT, fmt.Sprintf("CVE-2099-NOPE-%s", sfx))
	if unknown != nil {
		t.Errorf("unknown CVE must return nil (→404), got %+v", unknown)
	}
}

// TestCVEImpact_TenantIsolation_BeltAndBraces is the focused tenant-boundary
// companion. It documents the two-layer guarantee: with a NOBYPASSRLS app role
// (the CI configuration) RLS is authoritative and the foreign rows are
// invisible; the query's explicit tenant_id predicate is the defence-in-depth
// belt that becomes load-bearing only if RLS is ever disabled. Removing that
// belt (the M28 mutation) under a BYPASSRLS role makes this test fail — both
// the affected list and total_project_count would then absorb the foreign
// tenant's project.
func TestCVEImpact_TenantIsolation_BeltAndBraces(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyVS(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	// Report whether the app role bypasses RLS so the run log makes the
	// guarantee under test explicit.
	var bypass bool
	_ = appDB.QueryRow(`SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass)
	t.Logf("app role bypasses RLS = %v (false → RLS authoritative; true → explicit tenant_id predicate is sole guard)", bypass)

	tenantT := seedTenantVS(t, migDB, "ISO-T")
	tenantF := seedTenantVS(t, migDB, "ISO-F")
	// Uppercase the hex suffix: GetCVEImpact normalises the input cve_id with
	// strings.ToUpper (correct for real CVE-YYYY-NNNNN ids), so the seeded
	// cve_id must already be uppercase to round-trip.
	sfx := strings.ToUpper(uuid.New().String()[:8])
	vX := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-ISO-%s", sfx))
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenantT, tenantF)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vX)
	})

	// Tenant T: one project affected by vX.
	projT := uuid.New()
	seedProjectVS(t, migDB, tenantT, projT, "T target")
	sbomT := seedSbomVS(t, migDB, tenantT, projT)
	compT := seedComponentVS(t, migDB, tenantT, sbomT, "libiso", "1.0", "pkg:generic/iso@1.0")
	linkCompVulnVS(t, migDB, compT, vX)

	// Foreign tenant F: SAME vX, SAME purl — would match if the boundary were
	// absent.
	projF := uuid.New()
	seedProjectVS(t, migDB, tenantF, projF, "F source")
	sbomF := seedSbomVS(t, migDB, tenantF, projF)
	compF := seedComponentVS(t, migDB, tenantF, sbomF, "libiso", "1.0", "pkg:generic/iso@1.0")
	linkCompVulnVS(t, migDB, compF, vX)

	got := runImpact(t, appDB, tenantT, fmt.Sprintf("CVE-2026-ISO-%s", sfx))
	if got == nil {
		t.Fatalf("expected non-nil impact for tenant T")
	}

	// Only tenant T's single project may appear.
	if got.AffectedProjectCount != 1 {
		t.Fatalf("tenant isolation violated: affected_project_count = %d, want 1: %+v", got.AffectedProjectCount, got.AffectedProjects)
	}
	for _, p := range got.AffectedProjects {
		if p.ProjectID == projF {
			t.Fatalf("TENANT LEAK: foreign project %s surfaced", projF)
		}
	}
	// total_project_count must count only tenant T's project (1), not F's.
	if got.TotalProjectCount != 1 {
		t.Fatalf("tenant isolation violated: total_project_count = %d, want 1 (foreign tenant's project excluded)", got.TotalProjectCount)
	}
}

// TestCVEImpact_MultiSnapshotDedup pins the F390 fix (M28-D): a project that has
// uploaded several SBOM snapshots, each carrying the SAME logical component
// (identical name/version/purl) affected by the CVE, must count that component
// ONCE — not once per snapshot. SBOMHub keeps every SBOM upload (SbomRepository
// .ListByProject returns them all), and the blast-radius aggregation spans all
// of a project's snapshots to stay consistent with SearchByCVE and the dashboard
// counters. Without the SELECT DISTINCT on the logical component identity in
// AggregateCVEImpact, the shared component's rows accumulate across snapshots and
// component_count inflates (R1 measured 2 for a 2-snapshot project). The project
// itself is already deduped by the per-project grouping, so
// affected_project_count stays 1 regardless.
//
// The removal of that DISTINCT is the F390 mutation: it makes this test fail
// (component_count becomes 3 instead of 2) and is reverted afterwards.
func TestCVEImpact_MultiSnapshotDedup(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyVS(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "SNAP-T")
	sfx := strings.ToUpper(uuid.New().String()[:8])
	cveID := fmt.Sprintf("CVE-2026-SNAP-%s", sfx)
	vID := seedVulnVS(t, migDB, cveID)
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantT)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vID)
	})

	// One project, TWO SBOM snapshots. The older and newer snapshot each carry
	// the SAME logical component (identical name/version/purl) linked to the CVE;
	// the newer snapshot additionally carries a DISTINCT second component. This
	// proves the DISTINCT dedups by logical identity (libshared → 1) rather than
	// blanket-collapsing every component to a single row (libextra survives too).
	projID := uuid.New()
	seedProjectVS(t, migDB, tenantT, projID, "snap-app")

	sbomOld := seedSbomVS(t, migDB, tenantT, projID)
	compOld := seedComponentVS(t, migDB, tenantT, sbomOld, "libshared", "1.0", "pkg:generic/libshared@1.0")
	linkCompVulnVS(t, migDB, compOld, vID)

	sbomNew := seedSbomVS(t, migDB, tenantT, projID)
	compNewSame := seedComponentVS(t, migDB, tenantT, sbomNew, "libshared", "1.0", "pkg:generic/libshared@1.0")
	linkCompVulnVS(t, migDB, compNewSame, vID)
	compNewOther := seedComponentVS(t, migDB, tenantT, sbomNew, "libextra", "2.0", "pkg:generic/libextra@2.0")
	linkCompVulnVS(t, migDB, compNewOther, vID)

	got := runImpact(t, appDB, tenantT, cveID)
	if got == nil {
		t.Fatalf("expected non-nil impact for %s", cveID)
	}

	// The project is deduped by grouping regardless of snapshot count.
	if got.AffectedProjectCount != 1 || len(got.AffectedProjects) != 1 {
		t.Fatalf("affected_project_count = %d (len %d), want 1", got.AffectedProjectCount, len(got.AffectedProjects))
	}
	p := got.AffectedProjects[0]

	// Two DISTINCT logical components: libshared (once, deduped across the two
	// snapshots) + libextra. A count of 3 means snapshot inflation (DISTINCT
	// dropped).
	if p.ComponentCount != 2 || len(p.AffectedComponents) != 2 {
		t.Fatalf("component_count = %d (len %d), want 2 (libshared deduped across 2 snapshots + libextra); >2 == snapshot inflation", p.ComponentCount, len(p.AffectedComponents))
	}

	// Exactly one libshared row survives the dedup.
	shared := 0
	for _, c := range p.AffectedComponents {
		if c.Name == "libshared" && c.Version == "1.0" && c.Purl == "pkg:generic/libshared@1.0" {
			shared++
		}
	}
	if shared != 1 {
		t.Errorf("libshared appeared %d times across snapshots, want exactly 1 (DISTINCT dedup)", shared)
	}
}

// TestCVEImpact_NullMetaCoalesced pins the F394 fix (M28-D R2b): a KNOWN CVE
// whose vulnerabilities row has a NULL severity and/or NULL cvss_score (both
// columns are nullable in 001_init, and real NVD rows do arrive with a missing
// CVSS) must NOT crash the impact lookup. Before the fix GetVulnerabilityImpactMeta
// scanned the SQL NULL straight into a Go string/float64, which errors and 500s
// — and never reaches the sql.ErrNoRows path, so it also breaks the "unknown CVE
// -> 404" vs "known CVE" distinction. After the COALESCE guard the metadata
// resolves to severity='UNKNOWN' (UPPERCASE, dashboard convention) and
// cvss_score=0, and the affected project still aggregates normally.
//
// The removal of the COALESCE is the F394 mutation: with it gone, runImpact's
// GetCVEImpact returns a scan error and t.Fatal fires (the 500 path), and it is
// reverted afterwards.
func TestCVEImpact_NullMetaCoalesced(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyVS(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "NULLMETA-T")
	sfx := strings.ToUpper(uuid.New().String()[:8])
	cveID := fmt.Sprintf("CVE-2026-NULLMETA-%s", sfx)

	// Insert a global vulnerability row with NULL severity AND NULL cvss_score
	// (vulnerabilities is RLS-exempt, so the migrator pool inserts directly).
	vNull := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		 VALUES ($1,$2,'null-meta vuln',NULL,NULL)`, vNull, cveID); err != nil {
		t.Fatalf("seed null-meta vuln: %v", err)
	}
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantT)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vNull)
	})

	// One project affected by the null-meta CVE.
	projID := uuid.New()
	seedProjectVS(t, migDB, tenantT, projID, "nullmeta-app")
	sbomID := seedSbomVS(t, migDB, tenantT, projID)
	compID := seedComponentVS(t, migDB, tenantT, sbomID, "libnull", "1.0", "pkg:generic/libnull@1.0")
	linkCompVulnVS(t, migDB, compID, vNull)

	// runImpact t.Fatals on a scan error, so simply reaching a non-nil result is
	// the "no 500" assertion the mutation breaks.
	got := runImpact(t, appDB, tenantT, cveID)
	if got == nil {
		t.Fatalf("expected non-nil impact for known null-meta CVE %s (must not 404)", cveID)
	}

	// COALESCE defaults surface gracefully instead of crashing.
	if got.Severity != "UNKNOWN" {
		t.Errorf("severity = %q, want UNKNOWN (COALESCE default)", got.Severity)
	}
	if got.CVSSScore != 0 {
		t.Errorf("cvss_score = %v, want 0 (COALESCE default)", got.CVSSScore)
	}
	// The affected project still aggregates normally despite the null metadata.
	if got.AffectedProjectCount != 1 || len(got.AffectedProjects) != 1 {
		t.Fatalf("affected_project_count = %d (len %d), want 1", got.AffectedProjectCount, len(got.AffectedProjects))
	}
}
