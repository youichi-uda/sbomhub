//go:build integration

// Package service — cross-project VEX apply integration test
// (M27-A / F381, issue #132).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestVEXApply ./internal/service
//
// -count=1 is load-bearing: this test asserts against live DB rows +
// FORCE ROW LEVEL SECURITY behaviour, neither of which is an input to
// go's test cache. Re-running after re-seeding with an unchanged binary
// would otherwise return the previous cached verdict.
//
// Prerequisites (skipped otherwise) — identical to the M26 aggregation
// integration test, plus migration 052 (vex_statement_provenance):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 052 — the api server's auto-migrate covers this.
//
// It reuses the seed / RLS helpers from vex_suggestions_integration_test.go
// (same package + build tag): vexSuggestionsTestEnv, openOrSkipVS,
// schemaReadyVS, seedTenantVS, seedProjectVS, seedSbomVS, seedComponentVS,
// seedVulnVS, linkCompVulnVS, seedVexStmtVS, withTenantTxVS.
//
// What this test pins down:
//
//  1. A purl-match apply materialises a target vex_statements row +
//     a vex_statement_provenance row with truthful source attribution.
//  2. A foreign-tenant source_statement_id is rejected (tenant isolation:
//     RLS authoritative + explicit tenant_id predicate).
//  3. Match re-verification (injection guard): a source whose vulnerability
//     or purl does not match the target is rejected — an attacker cannot
//     inject an arbitrary status onto an arbitrary component.
//  4. Applying onto a (project, vuln, component) the target already triaged
//     returns ErrVEXApplyAlreadyTriaged (the handler maps it to 409).
package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// schemaReadyApply extends schemaReadyVS with the provenance table +
// its FORCE RLS state (migration 052).
func schemaReadyApply(t *testing.T, db *sql.DB) bool {
	t.Helper()
	if !schemaReadyVS(t, db) {
		return false
	}
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.tables
			WHERE table_schema='public' AND table_name='vex_statement_provenance')`).Scan(&exists); err != nil {
		t.Skipf("existence check for vex_statement_provenance failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("table vex_statement_provenance not present -- run migration 052 first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.vex_statement_provenance'::regclass`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("vex_statement_provenance RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("vex_statement_provenance RLS not ENABLE+FORCE (enabled=%v force=%v) -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

// applySuggestionVS runs the real VEXService.ApplySuggestion for (tenant,
// project) through an app-role tx that has SET LOCAL app.current_tenant_id,
// so RLS is active exactly as on a live request. inspect is invoked with the
// SAME tx still open so the test can read the just-written rows; the tx is
// then rolled back (nothing persists → cleanup is only the seeded tenant +
// global vulnerabilities).
func applySuggestionVS(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, in ApplySuggestionInput, inspect func(tx *sql.Tx, res *VEXApplyResult, err error)) {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("applySuggestionVS begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("applySuggestionVS SET LOCAL: %v", err)
	}
	svc := NewVEXService(repository.NewVEXRepository(appDB), repository.NewVulnerabilityRepository(appDB))
	ctx := database.WithTx(context.Background(), tx)
	res, applyErr := svc.ApplySuggestion(ctx, in)
	inspect(tx, res, applyErr)
}

// TestVEXApply_PurlMatch_CreatesStatementAndProvenance pins case 1.
func TestVEXApply_PurlMatch_CreatesStatementAndProvenance(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyApply(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "AP")
	sfx := uuid.New().String()[:8]
	v1 := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-AP1-%s", sfx))
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantT)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, v1)
	})

	// Source project A: component-specific approved statement on a shared purl.
	projA := uuid.New()
	seedProjectVS(t, migDB, tenantT, projA, "Apply A")
	sbomA := seedSbomVS(t, migDB, tenantT, projA)
	compA := seedComponentVS(t, migDB, tenantT, sbomA, "libshared", "1.0", "pkg:generic/shared@1.0")
	linkCompVulnVS(t, migDB, compA, v1)
	source := seedVexStmtVS(t, migDB, tenantT, projA, v1, &compA, "not_affected")

	// Target project B: component with the SAME purl, affected by v1.
	projB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projB, "Apply B")
	sbomB := seedSbomVS(t, migDB, tenantT, projB)
	compB := seedComponentVS(t, migDB, tenantT, sbomB, "libshared", "1.0", "pkg:generic/shared@1.0")
	linkCompVulnVS(t, migDB, compB, v1)

	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: source,
		TargetComponentID: compB,
		VulnerabilityID:   v1,
		CreatedBy:         "tester",
	}, func(tx *sql.Tx, res *VEXApplyResult, err error) {
		if err != nil {
			t.Fatalf("ApplySuggestion failed: %v", err)
		}
		if res.MatchType != model.VEXMatchTypePurl {
			t.Errorf("match_type = %q, want %q", res.MatchType, model.VEXMatchTypePurl)
		}
		st := res.Statement
		if st == nil {
			t.Fatal("nil statement")
		}
		if st.ProjectID != projB || st.VulnerabilityID != v1 || st.ComponentID == nil || *st.ComponentID != compB {
			t.Errorf("target statement mis-shaped: %+v", st)
		}
		if string(st.Status) != "not_affected" {
			t.Errorf("copied status = %q, want not_affected", st.Status)
		}
		if st.TenantID != tenantT {
			t.Errorf("target statement tenant = %s, want %s", st.TenantID, tenantT)
		}

		// Provenance row: truthful source attribution, same tenant.
		var srcStmt, srcProj, tgtStmt, ten uuid.UUID
		if err := tx.QueryRow(`
			SELECT source_statement_id, source_project_id, target_statement_id, tenant_id
			FROM vex_statement_provenance WHERE target_statement_id = $1`, st.ID).
			Scan(&srcStmt, &srcProj, &tgtStmt, &ten); err != nil {
			t.Fatalf("provenance row not found for target %s: %v", st.ID, err)
		}
		if srcStmt != source {
			t.Errorf("provenance source_statement_id = %s, want %s", srcStmt, source)
		}
		if srcProj != projA {
			t.Errorf("provenance source_project_id = %s, want source project A %s", srcProj, projA)
		}
		if tgtStmt != st.ID {
			t.Errorf("provenance target_statement_id = %s, want %s", tgtStmt, st.ID)
		}
		if ten != tenantT {
			t.Errorf("provenance tenant_id = %s, want %s", ten, tenantT)
		}
	})
}

// TestVEXApply_ForeignTenantSource_Rejected pins case 2: a source statement
// belonging to another tenant is not resolvable, so apply is rejected with
// ErrVEXApplySourceNotFound (RLS authoritative + explicit tenant predicate).
func TestVEXApply_ForeignTenantSource_Rejected(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyApply(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "APT")
	tenantF := seedTenantVS(t, migDB, "APF")
	sfx := uuid.New().String()[:8]
	v1 := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-APX-%s", sfx))
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenantT, tenantF)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, v1)
	})

	// Foreign tenant F owns the source statement (same purl / vuln — the
	// strongest possible leak candidate).
	projF := uuid.New()
	seedProjectVS(t, migDB, tenantF, projF, "Apply F src")
	sbomF := seedSbomVS(t, migDB, tenantF, projF)
	compF := seedComponentVS(t, migDB, tenantF, sbomF, "libiso", "1.0", "pkg:generic/iso@1.0")
	linkCompVulnVS(t, migDB, compF, v1)
	foreignSource := seedVexStmtVS(t, migDB, tenantF, projF, v1, &compF, "not_affected")

	// Target project in tenant T with the same purl.
	projB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projB, "Apply T tgt")
	sbomB := seedSbomVS(t, migDB, tenantT, projB)
	compB := seedComponentVS(t, migDB, tenantT, sbomB, "libiso", "1.0", "pkg:generic/iso@1.0")
	linkCompVulnVS(t, migDB, compB, v1)

	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: foreignSource, // belongs to tenant F
		TargetComponentID: compB,
		VulnerabilityID:   v1,
		CreatedBy:         "tester",
	}, func(tx *sql.Tx, res *VEXApplyResult, err error) {
		if !errors.Is(err, ErrVEXApplySourceNotFound) {
			t.Fatalf("cross-tenant apply must reject with ErrVEXApplySourceNotFound, got err=%v res=%+v", err, res)
		}
		// And nothing was written.
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM vex_statement_provenance WHERE source_statement_id = $1`, foreignSource).Scan(&n); err != nil {
			t.Fatalf("count provenance: %v", err)
		}
		if n != 0 {
			t.Errorf("cross-tenant apply wrote %d provenance rows, want 0", n)
		}
	})
}

// TestVEXApply_MatchReverification_Injection pins case 3: the injection
// guard. Two shapes must both reject with ErrVEXApplyMatchFailed —
//   - purl mismatch: a component-specific source for coordinate P1 cannot be
//     applied onto a target component with a DIFFERENT coordinate P2 (even
//     when both are affected by the same vuln);
//   - vulnerability mismatch: a source for vuln v1 cannot be applied under a
//     claimed vulnerability_id v2.
func TestVEXApply_MatchReverification_Injection(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyApply(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "APM")
	sfx := uuid.New().String()[:8]
	v1 := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-APM1-%s", sfx))
	v2 := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-APM2-%s", sfx))
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantT)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id IN ($1,$2)`, v1, v2)
	})

	// Source project A: component-specific statement for coordinate P1 on v1.
	projA := uuid.New()
	seedProjectVS(t, migDB, tenantT, projA, "APM A")
	sbomA := seedSbomVS(t, migDB, tenantT, projA)
	compA := seedComponentVS(t, migDB, tenantT, sbomA, "libp1", "1.0", "pkg:generic/p1@1.0")
	linkCompVulnVS(t, migDB, compA, v1)
	source := seedVexStmtVS(t, migDB, tenantT, projA, v1, &compA, "not_affected")

	// Target project B: a DIFFERENT coordinate P2, affected by BOTH v1 and v2.
	projB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projB, "APM B")
	sbomB := seedSbomVS(t, migDB, tenantT, projB)
	compB := seedComponentVS(t, migDB, tenantT, sbomB, "libp2", "1.0", "pkg:generic/p2@1.0")
	linkCompVulnVS(t, migDB, compB, v1)
	linkCompVulnVS(t, migDB, compB, v2)

	// (a) purl mismatch: source coordinate P1 injected onto target P2.
	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: source,
		TargetComponentID: compB, // purl P2 != source purl P1
		VulnerabilityID:   v1,
		CreatedBy:         "tester",
	}, func(_ *sql.Tx, res *VEXApplyResult, err error) {
		if !errors.Is(err, ErrVEXApplyMatchFailed) {
			t.Fatalf("purl-mismatch injection must reject with ErrVEXApplyMatchFailed, got err=%v res=%+v", err, res)
		}
	})

	// (b) vulnerability mismatch: source is for v1, claimed vuln is v2.
	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: source,
		TargetComponentID: compB,
		VulnerabilityID:   v2, // source.vulnerability_id is v1
		CreatedBy:         "tester",
	}, func(_ *sql.Tx, res *VEXApplyResult, err error) {
		if !errors.Is(err, ErrVEXApplyMatchFailed) {
			t.Fatalf("vuln-mismatch injection must reject with ErrVEXApplyMatchFailed, got err=%v res=%+v", err, res)
		}
	})
}

// TestVEXApply_ExistingTarget_409 pins case 4: applying onto a
// (project, vuln, component) the target already triaged returns
// ErrVEXApplyAlreadyTriaged (handler maps to 409, never overwrites).
func TestVEXApply_ExistingTarget_409(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyApply(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "APC")
	sfx := uuid.New().String()[:8]
	v1 := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-APC1-%s", sfx))
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantT)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, v1)
	})

	projA := uuid.New()
	seedProjectVS(t, migDB, tenantT, projA, "APC A")
	sbomA := seedSbomVS(t, migDB, tenantT, projA)
	compA := seedComponentVS(t, migDB, tenantT, sbomA, "libshared", "1.0", "pkg:generic/shared@1.0")
	linkCompVulnVS(t, migDB, compA, v1)
	source := seedVexStmtVS(t, migDB, tenantT, projA, v1, &compA, "not_affected")

	projB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projB, "APC B")
	sbomB := seedSbomVS(t, migDB, tenantT, projB)
	compB := seedComponentVS(t, migDB, tenantT, sbomB, "libshared", "1.0", "pkg:generic/shared@1.0")
	linkCompVulnVS(t, migDB, compB, v1)
	// B already triaged (v1, compB).
	seedVexStmtVS(t, migDB, tenantT, projB, v1, &compB, "affected")

	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: source,
		TargetComponentID: compB,
		VulnerabilityID:   v1,
		CreatedBy:         "tester",
	}, func(_ *sql.Tx, res *VEXApplyResult, err error) {
		if !errors.Is(err, ErrVEXApplyAlreadyTriaged) {
			t.Fatalf("apply onto already-triaged (project, vuln, component) must reject with ErrVEXApplyAlreadyTriaged, got err=%v res=%+v", err, res)
		}
	})
}

// TestVEXApply_TargetNotLinkedToVuln_Rejected pins the F383 injection variant
// (issue #132/#133): the target component must be AFFECTED by the vulnerability
// — linked via component_vulnerabilities in the target project — exactly as the
// M26 aggregation's `ta` subquery requires. A crafted apply request that pairs
// a real, tenant-visible source statement with a target component the
// vulnerability does NOT touch (one GetSuggestions would never surface) must be
// rejected with ErrVEXApplyMatchFailed for BOTH match branches:
//
//   - (a) vulnerability_only: a component-agnostic source applied onto a target
//     component that is not linked to the vuln;
//   - (b) purl: a component-specific source whose purl EQUALS the target's, but
//     the target component is not linked to the vuln.
//
// Without the linkage re-check both would apply (the purl / vuln / ownership
// predicates all pass), forging a verdict onto a non-affected component. A
// third sub-case pins that the SAME shapes DO succeed once the target is
// linked — proving the guard is a linkage gate, not an unconditional reject.
func TestVEXApply_TargetNotLinkedToVuln_Rejected(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyApply(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "APL")
	sfx := uuid.New().String()[:8]
	vAgn := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-APL-AGN-%s", sfx))
	vPurl := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-APL-PURL-%s", sfx))
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantT)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id IN ($1,$2)`, vAgn, vPurl)
	})

	// Source project A.
	projA := uuid.New()
	seedProjectVS(t, migDB, tenantT, projA, "APL A")
	sbomA := seedSbomVS(t, migDB, tenantT, projA)
	// (a) component-agnostic (NULL) approved statement for vAgn.
	sourceAgn := seedVexStmtVS(t, migDB, tenantT, projA, vAgn, nil, "not_affected")
	// (b) component-specific approved statement for vPurl on a shared purl.
	compA := seedComponentVS(t, migDB, tenantT, sbomA, "libshared", "1.0", "pkg:generic/aplshared@1.0")
	linkCompVulnVS(t, migDB, compA, vPurl)
	sourcePurl := seedVexStmtVS(t, migDB, tenantT, projA, vPurl, &compA, "not_affected")

	// Target project B. compB shares compA's purl but is NOT linked to either
	// vuln (no component_vulnerabilities rows) — the vulnerability does not
	// actually affect it, so no suggestion could ever surface for it.
	projB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projB, "APL B")
	sbomB := seedSbomVS(t, migDB, tenantT, projB)
	compB := seedComponentVS(t, migDB, tenantT, sbomB, "libshared", "1.0", "pkg:generic/aplshared@1.0")

	// (a) vulnerability_only injection: target not linked to vAgn → reject.
	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: sourceAgn,
		TargetComponentID: compB,
		VulnerabilityID:   vAgn,
		CreatedBy:         "tester",
	}, func(tx *sql.Tx, res *VEXApplyResult, err error) {
		if !errors.Is(err, ErrVEXApplyMatchFailed) {
			t.Fatalf("(a) vulnerability_only apply onto non-affected component must reject with ErrVEXApplyMatchFailed, got err=%v res=%+v", err, res)
		}
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM vex_statements WHERE project_id = $1 AND vulnerability_id = $2`, projB, vAgn).Scan(&n); err != nil {
			t.Fatalf("count target statements: %v", err)
		}
		if n != 0 {
			t.Errorf("(a) rejected apply still wrote %d target statement rows, want 0", n)
		}
	})

	// (b) purl injection: target purl matches source, but target not linked to
	// vPurl → reject (the linkage gate, not the purl check, is what rejects).
	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: sourcePurl,
		TargetComponentID: compB,
		VulnerabilityID:   vPurl,
		CreatedBy:         "tester",
	}, func(_ *sql.Tx, res *VEXApplyResult, err error) {
		if !errors.Is(err, ErrVEXApplyMatchFailed) {
			t.Fatalf("(b) purl apply onto non-affected component must reject with ErrVEXApplyMatchFailed, got err=%v res=%+v", err, res)
		}
	})

	// (c) control: link compB to vPurl and the SAME purl apply now succeeds —
	// proving the guard gates on linkage, not an unconditional reject.
	linkCompVulnVS(t, migDB, compB, vPurl)
	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: sourcePurl,
		TargetComponentID: compB,
		VulnerabilityID:   vPurl,
		CreatedBy:         "tester",
	}, func(_ *sql.Tx, res *VEXApplyResult, err error) {
		if err != nil {
			t.Fatalf("(c) linked purl apply must succeed once component_vulnerabilities links the target, got err=%v", err)
		}
		if res == nil || res.MatchType != model.VEXMatchTypePurl {
			t.Errorf("(c) linked purl apply match_type = %v, want %q", res, model.VEXMatchTypePurl)
		}
	})
}

// TestVEXApply_ProjectWideExisting_409 pins F386 (issue #132/#133): apply
// idempotency must mirror the M26 aggregation's already-triaged exclusion,
// which is a SUPERSET of an exact-component match — a project-wide
// (component_id IS NULL) statement for the vulnerability ALSO suppresses the
// suggestion. So applying a component-specific reuse onto a target that
// already holds a project-wide decision for the same vulnerability must
// return ErrVEXApplyAlreadyTriaged (409), NOT create a second, overlapping
// component-specific row (which GetSuggestions would never have offered).
//
// Interaction with the F383 linkage check: the target component IS linked to
// the vulnerability here (so verifySuggestionMatch passes and we actually
// reach the idempotency step), and the project-wide vex_statement is
// orthogonal to component_vulnerabilities linkage — the two guards are
// independent, so this exercises the 409 path cleanly rather than colliding
// with the 400 linkage reject.
func TestVEXApply_ProjectWideExisting_409(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyApply(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "APW")
	sfx := uuid.New().String()[:8]
	v1 := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-APW1-%s", sfx))
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantT)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, v1)
	})

	// Source project A: component-specific approved statement on a shared purl.
	projA := uuid.New()
	seedProjectVS(t, migDB, tenantT, projA, "APW A")
	sbomA := seedSbomVS(t, migDB, tenantT, projA)
	compA := seedComponentVS(t, migDB, tenantT, sbomA, "libshared", "1.0", "pkg:generic/apwshared@1.0")
	linkCompVulnVS(t, migDB, compA, v1)
	source := seedVexStmtVS(t, migDB, tenantT, projA, v1, &compA, "not_affected")

	// Target project B: compB shares the purl AND is linked to v1 (so the F383
	// linkage + purl match both pass), but B has already made a PROJECT-WIDE
	// (component_id NULL) decision on v1 — the exact-component check would miss
	// it, so this is the F386 regression.
	projB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projB, "APW B")
	sbomB := seedSbomVS(t, migDB, tenantT, projB)
	compB := seedComponentVS(t, migDB, tenantT, sbomB, "libshared", "1.0", "pkg:generic/apwshared@1.0")
	linkCompVulnVS(t, migDB, compB, v1)
	seedVexStmtVS(t, migDB, tenantT, projB, v1, nil, "affected") // project-wide (NULL component)

	applySuggestionVS(t, appDB, tenantT, ApplySuggestionInput{
		TenantID:          tenantT,
		ProjectID:         projB,
		SourceStatementID: source,
		TargetComponentID: compB,
		VulnerabilityID:   v1,
		CreatedBy:         "tester",
	}, func(tx *sql.Tx, res *VEXApplyResult, err error) {
		if !errors.Is(err, ErrVEXApplyAlreadyTriaged) {
			t.Fatalf("apply onto a target with a project-wide (component_id NULL) decision must reject with ErrVEXApplyAlreadyTriaged, got err=%v res=%+v", err, res)
		}
		// No new component-specific row for (projB, v1, compB) was created.
		var nStmt int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM vex_statements WHERE project_id = $1 AND vulnerability_id = $2 AND component_id = $3`, projB, v1, compB).Scan(&nStmt); err != nil {
			t.Fatalf("count component-specific target statements: %v", err)
		}
		if nStmt != 0 {
			t.Errorf("409-rejected apply created %d overlapping component-specific rows, want 0", nStmt)
		}
		// And no provenance row was written.
		var nProv int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM vex_statement_provenance WHERE source_statement_id = $1`, source).Scan(&nProv); err != nil {
			t.Fatalf("count provenance: %v", err)
		}
		if nProv != 0 {
			t.Errorf("409-rejected apply wrote %d provenance rows, want 0", nProv)
		}
	})
}
