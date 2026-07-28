//go:build integration

// Package repository — M47 W4: EPSS 0-sentinel eradication across the read
// paths that surface an exploitation probability to an operator.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M47W4_EPSSSentinel' ./internal/repository
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Prerequisites (skipped otherwise): same as
// m46_w4_cvss_sentinel_integration_test.go (postgres up, DATABASE_URL =
// sbomhub_app / MIGRATE_DATABASE_URL = sbomhub_migrator, schema migrated
// through 055 for the epss_* columns).
//
// What these tests pin down:
//
// vulnerabilities.epss_score is NULL when FIRST.org has no score for a CVE.
// That is the normal state before the scheduled epss_sync reaches a row
// (252 of 10,899 rows on the 2026-07-29 dev DB), and it is the state
// migration 059's tombstone deliberately RESTORES when a sync receives an
// unusable value. Every read path below used to COALESCE(epss_score, 0)
// into a bare float64, so "we have no idea how likely this is to be
// exploited" became indistinguishable from "FIRST predicts a ~0% chance".
//
// After W4 every path carries *float64 straight through: nil = no score,
// non-nil 0.0 = a real ~0% prediction. The distinction is not academic —
// epss_score is DECIMAL(5,4) and the writer rounds FIRST's 5dp input, so a
// published score below 0.00005 is stored as exactly 0.0000.
//
// SCOPE OF THESE TESTS. They drive the four REPOSITORY reads against a real
// Postgres and assert on the returned model structs: dashboard Top Risks
// (model.TopRisk, which the PDF/Excel reports also consume), SearchByCVE
// (model.CVESearchResult), GetVulnerabilityImpactMeta (model.CVEImpactMeta,
// the source of the impact/paths APIs and the web blast-radius badge) and
// getComponentVulnerabilities (model.Vulnerability).
//
// They stop at the model boundary. They do NOT exercise JSON serialisation,
// the TSX render sites, report PDF/Excel formatting, the scheduler's
// notification query, or the Slack/Discord/email renderers — those are
// covered separately by unit tests (service/report_cvss_test.go,
// service/notification_cvss_test.go and the inverted repository unit tests)
// and by the frontend's own typecheck/lint. What is pinned here is that the
// DB read itself no longer manufactures a 0.
//
// The EPSSScore assertions are written against `any` so this file compiles
// on both the pre-fix (bare float64) and post-fix (*float64) shapes; on the
// pre-fix shape the float64 branch fails the test with the sentinel
// diagnosis instead of a compile error.
package repository

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
)

// epssSentinelSeed builds one tenant with a project/sbom/component and three
// linked CVEs: no EPSS score at all, a real 0.0000 score, and a high score.
type epssSentinelSeed struct {
	tenant  uuid.UUID
	compID  uuid.UUID
	nullCVE string
	zeroCVE string
	highCVE string
}

func seedEPSSSentinel(t *testing.T, migDB *sql.DB, label string) epssSentinelSeed {
	t.Helper()

	tenant := seedIntegrationTenant(t, migDB, label)

	nullVulnID := uuid.New()
	zeroVulnID := uuid.New()
	highVulnID := uuid.New()
	registerCleanupExec(t, migDB, "m47w4 "+label+" vulnerabilities",
		`DELETE FROM vulnerabilities WHERE id IN ($1, $2, $3)`,
		nullVulnID, zeroVulnID, highVulnID)

	s := epssSentinelSeed{
		tenant:  tenant,
		nullCVE: "CVE-M47W4-NULL-" + tenant.String()[:8],
		zeroCVE: "CVE-M47W4-ZERO-" + tenant.String()[:8],
		highCVE: "CVE-M47W4-HIGH-" + tenant.String()[:8],
	}

	projectID := uuid.New()
	sbomID := uuid.New()
	s.compID = uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm47w4-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sboms (id, project_id, tenant_id, format) VALUES ($1, $2, $3, 'cyclonedx')
	`, sbomID, projectID, tenant); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version)
		VALUES ($1, $2, $3, 'm47w4-comp', '1.0.0')
	`, s.compID, tenant, sbomID); err != nil {
		t.Fatalf("seed component: %v", err)
	}

	// Un-scored CRITICAL: FIRST has no score. This is the row the sentinel
	// used to present as a ~0% exploitation probability.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, epss_score, epss_percentile)
		VALUES ($1, $2, 'm47w4 un-scored critical', 'CRITICAL', 9.8, NULL, NULL)
	`, nullVulnID, s.nullCVE); err != nil {
		t.Fatalf("seed NULL-epss vulnerability: %v", err)
	}
	// Real 0.0000: a FIRST score below 0.00005 rounded down by DECIMAL(5,4).
	// Must stay distinguishable from "no score".
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, epss_score, epss_percentile, epss_updated_at)
		VALUES ($1, $2, 'm47w4 real zero score', 'LOW', 3.1, 0.0, 0.0, NOW())
	`, zeroVulnID, s.zeroCVE); err != nil {
		t.Fatalf("seed 0.0-epss vulnerability: %v", err)
	}
	// Scored anchor for the ordering assertion.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, epss_score, epss_percentile, epss_updated_at)
		VALUES ($1, $2, 'm47w4 scored critical', 'CRITICAL', 7.5, 0.9123, 0.9876, NOW())
	`, highVulnID, s.highCVE); err != nil {
		t.Fatalf("seed 0.9123-epss vulnerability: %v", err)
	}

	for _, vulnID := range []uuid.UUID{nullVulnID, zeroVulnID, highVulnID} {
		if _, err := migDB.Exec(`
			INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
			VALUES ($1, $2, NOW())
		`, s.compID, vulnID); err != nil {
			t.Fatalf("seed component_vulnerabilities link: %v", err)
		}
	}
	return s
}

// assertEPSSUnscored fails if score is not the "no score" representation.
// Accepts `any` so the file compiles against the pre-fix bare-float64 shape,
// where it reports the sentinel diagnosis rather than failing to build.
func assertEPSSUnscored(t *testing.T, where string, score any) {
	t.Helper()
	switch v := score.(type) {
	case *float64:
		if v != nil {
			t.Errorf("%s: un-scored EPSS = %v, want nil (no score is NOT a ~0%% prediction)", where, *v)
		}
	case float64:
		t.Errorf("%s: EPSS is a bare float64 (%v): a CVE FIRST has never scored is reported as "+
			"a measured ~0%% exploitation probability", where, v)
	default:
		t.Errorf("%s: unexpected EPSS type %T", where, v)
	}
}

// assertEPSSRealZero fails unless score is a PRESENT 0.0 — the value a
// sentinel-based reader cannot distinguish from "unknown".
//
// The bare-float64 branch fails UNCONDITIONALLY. On that shape a 0 carries no
// information about whether a score is present, so it can never satisfy this
// assertion even when the underlying column really does hold 0.0 — accepting
// it would make the assertion vacuous on exactly the shape this wave removes.
// (Only reachable pre-fix; the field is *float64 post-fix.)
func assertEPSSRealZero(t *testing.T, where string, score any) {
	t.Helper()
	switch v := score.(type) {
	case *float64:
		if v == nil {
			t.Errorf("%s: real 0.0 EPSS = nil, want *0.0 (a rounded-to-zero FIRST score is a measurement)", where)
		} else if *v != 0 {
			t.Errorf("%s: real 0.0 EPSS = %v, want 0.0", where, *v)
		}
	case float64:
		t.Errorf("%s: EPSS is a bare float64 (%v): presence cannot be represented, so a real 0.0 "+
			"score is indistinguishable from an un-scored CVE", where, v)
	default:
		t.Errorf("%s: unexpected EPSS type %T", where, v)
	}
}

// TestM47W4_EPSSSentinel_TopRisks_UnscoredIsNilAndTailsOrder covers the
// dashboard Top Risks widget and, through model.TopRisk, the PDF and Excel
// reports that render the same rows.
func TestM47W4_EPSSSentinel_TopRisks_UnscoredIsNilAndTailsOrder(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	seed := seedEPSSSentinel(t, migDB, "m47w4-toprisks")
	dashRepo := NewDashboardRepository(appDB)

	readAsTenantTx(t, appDB, seed.tenant, func(ctx context.Context) {
		risks, err := dashRepo.GetTopRisksByTenant(ctx, seed.tenant, 10, "epss")
		if err != nil {
			t.Fatalf("GetTopRisksByTenant: %v", err)
		}
		if len(risks) != 3 {
			t.Fatalf("len(risks) = %d, want 3", len(risks))
		}

		byCVE := map[string]model.TopRisk{}
		for _, r := range risks {
			byCVE[r.CVEID] = r
		}

		nullRisk, ok := byCVE[seed.nullCVE]
		if !ok {
			t.Fatalf("un-scored CVE %s missing from Top Risks", seed.nullCVE)
		}
		assertEPSSUnscored(t, "TopRisks un-scored", any(nullRisk.EPSSScore))

		zeroRisk, ok := byCVE[seed.zeroCVE]
		if !ok {
			t.Fatalf("0.0-scored CVE %s missing from Top Risks", seed.zeroCVE)
		}
		assertEPSSRealZero(t, "TopRisks real 0.0", any(zeroRisk.EPSSScore))

		// Ordering (sort=epss): 0.9123 first, real 0.0 second, un-scored
		// LAST. topRisksOrderBy has carried `epss_score DESC NULLS LAST`
		// since M39, but it only starts doing anything now that NULLs
		// actually reach it — under the COALESCE the un-scored row tied
		// with the real 0.0 at 0 and the order between them was arbitrary.
		if risks[0].CVEID != seed.highCVE {
			t.Errorf("risks[0] = %s, want %s (0.9123 anchors the top)", risks[0].CVEID, seed.highCVE)
		}
		if risks[1].CVEID != seed.zeroCVE {
			t.Errorf("risks[1] = %s, want %s (real 0.0 outranks un-scored)", risks[1].CVEID, seed.zeroCVE)
		}
		if risks[2].CVEID != seed.nullCVE {
			t.Errorf("risks[2] = %s, want %s (un-scored tails via NULLS LAST)", risks[2].CVEID, seed.nullCVE)
		}
	})
}

// TestM47W4_EPSSSentinel_SearchByCVE_UnscoredIsNilNotZero covers the CVE
// search surface — the page an operator opens to triage one CVE.
func TestM47W4_EPSSSentinel_SearchByCVE_UnscoredIsNilNotZero(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	seed := seedEPSSSentinel(t, migDB, "m47w4-search")
	searchRepo := NewSearchRepository(appDB)

	readAsTenantTx(t, appDB, seed.tenant, func(ctx context.Context) {
		got, err := searchRepo.SearchByCVE(ctx, seed.nullCVE)
		if err != nil {
			t.Fatalf("SearchByCVE(un-scored): %v", err)
		}
		if got == nil {
			t.Fatalf("SearchByCVE(%s) = nil, want a result for a known CVE", seed.nullCVE)
		}
		assertEPSSUnscored(t, "SearchByCVE un-scored", any(got.EPSSScore))

		gotZero, err := searchRepo.SearchByCVE(ctx, seed.zeroCVE)
		if err != nil {
			t.Fatalf("SearchByCVE(real 0.0): %v", err)
		}
		if gotZero == nil {
			t.Fatalf("SearchByCVE(%s) = nil, want a result for a known CVE", seed.zeroCVE)
		}
		assertEPSSRealZero(t, "SearchByCVE real 0.0", any(gotZero.EPSSScore))
	})
}

// TestM47W4_EPSSSentinel_ImpactMeta_UnscoredIsNilNotZero covers the
// blast-radius (impact) and paths APIs, and through them the web
// blast-radius summary badge whose F391 suppress-on-0 rule this replaces.
func TestM47W4_EPSSSentinel_ImpactMeta_UnscoredIsNilNotZero(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	seed := seedEPSSSentinel(t, migDB, "m47w4-impact")
	searchRepo := NewSearchRepository(appDB)

	readAsTenantTx(t, appDB, seed.tenant, func(ctx context.Context) {
		meta, err := searchRepo.GetVulnerabilityImpactMeta(ctx, seed.nullCVE)
		if err != nil {
			t.Fatalf("GetVulnerabilityImpactMeta(un-scored): %v", err)
		}
		if meta == nil {
			t.Fatalf("GetVulnerabilityImpactMeta(%s) = nil, want meta for a known CVE", seed.nullCVE)
		}
		assertEPSSUnscored(t, "ImpactMeta un-scored", any(meta.EPSSScore))

		metaZero, err := searchRepo.GetVulnerabilityImpactMeta(ctx, seed.zeroCVE)
		if err != nil {
			t.Fatalf("GetVulnerabilityImpactMeta(real 0.0): %v", err)
		}
		if metaZero == nil {
			t.Fatalf("GetVulnerabilityImpactMeta(%s) = nil, want meta for a known CVE", seed.zeroCVE)
		}
		assertEPSSRealZero(t, "ImpactMeta real 0.0", any(metaZero.EPSSScore))
	})
}

// TestM47W4_EPSSSentinel_ComponentVulns_NullAndRealZeroAreDistinct covers the
// project vulnerability list. Its pre-fix form was COALESCE(...,0) plus a
// `> 0` guard, which is a different failure from the other paths: it mapped
// BOTH states to nil, so a CVE FIRST scores at ~0% was reported as un-scored
// and the real measurement was discarded.
func TestM47W4_EPSSSentinel_ComponentVulns_NullAndRealZeroAreDistinct(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	seed := seedEPSSSentinel(t, migDB, "m47w4-complist")
	searchRepo := NewSearchRepository(appDB)

	readAsTenantTx(t, appDB, seed.tenant, func(ctx context.Context) {
		vulns, err := searchRepo.getComponentVulnerabilities(ctx, seed.compID)
		if err != nil {
			t.Fatalf("getComponentVulnerabilities: %v", err)
		}
		if len(vulns) != 3 {
			t.Fatalf("len(vulns) = %d, want 3", len(vulns))
		}

		byCVE := map[string]model.Vulnerability{}
		for _, v := range vulns {
			byCVE[v.CVEID] = v
		}

		nullVuln, ok := byCVE[seed.nullCVE]
		if !ok {
			t.Fatalf("un-scored CVE %s missing from the component list", seed.nullCVE)
		}
		if nullVuln.EPSSScore != nil {
			t.Errorf("un-scored EPSSScore = %v, want nil", *nullVuln.EPSSScore)
		}
		if nullVuln.EPSSPercentile != nil {
			t.Errorf("un-scored EPSSPercentile = %v, want nil", *nullVuln.EPSSPercentile)
		}

		zeroVuln, ok := byCVE[seed.zeroCVE]
		if !ok {
			t.Fatalf("0.0-scored CVE %s missing from the component list", seed.zeroCVE)
		}
		if zeroVuln.EPSSScore == nil {
			t.Errorf("real 0.0 EPSSScore = nil, want *0.0 — the `> 0` guard discarded a real measurement")
		} else if *zeroVuln.EPSSScore != 0 {
			t.Errorf("real 0.0 EPSSScore = %v, want 0.0", *zeroVuln.EPSSScore)
		}
		if zeroVuln.EPSSPercentile == nil {
			t.Errorf("real 0.0 EPSSPercentile = nil, want *0.0")
		}
	})
}
