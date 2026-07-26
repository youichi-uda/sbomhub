//go:build integration

// Package repository — M46 Track A wave 4: CVSS 0-sentinel eradication on
// the dashboard Top Risks and impact (blast-radius) read paths.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M46W4_CVSSSentinel' ./internal/repository
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Prerequisites (skipped otherwise): same as
// vulnerability_null_scan_integration_test.go (postgres up, DATABASE_URL =
// sbomhub_app / MIGRATE_DATABASE_URL = sbomhub_migrator, schema migrated).
//
// What these tests pin down (Codex round B-1 Medium 1 & 2):
//
// vulnerabilities.cvss_score is NULL for un-scored rows (NVD "Awaiting
// Analysis"), and CVSS 0.0 is a REAL score ("None"). The Top Risks query
// (dashboard / PDF / Excel report) and GetVulnerabilityImpactMeta (impact +
// paths APIs) used to COALESCE(cvss_score, 0) into a bare float64, so an
// un-scored CRITICAL rendered as "CVSS 0.0" — presented as harmless. After
// wave 4 both paths carry *float64 straight through: nil = un-scored,
// 0.0 = the real "None" score, and the two are distinguishable end to end
// (same contract as model.Vulnerability, f97c7fa).
//
// The CVSSScore assertions are written against `any` so this file compiles
// on both the pre-fix (bare float64) and post-fix (*float64) shapes; on the
// pre-fix shape the float64 branch fails the test with the sentinel
// diagnosis instead of a compile error.
package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestM46W4_CVSSSentinel_TopRisks_UnscoredIsNilAndTailsOrder(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "m46w4-toprisks")

	nullVulnID := uuid.New()
	zeroVulnID := uuid.New()
	highVulnID := uuid.New()
	registerCleanupExec(t, migDB, "m46w4 toprisks vulnerabilities",
		`DELETE FROM vulnerabilities WHERE id IN ($1, $2, $3)`,
		nullVulnID, zeroVulnID, highVulnID)

	nullCVE := "CVE-M46W4-NULL-" + tenant.String()[:8]
	zeroCVE := "CVE-M46W4-ZERO-" + tenant.String()[:8]
	highCVE := "CVE-M46W4-HIGH-" + tenant.String()[:8]

	projectID := uuid.New()
	sbomID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46w4-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sboms (id, project_id, tenant_id, format) VALUES ($1, $2, $3, 'cyclonedx')
	`, sbomID, projectID, tenant); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}

	compID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version)
		VALUES ($1, $2, $3, 'm46w4-comp', '1.0.0')
	`, compID, tenant, sbomID); err != nil {
		t.Fatalf("seed component: %v", err)
	}

	// Un-scored CRITICAL: the NVD "Awaiting Analysis" shape the sentinel
	// used to disguise as a harmless 0.0.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'm46w4 un-scored critical', 'CRITICAL', NULL)
	`, nullVulnID, nullCVE); err != nil {
		t.Fatalf("seed NULL-cvss vulnerability: %v", err)
	}
	// Real 0.0 ("None") score — must stay distinguishable from un-scored.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'm46w4 real none score', 'LOW', 0.0)
	`, zeroVulnID, zeroCVE); err != nil {
		t.Fatalf("seed 0.0-cvss vulnerability: %v", err)
	}
	// Scored anchor for the ordering assertion.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'm46w4 scored critical', 'CRITICAL', 9.8)
	`, highVulnID, highCVE); err != nil {
		t.Fatalf("seed 9.8-cvss vulnerability: %v", err)
	}
	for _, vulnID := range []uuid.UUID{nullVulnID, zeroVulnID, highVulnID} {
		if _, err := migDB.Exec(`
			INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
			VALUES ($1, $2, NOW())
		`, compID, vulnID); err != nil {
			t.Fatalf("seed component_vulnerabilities link: %v", err)
		}
	}

	dashRepo := NewDashboardRepository(appDB)

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		risks, err := dashRepo.GetTopRisksByTenant(ctx, tenant, 10, "cvss")
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

		// Un-scored row: nil, NOT 0.0 (the wave-4 flip).
		nullRisk, ok := byCVE[nullCVE]
		if !ok {
			t.Fatalf("un-scored CVE %s missing from Top Risks", nullCVE)
		}
		switch v := any(nullRisk.CVSSScore).(type) {
		case *float64:
			if v != nil {
				t.Errorf("un-scored CVE CVSSScore = %v, want nil (un-scored is NOT 0.0)", *v)
			}
		case float64:
			t.Errorf("TopRisk.CVSSScore is a bare float64 (%v): un-scored reads as a 0.0 sentinel "+
				"and an un-triaged CRITICAL renders as harmless", v)
		default:
			t.Errorf("unexpected CVSSScore type %T", v)
		}

		// Real 0.0 row: present AND non-nil — nil vs 0.0 must stay distinct.
		zeroRisk, ok := byCVE[zeroCVE]
		if !ok {
			t.Fatalf("0.0-scored CVE %s missing from Top Risks", zeroCVE)
		}
		switch v := any(zeroRisk.CVSSScore).(type) {
		case *float64:
			if v == nil {
				t.Errorf("real 0.0-scored CVE CVSSScore = nil, want *0.0 (0.0 is a real 'None' score)")
			} else if *v != 0 {
				t.Errorf("real 0.0-scored CVE CVSSScore = %v, want 0.0", *v)
			}
		case float64:
			if v != 0 {
				t.Errorf("real 0.0-scored CVE CVSSScore = %v, want 0.0", v)
			}
		}

		// Ordering (sort=cvss): scored 9.8 first, real 0.0 second, un-scored
		// LAST (ORDER BY cvss_score DESC NULLS LAST — Postgres' DESC default
		// NULLS FIRST would float the un-scored row above the CRITICAL).
		if risks[0].CVEID != highCVE {
			t.Errorf("risks[0] = %s, want %s (9.8 anchors the top)", risks[0].CVEID, highCVE)
		}
		if risks[1].CVEID != zeroCVE {
			t.Errorf("risks[1] = %s, want %s (real 0.0 outranks un-scored)", risks[1].CVEID, zeroCVE)
		}
		if risks[2].CVEID != nullCVE {
			t.Errorf("risks[2] = %s, want %s (un-scored tails via NULLS LAST)", risks[2].CVEID, nullCVE)
		}
	})
}

func TestM46W4_CVSSSentinel_ImpactMeta_UnscoredIsNilNotZero(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "m46w4-impact")

	nullVulnID := uuid.New()
	zeroVulnID := uuid.New()
	registerCleanupExec(t, migDB, "m46w4 impact vulnerabilities",
		`DELETE FROM vulnerabilities WHERE id IN ($1, $2)`, nullVulnID, zeroVulnID)

	nullCVE := "CVE-M46W4-IMP-NULL-" + tenant.String()[:8]
	zeroCVE := "CVE-M46W4-IMP-ZERO-" + tenant.String()[:8]

	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'm46w4 impact un-scored', 'CRITICAL', NULL)
	`, nullVulnID, nullCVE); err != nil {
		t.Fatalf("seed NULL-cvss vulnerability: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'm46w4 impact real none', 'LOW', 0.0)
	`, zeroVulnID, zeroCVE); err != nil {
		t.Fatalf("seed 0.0-cvss vulnerability: %v", err)
	}

	searchRepo := NewSearchRepository(appDB)

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		// Un-scored CVE: meta resolves (known CVE, no 404) with nil CVSS.
		meta, err := searchRepo.GetVulnerabilityImpactMeta(ctx, nullCVE)
		if err != nil {
			t.Fatalf("GetVulnerabilityImpactMeta(%s): %v", nullCVE, err)
		}
		if meta == nil {
			t.Fatalf("meta for known un-scored CVE %s is nil (must not 404)", nullCVE)
		}
		switch v := any(meta.CVSSScore).(type) {
		case *float64:
			if v != nil {
				t.Errorf("un-scored CVE CVSSScore = %v, want nil (un-scored is NOT 0.0)", *v)
			}
		case float64:
			t.Errorf("CVEImpactMeta.CVSSScore is a bare float64 (%v): the impact/paths APIs "+
				"present an un-scored CVE as CVSS 0.0", v)
		default:
			t.Errorf("unexpected CVSSScore type %T", v)
		}

		// Real 0.0-scored CVE: non-nil *0.0 — distinguishable from un-scored.
		meta0, err := searchRepo.GetVulnerabilityImpactMeta(ctx, zeroCVE)
		if err != nil {
			t.Fatalf("GetVulnerabilityImpactMeta(%s): %v", zeroCVE, err)
		}
		if meta0 == nil {
			t.Fatalf("meta for known 0.0-scored CVE %s is nil", zeroCVE)
		}
		switch v := any(meta0.CVSSScore).(type) {
		case *float64:
			if v == nil {
				t.Errorf("real 0.0-scored CVE CVSSScore = nil, want *0.0 (0.0 is a real 'None' score)")
			} else if *v != 0 {
				t.Errorf("real 0.0-scored CVE CVSSScore = %v, want 0.0", *v)
			}
		case float64:
			if v != 0 {
				t.Errorf("real 0.0-scored CVE CVSSScore = %v, want 0.0", v)
			}
		}
	})
}
