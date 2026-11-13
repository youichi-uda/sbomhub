//go:build integration

// Package repository — cvss_version (M67, migration 069; published since
// M71) on the dashboard Top Risks and SSVC assessment reads, against a real
// migrated schema under the RLS-enforced app role.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'CVSSVersion_DashboardSSVC' ./internal/repository
//
// Prerequisites (skipped otherwise): same as
// vulnerability_null_scan_integration_test.go.
package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCVSSVersion_DashboardSSVC_Integration(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "ssvc_assessments") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "cvssver-dash-ssvc")

	scoredID, versionOnlyID, unknownID := uuid.New(), uuid.New(), uuid.New()
	registerCleanupExec(t, migDB, "cvssver vulnerabilities",
		`DELETE FROM vulnerabilities WHERE id IN ($1, $2, $3)`, scoredID, versionOnlyID, unknownID)
	sfx := tenant.String()[:8]
	cves := map[uuid.UUID]string{
		scoredID:      "CVE-CVSSVER-SCORED-" + sfx,
		versionOnlyID: "CVE-CVSSVER-VONLY-" + sfx,
		unknownID:     "CVE-CVSSVER-UNKNOWN-" + sfx,
	}
	seed := []struct {
		id      uuid.UUID
		score   any
		version any
	}{
		{scoredID, 9.8, "3.1"},
		{versionOnlyID, nil, "4.0"},
		{unknownID, 5.0, nil},
	}
	for _, s := range seed {
		if _, err := migDB.Exec(`
			INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, cvss_version)
			VALUES ($1, $2, 'cvssver', 'HIGH', $3, $4)
		`, s.id, cves[s.id], s.score, s.version); err != nil {
			t.Fatalf("seed vulnerability: %v", err)
		}
	}

	projectID, sbomID, compID := uuid.New(), uuid.New(), uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'cvssver-project')
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
		VALUES ($1, $2, $3, 'cvssver-comp', '1.0.0')
	`, compID, tenant, sbomID); err != nil {
		t.Fatalf("seed component: %v", err)
	}
	for _, s := range seed {
		if _, err := migDB.Exec(`
			INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
			VALUES ($1, $2, NOW())
		`, compID, s.id); err != nil {
			t.Fatalf("seed component_vulnerabilities link: %v", err)
		}
		if err := execAsTenant(t, migDB, tenant, `
			INSERT INTO ssvc_assessments (id, project_id, tenant_id, vulnerability_id, cve_id,
				exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
				decision, exploitation_auto, automatable_auto, assessed_by, assessed_at, notes)
			VALUES ($1, $2, $3, $4, $5, 'none', 'no', 'partial', 'minimal', 'minimal',
				'immediate', false, false, NULL, $6, NULL)
		`, uuid.New(), projectID, tenant, s.id, cves[s.id], time.Now()); err != nil {
			t.Fatalf("seed ssvc_assessment: %v", err)
		}
	}

	want := map[string]*string{}
	for _, s := range seed {
		if v, ok := s.version.(string); ok {
			want[cves[s.id]] = &v
		} else {
			want[cves[s.id]] = nil
		}
	}
	check := func(label, cve string, got *string) {
		t.Helper()
		w, ok := want[cve]
		if !ok {
			return // another tenant's / test's row
		}
		switch {
		case w == nil && got != nil:
			t.Errorf("%s %s: cvss_version = %q, want nil (NULL column)", label, cve, *got)
		case w != nil && (got == nil || *got != *w):
			t.Errorf("%s %s: cvss_version = %v, want %q", label, cve, got, *w)
		}
	}

	dashRepo := NewDashboardRepository(appDB)
	ssvcRepo := NewSSVCRepository(appDB)
	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		risks, err := dashRepo.GetTopRisksByTenant(ctx, tenant, 10, "cvss")
		if err != nil {
			t.Fatalf("GetTopRisksByTenant: %v", err)
		}
		if len(risks) != 3 {
			t.Fatalf("len(risks) = %d, want 3", len(risks))
		}
		for _, r := range risks {
			check("top-risks", r.CVEID, r.CVSSVersion)
		}

		list, total, err := ssvcRepo.ListAssessments(ctx, projectID, nil, 50, 0)
		if err != nil {
			t.Fatalf("ListAssessments: %v", err)
		}
		if total != 3 || len(list) != 3 {
			t.Fatalf("ListAssessments total=%d len=%d, want 3", total, len(list))
		}
		for _, a := range list {
			check("ssvc list", a.CVEID, a.VulnerabilityCVSSVersion)
		}

		imm, err := ssvcRepo.GetImmediateAssessments(ctx)
		if err != nil {
			t.Fatalf("GetImmediateAssessments: %v", err)
		}
		seen := 0
		for _, a := range imm {
			if _, ok := want[a.CVEID]; ok {
				seen++
			}
			check("ssvc immediate", a.CVEID, a.VulnerabilityCVSSVersion)
		}
		if seen != 3 {
			t.Fatalf("GetImmediateAssessments saw %d of the 3 seeded rows", seen)
		}
	})
}
