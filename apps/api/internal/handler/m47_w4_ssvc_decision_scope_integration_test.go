//go:build integration

// Package handler — M47 W4: the SSVC decision is per (tenant, project) and
// must not be projected onto the global CVE row.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M47W4_SSVCDecisionScope' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Prerequisites (skipped otherwise): same env contract as
// ssvc_manual_assess_binding_integration_test.go, whose helpers this file
// reuses (postgres up, DATABASE_URL = sbomhub_app / MIGRATE_DATABASE_URL =
// sbomhub_migrator, schema migrated through 062).
//
// What these tests pin down:
//
// SSVCService.AssessVulnerability and AutoAssessVulnerability both used to
// finish by writing the computed decision to vulnerabilities.ssvc_decision.
// `vulnerabilities` is the shared, tenant-less CVE catalogue — 001_init
// declares no tenant_id and it is a recorded RLS exemption — so that column
// held whichever tenant assessed the CVE most recently. Two tenants
// assessing the same CVE silently overwrote each other, and the write also
// bumped the shared row's updated_at.
//
// The decision is inherently project-specific: the SSVC tree is evaluated
// from the assessing project's mission prevalence, safety impact and system
// exposure, so two projects reaching different decisions for one CVE is
// CORRECT behaviour, not a conflict to be resolved by last-write-wins.
//
// M47 W4 removed both writes and migration 062 dropped the column. The
// authoritative record is the ssvc_assessments row keyed by (tenant_id,
// project_id, vulnerability_id).
package handler

import (
	"database/sql"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	_ "github.com/lib/pq"
)

// ssvcScopeTenant is one tenant with a project whose component carries the
// SHARED vulnerability, i.e. everything needed to drive a real assessment.
type ssvcScopeTenant struct {
	tenantID  uuid.UUID
	projectID uuid.UUID
}

// seedSSVCScopeSharedVuln creates ONE global vulnerability plus `n` tenants,
// each with its own project/sbom/component linked to that same vulnerability.
// The shared vulnerability id is what makes the cross-tenant clobber possible:
// every tenant's assessment resolves to the same global row.
func seedSSVCScopeSharedVuln(t *testing.T, migDB *sql.DB, label string, n int) (uuid.UUID, string, []ssvcScopeTenant) {
	t.Helper()

	vulnID := uuid.New()
	cveID := fmt.Sprintf("CVE-2095-%07d", uuid.New().ID()%10000000)
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'm47w4 ssvc scope shared vuln', 'HIGH', 7.5)`,
		vulnID, cveID); err != nil {
		t.Fatalf("seed shared vulnerability: %v", err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID); err != nil {
			t.Errorf("C27 cleanup: delete shared vulnerability %s: %v", vulnID, err)
		}
	})

	tenants := make([]ssvcScopeTenant, 0, n)
	for i := 0; i < n; i++ {
		tenantID := uuid.New()
		org := fmt.Sprintf("ssvcscope-%s-%d-%s", label, i, tenantID)
		if _, err := migDB.Exec(
			`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
			tenantID, org, org, org); err != nil {
			t.Fatalf("seed tenant %d: %v", i, err)
		}
		tid := tenantID
		t.Cleanup(func() {
			if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tid); err != nil {
				t.Errorf("C27 cleanup: delete tenant %s: %v", tid, err)
			}
		})

		execAsTenant := func(query string, args ...any) {
			t.Helper()
			tx, err := migDB.Begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
				t.Fatalf("SET LOCAL: %v", err)
			}
			if _, err := tx.Exec(query, args...); err != nil {
				t.Fatalf("exec as tenant: %v\nquery: %s", err, query)
			}
			if err := tx.Commit(); err != nil {
				t.Fatalf("commit: %v", err)
			}
		}

		projectID := uuid.New()
		sbomID := uuid.New()
		componentID := uuid.New()
		execAsTenant(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
			projectID, tenantID, fmt.Sprintf("ssvcscope-%s-%d-project", label, i))
		execAsTenant(`
			INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
			VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{}'::jsonb, NOW())`,
			sbomID, tenantID, projectID)
		execAsTenant(`
			INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, created_at)
			VALUES ($1, $2, $3, 'libssvcscope', '1.0', 'library', 'pkg:generic/ssvcscope@1.0', NOW())`,
			componentID, tenantID, sbomID)

		if _, err := migDB.Exec(
			`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`,
			componentID, vulnID); err != nil {
			t.Fatalf("link tenant %d component to shared vuln: %v", i, err)
		}

		tenants = append(tenants, ssvcScopeTenant{tenantID: tenantID, projectID: projectID})
	}
	return vulnID, cveID, tenants
}

// Two decision payloads that MUST produce different outcomes, so a clobber is
// unmistakable rather than an accidental match. Values are constrained by
// migration 021's enums (safety_impact is only minimal|significant).
//
//	quiet -> defer      (none / no / partial / support / minimal)
//	loud  -> immediate  (active / yes / total / essential / significant;
//	                     CalculateDecision: "Active + essential mission")
const (
	ssvcScopeQuietBody = `{"exploitation":"none","automatable":"no","technical_impact":"partial",` +
		`"mission_prevalence":"support","safety_impact":"minimal","notes":"m47w4 quiet"}`
	ssvcScopeLoudBody = `{"exploitation":"active","automatable":"yes","technical_impact":"total",` +
		`"mission_prevalence":"essential","safety_impact":"significant","notes":"m47w4 loud"}`
)

// TestM47W4_SSVCDecisionScope_CrossTenantAssessmentsDoNotOverwrite is the
// headline regression: two DIFFERENT tenants assess the same global CVE with
// opposite inputs. Each must keep its own decision.
//
// Pre-fix, both assessments also wrote vulnerabilities.ssvc_decision, so the
// second tenant's `immediate` replaced the first tenant's `defer` on a row
// every tenant shares. The ssvc_assessments rows themselves were always
// correctly scoped — the leak was entirely in the global projection, which is
// why this test asserts BOTH that each tenant's own row survives AND that the
// global row carries no decision column to leak through.
func TestM47W4_SSVCDecisionScope_CrossTenantAssessmentsDoNotOverwrite(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	vulnID, cveID, tenants := seedSSVCScopeSharedVuln(t, migDB, "xtenant", 2)
	h := ssvcABHandler(appDB)

	// Tenant 0 assesses quietly -> defer.
	code, body := ssvcMBAssess(t, appDB, h, tenants[0].tenantID, tenants[0].projectID, vulnID,
		"", ssvcScopeQuietBody)
	if code != http.StatusOK {
		t.Fatalf("tenant 0 assess: status %d body %s, want 200", code, body)
	}

	// Tenant 1 assesses loudly -> immediate. This is the write that used to
	// clobber tenant 0's decision on the shared row.
	code, body = ssvcMBAssess(t, appDB, h, tenants[1].tenantID, tenants[1].projectID, vulnID,
		"", ssvcScopeLoudBody)
	if code != http.StatusOK {
		t.Fatalf("tenant 1 assess: status %d body %s, want 200", code, body)
	}

	// Each tenant still owns its own decision.
	for i, want := range []string{"defer", "immediate"} {
		var got string
		if err := ssvcABScanAsTenant(t, migDB, tenants[i].tenantID, `
			SELECT decision FROM ssvc_assessments
			WHERE vulnerability_id = $1 AND project_id = $2`,
			[]any{vulnID, tenants[i].projectID}, &got); err != nil {
			t.Fatalf("read tenant %d assessment: %v", i, err)
		}
		if got != want {
			t.Errorf("tenant %d decision = %q, want %q (a later tenant's assessment overwrote it)",
				i, got, want)
		}
	}

	// And the shared CVE row has nowhere to hold a per-project decision.
	assertNoGlobalSSVCDecisionColumn(t, migDB, vulnID)
	_ = cveID
}

// assertNoGlobalSSVCDecisionColumn pins the M47 W4 / migration 062 contract:
// `vulnerabilities` is the shared, tenant-less CVE catalogue, so it must carry
// no per-(tenant, project) SSVC decision column. Re-adding one lets the last
// tenant to assess a CVE overwrite every other tenant's decision, with no RLS
// backstop on that table to catch it.
//
// When the column IS present the failure message reports the value currently
// on the shared row, so the diagnosis names the surviving winner of the
// cross-tenant race rather than just "column exists".
func assertNoGlobalSSVCDecisionColumn(t *testing.T, migDB *sql.DB, vulnID uuid.UUID) {
	t.Helper()
	var n int
	if err := migDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_name = 'vulnerabilities' AND column_name = 'ssvc_decision'`).Scan(&n); err != nil {
		t.Fatalf("probe vulnerabilities.ssvc_decision: %v", err)
	}
	if n == 0 {
		return
	}
	var held sql.NullString
	if err := migDB.QueryRow(
		`SELECT ssvc_decision::text FROM vulnerabilities WHERE id = $1`, vulnID).Scan(&held); err != nil {
		t.Errorf("vulnerabilities still carries an ssvc_decision column — a per-project decision on "+
			"the global CVE row is cross-tenant last-write-wins (M47 W4 / migration 062); "+
			"reading its value failed: %v", err)
		return
	}
	t.Errorf("vulnerabilities still carries an ssvc_decision column and row %s holds %q — that single "+
		"slot on the shared CVE row is whichever (tenant, project) assessed last, overwriting every "+
		"other tenant's decision (M47 W4 / migration 062)", vulnID, held.String)
}

// TestM47W4_SSVCDecisionScope_CrossProjectSameTenantDoNotOverwrite is the
// single-tenant form of the same finding: one tenant, two projects, one CVE.
// Different projects legitimately reach different decisions because the SSVC
// tree consumes project-level mission prevalence / safety impact / exposure.
func TestM47W4_SSVCDecisionScope_CrossProjectSameTenantDoNotOverwrite(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	vulnID, _, tenants := seedSSVCScopeSharedVuln(t, migDB, "xproject", 1)
	tenantID := tenants[0].tenantID
	projectA := tenants[0].projectID
	h := ssvcABHandler(appDB)

	// A second project in the SAME tenant, carrying the same vulnerability.
	projectB := uuid.New()
	sbomB := uuid.New()
	compB := uuid.New()
	execB := func(query string, args ...any) {
		t.Helper()
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		if _, err := tx.Exec(query, args...); err != nil {
			t.Fatalf("exec as tenant: %v\nquery: %s", err, query)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	execB(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'ssvcscope-xproject-project-b')`,
		projectB, tenantID)
	execB(`
		INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
		VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{}'::jsonb, NOW())`, sbomB, tenantID, projectB)
	execB(`
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, created_at)
		VALUES ($1, $2, $3, 'libssvcscope-b', '1.0', 'library', 'pkg:generic/ssvcscope-b@1.0', NOW())`,
		compB, tenantID, sbomB)
	if _, err := migDB.Exec(
		`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`,
		compB, vulnID); err != nil {
		t.Fatalf("link project B component to shared vuln: %v", err)
	}

	if code, body := ssvcMBAssess(t, appDB, h, tenantID, projectA, vulnID, "", ssvcScopeQuietBody); code != http.StatusOK {
		t.Fatalf("project A assess: status %d body %s, want 200", code, body)
	}
	if code, body := ssvcMBAssess(t, appDB, h, tenantID, projectB, vulnID, "", ssvcScopeLoudBody); code != http.StatusOK {
		t.Fatalf("project B assess: status %d body %s, want 200", code, body)
	}

	for _, tc := range []struct {
		project uuid.UUID
		want    string
		label   string
	}{
		{projectA, "defer", "A"},
		{projectB, "immediate", "B"},
	} {
		var got string
		if err := ssvcABScanAsTenant(t, migDB, tenantID, `
			SELECT decision FROM ssvc_assessments
			WHERE vulnerability_id = $1 AND project_id = $2`,
			[]any{vulnID, tc.project}, &got); err != nil {
			t.Fatalf("read project %s assessment: %v", tc.label, err)
		}
		if got != tc.want {
			t.Errorf("project %s decision = %q, want %q (the other project's assessment overwrote it)",
				tc.label, got, tc.want)
		}
	}

	// migration 021's UNIQUE(project_id, vulnerability_id) means two rows is
	// the correct cardinality — one decision per project, not one per CVE.
	var n int
	if err := ssvcABScanAsTenant(t, migDB, tenantID, `
		SELECT COUNT(*) FROM ssvc_assessments WHERE vulnerability_id = $1`,
		[]any{vulnID}, &n); err != nil {
		t.Fatalf("count assessments: %v", err)
	}
	if n != 2 {
		t.Errorf("ssvc_assessments rows for the shared vuln = %d, want 2 (one per project)", n)
	}
}

// TestM47W4_SSVCDecisionScope_AssessmentDoesNotTouchGlobalRow pins the second
// half of the finding: the removed write also carried `updated_at = NOW()`, so
// every assessment bumped the shared CVE row's timestamp. `updated_at` on
// `vulnerabilities` means "when the upstream feed last changed this CVE" and is
// published straight through the JSON API, so a tenant's private triage action
// was surfacing as upstream freshness to every other tenant.
func TestM47W4_SSVCDecisionScope_AssessmentDoesNotTouchGlobalRow(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	vulnID, _, tenants := seedSSVCScopeSharedVuln(t, migDB, "notouch", 1)
	h := ssvcABHandler(appDB)

	var before time.Time
	if err := migDB.QueryRow(`SELECT updated_at FROM vulnerabilities WHERE id = $1`, vulnID).
		Scan(&before); err != nil {
		t.Fatalf("read updated_at before: %v", err)
	}

	// Sleep past the timestamp resolution so a bump would be observable.
	time.Sleep(10 * time.Millisecond)

	if code, body := ssvcMBAssess(t, appDB, h, tenants[0].tenantID, tenants[0].projectID, vulnID,
		"", ssvcScopeLoudBody); code != http.StatusOK {
		t.Fatalf("assess: status %d body %s, want 200", code, body)
	}

	var after time.Time
	if err := migDB.QueryRow(`SELECT updated_at FROM vulnerabilities WHERE id = $1`, vulnID).
		Scan(&after); err != nil {
		t.Fatalf("read updated_at after: %v", err)
	}
	if !after.Equal(before) {
		t.Errorf("vulnerabilities.updated_at moved %v -> %v: a per-project SSVC assessment must not "+
			"mutate the shared CVE row (M47 W4)", before, after)
	}
}
