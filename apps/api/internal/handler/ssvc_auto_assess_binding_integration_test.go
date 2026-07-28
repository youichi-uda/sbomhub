//go:build integration

// Package handler — SSVC auto-assess server-side CVE binding (M46 Codex
// final round, Medium #1).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'SSVCAutoAssessBinding' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// What this pins down (the finding's exact failure scenario):
//
// POST /api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc/auto accepted a
// caller-controlled `?cve_id=` query parameter and used it VERBATIM as the
// evidence key: KEV lookup, EPSS lookup (GetByCVE) and CVSS all keyed on the
// query string, while the assessment row and the denormalized
// vulnerabilities.ssvc_decision write keyed on :vuln_id. A caller could
// therefore assess vulnerability A "based on" vulnerability B's KEV/EPSS/CVSS
// — and, because :vuln_id itself was never checked against the project, could
// also mint assessments (and flip the GLOBAL vulnerabilities.ssvc_decision
// column) for vulnerabilities entirely outside their project/tenant scope.
// The EPSS branch of this path was dead code until def6a46 wired epss_* into
// GetByCVE, which is what made the spoof actually able to flip `automatable`.
//
// Contract after the fix (kept by this test):
//   - the `cve_id` query parameter is IGNORED; the CVE is derived
//     server-side from :vuln_id (GetCVEIDByIDInProject);
//   - the (tenant, project, vulnerability) membership is verified through
//     the RLS-protected components/sboms join; a vulnerability not linked
//     to the project answers 404 with NO assessment row created and NO
//     ssvc_decision write;
//   - a well-scoped request keeps working end-to-end (200, assessment
//     persisted under the vulnerability's own CVE + own evidence).
//
// The handler is driven through a real echo context with the request ctx
// carrying an app-role tx that has SET LOCAL app.current_tenant_id — exactly
// what the TenantTx middleware provides on a live request, so RLS is active.
//
// C27: tenants CASCADE reaps projects/sboms/components; global
// vulnerabilities rows are reaped explicitly via t.Cleanup.
package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ssvcABSeed is one test's fixture set: tenant T with project P holding one
// component affected by vuln A (weak evidence), plus global vuln B (strong
// evidence: high EPSS + high CVSS) NOT linked to any of T's components.
type ssvcABSeed struct {
	tenantID  uuid.UUID
	projectID uuid.UUID
	vulnA     uuid.UUID
	cveA      string
	vulnB     uuid.UUID
	cveB      string
}

func ssvcABSeedAll(t *testing.T, migDB *sql.DB, label string) ssvcABSeed {
	t.Helper()

	tenantID := uuid.New()
	org := "ssvcab-" + label + "-" + tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		tenantID, org, "ssvcab "+label, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s: %v", tenantID, err)
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
	execAsTenant(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
		projectID, tenantID, "ssvcab-"+label+"-project")
	sbomID := uuid.New()
	execAsTenant(`
		INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
		VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{}'::jsonb, NOW())`,
		sbomID, tenantID, projectID)
	componentID := uuid.New()
	execAsTenant(`
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, created_at)
		VALUES ($1, $2, $3, 'libssvcab', '1.0', 'library', 'pkg:generic/ssvcab@1.0', NOW())`,
		componentID, tenantID, sbomID)

	// Unique, ValidateCVEID-conformant CVE ids (cve_id is globally UNIQUE).
	sfx := uuid.New().ID() % 10000000
	seed := ssvcABSeed{
		tenantID:  tenantID,
		projectID: projectID,
		cveA:      fmt.Sprintf("CVE-2097-%07d", sfx),
		cveB:      fmt.Sprintf("CVE-2096-%07d", sfx),
	}

	// Vuln A: linked to the project's component. Weak evidence on purpose:
	// no EPSS, CVSS 5.0 (< 7.0), not in KEV — its honest auto-assessment is
	// automatable=no / technical_impact=partial / decision=defer.
	seed.vulnA = uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'ssvcab weak vuln', 'MEDIUM', 5.0)`,
		seed.vulnA, seed.cveA); err != nil {
		t.Fatalf("seed vuln A: %v", err)
	}
	vulnAID := seed.vulnA
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnAID); err != nil {
			t.Errorf("C27 cleanup: delete vuln A %s: %v", vulnAID, err)
		}
	})
	if _, err := migDB.Exec(
		`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`,
		componentID, seed.vulnA); err != nil {
		t.Fatalf("link component to vuln A: %v", err)
	}

	// Vuln B: NOT linked to any component of this tenant. Strong evidence —
	// EPSS 0.97 (> 0.5 => automatable) and CVSS 9.8 (>= 7.0 => total impact)
	// — so if B's evidence leaks into A's assessment the difference is
	// unmistakable.
	seed.vulnB = uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score,
			epss_score, epss_percentile, epss_updated_at)
		VALUES ($1, $2, 'ssvcab strong vuln', 'CRITICAL', 9.8, 0.97, 0.999, NOW())`,
		seed.vulnB, seed.cveB); err != nil {
		t.Fatalf("seed vuln B: %v", err)
	}
	vulnBID := seed.vulnB
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnBID); err != nil {
			t.Errorf("C27 cleanup: delete vuln B %s: %v", vulnBID, err)
		}
	})

	return seed
}

// ssvcABScanAsTenant runs one QueryRow+Scan inside a migrator tx that has
// SET LOCAL app.current_tenant_id — required for reading ssvc_assessments,
// which is FORCE RLS (so even the migrator/owner role is subject to the
// tenant policy; a bare pooled read sees either no rows or a stale-GUC
// empty-string-to-uuid cast error).
func ssvcABScanAsTenant(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, query string, args []any, dest ...any) error {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("ssvcABScanAsTenant begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("ssvcABScanAsTenant SET LOCAL: %v", err)
	}
	return tx.QueryRow(query, args...).Scan(dest...)
}

func ssvcABHandler(appDB *sql.DB) *SSVCHandler {
	svc := service.NewSSVCService(
		repository.NewSSVCRepository(appDB),
		repository.NewVulnerabilityRepository(appDB),
		repository.NewKEVRepository(appDB),
	)
	return NewSSVCHandler(svc)
}

// ssvcABAutoAssess drives POST .../vulnerabilities/:vuln_id/ssvc/auto through
// a real echo context inside an app-role tenant tx (RLS active, like a live
// request behind TenantTx). rawQuery carries the hostile `cve_id=...` spoof.
// Returns the HTTP status (from the recorder on success, from the
// *echo.HTTPError on failure) and the response body.
func ssvcABAutoAssess(t *testing.T, appDB *sql.DB, h *SSVCHandler,
	tenantID, projectID, vulnID uuid.UUID, rawQuery string) (int, string) {
	t.Helper()

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL app.current_tenant_id: %v", err)
	}

	e := echo.New()
	target := "/api/v1/projects/" + projectID.String() + "/vulnerabilities/" + vulnID.String() + "/ssvc/auto"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodPost, target, nil)
	req = req.WithContext(database.WithTx(context.Background(), tx))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "vuln_id")
	c.SetParamValues(projectID.String(), vulnID.String())
	c.Set("tenant_id", tenantID)

	herr := h.AutoAssessVulnerability(c)
	// Commit either way: the production TenantTx commits on 2xx and rolls
	// back on error, but committing here regardless lets the test assert
	// "no rows were written" the STRONG way — proving the handler itself
	// refused to write, not that a rollback cleaned up after it.
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tenant tx: %v", err)
	}
	committed = true

	if herr != nil {
		var he *echo.HTTPError
		if errors.As(herr, &he) {
			return he.Code, fmt.Sprintf("%v", he.Message)
		}
		t.Fatalf("AutoAssessVulnerability returned non-HTTP error: %v", herr)
	}
	return rec.Code, rec.Body.String()
}

// TestSSVCAutoAssessBinding_SpoofedCVEQueryCannotDriveAssessment: vuln A is
// in the project; the caller spoofs ?cve_id=B (high EPSS + high CVSS).
// Pre-fix, A's assessment came out automatable=yes / technical_impact=total
// / decision=scheduled with cve_id=B stored on the row — B's evidence
// laundered into A's triage verdict. Post-fix the query parameter is inert:
// the assessment must reflect A's own (weak) evidence under A's own CVE.
func TestSSVCAutoAssessBinding_SpoofedCVEQueryCannotDriveAssessment(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "spoof")
	h := ssvcABHandler(appDB)

	code, body := ssvcABAutoAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnA,
		"cve_id="+seed.cveB)
	if code != http.StatusOK {
		t.Fatalf("auto-assess of in-project vuln A: status %d body %s, want 200", code, body)
	}

	var gotCVE, automatable, technicalImpact, decision string
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID, `
		SELECT cve_id, automatable, technical_impact, decision
		FROM ssvc_assessments
		WHERE project_id = $1 AND vulnerability_id = $2`,
		[]any{seed.projectID, seed.vulnA},
		&gotCVE, &automatable, &technicalImpact, &decision); err != nil {
		t.Fatalf("read assessment row for vuln A: %v", err)
	}
	if gotCVE != seed.cveA {
		t.Errorf("assessment cve_id = %q, want %q (server must derive the CVE from :vuln_id, not trust ?cve_id=%s)",
			gotCVE, seed.cveA, seed.cveB)
	}
	if automatable != "no" {
		t.Errorf("automatable = %q, want %q (A has no EPSS; yes means B's 0.97 EPSS drove A's assessment)",
			automatable, "no")
	}
	if technicalImpact != "partial" {
		t.Errorf("technical_impact = %q, want %q (A's CVSS is 5.0; total means B's 9.8 leaked in)",
			technicalImpact, "partial")
	}
	if decision != "defer" {
		t.Errorf("decision = %q, want %q (A's own evidence is weak)", decision, "defer")
	}

	// M47 W4: this used to also assert the denormalized
	// vulnerabilities.ssvc_decision write. That write is gone and migration
	// 062 dropped the column — the ssvc_assessments assertions above are now
	// the whole record. assertNoGlobalSSVCDecisionColumn pins that the
	// per-project decision has no home on the shared CVE row.
	assertNoGlobalSSVCDecisionColumn(t, migDB, seed.vulnA)
}

// TestSSVCAutoAssessBinding_VulnOutsideProjectIs404NoWrites: :vuln_id = B,
// which exists globally but is not linked to any component of the caller's
// project. Pre-fix this answered 200, minted an ssvc_assessments row for B
// under the caller's project AND flipped the GLOBAL
// vulnerabilities.ssvc_decision column on B. Post-fix: 404, zero writes.
func TestSSVCAutoAssessBinding_VulnOutsideProjectIs404NoWrites(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "scope")
	h := ssvcABHandler(appDB)

	// The cve_id param is what a pre-fix client sent; post-fix it is inert.
	code, body := ssvcABAutoAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnB,
		"cve_id="+seed.cveB)
	if code != http.StatusNotFound {
		t.Errorf("auto-assess of out-of-project vuln B: status %d body %s, want 404", code, body)
	}

	var assessments int
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID, `
		SELECT COUNT(*) FROM ssvc_assessments WHERE vulnerability_id = $1`,
		[]any{seed.vulnB}, &assessments); err != nil {
		t.Fatalf("count assessments for B: %v", err)
	}
	if assessments != 0 {
		t.Errorf("ssvc_assessments rows for out-of-project vuln B = %d, want 0", assessments)
	}

	// M47 W4: the "did the global row get flipped for B" check is now
	// structural — the column the leak used no longer exists.
	assertNoGlobalSSVCDecisionColumn(t, migDB, seed.vulnB)
}

// TestSSVCAutoAssessBinding_ForeignTenantVulnIs404: vuln C IS linked to a
// component — but in a DIFFERENT tenant's project. Requesting it under the
// caller's own project must 404: the membership join runs through the
// RLS-protected components/sboms tables with explicit tenant/project
// predicates, so another tenant's linkage can never vouch for scope.
func TestSSVCAutoAssessBinding_ForeignTenantVulnIs404(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := ssvcABSeedAll(t, migDB, "caller")
	foreign := ssvcABSeedAll(t, migDB, "foreign") // foreign.vulnA is linked in the FOREIGN tenant only
	h := ssvcABHandler(appDB)

	code, body := ssvcABAutoAssess(t, appDB, h, caller.tenantID, caller.projectID, foreign.vulnA,
		"cve_id="+foreign.cveA)
	if code != http.StatusNotFound {
		t.Errorf("auto-assess of foreign tenant's vuln: status %d body %s, want 404", code, body)
	}

	var assessments int
	if err := ssvcABScanAsTenant(t, migDB, caller.tenantID, `
		SELECT COUNT(*) FROM ssvc_assessments WHERE vulnerability_id = $1 AND project_id = $2`,
		[]any{foreign.vulnA, caller.projectID}, &assessments); err != nil {
		t.Fatalf("count assessments: %v", err)
	}
	if assessments != 0 {
		t.Errorf("caller minted %d assessment row(s) for a foreign tenant's vulnerability, want 0", assessments)
	}
}
