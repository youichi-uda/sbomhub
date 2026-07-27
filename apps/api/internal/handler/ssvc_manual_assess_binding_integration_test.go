//go:build integration

// Package handler — SSVC MANUAL assessment server-side CVE binding (M46 Codex
// final round, Medium #1 second route).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'SSVCManualAssessBinding' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Why this file exists at all: 9704eb9 closed the identical hole on the
// AUTO-assess route (see ssvc_auto_assess_binding_integration_test.go) and
// stopped there. POST /api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc —
// the MANUAL route — still REQUIRED a caller-supplied `?cve_id=` and stored
// it verbatim on the assessment row, and never checked :vuln_id against the
// caller's (tenant, project) at all. An authenticated tenant could therefore:
//
//   - pair an in-project vulnerability with an arbitrary CVE, poisoning the
//     key that GetAssessmentByCVE, the VEX/report joins and every operator
//     reading the row depend on; and
//   - assess a vulnerability that is not linked to any of its components —
//     200, an ssvc_assessments row minted under its own project, and a write
//     to the GLOBAL vulnerabilities.ssvc_decision column of a vulnerability
//     outside its scope.
//
// Contract after the fix (kept by this test), identical to the auto route:
//   - the `cve_id` query parameter is IGNORED; the CVE is derived
//     server-side from :vuln_id (GetCVEIDByIDInProject);
//   - the (tenant, project, vulnerability) membership is verified through
//     the RLS-protected components/sboms join; a vulnerability not linked
//     to the project answers 404 with NO assessment row created and NO
//     ssvc_decision write, and "unknown" is indistinguishable from
//     "someone else's" (one sentinel);
//   - a row that already carries a mispaired cve_id is REPAIRED on the next
//     assessment (UpdateAssessment persists cve_id).
//
// Fixtures and the echo/tx driving helpers are shared with the auto-assess
// binding test in this package (ssvcABSeedAll / ssvcABScanAsTenant /
// ssvcABHandler) — same package, same build tag, same seed shape.
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
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
)

// ssvcMBAssess drives POST .../vulnerabilities/:vuln_id/ssvc through a real
// echo context inside an app-role tenant tx (RLS active, like a live request
// behind TenantTx). rawQuery carries the hostile `cve_id=...` spoof. Returns
// the HTTP status (from the recorder on success, from the *echo.HTTPError on
// failure) and the response body.
func ssvcMBAssess(t *testing.T, appDB *sql.DB, h *SSVCHandler,
	tenantID, projectID, vulnID uuid.UUID, rawQuery, body string) (int, string) {
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
	target := "/api/v1/projects/" + projectID.String() + "/vulnerabilities/" + vulnID.String() + "/ssvc"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req = req.WithContext(database.WithTx(context.Background(), tx))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "vuln_id")
	c.SetParamValues(projectID.String(), vulnID.String())
	c.Set("tenant_id", tenantID)

	herr := h.AssessVulnerability(c)
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
		t.Fatalf("AssessVulnerability returned non-HTTP error: %v", herr)
	}
	return rec.Code, rec.Body.String()
}

// ssvcMBBody is a well-formed manual assessment payload. The values are
// deliberately the "quiet" end of the decision tree (none/no/partial/support/
// minimal) so the resulting decision is `defer` and any drift is obvious.
const ssvcMBBody = `{"exploitation":"none","automatable":"no","technical_impact":"partial",` +
	`"mission_prevalence":"support","safety_impact":"minimal","notes":"manual binding test"}`

// TestSSVCManualAssessBinding_SpoofedCVEQueryCannotDriveAssessment: vuln A is
// in the project; the caller spoofs ?cve_id=B. Pre-fix the assessment row was
// written with cve_id = B — an in-project vulnerability permanently mispaired
// with an unrelated CVE. Post-fix the query parameter is inert and the row
// carries A's own authoritative CVE.
func TestSSVCManualAssessBinding_SpoofedCVEQueryCannotDriveAssessment(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "mspoof")
	h := ssvcABHandler(appDB)

	code, body := ssvcMBAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnA,
		"cve_id="+seed.cveB, ssvcMBBody)
	if code != http.StatusOK {
		t.Fatalf("manual assess of in-project vuln A: status %d body %s, want 200", code, body)
	}

	var gotCVE, decision string
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID, `
		SELECT cve_id, decision
		FROM ssvc_assessments
		WHERE project_id = $1 AND vulnerability_id = $2`,
		[]any{seed.projectID, seed.vulnA},
		&gotCVE, &decision); err != nil {
		t.Fatalf("read assessment row for vuln A: %v", err)
	}
	if gotCVE != seed.cveA {
		t.Errorf("assessment cve_id = %q, want %q (server must derive the CVE from :vuln_id, not trust ?cve_id=%s)",
			gotCVE, seed.cveA, seed.cveB)
	}
	if decision != "defer" {
		t.Errorf("decision = %q, want %q (the submitted inputs are the quiet end of the tree)", decision, "defer")
	}

	// The response body is what a client persists; it must not echo the spoof.
	if strings.Contains(body, seed.cveB) {
		t.Errorf("response body carries the spoofed CVE %s: %s", seed.cveB, body)
	}
}

// TestSSVCManualAssessBinding_OmittedCVEQueryStillWorks: the parameter is
// inert, not merely overridden — a client that sends no cve_id at all must
// still get a correctly-bound assessment. Pre-fix this was a hard 400
// ("cve_id is required"), which is why the parameter existed in the first
// place; the server no longer needs it.
func TestSSVCManualAssessBinding_OmittedCVEQueryStillWorks(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "mnoparam")
	h := ssvcABHandler(appDB)

	code, body := ssvcMBAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnA,
		"", ssvcMBBody)
	if code != http.StatusOK {
		t.Fatalf("manual assess without ?cve_id=: status %d body %s, want 200", code, body)
	}

	var gotCVE string
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID, `
		SELECT cve_id FROM ssvc_assessments WHERE project_id = $1 AND vulnerability_id = $2`,
		[]any{seed.projectID, seed.vulnA}, &gotCVE); err != nil {
		t.Fatalf("read assessment row for vuln A: %v", err)
	}
	if gotCVE != seed.cveA {
		t.Errorf("assessment cve_id = %q, want %q", gotCVE, seed.cveA)
	}
}

// TestSSVCManualAssessBinding_VulnOutsideProjectIs404NoWrites: :vuln_id = B,
// which exists globally but is not linked to any component of the caller's
// project. Pre-fix this answered 200, minted an ssvc_assessments row for B
// under the caller's project AND flipped the GLOBAL
// vulnerabilities.ssvc_decision column on B. Post-fix: 404, zero writes.
func TestSSVCManualAssessBinding_VulnOutsideProjectIs404NoWrites(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "mscope")
	h := ssvcABHandler(appDB)

	code, body := ssvcMBAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnB,
		"cve_id="+seed.cveB, ssvcMBBody)
	if code != http.StatusNotFound {
		t.Errorf("manual assess of out-of-project vuln B: status %d body %s, want 404", code, body)
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

	var vulnDecision sql.NullString
	if err := migDB.QueryRow(`SELECT ssvc_decision FROM vulnerabilities WHERE id = $1`, seed.vulnB).
		Scan(&vulnDecision); err != nil {
		t.Fatalf("read vulnerabilities.ssvc_decision for B: %v", err)
	}
	if vulnDecision.Valid {
		t.Errorf("global vulnerabilities.ssvc_decision for out-of-project B was written (%q), want NULL",
			vulnDecision.String)
	}
}

// TestSSVCManualAssessBinding_ForeignTenantVulnIs404: vuln C IS linked to a
// component — but in a DIFFERENT tenant's project. Requesting it under the
// caller's own project must 404: the membership join runs through the
// RLS-protected components/sboms tables with explicit tenant/project
// predicates, so another tenant's linkage can never vouch for scope.
func TestSSVCManualAssessBinding_ForeignTenantVulnIs404(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := ssvcABSeedAll(t, migDB, "mcaller")
	foreign := ssvcABSeedAll(t, migDB, "mforeign") // foreign.vulnA is linked in the FOREIGN tenant only
	h := ssvcABHandler(appDB)

	code, body := ssvcMBAssess(t, appDB, h, caller.tenantID, caller.projectID, foreign.vulnA,
		"cve_id="+foreign.cveA, ssvcMBBody)
	if code != http.StatusNotFound {
		t.Errorf("manual assess of foreign tenant's vuln: status %d body %s, want 404", code, body)
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

// TestSSVCManualAssessBinding_ExistingMispairedRowIsRepaired: a row minted by
// a PRE-FIX caller carries someone else's cve_id. The update path used to
// leave cve_id out of the SET list entirely, so the mispairing survived every
// subsequent legitimate assessment. Re-assessing must now re-stamp the
// authoritative CVE.
func TestSSVCManualAssessBinding_ExistingMispairedRowIsRepaired(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "mrepair")
	h := ssvcABHandler(appDB)

	// Seed the damage a pre-fix POST left behind: vuln A's assessment row
	// stored under B's CVE.
	assessmentID := uuid.New()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO ssvc_assessments (
			id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
			decision, exploitation_auto, automatable_auto, assessed_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'none', 'no', 'partial', 'support', 'minimal',
			'defer', false, false, NOW(), NOW(), NOW())`,
		assessmentID, seed.projectID, seed.tenantID, seed.vulnA, seed.cveB); err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed mispaired assessment: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit mispaired seed: %v", err)
	}

	code, body := ssvcMBAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnA, "", ssvcMBBody)
	if code != http.StatusOK {
		t.Fatalf("re-assess of in-project vuln A: status %d body %s, want 200", code, body)
	}

	var gotCVE string
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID,
		`SELECT cve_id FROM ssvc_assessments WHERE id = $1`,
		[]any{assessmentID}, &gotCVE); err != nil {
		t.Fatalf("read repaired assessment row: %v", err)
	}
	if gotCVE != seed.cveA {
		t.Errorf("assessment cve_id after re-assessment = %q, want %q (a mispaired row must be repaired, not preserved)",
			gotCVE, seed.cveA)
	}
}

// ssvcMBDelete drives DELETE .../ssvc/assessments/:assessment_id through a
// real echo context inside an app-role tenant tx.
func ssvcMBDelete(t *testing.T, appDB *sql.DB, h *SSVCHandler,
	tenantID, projectID, assessmentID uuid.UUID) (int, string) {
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
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/projects/"+projectID.String()+"/ssvc/assessments/"+assessmentID.String(), nil)
	req = req.WithContext(database.WithTx(context.Background(), tx))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "assessment_id")
	c.SetParamValues(projectID.String(), assessmentID.String())
	c.Set("tenant_id", tenantID)

	herr := h.DeleteAssessment(c)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tenant tx: %v", err)
	}
	committed = true

	if herr != nil {
		var he *echo.HTTPError
		if errors.As(herr, &he) {
			return he.Code, fmt.Sprintf("%v", he.Message)
		}
		t.Fatalf("DeleteAssessment returned non-HTTP error: %v", herr)
	}
	return rec.Code, rec.Body.String()
}

// ssvcMBSecondProject adds a second project to an existing seeded tenant, so
// the "same tenant, wrong project" case can be exercised.
func ssvcMBSecondProject(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, label string) uuid.UUID {
	t.Helper()
	projectID := uuid.New()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
		projectID, tenantID, "ssvcmb-"+label+"-project2"); err != nil {
		t.Fatalf("insert second project: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit second project: %v", err)
	}
	return projectID
}

// TestSSVCDeleteAssessmentScope_WrongProjectIs404AndKeepsTheRow: the route
// names a project, and pre-fix that segment was PARSED NOWHERE — the
// repository ran `DELETE FROM ssvc_assessments WHERE id = $1`. Any assessment
// in the tenant could therefore be destroyed through any project's URL, and
// the endpoint answered 204 whether or not it hit anything.
func TestSSVCDeleteAssessmentScope_WrongProjectIs404AndKeepsTheRow(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "mdel")
	h := ssvcABHandler(appDB)

	// Mint a real assessment through the (now correctly bound) manual route.
	if code, body := ssvcMBAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnA, "", ssvcMBBody); code != http.StatusOK {
		t.Fatalf("seed assessment via manual route: status %d body %s, want 200", code, body)
	}
	var assessmentID uuid.UUID
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID,
		`SELECT id FROM ssvc_assessments WHERE project_id = $1 AND vulnerability_id = $2`,
		[]any{seed.projectID, seed.vulnA}, &assessmentID); err != nil {
		t.Fatalf("read seeded assessment id: %v", err)
	}

	// Same tenant, WRONG project: must not delete.
	otherProject := ssvcMBSecondProject(t, migDB, seed.tenantID, "mdel")
	code, body := ssvcMBDelete(t, appDB, h, seed.tenantID, otherProject, assessmentID)
	if code != http.StatusNotFound {
		t.Errorf("delete through a different project of the same tenant: status %d body %s, want 404", code, body)
	}
	var alive int
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM ssvc_assessments WHERE id = $1`, []any{assessmentID}, &alive); err != nil {
		t.Fatalf("count assessment after cross-project delete: %v", err)
	}
	if alive != 1 {
		t.Errorf("assessment rows after a cross-project delete = %d, want 1 (the row must survive)", alive)
	}

	// Correct project: deletes, and reports it.
	code, body = ssvcMBDelete(t, appDB, h, seed.tenantID, seed.projectID, assessmentID)
	if code != http.StatusNoContent {
		t.Errorf("delete through the owning project: status %d body %s, want 204", code, body)
	}
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM ssvc_assessments WHERE id = $1`, []any{assessmentID}, &alive); err != nil {
		t.Fatalf("count assessment after in-project delete: %v", err)
	}
	if alive != 0 {
		t.Errorf("assessment rows after the owning project's delete = %d, want 0", alive)
	}

	// A second delete of the same id must now 404, not the pre-fix lying 204.
	if code, body = ssvcMBDelete(t, appDB, h, seed.tenantID, seed.projectID, assessmentID); code != http.StatusNotFound {
		t.Errorf("delete of an already-deleted assessment: status %d body %s, want 404 (a 204 for a row that was never touched is a lie)", code, body)
	}
}

// TestSSVCDeleteAssessmentScope_ForeignTenantIs404: RLS already blocks this,
// but the explicit tenant predicate is the defence-in-depth half — pin both.
func TestSSVCDeleteAssessmentScope_ForeignTenantIs404(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	victim := ssvcABSeedAll(t, migDB, "mdelvictim")
	attacker := ssvcABSeedAll(t, migDB, "mdelattacker")
	h := ssvcABHandler(appDB)

	if code, body := ssvcMBAssess(t, appDB, h, victim.tenantID, victim.projectID, victim.vulnA, "", ssvcMBBody); code != http.StatusOK {
		t.Fatalf("seed victim assessment: status %d body %s, want 200", code, body)
	}
	var assessmentID uuid.UUID
	if err := ssvcABScanAsTenant(t, migDB, victim.tenantID,
		`SELECT id FROM ssvc_assessments WHERE project_id = $1 AND vulnerability_id = $2`,
		[]any{victim.projectID, victim.vulnA}, &assessmentID); err != nil {
		t.Fatalf("read victim assessment id: %v", err)
	}

	if code, body := ssvcMBDelete(t, appDB, h, attacker.tenantID, attacker.projectID, assessmentID); code != http.StatusNotFound {
		t.Errorf("cross-tenant delete: status %d body %s, want 404", code, body)
	}
	var alive int
	if err := ssvcABScanAsTenant(t, migDB, victim.tenantID,
		`SELECT COUNT(*) FROM ssvc_assessments WHERE id = $1`, []any{assessmentID}, &alive); err != nil {
		t.Fatalf("count victim assessment: %v", err)
	}
	if alive != 1 {
		t.Errorf("victim assessment rows after a cross-tenant delete = %d, want 1", alive)
	}
}

// ssvcMBHistory drives GET .../ssvc/assessments/:assessment_id/history.
func ssvcMBHistory(t *testing.T, appDB *sql.DB, h *SSVCHandler,
	tenantID, projectID, assessmentID uuid.UUID) (int, string) {
	t.Helper()

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL app.current_tenant_id: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+projectID.String()+"/ssvc/assessments/"+assessmentID.String()+"/history", nil)
	req = req.WithContext(database.WithTx(context.Background(), tx))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "assessment_id")
	c.SetParamValues(projectID.String(), assessmentID.String())
	c.Set("tenant_id", tenantID)

	if herr := h.GetAssessmentHistory(c); herr != nil {
		var he *echo.HTTPError
		if errors.As(herr, &he) {
			return he.Code, fmt.Sprintf("%v", he.Message)
		}
		t.Fatalf("GetAssessmentHistory returned non-HTTP error: %v", herr)
	}
	return rec.Code, rec.Body.String()
}

// TestSSVCAssessmentHistoryScope_WrongProjectSeesNothing: like DeleteAssessment,
// the history read ignored the route's :id entirely — ssvc_assessment_history
// carries no project_id of its own and the statement filtered on
// assessment_id alone, so any assessment's decision-change trail was readable
// through any of the tenant's project URLs. Post-fix the parent assessment is
// joined and constrained; an out-of-scope id reads as an empty history (the
// same answer as an assessment that never changed, so it cannot be used as an
// existence probe).
func TestSSVCAssessmentHistoryScope_WrongProjectSeesNothing(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "mhist")
	h := ssvcABHandler(appDB)

	// Two assessments in a row produce exactly one history entry (the second
	// call records the change from the first).
	if code, body := ssvcMBAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnA, "", ssvcMBBody); code != http.StatusOK {
		t.Fatalf("first assessment: status %d body %s, want 200", code, body)
	}
	const louder = `{"exploitation":"active","automatable":"yes","technical_impact":"total",` +
		`"mission_prevalence":"essential","safety_impact":"significant","notes":"changed"}`
	if code, body := ssvcMBAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnA, "", louder); code != http.StatusOK {
		t.Fatalf("second assessment: status %d body %s, want 200", code, body)
	}

	var assessmentID uuid.UUID
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID,
		`SELECT id FROM ssvc_assessments WHERE project_id = $1 AND vulnerability_id = $2`,
		[]any{seed.projectID, seed.vulnA}, &assessmentID); err != nil {
		t.Fatalf("read assessment id: %v", err)
	}
	var historyRows int
	if err := ssvcABScanAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM ssvc_assessment_history WHERE assessment_id = $1`,
		[]any{assessmentID}, &historyRows); err != nil {
		t.Fatalf("count history rows: %v", err)
	}
	if historyRows == 0 {
		t.Fatal("precondition: no history row was recorded, so this test would pass vacuously")
	}

	// Owning project: the history is visible.
	code, body := ssvcMBHistory(t, appDB, h, seed.tenantID, seed.projectID, assessmentID)
	if code != http.StatusOK {
		t.Fatalf("history through the owning project: status %d body %s, want 200", code, body)
	}
	if !strings.Contains(body, "immediate") {
		t.Errorf("history through the owning project = %s, want the recorded decision change", body)
	}

	// Same tenant, wrong project: nothing.
	otherProject := ssvcMBSecondProject(t, migDB, seed.tenantID, "mhist")
	code, body = ssvcMBHistory(t, appDB, h, seed.tenantID, otherProject, assessmentID)
	if code != http.StatusOK {
		t.Fatalf("history through a different project: status %d body %s, want 200 with an empty list", code, body)
	}
	if strings.Contains(body, "immediate") || strings.Contains(body, "assessment_id") {
		t.Errorf("history through a different project leaked rows: %s (the route's :id must scope the read)", body)
	}
}
