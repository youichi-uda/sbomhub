//go:build integration

// Package handler — M50: GET /projects/:id/ssvc/assessments/:assessment_id/history
// was the ONE sub-resource route that answered `200 []` where every sibling
// answers 404.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M50SSVCHistory' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// Measured over real HTTP on a throwaway stack (2026-08-05, `anonymous`
// self-host, api :18085 / postgres :15438) BEFORE the fix — the four cells
// below were byte-identical `200 []`, and the fifth (an assessment the caller
// owns, with history) returned rows, so the fixtures were demonstrably
// visible and the emptiness was the contract, not an invisible fixture:
//
//	cell                              status  sha256[:16]        body
//	positive control (own, hist=2)    200     f2370f09294ea7f1   [{...}, {...}]
//	own project, hist=0               200     37517e5f3dc66819   []
//	unassigned random UUID            200     37517e5f3dc66819   []
//	sibling project (same tenant)     200     37517e5f3dc66819   []
//	foreign tenant                    200     37517e5f3dc66819   []
//
// and AFTER the fix, same stack, same fixtures:
//
//	positive control (own, hist=2)    200     f2370f09294ea7f1   [{...}, {...}]
//	own project, hist=0               200     37517e5f3dc66819   []
//	unassigned random UUID            404     ae9ad7573f76f2c5   {"message":"assessment not found in project"}
//	sibling project (same tenant)     404     ae9ad7573f76f2c5   {"message":"assessment not found in project"}
//	foreign tenant                    404     ae9ad7573f76f2c5   {"message":"assessment not found in project"}
//
// The three 404 responses were also compared INCLUDING response headers (Date
// and X-Request-Id stripped) and hashed identically:
// b1e4a747f2dff4d993db287315d04497d475d9c441f8960b6ef1df81c4111d80.
//
// The tests below drive handlers directly, so they pin status + message
// rather than serialised wire bytes; that is why the wire-level equality is
// recorded here as a measurement rather than asserted in code.
//
// M47 W1's contract is that "unknown" and "yours but out of scope" collapse
// into ONE answer so the status cannot be used as an existence oracle. The
// pre-fix history route satisfied the anti-probing half (all four cells were
// identical) but picked the WRONG member of the pair: `200 []` also collapses
// a fourth case — "your assessment, which has simply never changed" — into
// the same answer, which the sibling GET/DELETE routes keep distinct. The
// third case is real data with a real client meaning, so it must stay
// `200 []`; only the out-of-scope three move to 404. That distinction is what
// TestM50SSVCHistory_OwnAssessmentWithoutChangesIsStill200EmptyList pins.
package handler

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// m50SeedAssessmentWithHistory inserts one ssvc_assessments row plus one
// ssvc_assessment_history row for it, as `tenantID`. Both tables are FORCE
// RLS (042 / 043), so the write runs inside a tx with app.current_tenant_id
// bound — the migrator role is subject to the policy like anyone else.
//
// The rows are seeded directly rather than driven through AssessVulnerability
// because the point of the fixture is only that the id EXISTS somewhere the
// caller cannot reach; making it reachable enough for the handler to mint it
// would defeat the purpose.
func m50SeedAssessmentWithHistory(t *testing.T, migDB *sql.DB,
	tenantID, projectID, vulnID uuid.UUID, cveID, marker string) uuid.UUID {
	t.Helper()

	assessmentID := uuid.New()
	historyID := uuid.New()

	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("m50SeedAssessmentWithHistory begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("m50SeedAssessmentWithHistory SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO ssvc_assessments
			(id, project_id, tenant_id, vulnerability_id, cve_id,
			 exploitation, automatable, technical_impact, mission_prevalence,
			 safety_impact, decision)
		VALUES ($1, $2, $3, $4, $5, 'active', 'yes', 'total', 'essential',
			'significant', 'immediate')`,
		assessmentID, projectID, tenantID, vulnID, cveID); err != nil {
		t.Fatalf("m50SeedAssessmentWithHistory insert assessment: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO ssvc_assessment_history
			(id, assessment_id,
			 prev_exploitation, prev_automatable, prev_technical_impact,
			 prev_mission_prevalence, prev_safety_impact, prev_decision,
			 new_exploitation, new_automatable, new_technical_impact,
			 new_mission_prevalence, new_safety_impact, new_decision,
			 change_reason)
		VALUES ($1, $2, 'none', 'no', 'partial', 'minimal', 'minimal', 'defer',
			'active', 'yes', 'total', 'essential', 'significant', 'immediate', $3)`,
		historyID, assessmentID, marker); err != nil {
		t.Fatalf("m50SeedAssessmentWithHistory insert history: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("m50SeedAssessmentWithHistory commit: %v", err)
	}
	return assessmentID
}

// TestM50SSVCHistory_UnknownSiblingAndForeignAnswerAlike is the core M47 W1
// property applied to the one route that was exempt from it: the three
// out-of-scope cells must be ONE answer, and that answer must be the 404 the
// sibling routes give — not a 200 that is indistinguishable from real data.
//
// Pre-fix this test fails on the status assertions (every cell was 200), which
// is what makes it a reproduction rather than a restatement.
func TestM50SSVCHistory_UnknownSiblingAndForeignAnswerAlike(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := ssvcABSeedAll(t, migDB, "m50hist")
	h := ssvcABHandler(appDB)

	// --- positive control: an assessment the caller owns, WITH history. ---
	// Two assessments in a row record exactly one change.
	if code, body := ssvcMBAssess(t, appDB, h, caller.tenantID, caller.projectID, caller.vulnA, "", ssvcMBBody); code != http.StatusOK {
		t.Fatalf("seed first assessment: status %d body %s, want 200", code, body)
	}
	const louder = `{"exploitation":"active","automatable":"yes","technical_impact":"total",` +
		`"mission_prevalence":"essential","safety_impact":"significant","notes":"changed"}`
	if code, body := ssvcMBAssess(t, appDB, h, caller.tenantID, caller.projectID, caller.vulnA, "", louder); code != http.StatusOK {
		t.Fatalf("seed second assessment: status %d body %s, want 200", code, body)
	}

	var ownID uuid.UUID
	if err := ssvcABScanAsTenant(t, migDB, caller.tenantID,
		`SELECT id FROM ssvc_assessments WHERE project_id = $1 AND vulnerability_id = $2`,
		[]any{caller.projectID, caller.vulnA}, &ownID); err != nil {
		t.Fatalf("read own assessment id: %v", err)
	}
	var ownRows int
	if err := ssvcABScanAsTenant(t, migDB, caller.tenantID,
		`SELECT COUNT(*) FROM ssvc_assessment_history WHERE assessment_id = $1`,
		[]any{ownID}, &ownRows); err != nil {
		t.Fatalf("count own history rows: %v", err)
	}
	if ownRows == 0 {
		t.Fatal("precondition: no history row was recorded, so every cell below would be vacuously empty")
	}

	code, positive := ssvcMBHistory(t, appDB, h, caller.tenantID, caller.projectID, ownID)
	if code != http.StatusOK {
		t.Fatalf("POSITIVE CONTROL — own assessment with history: status %d body %s, want 200. "+
			"Without this cell passing, the 404s below prove nothing (an invisible fixture "+
			"answers the same way as a scoped-out one)", code, positive)
	}
	if !strings.Contains(positive, "assessment_id") {
		t.Fatalf("POSITIVE CONTROL — own assessment with history returned %s, want the recorded change", positive)
	}

	// --- the three out-of-scope cells. ---
	sibling := ssvcMBSecondProject(t, migDB, caller.tenantID, "m50hist")
	siblingID := m50SeedAssessmentWithHistory(t, migDB, caller.tenantID, sibling,
		caller.vulnB, caller.cveB, "SIBLING PROJECT SECRET")

	foreign := ssvcABSeedAll(t, migDB, "m50hist-foreign")
	foreignID := m50SeedAssessmentWithHistory(t, migDB, foreign.tenantID, foreign.projectID,
		foreign.vulnA, foreign.cveA, "FOREIGN TENANT SECRET")

	unknownID := uuid.New()

	cells := []struct {
		name string
		id   uuid.UUID
	}{
		{"unassigned id", unknownID},
		{"sibling project of the SAME tenant", siblingID},
		{"foreign tenant", foreignID},
	}

	type answer struct {
		code int
		body string
	}
	answers := make([]answer, len(cells))
	for i, cell := range cells {
		code, body := ssvcMBHistory(t, appDB, h, caller.tenantID, caller.projectID, cell.id)
		if code != http.StatusNotFound {
			t.Errorf("history for %s: status %d body %s, want 404 "+
				"(every sibling sub-resource route — ssvc DELETE, cra-reports, vex-drafts, "+
				"scan-status, vex, licenses, components — answers 404 here; a 200 makes this "+
				"route the odd one out)", cell.name, code, body)
		}
		if strings.Contains(body, "SECRET") || strings.Contains(body, "assessment_id") {
			t.Errorf("history for %s leaked rows: %s", cell.name, body)
		}
		answers[i] = answer{code, body}
	}

	// The M47 W1 property: the three answers must be indistinguishable.
	// Compared against index 0 unconditionally — an "if first == \"\" { first =
	// got; continue }" accumulator would skip the comparison entirely in the
	// one case (all bodies empty) where it must not.
	for i := 1; i < len(answers); i++ {
		if answers[i] != answers[0] {
			t.Errorf("out-of-scope answers differ: %s -> %d %q vs %s -> %d %q — the status and "+
				"body must not tell an unknown id apart from one the caller does not own",
				cells[i].name, answers[i].code, answers[i].body,
				cells[0].name, answers[0].code, answers[0].body)
		}
	}

	// And the answer must be the SIBLING ROUTE's answer, not merely some 404 of
	// its own. DELETE on the same out-of-scope id is the route this one was
	// diverging from; drive it and compare the pair. (Codex R1, Low: this file
	// exercises handlers directly, so it pins status + message rather than the
	// serialised wire bytes. The wire-level equality was measured separately
	// over real HTTP — see the table in this file's package comment.)
	delCode, delBody := ssvcMBDelete(t, appDB, h, caller.tenantID, caller.projectID, unknownID)
	if delCode != answers[0].code || delBody != answers[0].body {
		t.Errorf("history answers %d %q for an out-of-scope id but the sibling DELETE answers "+
			"%d %q — the whole point of this wave is that the two agree",
			answers[0].code, answers[0].body, delCode, delBody)
	}
}

// TestM50SSVCHistory_ZeroUUIDAssessmentIsNotShortCircuitedTo404 (Codex R1,
// High): the first cut of AssessmentInProject answered `false` WITHOUT
// querying when any id was `uuid.Nil`, copying the guard scope_checks.go's
// predicates use. `00000000-0000-0000-0000-000000000000` is a legal
// PostgreSQL uuid, nothing in the schema or in CreateAssessment forbids it as
// a primary key, and `uuid.Parse` accepts it in the route — so an in-scope
// assessment carrying that id read its history fine before this wave and
// would have 404'd after. Contrived, but it is a real row answering with
// someone else's error, which is the defect class this wave is closing.
//
// Note what the guard did NOT do: it was not an oracle (the fast 404 was the
// same whether or not the zero row existed). It was a correctness bug only,
// which is why the fix is to delete the short circuit and let the predicate
// answer.
func TestM50SSVCHistory_ZeroUUIDAssessmentIsNotShortCircuitedTo404(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "m50zero")
	h := ssvcABHandler(appDB)

	// Seed an in-scope assessment (with history) whose PK is the zero uuid.
	zeroID := uuid.Nil
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO ssvc_assessments
			(id, project_id, tenant_id, vulnerability_id, cve_id,
			 exploitation, automatable, technical_impact, mission_prevalence,
			 safety_impact, decision)
		VALUES ($1, $2, $3, $4, $5, 'active', 'yes', 'total', 'essential',
			'significant', 'immediate')`,
		zeroID, seed.projectID, seed.tenantID, seed.vulnA, seed.cveA); err != nil {
		t.Fatalf("insert zero-uuid assessment (if PostgreSQL refused this, the "+
			"guard would be defensible and this test should be deleted): %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO ssvc_assessment_history
			(assessment_id,
			 new_exploitation, new_automatable, new_technical_impact,
			 new_mission_prevalence, new_safety_impact, new_decision,
			 change_reason)
		VALUES ($1, 'active', 'yes', 'total', 'essential', 'significant',
			'immediate', 'ZERO UUID ROW')`, zeroID); err != nil {
		t.Fatalf("insert history for the zero-uuid assessment: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// C27: the seed's tenant cleanup cascades, but the zero uuid is a global
	// singleton — leaving it behind would collide with the next run of this
	// test. Reap it explicitly.
	t.Cleanup(func() {
		cleanupTx, err := migDB.Begin()
		if err != nil {
			t.Errorf("C27 cleanup begin: %v", err)
			return
		}
		defer func() { _ = cleanupTx.Rollback() }()
		if _, err := cleanupTx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
			t.Errorf("C27 cleanup SET LOCAL: %v", err)
			return
		}
		if _, err := cleanupTx.Exec(`DELETE FROM ssvc_assessments WHERE id = $1`, zeroID); err != nil {
			t.Errorf("C27 cleanup delete zero-uuid assessment: %v", err)
			return
		}
		if err := cleanupTx.Commit(); err != nil {
			t.Errorf("C27 cleanup commit: %v", err)
		}
	})

	code, body := ssvcMBHistory(t, appDB, h, seed.tenantID, seed.projectID, zeroID)
	if code != http.StatusOK {
		t.Fatalf("history of an IN-SCOPE assessment whose id is the zero uuid: status %d "+
			"body %s, want 200 — a short circuit on uuid.Nil turns a real, readable row "+
			"into someone else's 404", code, body)
	}
	if !strings.Contains(body, "ZERO UUID ROW") {
		t.Errorf("history of the zero-uuid assessment = %s, want the recorded change", body)
	}
}

// TestM50SSVCHistory_OwnAssessmentWithoutChangesIsStill200EmptyList is the
// half the 404 must NOT eat.
//
// "This assessment exists in your project and has never been changed" is real
// data with a real client meaning (apps/web/src/lib/api.ts `ssvc.getHistory`
// types the response as an array and coalesces a null body to `[]`; a 404
// would surface as a thrown error). Collapsing it into the out-of-scope 404
// would turn a correct empty answer into a lie about the assessment's
// existence — the exact defect this wave is fixing, mirrored.
func TestM50SSVCHistory_OwnAssessmentWithoutChangesIsStill200EmptyList(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := ssvcABSeedAll(t, migDB, "m50fresh")
	h := ssvcABHandler(appDB)

	// Exactly ONE assessment: nothing has changed yet, so there is no history.
	if code, body := ssvcMBAssess(t, appDB, h, seed.tenantID, seed.projectID, seed.vulnA, "", ssvcMBBody); code != http.StatusOK {
		t.Fatalf("assess: status %d body %s, want 200", code, body)
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
	if historyRows != 0 {
		t.Fatalf("precondition: a single assessment recorded %d history rows, want 0 "+
			"(this test needs the never-changed shape)", historyRows)
	}

	code, body := ssvcMBHistory(t, appDB, h, seed.tenantID, seed.projectID, assessmentID)
	if code != http.StatusOK {
		t.Fatalf("history of an OWN, never-changed assessment: status %d body %s, want 200 "+
			"(the out-of-scope 404 must not swallow this case)", code, body)
	}
	if strings.TrimSpace(body) != "[]" {
		t.Errorf("history of an OWN, never-changed assessment = %q, want %q", body, "[]")
	}
}
