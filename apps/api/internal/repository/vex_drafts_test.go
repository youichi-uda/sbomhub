package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// validEvidence is a helper that produces a non-empty JSONB evidence
// array so each test does not have to spell out the full citation
// shape. The CHECK constraint at the DB layer requires
// jsonb_array_length(evidence) > 0; this satisfies that.
func validEvidence() json.RawMessage {
	return json.RawMessage(`[{"kind":"advisory_excerpt","ref":"00000000-0000-0000-0000-000000000001"}]`)
}

// TestVEXDraftsRepository_Insert_PassesTenantID asserts the INSERT
// column ordering matches migration 035 and binds tenant_id at
// position 2 -- the same load-bearing position that the RLS WITH
// CHECK policy compares against. A mis-positioned bind would silently
// land tenant_id wrong, which the RLS layer would reject at runtime
// with a confusing error, or, worse, in a future world where RLS is
// removed, would leak rows across tenants.
func TestVEXDraftsRepository_Insert_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	sbomID := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	excerptID := uuid.New()
	reachID := uuid.New()
	llmID := uuid.New()
	createdBy := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()
	conf := 0.87
	ev := validEvidence()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO vex_drafts")).
		WithArgs(
			rowID,             // $1  id
			tenantID,          // $2  tenant_id
			projectID,         // $3  project_id
			sbomID,            // $4  sbom_id
			componentID,       // $5  component_id
			vulnID,            // $6  vulnerability_id
			"CVE-2025-99999",  // $7  cve_id
			"not_affected",    // $8  state
			"code_not_reachable", // $9  justification
			"detail body",     // $10 detail
			conf,              // $11 confidence
			"openai",          // $12 provider
			"gpt-4o",          // $13 model
			"p" + repeatHex(63), // $14 prompt_hash (64 hex chars)
			"r" + repeatHex(63), // $15 response_hash
			[]byte(ev),        // $16 evidence
			excerptID,         // $17 advisory_excerpt_id
			reachID,           // $18 reachability_result_id
			llmID,             // $19 llm_call_id
			"pending",         // $20 decision (default)
			nil,               // $21 decision_by
			nil,               // $22 decision_at
			nil,               // $23 decision_note
			createdBy,         // $24 created_by
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(rowID, now, now))

	d := &VEXDraft{
		ID:                   rowID,
		TenantID:             tenantID,
		ProjectID:            projectID,
		SBOMID:               &sbomID,
		ComponentID:          componentID,
		VulnerabilityID:      vulnID,
		CVEID:                "CVE-2025-99999",
		State:                "not_affected",
		Justification:        "code_not_reachable",
		Detail:               "detail body",
		Confidence:           &conf,
		Provider:             "openai",
		Model:                "gpt-4o",
		PromptHash:           "p" + repeatHex(63),
		ResponseHash:         "r" + repeatHex(63),
		Evidence:             ev,
		AdvisoryExcerptID:    &excerptID,
		ReachabilityResultID: &reachID,
		LLMCallID:            &llmID,
		CreatedBy:            &createdBy,
	}
	if err := repo.Insert(context.Background(), d); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if d.Decision != "pending" {
		t.Errorf("expected Insert to default Decision to pending, got %q", d.Decision)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestVEXDraftsRepository_Insert_RejectsZeroTenant pins the fail-fast
// on missing tenant -- same rationale as the other M1 repositories.
func TestVEXDraftsRepository_Insert_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	err = repo.Insert(context.Background(), &VEXDraft{
		// TenantID intentionally zero
		ProjectID:       uuid.New(),
		ComponentID:     uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2025-1",
		State:           "under_investigation",
		Evidence:        validEvidence(),
	})
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestVEXDraftsRepository_Insert_RejectsNil guards the nil-pointer
// case.
func TestVEXDraftsRepository_Insert_RejectsNil(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	if err := repo.Insert(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil VEXDraft, got nil")
	}
}

// TestVEXDraftsRepository_Insert_RejectsEmptyRequired pins the per-
// field validation. project_id / component_id / vulnerability_id /
// cve_id / state are all required.
func TestVEXDraftsRepository_Insert_RejectsEmptyRequired(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	ev := validEvidence()

	cases := []struct {
		name string
		d    *VEXDraft
	}{
		{"no project_id", &VEXDraft{TenantID: tenantID, ComponentID: componentID, VulnerabilityID: vulnID, CVEID: "CVE-2025-1", State: "under_investigation", Evidence: ev}},
		{"no component_id", &VEXDraft{TenantID: tenantID, ProjectID: projectID, VulnerabilityID: vulnID, CVEID: "CVE-2025-1", State: "under_investigation", Evidence: ev}},
		{"no vulnerability_id", &VEXDraft{TenantID: tenantID, ProjectID: projectID, ComponentID: componentID, CVEID: "CVE-2025-1", State: "under_investigation", Evidence: ev}},
		{"no cve_id", &VEXDraft{TenantID: tenantID, ProjectID: projectID, ComponentID: componentID, VulnerabilityID: vulnID, State: "under_investigation", Evidence: ev}},
		{"no state", &VEXDraft{TenantID: tenantID, ProjectID: projectID, ComponentID: componentID, VulnerabilityID: vulnID, CVEID: "CVE-2025-1", Evidence: ev}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := repo.Insert(context.Background(), tc.d); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestVEXDraftsRepository_Insert_RejectsConfidenceOutOfRange pins the
// [0,1] range check. The DB CHECK constraint also catches this but
// we validate locally so a buggy provider surfaces as a repository
// error, not a pq constraint error.
func TestVEXDraftsRepository_Insert_RejectsConfidenceOutOfRange(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	bad := 1.5

	if err := repo.Insert(context.Background(), &VEXDraft{
		TenantID:        tenantID,
		ProjectID:       projectID,
		ComponentID:     componentID,
		VulnerabilityID: vulnID,
		CVEID:           "CVE-2025-1",
		State:           "not_affected",
		Confidence:      &bad,
		Evidence:        validEvidence(),
	}); err == nil {
		t.Fatal("expected error for confidence > 1, got nil")
	}

	worse := -0.1
	if err := repo.Insert(context.Background(), &VEXDraft{
		TenantID:        tenantID,
		ProjectID:       projectID,
		ComponentID:     componentID,
		VulnerabilityID: vulnID,
		CVEID:           "CVE-2025-1",
		State:           "not_affected",
		Confidence:      &worse,
		Evidence:        validEvidence(),
	}); err == nil {
		t.Fatal("expected error for confidence < 0, got nil")
	}
}

// TestVEXDraftsRepository_Insert_RequiresEvidence pins the load-
// bearing "no AI output without evidence" rule
// (PRODUCT_REBOOT_PLAN.md §8.5). The DB CHECK also catches this but
// the local guard turns the error into a clearer message and skips
// the round-trip.
func TestVEXDraftsRepository_Insert_RequiresEvidence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()

	cases := []struct {
		name string
		ev   json.RawMessage
	}{
		{"nil evidence", nil},
		{"empty bytes", json.RawMessage("")},
		{"empty array", json.RawMessage("[]")},
		{"not an array (object)", json.RawMessage(`{"kind":"x"}`)},
		{"not an array (string)", json.RawMessage(`"single"`)},
		{"malformed json", json.RawMessage(`[`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &VEXDraft{
				TenantID:        tenantID,
				ProjectID:       projectID,
				ComponentID:     componentID,
				VulnerabilityID: vulnID,
				CVEID:           "CVE-2025-1",
				State:           "not_affected",
				Evidence:        tc.ev,
			}
			if err := repo.Insert(context.Background(), d); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued for empty-evidence cases: %v", err)
	}
}

// TestVEXDraftsRepository_Insert_AssignsIDAndDecision verifies the
// repository allocates a UUID when none is supplied AND defaults
// Decision to 'pending'.
func TestVEXDraftsRepository_Insert_AssignsIDAndDecision(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	now := time.Now().UTC()
	ev := validEvidence()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO vex_drafts")).
		WithArgs(
			sqlmock.AnyArg(), // $1  id (generated)
			tenantID,         // $2
			projectID,        // $3
			nil,              // $4  sbom_id (nil)
			componentID,      // $5
			vulnID,           // $6
			"CVE-2025-1",     // $7
			"under_investigation", // $8
			nil,              // $9  justification (empty -> NULL)
			nil,              // $10 detail (empty -> NULL)
			nil,              // $11 confidence (nil)
			nil,              // $12 provider (empty -> NULL)
			nil,              // $13 model
			nil,              // $14 prompt_hash
			nil,              // $15 response_hash
			[]byte(ev),       // $16 evidence
			nil,              // $17 advisory_excerpt_id
			nil,              // $18 reachability_result_id
			nil,              // $19 llm_call_id
			"pending",        // $20 decision default
			nil,              // $21 decision_by
			nil,              // $22 decision_at
			nil,              // $23 decision_note
			nil,              // $24 created_by
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(uuid.New(), now, now))

	d := &VEXDraft{
		TenantID:        tenantID,
		ProjectID:       projectID,
		ComponentID:     componentID,
		VulnerabilityID: vulnID,
		CVEID:           "CVE-2025-1",
		State:           "under_investigation",
		Evidence:        ev,
	}
	if err := repo.Insert(context.Background(), d); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if d.ID == uuid.Nil {
		t.Fatal("expected ID to be populated after Insert, got uuid.Nil")
	}
	if d.Decision != "pending" {
		t.Errorf("expected default Decision pending, got %q", d.Decision)
	}
	if d.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be populated after Insert, got zero")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestVEXDraftsRepository_Insert_WrapsDBError ensures driver errors
// surface with context.
func TestVEXDraftsRepository_Insert_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO vex_drafts")).
		WillReturnError(sql.ErrConnDone)

	err = repo.Insert(context.Background(), &VEXDraft{
		TenantID:        uuid.New(),
		ProjectID:       uuid.New(),
		ComponentID:     uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2025-1",
		State:           "under_investigation",
		Evidence:        validEvidence(),
	})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestVEXDraftsRepository_Get_ReturnsNilOnNoRows pins down the
// (*VEXDraft, error) contract for the "did we already draft this"
// check.
func TestVEXDraftsRepository_Get_ReturnsNilOnNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta("FROM vex_drafts")).
		WithArgs(tenantID, id).
		WillReturnError(sql.ErrNoRows)

	got, err := repo.Get(context.Background(), tenantID, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result, got %+v", got)
	}
}

// TestVEXDraftsRepository_Get_RejectsZero pins the fail-fast on
// missing tenant / id.
func TestVEXDraftsRepository_Get_RejectsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	if _, err := repo.Get(context.Background(), uuid.Nil, uuid.New()); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.Get(context.Background(), uuid.New(), uuid.Nil); err == nil {
		t.Fatal("expected error for zero id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestVEXDraftsRepository_ListByProject_PassesTenantID asserts the
// WHERE clause binds tenant_id at $1, project_id at $2, and applies
// LIMIT/OFFSET defaults.
func TestVEXDraftsRepository_ListByProject_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()

	rowCols := []string{
		"id", "tenant_id",
		"project_id", "sbom_id", "component_id", "vulnerability_id",
		"cve_id",
		"state", "justification", "detail", "confidence",
		"provider", "model", "prompt_hash", "response_hash",
		"evidence",
		"advisory_excerpt_id", "reachability_result_id", "llm_call_id",
		"decision", "decision_by", "decision_at", "decision_note",
		"created_by",
		"created_at", "updated_at",
	}

	mock.ExpectQuery(`SELECT[\s\S]+FROM vex_drafts[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2`).
		WithArgs(tenantID, projectID, 200, 0).
		WillReturnRows(sqlmock.NewRows(rowCols).AddRow(
			rowID, tenantID,
			projectID, nil, componentID, vulnID,
			"CVE-2025-1",
			"not_affected", "code_not_reachable", "ok", 0.9,
			"openai", "gpt-4o", nil, nil,
			[]byte(validEvidence()),
			nil, nil, nil,
			"pending", nil, nil, nil,
			nil,
			now, now,
		))

	out, err := repo.ListByProject(context.Background(), tenantID, projectID, VEXDraftListFilter{})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if out[0].TenantID != tenantID {
		t.Errorf("expected tenant_id %s, got %s", tenantID, out[0].TenantID)
	}
	if out[0].Confidence == nil || *out[0].Confidence != 0.9 {
		t.Errorf("unexpected confidence: %v", out[0].Confidence)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestVEXDraftsRepository_ListByProject_RejectsZeroTenant mirrors the
// read-side fail-fast.
func TestVEXDraftsRepository_ListByProject_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	if _, err := repo.ListByProject(context.Background(), uuid.Nil, uuid.New(), VEXDraftListFilter{}); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.ListByProject(context.Background(), uuid.New(), uuid.Nil, VEXDraftListFilter{}); err == nil {
		t.Fatal("expected error for zero project_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestVEXDraftsRepository_ListByProject_AppliesFilters covers the
// dynamic WHERE-builder for the (cve_id, decision) filter pair.
func TestVEXDraftsRepository_ListByProject_AppliesFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	rowCols := []string{
		"id", "tenant_id",
		"project_id", "sbom_id", "component_id", "vulnerability_id",
		"cve_id",
		"state", "justification", "detail", "confidence",
		"provider", "model", "prompt_hash", "response_hash",
		"evidence",
		"advisory_excerpt_id", "reachability_result_id", "llm_call_id",
		"decision", "decision_by", "decision_at", "decision_note",
		"created_by",
		"created_at", "updated_at",
	}

	mock.ExpectQuery(`SELECT[\s\S]+FROM vex_drafts[\s\S]+cve_id = \$3[\s\S]+decision = \$4`).
		WithArgs(tenantID, projectID, "CVE-2025-1", "pending", 10, 5).
		WillReturnRows(sqlmock.NewRows(rowCols))

	out, err := repo.ListByProject(context.Background(), tenantID, projectID, VEXDraftListFilter{
		CVEID:    "CVE-2025-1",
		Decision: "pending",
		Limit:    10,
		Offset:   5,
	})
	if err != nil {
		t.Fatalf("ListByProject with filters: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(out))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestVEXDraftsRepository_UpdateDecision_PassesArgs pins the UPDATE
// statement's argument shape. tenant_id at $1 (load-bearing for the
// belt-and-braces tenant scope), id at $2, decision lifecycle fields
// at $3..$6, then the COALESCE-overwrite slots for the edited case
// at $7..$9.
func TestVEXDraftsRepository_UpdateDecision_PassesArgs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()
	by := uuid.New()
	when := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	editedState := "affected"
	editedJust := "vulnerable_code_used"
	editedDetail := "operator override: function exposed via /api/v1/x"

	mock.ExpectExec(regexp.QuoteMeta("UPDATE vex_drafts SET")).
		WithArgs(
			tenantID,        // $1
			id,              // $2
			"edited",        // $3
			by,              // $4
			when,            // $5
			"reviewed",      // $6 decision_note
			editedState,     // $7 state COALESCE
			editedJust,      // $8 justification COALESCE
			editedDetail,    // $9 detail COALESCE
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.UpdateDecision(context.Background(), tenantID, id, VEXDraftDecisionUpdate{
		Decision:            "edited",
		DecisionBy:          by,
		DecisionAt:          when,
		DecisionNote:        "reviewed",
		EditedState:         &editedState,
		EditedJustification: &editedJust,
		EditedDetail:        &editedDetail,
	})
	if err != nil {
		t.Fatalf("UpdateDecision: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestVEXDraftsRepository_UpdateDecision_ApprovedKeepsAIFields verifies
// that an 'approved' decision leaves EditedState / EditedJustification /
// EditedDetail at NULL (-> COALESCE keeps existing AI values). This is
// the contract that protects the AI evidence trail.
func TestVEXDraftsRepository_UpdateDecision_ApprovedKeepsAIFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()
	by := uuid.New()

	mock.ExpectExec(regexp.QuoteMeta("UPDATE vex_drafts SET")).
		WithArgs(
			tenantID,         // $1
			id,               // $2
			"approved",       // $3
			by,               // $4
			sqlmock.AnyArg(), // $5 decision_at (defaulted to NOW())
			nil,              // $6 decision_note (empty -> NULL)
			nil,              // $7 state COALESCE (nil pointer -> NULL -> keep)
			nil,              // $8 justification COALESCE
			nil,              // $9 detail COALESCE
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.UpdateDecision(context.Background(), tenantID, id, VEXDraftDecisionUpdate{
		Decision:   "approved",
		DecisionBy: by,
	})
	if err != nil {
		t.Fatalf("UpdateDecision: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestVEXDraftsRepository_UpdateDecision_RejectsInvalidDecision pins
// the decision allow-list ('approved' | 'edited' | 'rejected'). The
// DB CHECK also catches this but the local guard turns a pq error
// into a clearer message and skips the round-trip.
func TestVEXDraftsRepository_UpdateDecision_RejectsInvalidDecision(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	cases := []string{"", "pending", "approve", "DELETED", "ok"}
	for _, dec := range cases {
		t.Run("decision="+dec, func(t *testing.T) {
			err := repo.UpdateDecision(context.Background(), uuid.New(), uuid.New(), VEXDraftDecisionUpdate{
				Decision:   dec,
				DecisionBy: uuid.New(),
			})
			if err == nil {
				t.Fatalf("expected error for decision %q, got nil", dec)
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestVEXDraftsRepository_UpdateDecision_RejectsZero pins the per-
// argument fail-fast.
func TestVEXDraftsRepository_UpdateDecision_RejectsZero(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()
	by := uuid.New()

	if err := repo.UpdateDecision(context.Background(), uuid.Nil, id, VEXDraftDecisionUpdate{Decision: "approved", DecisionBy: by}); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := repo.UpdateDecision(context.Background(), tenantID, uuid.Nil, VEXDraftDecisionUpdate{Decision: "approved", DecisionBy: by}); err == nil {
		t.Fatal("expected error for zero id, got nil")
	}
	if err := repo.UpdateDecision(context.Background(), tenantID, id, VEXDraftDecisionUpdate{Decision: "approved"}); err == nil {
		t.Fatal("expected error for zero decision_by, got nil")
	}
}

// TestVEXDraftsRepository_UpdateDecision_NoRowsErrors verifies the
// "silent no-op" guard: when the UPDATE matches zero rows (wrong
// id, wrong tenant), the repository returns a wrapped sql.ErrNoRows
// so handlers can distinguish "decision landed" from "id not found".
func TestVEXDraftsRepository_UpdateDecision_NoRowsErrors(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVEXDraftsRepository(db)
	mock.ExpectExec(regexp.QuoteMeta("UPDATE vex_drafts SET")).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.UpdateDecision(context.Background(), uuid.New(), uuid.New(), VEXDraftDecisionUpdate{
		Decision:   "approved",
		DecisionBy: uuid.New(),
	})
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected wrapped sql.ErrNoRows, got %v", err)
	}
}

// repeatHex returns a string of n hex characters built from 'a'.
// Useful to fill the CHAR(64) prompt_hash / response_hash columns
// in tests without computing a real SHA-256.
func repeatHex(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}
