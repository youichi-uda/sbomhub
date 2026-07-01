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

// validMetiEvidence returns a non-empty JSONB evidence array. Used by
// the happy-path tests that exercise an "achieved" verdict (the
// evaluator must cite SOMETHING). Empty / not_applicable cases use
// json.RawMessage(`[]`) inline to make the intent explicit.
func validMetiEvidence() json.RawMessage {
	return json.RawMessage(`[{"kind":"ci_config","ref":"github_actions"},{"kind":"sbom_history","ref":"last_30d"}]`)
}

// boolPtr returns a *bool literal helper -- json package's bool
// pointer-to-literal pattern is more readable than introducing a tiny
// helper function call inline for every test.
func metiBoolPtr(b bool) *bool { return &b }

// TestMetiAssessmentsRepository_Upsert_PassesTenantID asserts the
// INSERT column ordering matches migration 039 and binds tenant_id at
// position 2 -- the same load-bearing position that the RLS WITH
// CHECK policy compares against. A mis-positioned bind would silently
// land tenant_id wrong, which the RLS layer would reject at runtime
// with a confusing error, or, worse, in a future world where RLS is
// removed, would leak rows across tenants. Mirrors the cra_reports
// regression test for the same load-bearing invariant.
func TestMetiAssessmentsRepository_Upsert_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()
	ev := validMetiEvidence()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO meti_assessments")).
		WithArgs(
			rowID,            // $1 id
			tenantID,         // $2 tenant_id
			projectID,        // $3 project_id
			"ENV-SBOM-001",   // $4 criterion_id
			"env_setup",      // $5 criterion_phase
			"achieved",       // $6 status
			[]byte(ev),       // $7 evidence
			"1.0.0",          // $8 evaluator_version
			sqlmock.AnyArg(), // $9 evaluated_at (caller-supplied)
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "evaluated_at", "created_at", "updated_at"}).
			AddRow(rowID, now, now, now))

	a := &MetiAssessment{
		ID:               rowID,
		TenantID:         tenantID,
		ProjectID:        projectID,
		CriterionID:      "ENV-SBOM-001",
		CriterionPhase:   "env_setup",
		Status:           "achieved",
		Evidence:         ev,
		EvaluatorVersion: "1.0.0",
		EvaluatedAt:      now,
	}
	if err := repo.Upsert(context.Background(), a); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_Upsert_OnConflict pins the
// ON CONFLICT (tenant_id, project_id, criterion_id) DO UPDATE clause
// so a regression that drops or alters the conflict target fails this
// test. The conflict target IS the UNIQUE constraint that makes the
// "re-evaluation overwrites prior verdict" semantic work.
//
// The test also asserts that the override_* / improvement_action
// columns are NOT in the SET clause -- a re-evaluation must preserve
// the operator's prior override (see migration 039 header).
func TestMetiAssessmentsRepository_Upsert_OnConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(`INSERT INTO meti_assessments[\s\S]+ON CONFLICT \(tenant_id, project_id, criterion_id\) DO UPDATE SET[\s\S]+criterion_phase[\s\S]+status[\s\S]+evidence[\s\S]+evaluator_version[\s\S]+evaluated_at[\s\S]+updated_at`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "evaluated_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), now, now, now))

	a := &MetiAssessment{
		TenantID:       tenantID,
		ProjectID:      projectID,
		CriterionID:    "ENV-SBOM-001",
		CriterionPhase: "env_setup",
		Status:         "achieved",
		Evidence:       validMetiEvidence(),
	}
	if err := repo.Upsert(context.Background(), a); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_Upsert_RejectsZero pins the per-
// argument fail-fast. tenant_id / project_id / criterion_id /
// criterion_phase are all required.
func TestMetiAssessmentsRepository_Upsert_RejectsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	ev := validMetiEvidence()

	cases := []struct {
		name string
		a    *MetiAssessment
	}{
		{"nil", nil},
		{"no tenant_id", &MetiAssessment{ProjectID: projectID, CriterionID: "C1", CriterionPhase: "env_setup", Status: "achieved", Evidence: ev}},
		{"no project_id", &MetiAssessment{TenantID: tenantID, CriterionID: "C1", CriterionPhase: "env_setup", Status: "achieved", Evidence: ev}},
		{"no criterion_id", &MetiAssessment{TenantID: tenantID, ProjectID: projectID, CriterionPhase: "env_setup", Status: "achieved", Evidence: ev}},
		{"no criterion_phase", &MetiAssessment{TenantID: tenantID, ProjectID: projectID, CriterionID: "C1", Status: "achieved", Evidence: ev}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := repo.Upsert(context.Background(), tc.a); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestMetiAssessmentsRepository_Upsert_EvidenceNormalisation pins the
// "must be a JSON array" rule and the nil-evidence normalisation. F4
// regression-class guard variant: METI rows can legitimately carry
// evidence='[]' for not_applicable / needs_review cases (unlike
// vex_drafts / cra_reports where empty is forbidden). The repository
// normalises nil to '[]' so callers do not have to remember; non-
// array shapes are rejected locally so the error is "must be a JSON
// array" rather than "check_violation on meti_assessments_evidence_check".
func TestMetiAssessmentsRepository_Upsert_EvidenceNormalisation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Now().UTC()

	// nil evidence -> normalised to '[]' and the row inserts cleanly.
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO meti_assessments")).
		WithArgs(
			sqlmock.AnyArg(), // $1 id
			tenantID,         // $2
			projectID,        // $3
			"NA-001",         // $4 criterion_id
			"sbom_creation",  // $5 criterion_phase
			"not_applicable", // $6 status
			[]byte("[]"),     // $7 evidence -- normalised from nil
			nil,              // $8 evaluator_version (empty -> NULL)
			nil,              // $9 evaluated_at (zero -> NULL -> COALESCE NOW())
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "evaluated_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), now, now, now))

	if err := repo.Upsert(context.Background(), &MetiAssessment{
		TenantID:       tenantID,
		ProjectID:      projectID,
		CriterionID:    "NA-001",
		CriterionPhase: "sbom_creation",
		Status:         "not_applicable",
		Evidence:       nil,
	}); err != nil {
		t.Fatalf("Upsert with nil evidence: %v", err)
	}

	// Non-array shapes rejected locally (no SQL issued).
	for _, badEv := range []json.RawMessage{
		json.RawMessage(`{"kind":"x"}`),
		json.RawMessage(`"single"`),
		json.RawMessage(`42`),
		json.RawMessage(`[`), // malformed
	} {
		if err := repo.Upsert(context.Background(), &MetiAssessment{
			TenantID:       tenantID,
			ProjectID:      projectID,
			CriterionID:    "BAD-EV",
			CriterionPhase: "env_setup",
			Status:         "achieved",
			Evidence:       badEv,
		}); err == nil {
			t.Fatalf("expected error for non-array evidence %q, got nil", string(badEv))
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_Upsert_DefaultsStatus pins the
// Status='needs_review' default when the caller omits it. The DB
// column has the same default but applying it locally too keeps the
// in-memory struct in sync with the persisted row.
func TestMetiAssessmentsRepository_Upsert_DefaultsStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO meti_assessments")).
		WithArgs(
			sqlmock.AnyArg(), // $1 id (generated)
			tenantID,
			projectID,
			"NEW-001",
			"env_setup",
			"needs_review", // $6 default
			[]byte("[]"),   // $7 evidence normalised
			nil,            // $8 evaluator_version
			nil,            // $9 evaluated_at
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "evaluated_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), now, now, now))

	a := &MetiAssessment{
		TenantID:       tenantID,
		ProjectID:      projectID,
		CriterionID:    "NEW-001",
		CriterionPhase: "env_setup",
		// Status intentionally omitted
	}
	if err := repo.Upsert(context.Background(), a); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if a.Status != "needs_review" {
		t.Errorf("expected Upsert to default Status to needs_review, got %q", a.Status)
	}
	if a.ID == uuid.Nil {
		t.Fatal("expected ID to be populated after Upsert")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_Upsert_WrapsDBError ensures driver
// errors surface with context.
func TestMetiAssessmentsRepository_Upsert_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO meti_assessments")).
		WillReturnError(sql.ErrConnDone)

	err = repo.Upsert(context.Background(), &MetiAssessment{
		TenantID:       uuid.New(),
		ProjectID:      uuid.New(),
		CriterionID:    "C1",
		CriterionPhase: "env_setup",
		Status:         "achieved",
		Evidence:       validMetiEvidence(),
	})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestMetiAssessmentsRepository_Get_PassesCompositeKey asserts the
// SELECT binds tenant_id / project_id / criterion_id in the right
// order. The composite key is what the M3-4 handler holds from the
// URL path; binding it wrong (e.g. swapping tenant_id and project_id)
// would silently disclose another tenant's rows once RLS is loosened.
func TestMetiAssessmentsRepository_Get_PassesCompositeKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(`SELECT[\s\S]+FROM meti_assessments[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2 AND criterion_id = \$3`).
		WithArgs(tenantID, projectID, "ENV-SBOM-001").
		WillReturnRows(sqlmock.NewRows(metiAssessmentCols).AddRow(
			rowID, tenantID, projectID,
			"ENV-SBOM-001", "env_setup",
			"achieved", []byte(validMetiEvidence()),
			"1.0.0", now,
			nil, nil, nil, nil,
			nil,
			now, now,
		))

	got, err := repo.Get(context.Background(), tenantID, projectID, "ENV-SBOM-001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected row, got nil")
	}
	if got.TenantID != tenantID || got.ProjectID != projectID || got.CriterionID != "ENV-SBOM-001" {
		t.Errorf("composite key mismatch: %+v", got)
	}
	if got.Status != "achieved" {
		t.Errorf("expected status achieved, got %q", got.Status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_Get_ReturnsNilOnNoRows pins down the
// (*MetiAssessment, error) contract.
func TestMetiAssessmentsRepository_Get_ReturnsNilOnNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	mock.ExpectQuery(regexp.QuoteMeta("FROM meti_assessments")).
		WillReturnError(sql.ErrNoRows)

	got, err := repo.Get(context.Background(), uuid.New(), uuid.New(), "X")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

// TestMetiAssessmentsRepository_Get_RejectsZero pins the fail-fast on
// missing composite-key parts.
func TestMetiAssessmentsRepository_Get_RejectsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	if _, err := repo.Get(context.Background(), uuid.Nil, uuid.New(), "X"); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.Get(context.Background(), uuid.New(), uuid.Nil, "X"); err == nil {
		t.Fatal("expected error for zero project_id, got nil")
	}
	if _, err := repo.Get(context.Background(), uuid.New(), uuid.New(), ""); err == nil {
		t.Fatal("expected error for empty criterion_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// metiAssessmentCols is the column list returned by SELECT in
// Get/List. Kept in sync with scanMetiAssessmentRow's Scan call.
var metiAssessmentCols = []string{
	"id", "tenant_id", "project_id",
	"criterion_id", "criterion_phase",
	"status", "evidence",
	"evaluator_version", "evaluated_at",
	"override_status", "override_by", "override_at", "override_note",
	"improvement_action",
	"created_at", "updated_at",
}

// TestMetiAssessmentsRepository_ListByProject_PassesTenantID asserts
// the WHERE clause binds tenant_id at $1, project_id at $2, and
// applies LIMIT/OFFSET defaults (F24 pattern).
func TestMetiAssessmentsRepository_ListByProject_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(`SELECT[\s\S]+FROM meti_assessments[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2[\s\S]+ORDER BY criterion_phase ASC, criterion_id ASC[\s\S]+LIMIT \$3 OFFSET \$4`).
		WithArgs(tenantID, projectID, 100, 0). // F24-pattern default limit
		WillReturnRows(sqlmock.NewRows(metiAssessmentCols).AddRow(
			rowID, tenantID, projectID,
			"ENV-SBOM-001", "env_setup",
			"achieved", []byte(validMetiEvidence()),
			"1.0.0", now,
			nil, nil, nil, nil,
			nil,
			now, now,
		))

	out, err := repo.ListByProject(context.Background(), tenantID, projectID, MetiAssessmentListFilter{})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if out[0].TenantID != tenantID {
		t.Errorf("expected tenant_id %s, got %s", tenantID, out[0].TenantID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_ListByProject_RejectsZero mirrors the
// read-side fail-fast.
func TestMetiAssessmentsRepository_ListByProject_RejectsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	if _, err := repo.ListByProject(context.Background(), uuid.Nil, uuid.New(), MetiAssessmentListFilter{}); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.ListByProject(context.Background(), uuid.New(), uuid.Nil, MetiAssessmentListFilter{}); err == nil {
		t.Fatal("expected error for zero project_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestMetiAssessmentsRepository_ListByProject_AppliesFilters covers
// the dynamic WHERE-builder for the full filter set (criterion_phase,
// status, HasOverride). HasOverride compiles to an IS NULL / IS NOT
// NULL clause (no bind parameter) so the argument count only grows
// for the bind-shaped filters.
func TestMetiAssessmentsRepository_ListByProject_AppliesFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectQuery(`SELECT[\s\S]+FROM meti_assessments[\s\S]+criterion_phase = \$3[\s\S]+status = \$4[\s\S]+override_status IS NOT NULL[\s\S]+LIMIT \$5 OFFSET \$6`).
		WithArgs(tenantID, projectID, "env_setup", "achieved", 10, 5).
		WillReturnRows(sqlmock.NewRows(metiAssessmentCols))

	out, err := repo.ListByProject(context.Background(), tenantID, projectID, MetiAssessmentListFilter{
		CriterionPhase: "env_setup",
		Status:         "achieved",
		HasOverride:    metiBoolPtr(true),
		Limit:          10,
		Offset:         5,
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

// TestMetiAssessmentsRepo_ListByProject_LimitClamp pins the F24-
// pattern defense-in-depth clamp. The repository constants
// (metiAssessmentsListDefaultLimit=100, metiAssessmentsListMaxLimit=500)
// must be honored regardless of caller hygiene.
func TestMetiAssessmentsRepo_ListByProject_LimitClamp(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectQuery(`SELECT[\s\S]+FROM meti_assessments[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2[\s\S]+LIMIT \$3 OFFSET \$4`).
		WithArgs(tenantID, projectID, 500, 0).
		WillReturnRows(sqlmock.NewRows(metiAssessmentCols))

	if _, err := repo.ListByProject(context.Background(), tenantID, projectID, MetiAssessmentListFilter{
		Limit: 10000,
	}); err != nil {
		t.Fatalf("ListByProject with oversized limit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected SQL LIMIT to be clamped to 500: %v", err)
	}
}

// TestMetiAssessmentsRepository_CountByProject_PassesTenantID pins
// the F28-pattern X-Total-Count helper.
func TestMetiAssessmentsRepository_CountByProject_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM meti_assessments[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2`).
		WithArgs(tenantID, projectID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))

	n, err := repo.CountByProject(context.Background(), tenantID, projectID, MetiAssessmentListFilter{})
	if err != nil {
		t.Fatalf("CountByProject: %v", err)
	}
	if n != 42 {
		t.Errorf("expected count 42, got %d", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_CountByProject_AppliesFilters ensures
// the filter shape matches ListByProject so X-Total-Count and the
// page length are adjudicated on the same units (M1 F29 regression-
// class guard). Both queries share buildMetiAssessmentWhere so a drift
// here would mean ListByProject also drifted.
func TestMetiAssessmentsRepository_CountByProject_AppliesFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM meti_assessments[\s\S]+criterion_phase = \$3[\s\S]+status = \$4[\s\S]+override_status IS NULL`).
		WithArgs(tenantID, projectID, "sbom_creation", "not_achieved").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))

	n, err := repo.CountByProject(context.Background(), tenantID, projectID, MetiAssessmentListFilter{
		CriterionPhase: "sbom_creation",
		Status:         "not_achieved",
		HasOverride:    metiBoolPtr(false),
	})
	if err != nil {
		t.Fatalf("CountByProject with filters: %v", err)
	}
	if n != 7 {
		t.Errorf("expected count 7, got %d", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_CountByProject_RejectsZero pins the
// read-side fail-fast.
func TestMetiAssessmentsRepository_CountByProject_RejectsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	if _, err := repo.CountByProject(context.Background(), uuid.Nil, uuid.New(), MetiAssessmentListFilter{}); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.CountByProject(context.Background(), uuid.New(), uuid.Nil, MetiAssessmentListFilter{}); err == nil {
		t.Fatal("expected error for zero project_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestMetiAssessmentsRepository_OverrideStatus_PassesArgs pins the
// UPDATE statement's argument shape. tenant_id at $1, project_id at
// $2, criterion_id at $3 (the composite key), then override_status /
// override_by / override_at / override_note / improvement_action at
// $4..$8.
func TestMetiAssessmentsRepository_OverrideStatus_PassesArgs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	by := uuid.New()
	when := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	plan := "Adopt Renovate config by 2026-09; track via JIRA SEC-123"

	mock.ExpectExec(regexp.QuoteMeta("UPDATE meti_assessments SET")).
		WithArgs(
			tenantID,                   // $1
			projectID,                  // $2
			"ENV-SBOM-001",             // $3
			"achieved",                 // $4 override_status
			by,                         // $5 override_by
			when,                       // $6 override_at
			"operator override review", // $7 override_note
			plan,                       // $8 improvement_action COALESCE
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.OverrideStatus(context.Background(), tenantID, projectID, "ENV-SBOM-001", MetiAssessmentOverrideInput{
		OverrideStatus:    "achieved",
		OverrideBy:        by,
		OverrideAt:        when,
		OverrideNote:      "operator override review",
		ImprovementAction: &plan,
	})
	if err != nil {
		t.Fatalf("OverrideStatus: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_OverrideStatus_NoActionKeepsExisting
// verifies that omitting ImprovementAction leaves the column alone
// (NULL -> COALESCE keeps existing value).
func TestMetiAssessmentsRepository_OverrideStatus_NoActionKeepsExisting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	by := uuid.New()

	mock.ExpectExec(regexp.QuoteMeta("UPDATE meti_assessments SET")).
		WithArgs(
			tenantID,         // $1
			projectID,        // $2
			"C1",             // $3
			"not_achieved",   // $4
			by,               // $5
			sqlmock.AnyArg(), // $6 (defaulted)
			nil,              // $7 (empty note)
			nil,              // $8 ImprovementAction nil pointer -> NULL -> COALESCE keeps
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.OverrideStatus(context.Background(), tenantID, projectID, "C1", MetiAssessmentOverrideInput{
		OverrideStatus: "not_achieved",
		OverrideBy:     by,
	})
	if err != nil {
		t.Fatalf("OverrideStatus: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestMetiAssessmentsRepository_OverrideStatus_RejectsInvalid pins
// the allow-list ('achieved' | 'not_achieved' | 'needs_review' |
// 'not_applicable'). The empty string is rejected because clear-
// override is an explicit separate handler path (M3-4).
func TestMetiAssessmentsRepository_OverrideStatus_RejectsInvalid(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	cases := []string{"", "achieve", "DELETED", "ok", "pending"}
	for _, s := range cases {
		t.Run("override="+s, func(t *testing.T) {
			err := repo.OverrideStatus(context.Background(), uuid.New(), uuid.New(), "C1", MetiAssessmentOverrideInput{
				OverrideStatus: s,
				OverrideBy:     uuid.New(),
			})
			if err == nil {
				t.Fatalf("expected error for override_status %q, got nil", s)
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestMetiAssessmentsRepository_OverrideStatus_RejectsZero pins the
// per-argument fail-fast.
func TestMetiAssessmentsRepository_OverrideStatus_RejectsZero(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	by := uuid.New()
	good := MetiAssessmentOverrideInput{OverrideStatus: "achieved", OverrideBy: by}

	if err := repo.OverrideStatus(context.Background(), uuid.Nil, projectID, "C1", good); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := repo.OverrideStatus(context.Background(), tenantID, uuid.Nil, "C1", good); err == nil {
		t.Fatal("expected error for zero project_id, got nil")
	}
	if err := repo.OverrideStatus(context.Background(), tenantID, projectID, "", good); err == nil {
		t.Fatal("expected error for empty criterion_id, got nil")
	}
	if err := repo.OverrideStatus(context.Background(), tenantID, projectID, "C1", MetiAssessmentOverrideInput{OverrideStatus: "achieved"}); err == nil {
		t.Fatal("expected error for zero override_by, got nil")
	}
}

// TestMetiAssessmentsRepository_OverrideStatus_NoRowsErrors verifies
// the "silent no-op" guard: when the UPDATE matches zero rows (wrong
// composite key, wrong tenant, OR already overridden per F31), the
// repository returns a wrapped sql.ErrNoRows so handlers can
// distinguish "override landed" from "could not apply".
func TestMetiAssessmentsRepository_OverrideStatus_NoRowsErrors(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	mock.ExpectExec(regexp.QuoteMeta("UPDATE meti_assessments SET")).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.OverrideStatus(context.Background(), uuid.New(), uuid.New(), "C1", MetiAssessmentOverrideInput{
		OverrideStatus: "achieved",
		OverrideBy:     uuid.New(),
	})
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected wrapped sql.ErrNoRows, got %v", err)
	}
}

// TestMetiAssessmentsRepo_OverrideStatus_AlreadyOverridden_F31 pins
// the state-machine guard (M3 mirror of M2 Codex review #F31): the
// WHERE clause carries `AND override_status IS NULL`, so an already-
// overridden row matches zero rows and the repository returns
// wrapped sql.ErrNoRows. Without this guard, a follow-up
// OverrideStatus call against an already-overridden row would
// silently swap the operator verdict — losing the prior override's
// audit trail (override_by, override_at, override_note) without any
// 409 surfaced to the operator. Clear-then-re-override is a separate
// handler path so each transition emits its own audit_logs row.
//
// The test asserts BOTH the strict regex match on the guard literal
// in the SQL AND the wrapped sql.ErrNoRows return contract that the
// handler relies on to surface a 409.
func TestMetiAssessmentsRepo_OverrideStatus_AlreadyOverridden_F31(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	by := uuid.New()

	mock.ExpectExec(`UPDATE meti_assessments SET[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2 AND criterion_id = \$3[\s\S]+AND override_status IS NULL`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.OverrideStatus(context.Background(), tenantID, projectID, "C1", MetiAssessmentOverrideInput{
		OverrideStatus: "achieved",
		OverrideBy:     by,
	})
	if err == nil {
		t.Fatal("F31: expected sql.ErrNoRows when row already overridden, got nil")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("F31: expected wrapped sql.ErrNoRows, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("F31: SQL guard expectation not met: %v", err)
	}
}

// TestMetiAssessmentsRepo_ClearOverride_Success_F33 pins the M3
// Codex review #F33 fix: the ClearOverride UPDATE drops the override_*
// lifecycle fields when the row currently carries an override, and
// leaves the evaluator-owned columns + improvement_action alone. The
// test also pins the SQL ordering: tenant_id at $1, project_id at $2,
// criterion_id at $3 (the composite key the M3-4 handler holds), and
// the `AND override_status IS NOT NULL` state-machine guard literal.
func TestMetiAssessmentsRepo_ClearOverride_Success_F33(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectExec(`UPDATE meti_assessments SET[\s\S]+override_status = NULL[\s\S]+override_by\s*= NULL[\s\S]+override_at\s*= NULL[\s\S]+override_note\s*= NULL[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2 AND criterion_id = \$3[\s\S]+AND override_status IS NOT NULL`).
		WithArgs(tenantID, projectID, "ENV-SBOM-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.ClearOverride(context.Background(), tenantID, projectID, "ENV-SBOM-001"); err != nil {
		t.Fatalf("ClearOverride: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("F33: SQL expectation not met: %v", err)
	}
}

// TestMetiAssessmentsRepo_ClearOverride_NoOverride_F33 pins the
// state-machine guard: when the row currently has no override
// (override_status IS NULL), the UPDATE WHERE clause matches zero
// rows and the repository returns wrapped sql.ErrNoRows so the
// handler can surface a 404 ("no override to clear") instead of a
// silent no-op. Mirrors the F31 pattern on OverrideStatus.
func TestMetiAssessmentsRepo_ClearOverride_NoOverride_F33(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectExec(`UPDATE meti_assessments SET[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2 AND criterion_id = \$3[\s\S]+AND override_status IS NOT NULL`).
		WithArgs(tenantID, projectID, "C1").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.ClearOverride(context.Background(), tenantID, projectID, "C1")
	if err == nil {
		t.Fatal("F33: expected sql.ErrNoRows when no override to clear, got nil")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("F33: expected wrapped sql.ErrNoRows, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("F33: SQL guard expectation not met: %v", err)
	}
}

// TestMetiAssessmentsRepo_ClearOverride_RejectsZero pins the per-
// argument fail-fast on the composite key. Mirrors the OverrideStatus
// fail-fast.
func TestMetiAssessmentsRepo_ClearOverride_RejectsZero(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewMetiAssessmentsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	if err := repo.ClearOverride(context.Background(), uuid.Nil, projectID, "C1"); err == nil {
		t.Fatal("F33: expected error for zero tenant_id, got nil")
	}
	if err := repo.ClearOverride(context.Background(), tenantID, uuid.Nil, "C1"); err == nil {
		t.Fatal("F33: expected error for zero project_id, got nil")
	}
	if err := repo.ClearOverride(context.Background(), tenantID, projectID, ""); err == nil {
		t.Fatal("F33: expected error for empty criterion_id, got nil")
	}
}

// TestMetiAssessment_JSONShape pins the wire JSON tags. M1 F28 fix
// regression: the Web UI relies on snake_case keys; a missing or
// renamed tag would silently break the /meti/assessment page. We do
// not hand-roll a marshal-and-compare here because field order would
// be brittle; instead we round-trip a struct and assert every load-
// bearing key shows up in the marshalled JSON. Adding a new field
// without a json tag fails this test.
func TestMetiAssessment_JSONShape(t *testing.T) {
	by := uuid.New()
	when := time.Now().UTC()
	a := MetiAssessment{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProjectID:         uuid.New(),
		CriterionID:       "ENV-SBOM-001",
		CriterionPhase:    "env_setup",
		Status:            "achieved",
		Evidence:          validMetiEvidence(),
		EvaluatorVersion:  "1.0.0",
		EvaluatedAt:       when,
		OverrideStatus:    "not_achieved",
		OverrideBy:        &by,
		OverrideAt:        &when,
		OverrideNote:      "n",
		ImprovementAction: "plan",
		CreatedAt:         when,
		UpdatedAt:         when,
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	required := []string{
		`"id":`, `"tenant_id":`, `"project_id":`,
		`"criterion_id":`, `"criterion_phase":`,
		`"status":`, `"evidence":`,
		`"evaluator_version":`, `"evaluated_at":`,
		`"override_status":`, `"override_by":`, `"override_at":`, `"override_note":`,
		`"improvement_action":`,
		`"created_at":`, `"updated_at":`,
	}
	for _, key := range required {
		if !contains(s, key) {
			t.Errorf("expected wire JSON to contain %s; got %s", key, s)
		}
	}
}
