package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// ssvcWithVulnColumns mirrors the positional Scan order of the
// ssvc_assessments a JOIN vulnerabilities v projection used by both
// ListAssessments and GetImmediateAssessments. The column set is irrelevant to
// the zero-row assertion below (Scan is never reached), but keeping it accurate
// documents the query shape.
var ssvcWithVulnColumns = []string{
	"id", "project_id", "tenant_id", "vulnerability_id", "cve_id",
	"exploitation", "automatable", "technical_impact", "mission_prevalence", "safety_impact",
	"decision", "exploitation_auto", "automatable_auto", "assessed_by", "assessed_at",
	"notes", "created_at", "updated_at",
	"severity", "cvss_score", "in_kev", "epss_score",
}

// TestGetImmediateAssessments_ZeroRowsReturnsNonNilSlice pins the JSON
// API-contract fix: GetImmediateAssessments is serialized straight into the
// /api/v1/ssvc/immediate response body, whose Playwright E2E spec asserts
// Array.isArray(result). A nil slice marshals to JSON `null` (isArray == false),
// an initialized empty slice marshals to `[]`. This test proves the slice is
// non-nil on a zero-row result.
//
// Non-vacuous: on the pre-fix code (`var assessments []model.SSVCAssessmentWithVuln`)
// the loop never runs, so the returned slice is nil and the `!= nil` assertion
// FAILS. Only the fix (`assessments := []model.SSVCAssessmentWithVuln{}`) makes
// it pass.
func TestGetImmediateAssessments_ZeroRowsReturnsNonNilSlice(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSSVCRepository(db)

	// WHERE a.decision = 'immediate' — the query takes no bind args.
	mock.ExpectQuery(`(?is)FROM\s+ssvc_assessments\s+a`).
		WillReturnRows(sqlmock.NewRows(ssvcWithVulnColumns))

	got, err := repo.GetImmediateAssessments(context.Background())
	if err != nil {
		t.Fatalf("GetImmediateAssessments: %v", err)
	}
	if got == nil {
		t.Fatalf("returned slice is nil on zero rows; must be a non-nil empty slice so json.Marshal emits [] not null")
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestListAssessments_ZeroRowsReturnsNonNilSlice pins the same API-contract fix
// for ListAssessments, whose slice is serialized as {"assessments": ...} by the
// /api/v1/projects/:id/ssvc/assessments handler. ListAssessments issues two
// queries: a COUNT(*) then the paginated JOIN list. With zero matching rows the
// count is 0 and the list is empty; the returned slice must still be non-nil.
//
// Non-vacuous: pre-fix the nil-declared slice stays nil on zero rows, so the
// `!= nil` assertion FAILS.
func TestListAssessments_ZeroRowsReturnsNonNilSlice(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSSVCRepository(db)

	projectID := uuid.New()
	limit, offset := 50, 0

	// 1) Count query (ordered: must be matched before the list query).
	mock.ExpectQuery(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+ssvc_assessments`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// 2) Paginated list query — zero rows.
	mock.ExpectQuery(`(?is)FROM\s+ssvc_assessments\s+a`).
		WithArgs(projectID, limit, offset).
		WillReturnRows(sqlmock.NewRows(ssvcWithVulnColumns))

	got, total, err := repo.ListAssessments(context.Background(), projectID, nil, limit, offset)
	if err != nil {
		t.Fatalf("ListAssessments: %v", err)
	}
	if got == nil {
		t.Fatalf("returned slice is nil on zero rows; must be a non-nil empty slice so json.Marshal emits [] not null")
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
