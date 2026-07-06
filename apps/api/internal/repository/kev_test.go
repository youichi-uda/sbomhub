package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestGetKEVVulnerabilities_ZeroRowsReturnsNonNilSlice pins the JSON
// API-contract fix for the project KEV panel: GetKEVVulnerabilities is
// serialized as {"vulnerabilities": ...} by the /api/v1/projects/:id/kev
// handler, whose Playwright E2E spec asserts Array.isArray(result.vulnerabilities).
// A nil slice marshals to `null` (isArray == false); an initialized empty slice
// marshals to `[]`.
//
// Non-vacuous: pre-fix (`var vulnerabilities []model.Vulnerability`) the slice
// stays nil on a zero-row result, so the `!= nil` assertion FAILS. Only the fix
// (`vulnerabilities := []model.Vulnerability{}`) makes it pass.
func TestGetKEVVulnerabilities_ZeroRowsReturnsNonNilSlice(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewKEVRepository(db)

	projectID := uuid.New()
	// Positional Scan order of the vulnerabilities projection (irrelevant to the
	// zero-row assertion, kept accurate to document the query shape).
	cols := []string{
		"id", "cve_id", "description", "severity", "cvss_score",
		"epss_score", "epss_percentile", "epss_updated_at",
		"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
		"source", "published_at", "updated_at",
	}
	mock.ExpectQuery(`(?is)FROM\s+vulnerabilities\s+v`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows(cols))

	got, err := repo.GetKEVVulnerabilities(context.Background(), projectID)
	if err != nil {
		t.Fatalf("GetKEVVulnerabilities: %v", err)
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

// TestKEVList_ZeroRowsReturnsNonNilSlice pins the same fix for List, whose slice
// is serialized as {"entries": ...} by the /api/v1/kev handler. List issues a
// COUNT(*) then the paginated list query. With zero rows the returned slice must
// still be non-nil.
//
// Non-vacuous: pre-fix the nil-declared slice stays nil on zero rows, so the
// `!= nil` assertion FAILS.
func TestKEVList_ZeroRowsReturnsNonNilSlice(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewKEVRepository(db)

	limit, offset := 50, 0
	cols := []string{
		"id", "cve_id", "vendor_project", "product", "vulnerability_name",
		"short_description", "required_action", "date_added", "due_date",
		"known_ransomware_use", "notes", "created_at", "updated_at",
	}
	mock.ExpectQuery(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+kev_catalog`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?is)FROM\s+kev_catalog`).
		WithArgs(limit, offset).
		WillReturnRows(sqlmock.NewRows(cols))

	got, total, err := repo.List(context.Background(), limit, offset)
	if err != nil {
		t.Fatalf("List: %v", err)
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
