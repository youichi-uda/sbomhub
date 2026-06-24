package repository

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestStatsRepository_CountVulnerabilities_JoinsComponents verifies that
// CountVulnerabilities issues the tenant-scoped query against the
// `component_vulnerabilities ⨝ components` join rather than the raw
// `component_vulnerabilities` table (Codex R15 P2). Without this JOIN the
// cluster-wide distinct count leaks across tenants, since
// `component_vulnerabilities` has no `tenant_id` column / no RLS policy
// (see CountVulnerabilities godoc and migration 023_rls_security_hardening).
//
// The assertion is structural on the SQL itself: a future revert that
// dropped the JOIN would re-introduce the leak even if the COUNT happened
// to return a plausible number for the test fixture.
func TestStatsRepository_CountVulnerabilities_JoinsComponents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewStatsRepository(db)

	// Pattern intentionally requires both `component_vulnerabilities` aliased
	// as `cv` AND a `JOIN components` clause, so any future query that drops
	// the components join (and thereby re-introduces cross-tenant leakage)
	// will fail this expectation rather than just changing the SQL text.
	pattern := regexp.MustCompile(`(?is)SELECT\s+COUNT\(DISTINCT\s+cv\.vulnerability_id\)\s+FROM\s+component_vulnerabilities\s+cv\s+JOIN\s+components\s+c\s+ON\s+c\.id\s*=\s*cv\.component_id`)

	mock.ExpectQuery(pattern.String()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))

	got, err := repo.CountVulnerabilities(context.Background())
	if err != nil {
		t.Fatalf("CountVulnerabilities: %v", err)
	}
	if got != 7 {
		t.Fatalf("count = %d, want 7", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestStatsRepository_CountVulnerabilities_PropagatesError ensures DB
// errors are surfaced rather than swallowed.
func TestStatsRepository_CountVulnerabilities_PropagatesError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewStatsRepository(db)
	mock.ExpectQuery(`(?is)component_vulnerabilities`).
		WillReturnError(errors.New("boom"))

	if _, err := repo.CountVulnerabilities(context.Background()); err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
