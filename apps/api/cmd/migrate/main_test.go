package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// ----------------------------------------------------------------------------
// M46 Track C-3b pins for cmd/migrate:
//   - parseSteps replaces a discarded fmt.Sscanf error (garbage used to run
//     `down` with steps=1 silently; "2abc" used to parse as 2).
//   - getAppliedMigrations / migrateDown enforce the no-partial-results
//     rows.Err() contract: an iteration error aborts the run instead of
//     acting on a silently truncated version list.
// ----------------------------------------------------------------------------

func TestParseSteps(t *testing.T) {
	cases := []struct {
		arg     string
		want    int
		wantErr bool
	}{
		{arg: "1", want: 1},
		{arg: "3", want: 3},
		{arg: "42", want: 42},
		// Pre-fix, fmt.Sscanf silently left steps=1 on full garbage:
		{arg: "abc", wantErr: true},
		{arg: "", wantErr: true},
		// Pre-fix, fmt.Sscanf parsed the "2" prefix and ran with steps=2:
		{arg: "2abc", wantErr: true},
		// `down 0` / negative LIMITs must be rejected, not sent to PG:
		{arg: "0", wantErr: true},
		{arg: "-1", wantErr: true},
	}
	for _, tc := range cases {
		got, err := parseSteps(tc.arg)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseSteps(%q) = %d, want error", tc.arg, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSteps(%q): unexpected error: %v", tc.arg, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseSteps(%q) = %d, want %d", tc.arg, got, tc.want)
		}
	}
}

// TestGetAppliedMigrations_RowErrReturnsNoPartialResult pins the rows.Err()
// contract: when iteration fails mid-stream the function must return the
// error — NOT a truncated applied-set, which would make `up` re-apply
// migrations that already ran and make `status` lie. Pre-fix this returned
// (map with the rows read so far, nil).
func TestGetAppliedMigrations_RowErrReturnsNoPartialResult(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"version"}).
		AddRow("001_init").
		AddRow("002_later").
		RowError(1, errors.New("iteration boom"))
	mock.ExpectQuery(`SELECT version FROM schema_migrations`).WillReturnRows(rows)

	applied, err := getAppliedMigrations(db)
	if err == nil {
		t.Fatalf("want iteration error, got nil (applied=%v — a partial result)", applied)
	}
	if !strings.Contains(err.Error(), "failed to enumerate applied migrations") {
		t.Fatalf("error must name the enumeration failure, got: %v", err)
	}
	if applied != nil {
		t.Fatalf("no-partial-results contract violated: applied=%v, want nil", applied)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestMigrateDown_RowErrAbortsBeforeAnyRollback pins that a mid-iteration
// failure while enumerating the versions to roll back aborts the WHOLE run
// before any transaction is opened. Pre-fix the loop proceeded with the
// versions read before the failure (observable as a "down migration not
// found" / unexpected-Begin instead of the enumeration error).
func TestMigrateDown_RowErrAbortsBeforeAnyRollback(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"version"}).
		AddRow("002_later").
		AddRow("001_init").
		RowError(1, errors.New("iteration boom"))
	mock.ExpectQuery(`SELECT version FROM schema_migrations ORDER BY version DESC LIMIT \$1`).
		WithArgs(2).
		WillReturnRows(rows)
	// Deliberately NO ExpectBegin: acting on the partially-read version
	// list is itself the bug this test pins.

	err = migrateDown(db, 2)
	if err == nil {
		t.Fatal("want iteration error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to enumerate applied migrations") {
		t.Fatalf("error must be the enumeration failure (not a partial rollback attempt), got: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a rollback was attempted on a partial version list: %v", err)
	}
}
