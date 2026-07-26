package database

import (
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestGetAppliedMigrations_RowErrReturnsNoPartialResult pins the M46 Track
// C-3b rows.Err() contract on the startup auto-migration path: when the
// schema_migrations enumeration fails mid-stream, Migrate must see the
// error — NOT a silently truncated applied-set, which would re-apply
// migrations that already ran and abort boot with a far more confusing
// duplicate-object SQL error. Pre-fix this returned (partial map, nil).
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
