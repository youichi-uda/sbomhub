package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestM50_UpdateComponentEOLStatus_RejectsUnknownStatus pins that the
// repository refuses a status outside model.EOLStatus* BEFORE issuing the
// UPDATE.
//
// The empty string is the case that matters, and not merely because it is
// "some other string": model.Component types EOLStatus as a plain string, so
// GetComponentsWithEOL maps both SQL NULL and ” to "". A row stored with ”
// is indistinguishable on read from a row that was never assessed. Migration
// 064 adds the matching CHECK; this is the half that fails with a message
// naming the field instead of naming a constraint.
//
// sqlmock with no expectations is the assertion: if the guard were removed,
// the UPDATE would be issued and sqlmock would fail the test with "call to
// ExecQuery ... was not expected". That makes this a proof test rather than a
// "nothing happened" test — the absence being asserted has a detector.
func TestM50_UpdateComponentEOLStatus_RejectsUnknownStatus(t *testing.T) {
	cases := []struct {
		name   string
		status model.EOLStatus
	}{
		{"empty string collides with SQL NULL on read", ""},
		{"unknown value", "retired"},
		{"case mismatch is not normalised", "EOL"},
		{"whitespace is not trimmed", "eol "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()

			repo := NewEOLRepository(db)
			err = repo.UpdateComponentEOLStatus(context.Background(), uuid.New(),
				&model.ComponentEOLInfo{Status: tc.status})

			if !errors.Is(err, ErrInvalidEOLStatus) {
				t.Errorf("UpdateComponentEOLStatus(%q) error = %v, want ErrInvalidEOLStatus",
					tc.status, err)
			}
			// No statement may have been sent.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet/unexpected DB interaction for status %q: %v", tc.status, err)
			}
		})
	}
}

// TestM50_UpdateComponentEOLStatus_AcceptsEveryDefinedStatus is the other half:
// the guard must not reject a status the product actually produces. Iterating
// the four constants means adding a fifth to model without adding it to
// validEOLStatuses fails here rather than in production.
func TestM50_UpdateComponentEOLStatus_AcceptsEveryDefinedStatus(t *testing.T) {
	for _, status := range []model.EOLStatus{
		model.EOLStatusActive,
		model.EOLStatusEOL,
		model.EOLStatusEOS,
		model.EOLStatusUnknown,
	} {
		t.Run(string(status), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()

			mock.ExpectExec("UPDATE components SET").
				WillReturnResult(sqlmock.NewResult(0, 1))

			repo := NewEOLRepository(db)
			err = repo.UpdateComponentEOLStatus(context.Background(), uuid.New(),
				&model.ComponentEOLInfo{Status: status})
			if err != nil {
				t.Errorf("UpdateComponentEOLStatus(%q) = %v, want nil", status, err)
			}
			if errors.Is(err, ErrInvalidEOLStatus) {
				t.Errorf("%q is a defined model.EOLStatus but validEOLStatuses rejected it", status)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("expected UPDATE was not issued for status %q: %v", status, err)
			}
		})
	}
}

// TestM50_UpdateComponentEOLStatus_ZeroRowsStillReported guards the M47 W2
// contract while the new guard sits in front of it: a valid status that
// matches no row must still surface ErrComponentRowNotFound (which wraps
// sql.ErrNoRows), not be swallowed by the early return added in M50.
func TestM50_UpdateComponentEOLStatus_ZeroRowsStillReported(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectExec("UPDATE components SET").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewEOLRepository(db)
	err = repo.UpdateComponentEOLStatus(context.Background(), uuid.New(),
		&model.ComponentEOLInfo{Status: model.EOLStatusEOL})

	if !errors.Is(err, ErrComponentRowNotFound) {
		t.Errorf("0-row UPDATE error = %v, want ErrComponentRowNotFound", err)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("0-row UPDATE error = %v, want it to wrap sql.ErrNoRows so existing "+
			"handlers keep mapping it to 404", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectation: %v", err)
	}
}
