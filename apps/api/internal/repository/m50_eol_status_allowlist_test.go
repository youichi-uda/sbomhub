package repository

import (
	"context"
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
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
// The detector for "no statement was sent" is sqlmock itself, but NOT via
// ExpectationsWereMet(): with no expectations registered there is nothing
// unmet, so that call returns nil even when an unexpected Exec happened
// (measured — Codex round 1 #4 instrumented it and saw
// `ExpectationsWereMet after call = <nil>` in every subtest).
//
// What actually detects it is the return value: sqlmock answers an
// unregistered Exec with an error, that error propagates out of
// UpdateComponentEOLStatus, and the errors.Is(err, ErrInvalidEOLStatus)
// assertion below fails. Verified by deleting the guard in a scratch copy —
// all four subtests go red. So this is a proof test, just through a different
// detector than the first draft of this comment claimed.
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
			// No expectations are registered: any Exec that reaches sqlmock
			// is unregistered and comes back as an error.
			db, _, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()

			repo := NewEOLRepository(db)
			err = repo.UpdateComponentEOLStatus(context.Background(), uuid.New(),
				&model.ComponentEOLInfo{Status: tc.status})

			// A non-ErrInvalidEOLStatus error here is the signal that the
			// guard let the call through: it will be sqlmock's "call to
			// ExecQuery ... was not expected".
			if !errors.Is(err, ErrInvalidEOLStatus) {
				t.Errorf("UpdateComponentEOLStatus(%q) error = %v, want ErrInvalidEOLStatus "+
					"(a sqlmock \"was not expected\" error here means the guard did not "+
					"run and the UPDATE was issued)", tc.status, err)
			}
		})
	}
}

// TestM50_UpdateComponentEOLStatus_AcceptsEveryDefinedStatus is the other half:
// the guard must not reject a status the product actually produces.
//
// The status list is PARSED OUT OF model/eol.go rather than written here, so
// declaring a fifth model.EOLStatus* constant and forgetting validEOLStatuses
// fails in this test instead of at a production write. A hand-written list
// cannot do that — it simply never sees the new constant (Codex round 1 #5
// proved it by adding EOLStatusRetired to a scratch model copy and watching
// the earlier version of this test pass with four subtests).
//
// This mirrors the AST-derived route coverage test used for API-key project
// scope: derive the set from the source of truth, do not restate it.
func TestM50_UpdateComponentEOLStatus_AcceptsEveryDefinedStatus(t *testing.T) {
	declared := declaredEOLStatuses(t)
	if len(declared) < 4 {
		t.Fatalf("parsed %d EOLStatus constants from model/eol.go, want at least the 4 "+
			"known ones — the parser is probably no longer finding them: %v", len(declared), declared)
	}
	for _, status := range declared {
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
				t.Errorf("%q is declared in model/eol.go but validEOLStatuses rejects it — "+
					"add it to the allowlist in repository/eol.go AND to the CHECK in "+
					"migrations/064_components_eol_status_check.up.sql (and 065's down, "+
					"which restates the same definition)", status)
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
	// Wrapping sql.ErrNoRows keeps errors.Is compatibility for any future
	// caller that wants to branch on "no such row". No handler maps this to
	// 404 today — the only production consumer (service/eol.go) logs it and
	// continues the sweep (Codex round 1 #6 corrected an earlier claim that a
	// 404 path existed).
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("0-row UPDATE error = %v, want it to wrap sql.ErrNoRows", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectation: %v", err)
	}
}

// declaredEOLStatuses returns the value of every `EOLStatusX EOLStatus = "..."`
// constant declared in internal/model/eol.go, parsed from source.
//
// Parsing beats reflection here because Go constants are not enumerable at
// runtime: there is no way to ask the model package "what EOLStatus values
// exist". The alternative — a hand-maintained list — is exactly what this
// avoids, since it stays green while drifting out of date.
//
// The parser is deliberately narrow: same file, same type name, string literal
// values only. If model/eol.go moves or the constants change shape, the
// len(declared) < 4 guard above turns that into a loud failure rather than a
// silently empty set.
func declaredEOLStatuses(t *testing.T) []model.EOLStatus {
	t.Helper()

	const src = "../model/eol.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}

	var out []model.EOLStatus
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// Only constants explicitly typed EOLStatus.
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != "EOLStatus" {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s in %s: %v", lit.Value, src, err)
				}
				out = append(out, model.EOLStatus(val))
			}
		}
	}
	return out
}
