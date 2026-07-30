package repository

import (
	"context"
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

// declaredEOLStatuses returns every `EOLStatus*` string constant declared
// anywhere in internal/model, parsed from source.
//
// Parsing beats reflection because Go constants are not enumerable at runtime:
// there is no way to ask the model package "what EOLStatus values exist". A
// hand-maintained list is what this avoids — it stays green while drifting.
//
// Collection rule, and why it is by NAME and not only by declared type
// (Codex round 2 #2): the first version matched only specs whose type was the
// explicit identifier `EOLStatus`, in eol.go alone. Measured misses:
//
//	const ( ... EOLStatusRetired = "retired" )   // untyped, same block  → missed
//	// an explicitly typed constant in another model file                → missed
//
// The untyped form is the realistic one — an untyped string constant is still
// assignable to a model.EOLStatus parameter, so it reaches the allowlist check
// exactly like a typed one. Matching on the `EOLStatus` name prefix over every
// file in the package catches both, at the cost of also catching a constant
// that merely shares the prefix without being a status. That trade is
// deliberate: a false positive here is a loud test failure asking a human to
// look, whereas a false negative is the silent drift this test exists to stop.
func declaredEOLStatuses(t *testing.T) []model.EOLStatus {
	t.Helper()

	// os.ReadDir + ParseFile rather than parser.ParseDir, which is deprecated
	// as of Go 1.25. Neither considers build tags; that is fine here because
	// internal/model has no build-tagged files, and a future one would show up
	// as a count change rather than a silent miss.
	const dir = "../model"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	seen := map[string]struct{}{}
	var out []model.EOLStatus
	{
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
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
					for i, ident := range vs.Names {
						if !strings.HasPrefix(ident.Name, "EOLStatus") {
							continue
						}
						if i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						val, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatalf("unquote %s (%s in %s): %v",
								lit.Value, ident.Name, name, err)
						}
						if _, dup := seen[val]; dup {
							continue
						}
						seen[val] = struct{}{}
						out = append(out, model.EOLStatus(val))
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
