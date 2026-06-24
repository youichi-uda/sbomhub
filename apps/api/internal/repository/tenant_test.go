package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestTenantRepository_ListAllIDs covers the system-level tenant enumeration
// added for the codex-r4 scheduler RLS fix. Two behaviours matter:
//
//  1. Result rows are returned in the order they arrive (no client-side sort).
//  2. The query runs on r.db directly — it must NOT route through r.q(ctx),
//     otherwise it would be vulnerable to picking up a request-scoped tx and
//     producing wrong results for background jobs. sqlmock's default
//     ordering check would surface that change of behaviour.
func TestTenantRepository_ListAllIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewTenantRepository(db)

	t.Run("returns all ids in query order", func(t *testing.T) {
		id1 := uuid.New()
		id2 := uuid.New()
		id3 := uuid.New()

		mock.ExpectQuery(`SELECT id FROM tenants ORDER BY created_at`).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).
				AddRow(id1).
				AddRow(id2).
				AddRow(id3))

		got, err := repo.ListAllIDs(context.Background())
		if err != nil {
			t.Fatalf("ListAllIDs returned error: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 ids, got %d", len(got))
		}
		if got[0] != id1 || got[1] != id2 || got[2] != id3 {
			t.Fatalf("ids out of order: %v", got)
		}
	})

	t.Run("returns nil on empty tenants table", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM tenants ORDER BY created_at`).
			WillReturnRows(sqlmock.NewRows([]string{"id"}))

		got, err := repo.ListAllIDs(context.Background())
		if err != nil {
			t.Fatalf("ListAllIDs returned error: %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil for empty result, got %v", got)
		}
	})

	t.Run("propagates query errors", func(t *testing.T) {
		sentinel := errors.New("boom")
		mock.ExpectQuery(`SELECT id FROM tenants ORDER BY created_at`).
			WillReturnError(sentinel)

		_, err := repo.ListAllIDs(context.Background())
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected sentinel error, got %v", err)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet mock expectations: %v", err)
	}
}
