package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestQuerier_FallsBackToDB(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	if got := Querier(context.Background(), db); got == nil {
		t.Fatal("Querier returned nil")
	} else if _, isDB := got.(*sql.DB); !isDB {
		// Without a tx in ctx, Querier must hand back the *sql.DB itself so
		// legacy background-job paths keep working unchanged.
		t.Fatalf("Querier(no-tx) returned %T, want *sql.DB", got)
	}
}

func TestQuerier_PrefersTxFromContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT 1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	ctx := WithTx(context.Background(), tx)

	got, ok := TxFromContext(ctx)
	if !ok || got != tx {
		t.Fatalf("TxFromContext mismatch: ok=%v got=%v want=%v", ok, got, tx)
	}

	if _, err := Querier(ctx, db).ExecContext(ctx, "SELECT 1"); err != nil {
		t.Fatalf("ExecContext via Querier(tx): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestWithTx_NilTxIsNoOp(t *testing.T) {
	ctx := WithTx(context.Background(), nil)
	if tx, ok := TxFromContext(ctx); ok || tx != nil {
		t.Fatalf("WithTx(nil): expected pass-through, got ok=%v tx=%v", ok, tx)
	}
}

func TestWithTxFunc_CommitsOnSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT 1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	if err := WithTxFunc(context.Background(), db, func(ctx context.Context, _ *sql.Tx) error {
		_, err := Querier(ctx, db).ExecContext(ctx, "SELECT 1")
		return err
	}); err != nil {
		t.Fatalf("WithTxFunc returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestWithTxFunc_RollsBackOnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	sentinel := errors.New("boom")
	err = WithTxFunc(context.Background(), db, func(_ context.Context, _ *sql.Tx) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTxFunc error = %v, want %v", err, sentinel)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestWithTxFunc_RollsBackOnPanic(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	defer func() {
		p := recover()
		if p == nil {
			t.Fatal("expected panic to propagate, got none")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	}()

	_ = WithTxFunc(context.Background(), db, func(_ context.Context, _ *sql.Tx) error {
		panic("kaboom")
	})
}
