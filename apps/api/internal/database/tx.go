package database

import (
	"context"
	"database/sql"
	"fmt"
)

// Queryable abstracts the subset of *sql.DB / *sql.Tx that tenant-scoped
// repositories need. By depending on this interface (via Querier below) rather
// than directly on *sql.DB, a repository transparently joins whatever
// transaction the request middleware opened — which is how Trust Rescue 9.1.2
// (#3) keeps every per-request statement on a single connection that has
// `SET LOCAL app.current_tenant_id = '<uuid>'` set so RLS policies fire on the
// expected tenant.
//
// Only the three methods exercised by repository code are part of the
// interface to keep the surface small. PrepareContext / BeginTx are
// intentionally not included — repositories should not start nested
// transactions on their own.
type Queryable interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// txKey is the unexported context key for the per-request *sql.Tx. Using a
// dedicated type avoids accidental collisions with other context values.
type txKey struct{}

// WithTx returns a copy of ctx that carries tx. Repositories pick the tx up
// transparently via Querier; callers that need direct *sql.Tx access can use
// TxFromContext.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	if tx == nil {
		return ctx
	}
	return context.WithValue(ctx, txKey{}, tx)
}

// WithoutTx returns a copy of ctx with any attached *sql.Tx REMOVED, so
// repositories called with it fall back to the pooled *sql.DB (autocommit).
//
// This exists for the handful of endpoints that trigger a GLOBAL, non-tenant
// background job on demand (M46 Codex final round, round 2 Medium): those jobs
// write shared caches like `vulnerabilities` in many independent statements
// over tens of seconds, and running them inside the request's TenantTx is
// wrong twice over — a late failure rolls back every earlier statement that
// had already succeeded, and one failed statement poisons the transaction so
// every subsequent one fails with "current transaction is aborted". The
// scheduler already runs these jobs on a bare context; this makes the manual
// HTTP trigger behave identically.
//
// Do NOT use it to escape RLS: a context without a tx has no
// app.current_tenant_id bound, so any RLS-protected table read through it
// yields nothing. It is only appropriate for globally-scoped, non-tenant work.
func WithoutTx(ctx context.Context) context.Context {
	if ctx == nil {
		return ctx
	}
	if _, ok := TxFromContext(ctx); !ok {
		return ctx
	}
	return context.WithValue(ctx, txKey{}, (*sql.Tx)(nil))
}

// TxFromContext returns the *sql.Tx attached to ctx (or nil + false). Used by
// the middleware's diagnostics and by Querier below.
func TxFromContext(ctx context.Context) (*sql.Tx, bool) {
	if ctx == nil {
		return nil, false
	}
	tx, ok := ctx.Value(txKey{}).(*sql.Tx)
	if !ok || tx == nil {
		return nil, false
	}
	return tx, true
}

// Querier returns the active *sql.Tx from ctx if one is attached, otherwise
// the supplied db. This is the single hook repositories use to become
// tx-aware without churning every call site through a wrapper struct:
//
//	rows, err := database.Querier(ctx, r.db).QueryContext(ctx, q, args...)
//
// When no middleware has opened a tx (background jobs, schedulers, migration
// code), Querier degrades to the raw *sql.DB so legacy paths keep working.
func Querier(ctx context.Context, db *sql.DB) Queryable {
	if tx, ok := TxFromContext(ctx); ok {
		return tx
	}
	return db
}

// WithTxFunc runs fn inside a fresh transaction. Useful for code that wants
// to opt into transactional behavior without going through the request
// middleware (e.g. background jobs that still need RLS context). Commits if
// fn returns nil, rolls back otherwise. Panics are recovered just enough to
// roll back; the panic is then re-raised so call sites keep their stack
// trace.
func WithTxFunc(ctx context.Context, db *sql.DB, fn func(ctx context.Context, tx *sql.Tx) error) (rerr error) {
	if db == nil {
		return fmt.Errorf("database.WithTxFunc: db is nil")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database.WithTxFunc: begin: %w", err)
	}
	committed := false
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if committed {
			return
		}
		_ = tx.Rollback()
	}()

	if err := fn(WithTx(ctx, tx), tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("database.WithTxFunc: commit: %w", err)
	}
	committed = true
	return nil
}
