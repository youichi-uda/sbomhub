package triage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
)

// TxManager opens short-lived per-tenant transactions for the triage
// runner. It is the abstraction that lets the runner split its work into
// (Stage 1 short read tx → Stage 2 LLM call with NO tx → Stage 3 short
// write tx) so the request does not hold a Postgres connection across
// the slow LLM upstream call (M1 Codex review #F19).
//
// Production wiring binds a *DBTxManager that opens a real `*sql.Tx`
// via `db.BeginTx(...)` and sets `app.current_tenant_id` via
// `SELECT set_config(...)` so RLS policies fire on the expected tenant
// for every statement in the tx (mirrors the contract that the
// TenantTx middleware enforces for non-triage routes).
//
// Tests pass a *PassthroughTxManager that simply invokes fn(ctx) — no
// real tx is opened, no SET LOCAL is issued. The in-memory fakes used
// by runner_test.go ignore the tx-vs-db distinction so this preserves
// backward compatibility with the existing test surface while letting
// the production runner enforce real connection-pool hygiene.
//
// Detection of an ambient tx: when the caller's ctx already carries a
// *sql.Tx (via database.WithTx), the production manager reuses it
// instead of opening a nested transaction. This keeps the
// TenantTx-wrapped routes (e.g. GET /vex-drafts which still goes
// through TenantTx) working unchanged — the runner's tx management is
// a no-op when something upstream already opened a transaction.
type TxManager interface {
	// RunRead opens a read-only tx, binds SET LOCAL app.current_tenant_id
	// to tenantID, and runs fn with a tx-bound context. The tx commits on
	// fn return nil, rolls back on err or panic. When an ambient tx is
	// already attached to ctx, fn is invoked directly with ctx (no nested
	// tx) and the ambient tx's lifecycle is left to its owner.
	RunRead(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error

	// RunWrite opens a read/write tx, binds SET LOCAL app.current_tenant_id
	// to tenantID, and runs fn with a tx-bound context. Same ambient-tx
	// detection and commit/rollback semantics as RunRead.
	RunWrite(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error
}

// DBTxManager is the production TxManager bound to a *sql.DB. It is
// the TxManager wired in cmd/server/main.go.
type DBTxManager struct {
	db *sql.DB
}

// NewDBTxManager constructs a DBTxManager.
func NewDBTxManager(db *sql.DB) *DBTxManager {
	if db == nil {
		panic("triage.NewDBTxManager: db is required")
	}
	return &DBTxManager{db: db}
}

// RunRead implements TxManager.
func (m *DBTxManager) RunRead(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error {
	return m.run(ctx, tenantID, &sql.TxOptions{ReadOnly: true}, fn)
}

// RunWrite implements TxManager.
func (m *DBTxManager) RunWrite(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error {
	return m.run(ctx, tenantID, nil, fn)
}

func (m *DBTxManager) run(ctx context.Context, tenantID uuid.UUID, opts *sql.TxOptions, fn func(ctx context.Context) error) (rerr error) {
	if tenantID == uuid.Nil {
		return fmt.Errorf("triage.DBTxManager: tenant_id is required")
	}
	// Ambient tx in ctx? Skip nested begin — fn reuses it. The caller
	// is responsible for SET LOCAL on the outer tx.
	if _, hasTx := database.TxFromContext(ctx); hasTx {
		return fn(ctx)
	}

	tx, err := m.db.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("triage.DBTxManager: begin: %w", err)
	}
	committed := false
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Bind RLS GUC for the lifetime of the tx.
	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('app.current_tenant_id', $1, true)`,
		tenantID.String(),
	); err != nil {
		return fmt.Errorf("triage.DBTxManager: SET LOCAL: %w", err)
	}

	txCtx := database.WithTx(ctx, tx)
	if err := fn(txCtx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("triage.DBTxManager: commit: %w", err)
	}
	committed = true
	return nil
}

// PassthroughTxManager is the no-op TxManager used by tests (and by the
// runner as its default when RunnerConfig.TxManager is nil). It does NOT
// open a real Postgres transaction; it simply invokes fn(ctx) directly.
//
// This is safe for the in-memory fakes used by runner_test.go (which
// ignore the tx/db distinction) AND for production paths that pass
// through repositories whose `q(ctx)` helper degrades to the raw *sql.DB
// when no tx is bound — i.e. legacy code paths that have never opened a
// transaction continue to work.
//
// Production wiring MUST pass a *DBTxManager so the F19 DB-pool fix
// actually takes effect; the default-passthrough is a unit-test
// convenience only.
type PassthroughTxManager struct{}

// RunRead implements TxManager.
func (PassthroughTxManager) RunRead(ctx context.Context, _ uuid.UUID, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// RunWrite implements TxManager.
func (PassthroughTxManager) RunWrite(ctx context.Context, _ uuid.UUID, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
