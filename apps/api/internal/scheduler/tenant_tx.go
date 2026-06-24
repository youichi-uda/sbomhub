// Package scheduler — tenant_tx.go
//
// Shared helper for background jobs that touch RLS-enabled tables.
//
// Why this exists (codex-r4 Finding P1):
//   The runtime app role `sbomhub_app` is NOBYPASSRLS + FORCE ROW LEVEL
//   SECURITY (see migrations 023 / 027 / 028 / 029). Every RLS policy on the
//   per-tenant tables (projects, sboms, components, report_settings,
//   vulnerability_tickets, notification_settings, …) requires
//   `current_setting('app.current_tenant_id')` to match the row's
//   `tenant_id`. Request handlers get this GUC for free through the
//   `TenantTx` middleware. Background jobs do NOT pass through middleware —
//   they run on a bare `context.Background()` against `j.db` — so without
//   help they silently see zero rows and every scheduled scan / report /
//   ticket sync becomes a no-op.
//
// The fix is intentionally simple: for each tenant the job needs to touch,
// open a fresh transaction, `SET LOCAL app.current_tenant_id` to that
// tenant's UUID, and run the per-tenant work inside the tx. `database.WithTx`
// attaches the tx to the context so any repository that uses
// `database.Querier(ctx, r.db)` automatically picks it up — no churn at the
// repository layer.
package scheduler

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
)

// runWithTenantTx opens a transaction on db, pins it to `tenantID` via
// `set_config('app.current_tenant_id', $1, true)`, and invokes fn with a
// ctx that carries the tx. The `is_local=true` flag scopes the GUC to the
// transaction only — once the tx commits or rolls back, the underlying
// pooled connection returns to the pool with no tenant residue, so two
// concurrent jobs cannot leak tenant context across each other.
//
// fn is expected to do all of its tenant-scoped work synchronously inside
// this call. Anything spawned on a goroutine that out-lives fn must NOT
// touch RLS tables through txCtx — by the time the goroutine runs, the tx
// will have been committed or rolled back and the connection released. If a
// goroutine genuinely needs tenant context (e.g. an async report email
// poller), it must call runWithTenantTx again for itself.
func runWithTenantTx(
	ctx context.Context,
	db *sql.DB,
	tenantID uuid.UUID,
	fn func(txCtx context.Context, tx *sql.Tx) error,
) error {
	return database.WithTxFunc(ctx, db, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(
			txCtx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); err != nil {
			return fmt.Errorf("scheduler: set tenant context for %s: %w", tenantID, err)
		}
		return fn(txCtx, tx)
	})
}
