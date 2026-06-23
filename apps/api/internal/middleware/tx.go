package middleware

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/database"
)

// TenantTx wraps every authenticated request in an explicit Postgres
// transaction with `SET LOCAL app.current_tenant_id = '<uuid>'` so that
// Row-Level Security policies fire on the expected tenant for the lifetime
// of the request.
//
// Trust Rescue 9.1.2 (#3). Background:
//
//   - The runtime DB role (sbomhub_app) is NOBYPASSRLS as of Wave 1.
//   - Tenant-scoped tables are FORCE ROW LEVEL SECURITY as of migration 023,
//     so policies fire even for table owners.
//   - The legacy `TenantRepository.SetCurrentTenant(ctx, ...)` calls
//     `set_config('app.current_tenant_id', $1, true)` against `*sql.DB`,
//     which Postgres executes inside an implicit single-statement transaction.
//     Because `is_local = true` scopes the GUC to the current transaction,
//     the setting dies the moment the next statement starts on a different
//     pooled connection — i.e. virtually every subsequent statement in the
//     request. The net effect is `current_setting('app.current_tenant_id',
//     true)` returns NULL inside handlers, RLS policies evaluate to false,
//     SELECTs return 0 rows, and tenant-aware INSERTs (Wave 2b's
//     `LookupProjectTenantID` chain in particular) silently fail.
//
// TenantTx fixes this by:
//
//  1. Opening a real BEGIN at the top of the request,
//  2. Calling `SELECT set_config('app.current_tenant_id', $1, true)` on
//     that transaction so the GUC is bound to the transaction (and thus to
//     a single pinned connection),
//  3. Injecting the *sql.Tx into the request context via database.WithTx so
//     repositories that go through `database.Querier(ctx, r.db)` reuse the
//     same connection,
//  4. Committing on 2xx/3xx success, rolling back on err or HTTP status
//     >= 400, and rolling back + re-panicking on panic.
//
// Placement: TenantTx must run AFTER the auth middleware that populates
// ContextKeyTenantID (Auth / APIKeyAuth+APIKeyTenant / MultiAuth) and SHOULD
// wrap any audit middleware so audit_logs writes — which are themselves
// RLS-enforced — see the same tenant GUC. The trade-off is that audit
// records for failed requests get rolled back along with the rest of the
// request's writes; this is acknowledged in the Trust Rescue review and
// will be revisited if it bites operationally.
//
// Routes that do not have a tenant context (public endpoints, webhooks)
// must NOT be wrapped in TenantTx.
func TenantTx(db *sql.DB) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (rerr error) {
			tenantID, ok := c.Get(ContextKeyTenantID).(uuid.UUID)
			if !ok || tenantID == uuid.Nil {
				// This is a programming error: TenantTx was wired onto a
				// route that did not get a tenant set by upstream auth.
				// Refuse the request rather than open a tx with no GUC,
				// which would silently break RLS isolation downstream.
				slog.Error("TenantTx: missing tenant context — middleware ordering bug",
					"path", c.Path(), "method", c.Request().Method)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "tenant context missing",
				})
			}

			ctx := c.Request().Context()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				slog.Error("TenantTx: BeginTx failed", "error", err, "tenant_id", tenantID)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "failed to open transaction",
				})
			}

			// `SET LOCAL` itself does not accept query placeholders in
			// Postgres, but `set_config(name, value, is_local)` does. The
			// third arg `true` keeps the GUC scoped to this transaction so
			// it cannot leak across pooled connections — see the comment
			// on `TenantRepository.SetCurrentTenant`.
			if _, err := tx.ExecContext(ctx,
				`SELECT set_config('app.current_tenant_id', $1, true)`,
				tenantID.String(),
			); err != nil {
				_ = tx.Rollback()
				slog.Error("TenantTx: SET LOCAL failed",
					"error", err, "tenant_id", tenantID)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "failed to set tenant context",
				})
			}

			// Attach the tx to the request context so repositories that go
			// through database.Querier pick it up transparently. Echo
			// caches Request() so we have to swap the request in for the
			// new context to be visible downstream.
			txCtx := database.WithTx(ctx, tx)
			origReq := c.Request()
			c.SetRequest(origReq.WithContext(txCtx))

			// Track whether we have already finalised the tx so the
			// deferred handler does not double-rollback / leak. Without
			// this guard, if Commit succeeds we would still hit
			// Rollback() in the defer.
			finalised := false
			defer func() {
				if p := recover(); p != nil {
					if !finalised {
						_ = tx.Rollback()
					}
					// Restore the original request so any outer recovery
					// middleware sees the unmodified context.
					c.SetRequest(origReq)
					panic(p)
				}
				if !finalised {
					// next() returned a non-error nil but somehow we never
					// committed (e.g. unexpected control flow). Be safe.
					_ = tx.Rollback()
				}
				c.SetRequest(origReq)
			}()

			rerr = next(c)
			status := c.Response().Status

			// Treat any handler-returned error OR any 4xx/5xx response as
			// a rollback signal. Note that c.Response().Status defaults to
			// 200 in Echo even when nothing has been written; combined
			// with rerr == nil this is genuine success.
			if rerr != nil || status >= http.StatusBadRequest {
				if rbErr := tx.Rollback(); rbErr != nil && rbErr != sql.ErrTxDone {
					slog.Warn("TenantTx: rollback failed",
						"error", rbErr, "tenant_id", tenantID,
						"status", status, "handler_err", rerr)
				}
				finalised = true
				return rerr
			}

			if cErr := tx.Commit(); cErr != nil {
				finalised = true
				slog.Error("TenantTx: commit failed",
					"error", cErr, "tenant_id", tenantID, "status", status)
				return cErr
			}
			finalised = true
			return nil
		}
	}
}
