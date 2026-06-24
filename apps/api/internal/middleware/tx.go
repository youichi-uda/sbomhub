package middleware

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/database"
)

// postCommitHooksKey is the unexported context key for the per-request
// post-commit hook registry. Hooks registered through RegisterPostCommit are
// run by TenantTx after the request's transaction commits successfully — see
// RegisterPostCommit godoc for the contract.
type postCommitHooksKey struct{}

// postCommitHookRegistry holds the slice of callbacks to run after a
// successful commit. A mutex guards the slice so handlers that fan out into
// goroutines and register hooks from each can still do so safely.
type postCommitHookRegistry struct {
	mu    sync.Mutex
	hooks []func()
}

func (r *postCommitHookRegistry) append(fn func()) {
	r.mu.Lock()
	r.hooks = append(r.hooks, fn)
	r.mu.Unlock()
}

func (r *postCommitHookRegistry) drain() []func() {
	r.mu.Lock()
	out := r.hooks
	r.hooks = nil
	r.mu.Unlock()
	return out
}

// RegisterPostCommit queues fn to run after the current request's TenantTx
// transaction commits successfully.
//
// Semantics:
//   - Hooks run sequentially in registration order on the request goroutine,
//     after Commit() returns nil and before TenantTx returns to the response
//     writer chain.
//   - Hooks DO NOT run if the request rolls back: any handler-returned error,
//     any 4xx/5xx response, any panic, or a Commit() failure.
//   - A panic inside a hook is recovered and logged so one bad hook cannot
//     take down the request — sibling hooks still run, the response is not
//     affected.
//   - Calling RegisterPostCommit outside of a TenantTx-wrapped route logs a
//     warning and silently drops the hook (no panic), to match the
//     middleware's "not on a tenant route → refuse the request" stance
//     without crashing exotic call sites.
//
// Typical use: a handler that has issued tenant-scoped INSERTs in the request
// transaction and wants to kick off a background job that depends on those
// rows being visible. Registering the launch as a post-commit hook avoids the
// race in which the background goroutine opens its own transaction before the
// request transaction commits, sees zero rows, and silently completes.
//
// Codex R2 P1: previously the SBOM upload handler launched its background
// vulnerability scan goroutine inside the request tx; the goroutine opened
// its own tx and called ComponentRepository.ListBySbom, which (correctly)
// could not see the un-committed parent INSERTs and so completed with 0
// components, 0 vulnerabilities — `sbomhub scan --fail-on critical` always
// exited 0.
func RegisterPostCommit(c echo.Context, fn func()) {
	if fn == nil {
		return
	}
	registry, _ := c.Request().Context().Value(postCommitHooksKey{}).(*postCommitHookRegistry)
	if registry == nil {
		slog.Warn("RegisterPostCommit called outside TenantTx — hook will not run",
			"path", c.Path(), "method", c.Request().Method)
		return
	}
	registry.append(fn)
}

// bufferedResponseWriter is an http.ResponseWriter shim that records the
// handler's status code, headers and body in memory instead of pushing them
// onto the wire immediately.
//
// Codex R20 P2: previously `c.JSON(http.StatusCreated, ...)` inside a
// TenantTx-wrapped handler wrote the response status + body to the client
// connection BEFORE the deferred `tx.Commit()` decided whether the
// underlying rows would actually persist. A commit that failed afterwards
// (constraint violation, network blip, ctx cancel, statement timeout)
// rolled the DB back while the client kept its 201 + body — and any
// RegisterPostCommit hook (notably the SBOM upload background-scan launch)
// never ran. Buffering moves the wire flush past the commit decision so
// the bytes that reach the client always reflect DB durability.
//
// The wrapper keeps its own header map and body buffer so that on
// commit-failure we can drop the handler's response cleanly without having
// to scrub already-set headers off the real writer. On commit success (or
// any rollback-with-response path) flushTo() copies headers + status code +
// body onto the real writer in one shot. Handlers that wrote nothing leave
// the buffer untouched, in which case flushTo is a no-op and the outer
// Echo error handler (or recovery middleware) can still own the response.
//
// No SBOMHub handler currently relies on streaming response writers (SSE,
// websockets, chunked file streaming): every JSON / Blob / NoContent path
// materialises the full body before writing, and a project-wide grep for
// http.Hijacker / http.Flusher / ResponseController over apps/api/internal
// turns up zero hits. If a future handler needs streaming under TenantTx
// it must either opt out of the middleware or skip the buffer (e.g. by
// detecting `text/event-stream` and bypassing the wrapper).
type bufferedResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
	// written becomes true the first time the handler called WriteHeader or
	// Write. We need to distinguish "handler never touched the response"
	// (flush should be a no-op so Echo can produce the response itself)
	// from "handler wrote an empty 200" (flush must still call WriteHeader
	// on the real writer so the client gets a status line).
	written bool
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
}

func (b *bufferedResponseWriter) Header() http.Header { return b.header }

func (b *bufferedResponseWriter) WriteHeader(code int) {
	if b.written {
		// Mirror net/http semantics: a second WriteHeader is a no-op (and
		// would normally log "superfluous WriteHeader"). Echo's Response
		// wrapper guards this above us, but defend in depth.
		return
	}
	b.statusCode = code
	b.written = true
}

func (b *bufferedResponseWriter) Write(p []byte) (int, error) {
	if !b.written {
		// net/http auto-sends 200 on the first Write if WriteHeader was not
		// called. Echo's Response.Write also sets Status = 200 in this case
		// before calling our WriteHeader, but again defend in depth.
		b.statusCode = http.StatusOK
		b.written = true
	}
	return b.body.Write(p)
}

// flushTo copies the buffered headers, status code, and body onto actual.
// If the handler never wrote anything (no WriteHeader, no Write, no
// Header().Set on this wrapper), flushTo is a no-op so the caller can let
// Echo or downstream middleware own the response.
func (b *bufferedResponseWriter) flushTo(actual http.ResponseWriter) {
	if !b.written && b.body.Len() == 0 && len(b.header) == 0 {
		return
	}
	// Replace any pre-existing values on the actual writer with what the
	// handler set. Pass-through would be simpler but leaves stale headers
	// in place if the actual writer was pre-populated upstream.
	dst := actual.Header()
	for k, vv := range b.header {
		dst.Del(k)
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	if b.written {
		actual.WriteHeader(b.statusCode)
	}
	if b.body.Len() > 0 {
		_, _ = actual.Write(b.body.Bytes())
	}
}

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
			// new context to be visible downstream. We also stash an empty
			// post-commit hook registry so handlers can opt into "run X
			// after my tenant tx commits" via RegisterPostCommit.
			postCommit := &postCommitHookRegistry{}
			txCtx := database.WithTx(ctx, tx)
			txCtx = context.WithValue(txCtx, postCommitHooksKey{}, postCommit)
			origReq := c.Request()
			c.SetRequest(origReq.WithContext(txCtx))

			// Wrap the response writer so the handler's status code + body
			// land in memory instead of on the wire. We can then decide,
			// based on tx commit outcome, whether to flush the handler's
			// response (success / handler-driven 4xx) or replace it with a
			// 500 (commit failure). See bufferedResponseWriter godoc.
			originalWriter := c.Response().Writer
			buffer := newBufferedResponseWriter()
			c.Response().Writer = buffer

			// restoreWriter swaps the real writer back into echo.Response so
			// any caller (Echo's error handler, outer recovery middleware,
			// our own c.JSON fallback below) writes to the wire rather than
			// to our discarded buffer. Idempotent.
			restoreWriter := func() {
				if c.Response().Writer == buffer {
					c.Response().Writer = originalWriter
				}
			}

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
					// Discard whatever the handler partially buffered — a
					// panic through here leaves the response undefined, so
					// let the outer recovery middleware write a clean 500
					// to the real writer.
					restoreWriter()
					c.SetRequest(origReq)
					panic(p)
				}
				if !finalised {
					// next() returned a non-error nil but somehow we never
					// committed (e.g. unexpected control flow). Be safe.
					_ = tx.Rollback()
				}
				// Belt-and-suspenders: the success / rollback paths below
				// restore the writer themselves, but if anything in the
				// finalisation slipped past, make sure the real writer is
				// back in place before we return to Echo.
				restoreWriter()
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
				// Flush whatever the handler wrote (a 4xx body, an error
				// payload, or nothing at all) to the real writer. The DB
				// side is rolled back, but the handler-shaped response —
				// notably the 4xx body it crafted — is what the client
				// expects to see. If the handler wrote nothing AND
				// returned an error, the buffer is empty, flush is a
				// no-op, and Echo's error handler will own the response
				// on the now-restored real writer.
				restoreWriter()
				buffer.flushTo(originalWriter)
				return rerr
			}

			if cErr := tx.Commit(); cErr != nil {
				finalised = true
				slog.Error("TenantTx: commit failed",
					"error", cErr, "tenant_id", tenantID, "status", status)
				// Critical: do NOT flush the handler's buffered 2xx. The DB
				// rolled back, so the client must not see the success
				// response. Reset Echo's response bookkeeping so c.JSON
				// will actually write a fresh 500 (otherwise Committed=true
				// from the handler would short-circuit the write).
				restoreWriter()
				resp := c.Response()
				resp.Status = 0
				resp.Size = 0
				resp.Committed = false
				// Also clear any headers the handler set in the buffer
				// that we intentionally did NOT propagate — the real
				// writer should reflect the error response, not the
				// rolled-back success response. (Headers set directly on
				// the real writer by upstream middleware survive.)
				if err := c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "transaction commit failed",
				}); err != nil {
					slog.Error("TenantTx: failed to write commit-failure response",
						"error", err, "tenant_id", tenantID)
					return err
				}
				// Post-commit hooks must NOT run on commit failure — the
				// data they depend on never landed. The early return here
				// preserves that invariant.
				return nil
			}
			finalised = true

			// Commit succeeded: flush the handler's buffered response to
			// the wire so the client finally sees the 2xx + body, then
			// run any post-commit hooks. Hooks run sequentially in
			// registration order on this goroutine; if a hook needs to
			// outlive the request it is the hook's job to spawn its own
			// goroutine (this matches how SbomHandler.startBackgroundScan
			// kicks off the NVD/JVN scan). Panics are recovered so one
			// buggy hook cannot crash the response. See
			// RegisterPostCommit godoc for the guarantees.
			restoreWriter()
			buffer.flushTo(originalWriter)
			for i, fn := range postCommit.drain() {
				runPostCommitHook(tenantID, i, fn)
			}
			return nil
		}
	}
}

// runPostCommitHook invokes fn with a recover so a panicking hook does not
// take down sibling hooks or the response writer. The recovery only logs;
// hooks that need to surface failure must do so out-of-band (e.g. via
// ScanTracker), exactly as they would in a goroutine they launched
// themselves.
func runPostCommitHook(tenantID uuid.UUID, idx int, fn func()) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("post-commit hook panicked",
				"tenant_id", tenantID, "hook_index", idx, "panic", p)
		}
	}()
	fn()
}
