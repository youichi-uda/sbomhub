package middleware

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// RequireWrite and RequireAdmin are the two role-gate middlewares shared by
// every mutating / privileged route mounted on MultiAuth. They were
// introduced in the M1 Codex review #F15 / #F16 fix to give us a single
// chokepoint for "this caller must have write / admin power on the
// authenticated tenant" — previously each handler decided on its own
// whether to consult TenantContext.CanWrite / CanAdmin, with the result
// that the canonical SBOM upload route (SbomHandler.Upload) never checked
// CanWrite at all, and the API-key management routes never checked
// CanAdmin. A read-scoped `sbh_...` key could therefore upload SBOMs
// (F15), and any tenant member could mint a write-capable API key (F16,
// privilege escalation).
//
// Middleware chain order. There are three registration shapes in
// cmd/server/main.go, and in all of them the guard sits IMMEDIATELY AFTER the
// middleware that establishes the tenant context and BEFORE RateLimitByAPIKey
// and TenantTx (Codex round 4, Low: "before anything that costs a resource"
// was too strong — the auth middleware ahead of it already did database work):
//
//	MultiAuth-fronted routes (registered on the Echo instance):
//	  MultiAuth -> RequireWrite/RequireAdmin -> RateLimitByAPIKey -> TenantTx -> Audit -> handler
//
//	Clerk / self-hosted routes (the authWrite / authAdmin groups):
//	  Auth -> RequireWrite/RequireAdmin -> TenantTx -> Audit -> handler
//
//	Legacy CLI API-key routes (the cliWrite group):
//	  APIKeyAuth -> APIKeyTenant -> RequireWrite -> TenantTx -> RateLimitByAPIKey -> MCPAudit -> handler
//
// The guard runs BEFORE RateLimitByAPIKey and TenantTx so a
// permission-denied request never pins a rate-limit token (a read-scoped
// key probing write endpoints would otherwise consume its 60 req/min
// budget on rejections) and never opens a Postgres transaction
// (BEGIN, SET LOCAL app.current_tenant_id).
//
// The property, stated exactly: a denial never ENTERS TenantTx, so it never
// opens or holds the request transaction. It is NOT independent of the
// database, and it is not "one query instead of two" — the auth middleware
// ahead of this issues several queries of its own (tenant + user lookup;
// APIKeyTenant additionally calls SetCurrentTenant on the CLI groups), so an
// outage during authentication is still answered 500 before this guard is
// consulted. Pinned by
// TestM47RRoleGuardRefusesWithoutTheRequestTransaction, which asserts exactly
// that: 403, and BeginTx never reached.
//
// M47R — WHAT A DENIAL DOES NOT DO. An earlier version of this comment
// claimed that "the audit middleware sees the 403 response and logs it",
// giving forensic visibility into privilege probes. That was never true
// and is not true now:
//
//   - the Clerk / self-hosted group routes used to pass the guard as a
//     PER-ROUTE argument to a group that already carried TenantTx, so the
//     real order was Auth -> TenantTx -> Audit -> guard. The audit row was
//     written — and then rolled back, because TenantTx rolls back on any
//     status >= 400. A DB outage also answered 500 instead of 403, since
//     BeginTx failed before the guard was ever consulted;
//   - with the M47R group split above, the guard short-circuits before the
//     Audit middleware is entered at all, so no audit row is attempted.
//
// Either way there is NO audit_logs row for a denial. The only ROLE-SPECIFIC
// record of a privilege probe is the slog.Warn below (path, method, tenant,
// user, role, IP); Echo's global request logger also records the 403, but with
// no role or tenant, so it cannot answer "who probed what". Persisting
// denials would require an audit write outside the request transaction; that
// is an open residual, not a property this middleware provides.
//
// Response body policy (F10 regulatory carry-over): a forbidden response
// returns a generic `{"error":"forbidden"}` JSON body. The precise
// reason (tenant_id, role, route, method) is logged via slog at warn
// level so operators can audit privilege-probe attempts without leaking
// the role allowlist or the role of the calling user back to the
// requester. This matches the #F10 contract on triage 404 sentinels.

// RequireWrite returns an Echo middleware that rejects requests whose
// caller does not have write privileges on the current tenant. It is the
// canonical guard for every API-key-reachable mutating endpoint
// (POST /api/v1/projects/:id/sbom, the triage / vex-drafts write routes,
// etc.).
//
// Authorisation source: TenantContext (Role from ContextKeyRole, set by Auth
// (Clerk JWT / self-hosted), by MultiAuth's API-key path, or by APIKeyTenant
// on the legacy CLI group — the latter two both map api_keys.permissions
// through roleFromAPIKeyPermissions).
//
// Failure modes:
//   - No tenant context (ContextKeyTenantID is unset) → 401 unauthorized.
//     This mirrors the handler-side unauthorized contract used by
//     VexDraftsHandler.RunTriage so a misconfigured route that bypasses
//     auth still does not leak a 403 (which would suggest auth ran).
//   - Tenant context present but role does not satisfy CanWrite() →
//     403 with the generic forbidden body.
func RequireWrite() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tc := NewTenantContext(c)
			if tc.TenantID() == uuid.Nil {
				slog.Warn("RequireWrite: missing tenant context",
					"path", c.Path(),
					"method", c.Request().Method,
					"ip", c.RealIP(),
				)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "unauthorized",
				})
			}
			if !tc.CanWrite() {
				slog.Warn("RequireWrite: insufficient role",
					"path", c.Path(),
					"method", c.Request().Method,
					"tenant_id", tc.TenantID(),
					"user_id", tc.UserID(),
					"role", tc.Role(),
					"ip", c.RealIP(),
				)
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "forbidden",
				})
			}
			return next(c)
		}
	}
}

// RequireAdmin returns an Echo middleware that rejects requests whose
// caller does not have admin privileges on the current tenant. It is the
// canonical guard for tenant administration: API-key management (CRUD on
// /apikeys and /projects/:id/apikeys), billing, the global-catalog sync
// triggers, and — since M47R — the tenant settings that hold a secret
// (/settings/llm, /tenant/settings/diff-webhook and its test fire).
//
// The handler-side allowlist (TenantContext.CanAdmin) is Owner or Admin
// only. Member, Viewer, and an unset role all fail the check. This is
// the M1 Codex review #F16 fix: previously any authenticated tenant user
// could call POST /api/v1/apikeys and mint a write-capable API key
// (privilege escalation — a Member could escape their role by issuing
// themselves a sbh_... key that, after the F14 MultiAuth integration,
// satisfied CanWrite on triage / SBOM upload routes).
//
// Failure modes mirror RequireWrite: 401 when no tenant context, 403
// with a generic body when the role does not satisfy CanAdmin. The
// precise denial reason is logged via slog at warn level.
//
// Naming collision note: middleware.RequireAdmin (this function) is the
// CanAdmin-on-tenant guard introduced in F16. There is also an older
// auth.go::RequireAdmin built on top of RequireRole(RoleOwner, RoleAdmin)
// — that helper is semantically equivalent (same role allowlist) but
// returns the legacy {"error":"insufficient permissions"} body and is
// retained for backwards compatibility with routes that have not yet
// been migrated. New write/admin gates should use the F15/F16 helpers
// in this file so the response body and log fields stay aligned.
func RequireAdmin() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tc := NewTenantContext(c)
			if tc.TenantID() == uuid.Nil {
				slog.Warn("RequireAdmin: missing tenant context",
					"path", c.Path(),
					"method", c.Request().Method,
					"ip", c.RealIP(),
				)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "unauthorized",
				})
			}
			if !tc.CanAdmin() {
				slog.Warn("RequireAdmin: insufficient role",
					"path", c.Path(),
					"method", c.Request().Method,
					"tenant_id", tc.TenantID(),
					"user_id", tc.UserID(),
					"role", tc.Role(),
					"ip", c.RealIP(),
				)
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "forbidden",
				})
			}
			return next(c)
		}
	}
}
