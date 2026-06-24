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
// Middleware chain order on every MultiAuth-fronted write route is:
//
//	MultiAuth -> RequireWrite/RequireAdmin -> RateLimitByAPIKey -> TenantTx -> Audit -> handler
//
// The role guard runs BEFORE RateLimitByAPIKey and TenantTx so a
// permission-denied request never pins a rate-limit token (a read-scoped
// key probing write endpoints would otherwise consume its 60 req/min
// budget on rejections) and never opens a Postgres transaction
// (SET LOCAL app.current_tenant_id, BEGIN). Audit still runs after the
// guard, but because the guard handler short-circuits with c.JSON(...)
// the audit middleware sees the 403 response and logs it — which is the
// behaviour we want for forensic visibility into privilege probes. See
// the route-wiring callsites in cmd/server/main.go for the exact order
// applied per endpoint.
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
// Authorisation source: TenantContext (Role from ContextKeyRole, set by
// either Auth (Clerk JWT / self-hosted) or MultiAuth's API-key path via
// roleFromAPIKeyPermissions).
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
// canonical guard for tenant-administration routes — currently API-key
// management (CRUD on /apikeys and /projects/:id/apikeys).
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
