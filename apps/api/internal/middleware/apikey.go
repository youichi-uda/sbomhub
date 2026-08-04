package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

const (
	APIKeyHeader  = "X-API-Key" //nolint:gosec // G101 false positive: this is the HTTP header *name* clients send keys in, not a credential value
	BearerPrefix  = "Bearer "
	ContextKeyAPI = "api_key"
)

// presentedAPIKey resolves the credential an API-key-only route group was given.
//
// Codex R2 (Low): this used to read `Header.Get`, which returns only the FIRST
// value of a repeated header, while MultiAuth (after Codex R1) reads them all.
// The two then disagreed about the same request — an empty first `X-API-Key`
// followed by a real one authenticated on the canonical routes and fell back to
// `Authorization` here, so one request could be two different principals
// depending on which route family it hit. Both now share pickSingleCredential.
//
// Ambiguity (two DIFFERENT values under one header) is refused rather than
// resolved by position.
//
// Codex R5 (Medium): the Authorization channel applies the same `sbh_` prefix
// rule MultiAuth does. It previously accepted ANY Bearer value here, on the
// stated grounds that these groups have no Clerk path and a key predating the
// prefix should keep working — but nothing in the product mints such a key
// (service.APIKeyService.generateAPIKey always emits `sbh_`), so that was a
// claim without a source, and it made one request resolve to an API key here and
// to a Clerk/self-hosted identity on the canonical routes. One rule, both
// middlewares.
//
// A key that genuinely lacks the prefix is still accepted in X-API-Key, which
// applies no prefix rule on either middleware.
func presentedAPIKey(r *http.Request) (raw string, present, ambiguous bool) {
	if v, ok, amb := pickSingleCredential(r.Header.Values(APIKeyHeader), asIs); amb || ok {
		return v, ok, amb
	}
	v, present, ambiguous := bearerFromRequest(r)
	if ambiguous || !present {
		return "", present, ambiguous
	}
	if v != "" && !strings.HasPrefix(v, apiKeyPrefix) {
		// A Bearer value that is not key-shaped is not a credential this
		// middleware can use. Reported as PRESENT with no value, so the caller
		// refuses it rather than answering "API key required" — the caller did
		// supply one.
		return "", true, false
	}
	return v, true, false
}

// APIKeyAuth returns a middleware that validates API keys
func APIKeyAuth(keyService *service.APIKeyService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey, present, ambiguous := presentedAPIKey(c.Request())

			if ambiguous || (present && apiKey == "") {
				slog.Warn("apikey: request carried an unusable API-key header")
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid API key",
				})
			}

			if !present {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "API key required. Use X-API-Key header or Authorization: Bearer <key>",
				})
			}

			// Validate the key
			key, err := keyService.ValidateKey(c.Request().Context(), apiKey)
			if err != nil {
				// Opaque auth failure: never leak whether it was a bad key
				// or an internal lookup error (F445). Log detail, return generic.
				slog.Warn("apikey: key validation failed", "error", err)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid API key",
				})
			}

			// Store key info in context for handlers to use
			c.Set(ContextKeyAPI, key)

			// M50 W2: a key with api_keys.project_id set may only act on that
			// project. Checked here — the moment the raw string becomes an
			// authenticated identity — rather than per route, so no route on
			// this middleware can be reached without the check. Tenant-level
			// keys (project_id IS NULL) return immediately and are unaffected.
			// See project_scope.go for the route table and the 403 rationale.
			if ok, err := apiKeyProjectScopeAllowed(c, key); !ok {
				return err
			}

			return next(c)
		}
	}
}

// OptionalAPIKeyAuth returns a middleware that validates API keys if present
// but doesn't require them (for mixed auth scenarios)
func OptionalAPIKeyAuth(keyService *service.APIKeyService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey, present, ambiguous := presentedAPIKey(c.Request())

			// Optional does not mean "ignorable": a credential the caller
			// supplied and this middleware cannot resolve must end the request,
			// not be dropped so the route runs anonymously (Codex R2 Low).
			if ambiguous || (present && apiKey == "") {
				slog.Warn("apikey: request carried an unusable API-key header")
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid API key",
				})
			}

			if present {
				// Validate the key if present
				key, err := keyService.ValidateKey(c.Request().Context(), apiKey)
				if err != nil {
					slog.Warn("apikey: key validation failed", "error", err)
					return c.JSON(http.StatusUnauthorized, map[string]string{
						"error": "invalid API key",
					})
				}
				c.Set(ContextKeyAPI, key)

				// M50 W2: same project-scope filter as APIKeyAuth. This
				// middleware is currently registered on no route in
				// cmd/server/main.go (pinned by
				// TestM50W2OptionalAPIKeyAuthIsUnwired), but it is exported and
				// it is one of the three ValidateKey call sites, so it carries
				// the check too — a route wired to it later inherits
				// default-deny instead of a bypass.
				if ok, err := apiKeyProjectScopeAllowed(c, key); !ok {
					return err
				}
			}

			return next(c)
		}
	}
}

// APIKeyTenant sets tenant context from the API key's own tenant_id.
//
// It sets exactly two context values and issues one statement:
// ContextKeyTenantID and ContextKeyRole, after SetCurrentTenant binds
// `app.current_tenant_id` for RLS. It does NOT look at api_keys.project_id —
// M50 W2 moved that check into APIKeyAuth, which runs ahead of this middleware on
// every group that uses the pair (see project_scope.go). An earlier version of
// this comment claimed a "fallback to project->tenant lookup for legacy
// project-level keys"; no such lookup was in the code, and there is none now:
// tenant_id is NOT NULL on api_keys, so there is nothing to fall back from.
//
// M1 Codex review #F18: in addition to ContextKeyTenantID, this middleware
// now also populates ContextKeyRole by mapping api_keys.permissions through
// roleFromAPIKeyPermissions (shared with MultiAuth's handleAPIKeyAuth in
// multiauth.go). Without that mapping, RequireWrite() — which we want to
// apply to the legacy /api/v1/cli/* write group — would reject every
// API-key caller with 403 because Role() defaulted to "". With the mapping
// in place, read-scoped keys (permissions="read" → RoleViewer) correctly
// fail RequireWrite while write/admin/owner keys (RoleMember / RoleAdmin)
// pass through. The F17 fail-closed default for unknown / empty values
// applies here too — a row that escaped CreateKey's allowlist cannot be
// used to drive writes on the legacy CLI group either.
func APIKeyTenant(projectRepo *repository.ProjectRepository, tenantRepo *repository.TenantRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key, ok := c.Get(ContextKeyAPI).(*model.APIKey)
			if !ok || key == nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid API key context",
				})
			}

			// New: Use tenant_id directly from the API key (tenant-level keys)
			tenantID := key.TenantID

			// Set tenant context for RLS
			if err := tenantRepo.SetCurrentTenant(c.Request().Context(), tenantID); err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to set tenant context"})
			}
			c.Set(ContextKeyTenantID, tenantID)

			// F18: map api_keys.permissions → ContextKeyRole so
			// downstream RequireWrite() on the legacy /api/v1/cli/* write
			// group (and any other route that adds the F15 role guard
			// behind APIKeyAuth + APIKeyTenant) can reject read-scoped
			// keys instead of silently accepting them. Mirrors what
			// MultiAuth.handleAPIKeyAuth does on the canonical path —
			// keep the two in sync via roleFromAPIKeyPermissions.
			c.Set(ContextKeyRole, roleFromAPIKeyPermissions(key.Permissions))

			return next(c)
		}
	}
}
