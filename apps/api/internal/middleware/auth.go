package middleware

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	clerkhttp "github.com/clerk/clerk-sdk-go/v2/http"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	ContextKeyUserID      = "user_id"
	ContextKeyUser        = "user"
	ContextKeyTenantID    = "tenant_id"
	ContextKeyTenant      = "tenant"
	ContextKeyRole        = "role"
	ContextKeyClerkOrgID  = "clerk_org_id"
	ContextKeyClerkUserID = "clerk_user_id"
)

// AuthContext holds authentication context for a request
type AuthContext struct {
	UserID       uuid.UUID
	TenantID     uuid.UUID
	ClerkUserID  string
	ClerkOrgID   string
	Role         string
	IsSelfHosted bool
}

// GetAuthContext retrieves the auth context from Echo context
func GetAuthContext(c echo.Context) *AuthContext {
	userID, _ := c.Get(ContextKeyUserID).(uuid.UUID)
	tenantID, _ := c.Get(ContextKeyTenantID).(uuid.UUID)
	role, _ := c.Get(ContextKeyRole).(string)
	clerkUserID, _ := c.Get(ContextKeyClerkUserID).(string)
	clerkOrgID, _ := c.Get(ContextKeyClerkOrgID).(string)

	return &AuthContext{
		UserID:       userID,
		TenantID:     tenantID,
		ClerkUserID:  clerkUserID,
		ClerkOrgID:   clerkOrgID,
		Role:         role,
		IsSelfHosted: clerkUserID == "self-hosted",
	}
}

// Auth returns a middleware that handles authentication based on mode
// - SaaS mode: Validates Clerk JWT token
// - Self-hosted mode: Uses default tenant/user
func Auth(cfg *config.Config, tenantRepo *repository.TenantRepository, userRepo *repository.UserRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()

			if cfg.IsSelfHosted() {
				return handleSelfHostedAuth(c, ctx, tenantRepo, userRepo, next)
			}

			return handleClerkAuth(c, ctx, tenantRepo, userRepo, next)
		}
	}
}

// handleSelfHostedAuth sets up default tenant and user for self-hosted mode
func handleSelfHostedAuth(c echo.Context, ctx context.Context, tenantRepo *repository.TenantRepository, userRepo *repository.UserRepository, next echo.HandlerFunc) error {
	// Get or create default tenant
	tenant, err := tenantRepo.GetOrCreateDefault(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to initialize default tenant",
		})
	}

	// Get or create default user
	user, err := userRepo.GetOrCreateDefault(ctx, tenant.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to initialize default user",
		})
	}

	// Set RLS context
	if err := tenantRepo.SetCurrentTenant(ctx, tenant.ID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to set tenant context",
		})
	}

	// Set context values
	c.Set(ContextKeyTenantID, tenant.ID)
	c.Set(ContextKeyTenant, tenant)
	c.Set(ContextKeyUserID, user.ID)
	c.Set(ContextKeyUser, user)
	c.Set(ContextKeyRole, model.RoleOwner)
	c.Set(ContextKeyClerkUserID, "self-hosted")
	c.Set(ContextKeyClerkOrgID, "self-hosted")

	return next(c)
}

// handleClerkAuth validates Clerk JWT and sets up tenant/user context.
// No config parameter: Clerk verification uses the process-global key
// (clerk.SetKey at startup — see verifyClerkJWT).
func handleClerkAuth(c echo.Context, ctx context.Context, tenantRepo *repository.TenantRepository, userRepo *repository.UserRepository, next echo.HandlerFunc) error {
	// Get token from Authorization header.
	//
	// M51: read through bearerFromRequest, the package's single Bearer rule,
	// rather than the `strings.TrimPrefix(authHeader, "Bearer ")` over
	// `Header.Get` that used to live here. That local rule differed from the one
	// MultiAuth / APIKeyAuth apply in four measurable ways — scheme case, the
	// number of delimiting spaces, a repeated header (first-wins here, refused
	// there), and an announced-but-empty credential (admitted here, refused
	// there) — so the same request line meant different things on different
	// routes of one server. See bearerFromRequest and bearer_parity_test.go.
	if bearerHeaderAbsent(c.Request()) {
		slog.Debug("Auth failed: missing authorization header")
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "missing authorization header",
		})
	}

	token, present, ambiguous := bearerFromRequest(c.Request())
	switch {
	case ambiguous:
		// Two DIFFERENT credentials under one header name. Picking either is a
		// guess about which the caller meant, and "take the first" is the rule
		// that produced the M50 fall-through. MultiAuth already refuses this;
		// now so does the Clerk window, which is what makes the accepted set
		// the same on both.
		slog.Warn("Auth failed: request carried conflicting Authorization values",
			"ip", c.RealIP())
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid authorization header format",
		})
	case !present, token == "":
		// `!present` is a non-Bearer scheme or a malformed one. `token == ""` is
		// `Authorization: Bearer ` with nothing after it — a credential
		// announced and not supplied, which previously slipped past this check
		// (TrimPrefix returns "" which is != the header) and reached Clerk as an
		// empty token.
		slog.Debug("Auth failed: invalid authorization header format")
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid authorization header format",
		})
	}

	slog.Debug("Verifying Clerk JWT", "token_length", len(token), "token_prefix", token[:min(20, len(token))])

	// Verify JWT with Clerk using official HTTP middleware
	claims, err := verifyClerkJWT(c, token)
	if err != nil {
		slog.Error("Clerk JWT verification failed", "error", err)
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid token",
		})
	}

	// SECURITY FIX: Only use organization ID from verified JWT claims
	// Previously, X-Clerk-Org-ID header was trusted, allowing any authenticated user
	// to spoof another organization and gain unauthorized access.
	// Now we only trust the org ID embedded in the verified JWT token.
	orgID := claims.OrgID

	// Log warning if header is present (indicates potential attack or outdated client)
	if headerOrgID := c.Request().Header.Get("X-Clerk-Org-ID"); headerOrgID != "" {
		if headerOrgID != orgID {
			slog.Warn("X-Clerk-Org-ID header mismatch - potential spoofing attempt",
				"header_org_id", headerOrgID,
				"jwt_org_id", orgID,
				"user_id", claims.UserID,
				"ip", c.RealIP(),
			)
		}
	}

	slog.Info("Clerk auth", "user_id", claims.UserID, "org_id", orgID)

	if orgID == "" {
		slog.Warn("Organization ID is empty - user must select an organization")
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "organization membership required - please select an organization",
		})
	}

	// Get or create tenant by Clerk org ID (auto-provisioning)
	tenant, err := tenantRepo.GetOrCreateByClerkOrgID(ctx, orgID, "")
	if err != nil {
		slog.Error("Failed to get or create tenant", "error", err, "clerk_org_id", orgID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get organization",
		})
	}

	// Get or create user by Clerk user ID (auto-provisioning)
	user, err := userRepo.GetByClerkUserID(ctx, claims.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Create user on first login
			now := time.Now()
			user = &model.User{
				ID:          uuid.New(),
				ClerkUserID: claims.UserID,
				Email:       claims.UserID + "@clerk.user", // Placeholder, will be updated via webhook
				Name:        "User",
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if err := userRepo.Create(ctx, user); err != nil {
				slog.Error("Failed to create user", "error", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "failed to create user",
				})
			}
		} else {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to get user",
			})
		}
	}

	// Get or create user's role in tenant (auto-provisioning)
	tenantUser, err := userRepo.GetUserRole(ctx, tenant.ID, user.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Add user to tenant (first user becomes owner)
			role := model.RoleMember
			if claims.OrgRole == "org:admin" {
				role = model.RoleOwner
			}
			tenantUser = &model.TenantUser{
				TenantID:  tenant.ID,
				UserID:    user.ID,
				Role:      role,
				CreatedAt: time.Now(),
			}
			if err := userRepo.AddToTenant(ctx, tenantUser); err != nil {
				slog.Error("Failed to add user to tenant", "error", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "failed to add user to organization",
				})
			}
		} else {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to get user role",
			})
		}
	}

	// Set RLS context
	if err := tenantRepo.SetCurrentTenant(ctx, tenant.ID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to set tenant context",
		})
	}

	// Set context values
	c.Set(ContextKeyTenantID, tenant.ID)
	c.Set(ContextKeyTenant, tenant)
	c.Set(ContextKeyUserID, user.ID)
	c.Set(ContextKeyUser, user)
	c.Set(ContextKeyRole, tenantUser.Role)
	c.Set(ContextKeyClerkUserID, claims.UserID)
	c.Set(ContextKeyClerkOrgID, orgID)

	return next(c)
}

// ClerkClaims represents the relevant claims from a Clerk JWT
type ClerkClaims struct {
	UserID  string
	OrgID   string
	OrgRole string
}

// bearerHeaderAbsent reports whether a request carries no Authorization value
// worth parsing.
//
// It reads EVERY value, not `Header.Get` (M51). With Get, the shape
//
//	Authorization:
//	Authorization: Bearer sbh_<a real key>
//
// answered "missing authorization header" while MultiAuth — which reads all
// values — honoured the key. One request, two answers.
//
// An empty value counts as absent rather than as a malformed credential: that
// is what a shell produces from `-H "Authorization: $UNSET"`, and asIs in
// multiauth.go has always treated the X-API-Key equivalent the same way.
func bearerHeaderAbsent(r *http.Request) bool {
	for _, v := range r.Header.Values(echo.HeaderAuthorization) {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}

// clerkAuthorizationRequest returns a copy of r whose Authorization header is
// the canonical `Bearer <token>`, leaving r itself untouched.
//
// # Why the header is re-emitted rather than passed through (M51)
//
// The Clerk SDK does its own parse of the header we hand it
// (clerk-sdk-go/v2@v2.0.0, http/middleware.go:61):
//
//	token := strings.TrimPrefix(authorization, "Bearer ")
//
// which is the same case-sensitive, exactly-one-space rule this file just
// stopped applying. Relaxing our own check and forwarding the raw header would
// therefore have changed the 401 BODY for `bearer <jwt>` and nothing else: the
// SDK would strip nothing, try to decode `bearer <jwt>` as a JWT, fail, and
// answer 401 anyway. The credential sets would still differ between the two
// windows, just less visibly.
//
// Emitting the token in the one spelling the SDK accepts makes the relaxation
// real end-to-end. It also collapses a repeated Authorization header to a single
// value — the caller has already been refused above unless every value agreed,
// so this cannot smuggle a second credential past the SDK's own Get.
//
// The copy is shallow with a cloned header map: handlers and the audit
// middleware read the original request after us, and rewriting a caller's
// header in place would make the access log disagree with the wire.
func clerkAuthorizationRequest(r *http.Request, token string) *http.Request {
	clone := *r
	clone.Header = r.Header.Clone()
	clone.Header.Set(echo.HeaderAuthorization, BearerPrefix+token)
	return &clone
}

// verifyClerkJWT verifies a Clerk JWT token using the official Clerk HTTP
// middleware. Verification relies on the process-global Clerk key
// (clerk.SetKey at startup), so no per-request config is needed.
//
// `token` is the credential handleClerkAuth already extracted with the
// package's shared Bearer rule; it is re-emitted canonically for the SDK — see
// clerkAuthorizationRequest.
func verifyClerkJWT(c echo.Context, token string) (*ClerkClaims, error) {
	// Use Clerk's official HTTP middleware to verify the token
	var claims *ClerkClaims
	var verifyErr error

	// Create a handler that extracts claims
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionClaims, ok := clerk.SessionClaimsFromContext(r.Context())
		if !ok || sessionClaims == nil {
			verifyErr = echo.NewHTTPError(http.StatusUnauthorized, "invalid session")
			return
		}
		claims = &ClerkClaims{
			UserID:  sessionClaims.Subject,
			OrgID:   sessionClaims.ActiveOrganizationID,
			OrgRole: sessionClaims.ActiveOrganizationRole,
		}
	})

	// Wrap with Clerk's authorization middleware
	protectedHandler := clerkhttp.WithHeaderAuthorization()(handler)

	// Create a response recorder (we don't need the response)
	recorder := &noopResponseWriter{}

	// Execute the middleware chain against a request whose Authorization header
	// is spelled the one way the SDK's own parser recognises.
	protectedHandler.ServeHTTP(recorder, clerkAuthorizationRequest(c.Request(), token))

	if verifyErr != nil {
		return nil, verifyErr
	}
	if claims == nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "failed to verify token")
	}

	return claims, nil
}

// noopResponseWriter is a no-op http.ResponseWriter for middleware execution
type noopResponseWriter struct {
	statusCode int
}

func (w *noopResponseWriter) Header() http.Header         { return http.Header{} }
func (w *noopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *noopResponseWriter) WriteHeader(code int)        { w.statusCode = code }

// RequireRole returns a middleware that checks if the user has the required role
func RequireRole(roles ...string) echo.MiddlewareFunc {
	roleSet := make(map[string]bool)
	for _, r := range roles {
		roleSet[r] = true
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			role, ok := c.Get(ContextKeyRole).(string)
			if !ok {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "role not found in context",
				})
			}

			if !roleSet[role] {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "insufficient permissions",
				})
			}

			return next(c)
		}
	}
}

// RequireOwner is a convenience middleware for owner-only endpoints.
//
// The companion RequireAdmin helper that previously lived in this file
// was replaced by the TenantContext-aware middleware.RequireAdmin
// implemented in role_guard.go (M1 Codex review #F16). The new helper
// returns the generic `{"error":"forbidden"}` 403 body (matching the
// #F10 sentinel-opacity contract) and shares its log/audit format with
// the F15 RequireWrite guard, so every privileged route reports
// privilege probes through the same operator-facing pipeline. The
// allowlist semantics are unchanged (Owner or Admin).
func RequireOwner() echo.MiddlewareFunc {
	return RequireRole(model.RoleOwner)
}
