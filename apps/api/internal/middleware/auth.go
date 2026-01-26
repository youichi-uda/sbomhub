package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	ContextKeyUserID   = "user_id"
	ContextKeyUser     = "user"
	ContextKeyTenantID = "tenant_id"
	ContextKeyTenant   = "tenant"
	ContextKeyRole     = "role"
	ContextKeyClerkOrgID = "clerk_org_id"
	ContextKeyClerkUserID = "clerk_user_id"
)

// AuthContext holds authentication context for a request
type AuthContext struct {
	UserID      uuid.UUID
	TenantID    uuid.UUID
	ClerkUserID string
	ClerkOrgID  string
	Role        string
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

			return handleClerkAuth(c, ctx, cfg, tenantRepo, userRepo, next)
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

// handleClerkAuth validates Clerk JWT and sets up tenant/user context
func handleClerkAuth(c echo.Context, ctx context.Context, cfg *config.Config, tenantRepo *repository.TenantRepository, userRepo *repository.UserRepository, next echo.HandlerFunc) error {
	// Get token from Authorization header
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "missing authorization header",
		})
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid authorization header format",
		})
	}

	// Verify JWT with Clerk
	claims, err := verifyClerkJWT(ctx, token, cfg.ClerkSecretKey)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid token: " + err.Error(),
		})
	}

	// Get organization ID from claims
	orgID := claims.OrgID
	if orgID == "" {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "organization membership required",
		})
	}

	// Get tenant by Clerk org ID
	tenant, err := tenantRepo.GetByClerkOrgID(ctx, orgID)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "organization not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get organization",
		})
	}

	// Get user by Clerk user ID
	user, err := userRepo.GetByClerkUserID(ctx, claims.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "user not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get user",
		})
	}

	// Get user's role in tenant
	tenantUser, err := userRepo.GetUserRole(ctx, tenant.ID, user.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "not a member of this organization",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get user role",
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
	c.Set(ContextKeyRole, tenantUser.Role)
	c.Set(ContextKeyClerkUserID, claims.UserID)
	c.Set(ContextKeyClerkOrgID, orgID)

	return next(c)
}

// ClerkClaims represents the relevant claims from a Clerk JWT
type ClerkClaims struct {
	UserID string
	OrgID  string
	OrgRole string
}

// verifyClerkJWT verifies a Clerk JWT token
// This is a simplified implementation - in production, use the official Clerk SDK
func verifyClerkJWT(ctx context.Context, token, secretKey string) (*ClerkClaims, error) {
	// TODO: Implement proper Clerk JWT verification using clerk-sdk-go
	// For now, return a placeholder that will be replaced with actual implementation
	//
	// import "github.com/clerk/clerk-sdk-go/v2/jwt"
	//
	// claims, err := jwt.Verify(ctx, &jwt.VerifyParams{
	//     Token: token,
	// })
	// if err != nil {
	//     return nil, err
	// }
	// return &ClerkClaims{
	//     UserID:  claims.Subject,
	//     OrgID:   claims.ActiveOrganizationID,
	//     OrgRole: claims.ActiveOrganizationRole,
	// }, nil

	return nil, echo.NewHTTPError(http.StatusNotImplemented, "Clerk JWT verification not implemented")
}

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

// RequireAdmin is a convenience middleware for admin-only endpoints
func RequireAdmin() echo.MiddlewareFunc {
	return RequireRole(model.RoleOwner, model.RoleAdmin)
}

// RequireOwner is a convenience middleware for owner-only endpoints
func RequireOwner() echo.MiddlewareFunc {
	return RequireRole(model.RoleOwner)
}
