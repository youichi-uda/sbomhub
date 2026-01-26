package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// TenantContext provides helper methods for accessing tenant info
type TenantContext struct {
	c echo.Context
}

// NewTenantContext creates a new TenantContext
func NewTenantContext(c echo.Context) *TenantContext {
	return &TenantContext{c: c}
}

// TenantID returns the current tenant ID
func (tc *TenantContext) TenantID() uuid.UUID {
	if id, ok := tc.c.Get(ContextKeyTenantID).(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

// Tenant returns the current tenant
func (tc *TenantContext) Tenant() *model.Tenant {
	if t, ok := tc.c.Get(ContextKeyTenant).(*model.Tenant); ok {
		return t
	}
	return nil
}

// UserID returns the current user ID
func (tc *TenantContext) UserID() uuid.UUID {
	if id, ok := tc.c.Get(ContextKeyUserID).(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

// User returns the current user
func (tc *TenantContext) User() *model.User {
	if u, ok := tc.c.Get(ContextKeyUser).(*model.User); ok {
		return u
	}
	return nil
}

// Role returns the current user's role in the tenant
func (tc *TenantContext) Role() string {
	if r, ok := tc.c.Get(ContextKeyRole).(string); ok {
		return r
	}
	return ""
}

// IsSelfHosted returns true if running in self-hosted mode
func (tc *TenantContext) IsSelfHosted() bool {
	if clerkID, ok := tc.c.Get(ContextKeyClerkUserID).(string); ok {
		return clerkID == "self-hosted"
	}
	return false
}

// CanWrite returns true if the user has write permissions
func (tc *TenantContext) CanWrite() bool {
	role := tc.Role()
	return role == model.RoleOwner || role == model.RoleAdmin || role == model.RoleMember
}

// CanAdmin returns true if the user has admin permissions
func (tc *TenantContext) CanAdmin() bool {
	role := tc.Role()
	return role == model.RoleOwner || role == model.RoleAdmin
}

// IsOwner returns true if the user is the owner
func (tc *TenantContext) IsOwner() bool {
	return tc.Role() == model.RoleOwner
}

// Helper functions for handlers

// GetTenantID retrieves tenant ID from context
func GetTenantID(c echo.Context) uuid.UUID {
	return NewTenantContext(c).TenantID()
}

// GetUserID retrieves user ID from context
func GetUserID(c echo.Context) uuid.UUID {
	return NewTenantContext(c).UserID()
}

// GetTenant retrieves tenant from context
func GetTenant(c echo.Context) *model.Tenant {
	return NewTenantContext(c).Tenant()
}

// GetUser retrieves user from context
func GetUser(c echo.Context) *model.User {
	return NewTenantContext(c).User()
}

// CheckTenantAccess verifies that a resource belongs to the current tenant
func CheckTenantAccess(c echo.Context, resourceTenantID uuid.UUID) bool {
	tenantID := GetTenantID(c)
	return tenantID != uuid.Nil && tenantID == resourceTenantID
}

// EnsureTenantAccess returns an error if the resource doesn't belong to current tenant
func EnsureTenantAccess(c echo.Context, resourceTenantID uuid.UUID) error {
	if !CheckTenantAccess(c, resourceTenantID) {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "access denied",
		})
	}
	return nil
}

// CheckProjectLimit verifies project count limit for the tenant
func CheckProjectLimit(tenantRepo *repository.TenantRepository, subRepo *repository.SubscriptionRepository, projectRepo interface{ CountByTenant(c echo.Context, id uuid.UUID) (int, error) }) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Only check on POST (create) requests
			if c.Request().Method != http.MethodPost {
				return next(c)
			}

			tc := NewTenantContext(c)
			tenant := tc.Tenant()
			if tenant == nil {
				return next(c)
			}

			// Self-hosted mode has no limits
			if tc.IsSelfHosted() {
				return next(c)
			}

			// Get plan limits
			limits, err := subRepo.GetPlanLimits(c.Request().Context(), tenant.Plan)
			if err != nil {
				return next(c) // Allow on error
			}

			// Check if unlimited
			if model.IsUnlimited(limits.MaxProjects) {
				return next(c)
			}

			// Count current projects
			count, err := projectRepo.CountByTenant(c, tc.TenantID())
			if err != nil {
				return next(c) // Allow on error
			}

			if !model.CheckLimit(count, limits.MaxProjects) {
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"error":   "project_limit_exceeded",
					"message": "プロジェクト数の上限に達しました",
					"limit":   limits.MaxProjects,
					"current": count,
				})
			}

			return next(c)
		}
	}
}

// CheckUserLimit verifies user count limit for the tenant
func CheckUserLimit(userRepo *repository.UserRepository, subRepo *repository.SubscriptionRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Only check on POST (create/invite) requests
			if c.Request().Method != http.MethodPost {
				return next(c)
			}

			tc := NewTenantContext(c)
			tenant := tc.Tenant()
			if tenant == nil {
				return next(c)
			}

			// Self-hosted mode has no limits
			if tc.IsSelfHosted() {
				return next(c)
			}

			// Get plan limits
			limits, err := subRepo.GetPlanLimits(c.Request().Context(), tenant.Plan)
			if err != nil {
				return next(c) // Allow on error
			}

			// Check if unlimited
			if model.IsUnlimited(limits.MaxUsers) {
				return next(c)
			}

			// Count current users
			count, err := userRepo.CountByTenant(c.Request().Context(), tc.TenantID())
			if err != nil {
				return next(c) // Allow on error
			}

			if !model.CheckLimit(count, limits.MaxUsers) {
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"error":   "user_limit_exceeded",
					"message": "ユーザー数の上限に達しました",
					"limit":   limits.MaxUsers,
					"current": count,
				})
			}

			return next(c)
		}
	}
}

// CheckFeature verifies that a feature is enabled for the tenant's plan
func CheckFeature(feature string, subRepo *repository.SubscriptionRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tc := NewTenantContext(c)
			tenant := tc.Tenant()
			if tenant == nil {
				return next(c)
			}

			// Self-hosted mode has all features
			if tc.IsSelfHosted() {
				return next(c)
			}

			// Get plan limits
			limits, err := subRepo.GetPlanLimits(c.Request().Context(), tenant.Plan)
			if err != nil {
				return next(c) // Allow on error
			}

			if !limits.HasFeature(feature) {
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"error":   "feature_not_available",
					"message": "この機能はご利用のプランでは使用できません",
					"feature": feature,
					"plan":    tenant.Plan,
				})
			}

			return next(c)
		}
	}
}
