package middleware

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Audit returns a middleware that logs all authenticated requests to the audit log.
// It determines the action and resource type from the HTTP method and path.
func Audit(auditRepo *repository.AuditRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)

			// Get auth context
			tenantID, hasTenant := c.Get(ContextKeyTenantID).(uuid.UUID)
			userID, hasUser := c.Get(ContextKeyUserID).(uuid.UUID)

			// Only log authenticated requests
			if !hasTenant {
				return err
			}

			// Determine action and resource from request
			action, resourceType := determineActionAndResource(c.Request().Method, c.Path())
			if action == "" {
				// Skip logging for unknown or excluded paths
				return err
			}

			// Extract resource ID from path if available
			resourceID := extractResourceID(c)

			details := map[string]interface{}{
				"path":       c.Path(),
				"method":     c.Request().Method,
				"status":     c.Response().Status,
				"latency_ms": time.Since(start).Milliseconds(),
			}

			// Add query parameters for GET requests
			if c.Request().Method == "GET" && len(c.QueryParams()) > 0 {
				details["query"] = c.QueryParams()
			}

			var tenantIDPtr *uuid.UUID
			var userIDPtr *uuid.UUID
			if hasTenant {
				tenantIDPtr = &tenantID
			}
			if hasUser {
				userIDPtr = &userID
			}

			_ = auditRepo.Log(c.Request().Context(), &model.CreateAuditLogInput{
				TenantID:     tenantIDPtr,
				UserID:       userIDPtr,
				Action:       action,
				ResourceType: resourceType,
				ResourceID:   resourceID,
				Details:      details,
				IPAddress:    c.RealIP(),
				UserAgent:    c.Request().UserAgent(),
			})

			return err
		}
	}
}

// determineActionAndResource determines the audit action and resource type from HTTP method and path.
func determineActionAndResource(method, path string) (action, resourceType string) {
	// Normalize path
	path = strings.TrimPrefix(path, "/api/v1")
	path = strings.TrimPrefix(path, "/api")

	// Skip certain paths
	if strings.HasPrefix(path, "/health") ||
		strings.HasPrefix(path, "/metrics") ||
		strings.HasPrefix(path, "/audit-logs") { // Avoid recursive logging
		return "", ""
	}

	// Project endpoints
	if strings.HasPrefix(path, "/projects") {
		resourceType = model.ResourceProject
		switch method {
		case "POST":
			if strings.Contains(path, "/sbom") {
				return model.ActionSBOMUploaded, model.ResourceSBOM
			}
			return model.ActionProjectCreated, model.ResourceProject
		case "PUT", "PATCH":
			return model.ActionProjectUpdated, model.ResourceProject
		case "DELETE":
			if strings.Contains(path, "/sbom") {
				return model.ActionSBOMDeleted, model.ResourceSBOM
			}
			return model.ActionProjectDeleted, model.ResourceProject
		case "GET":
			return "project.viewed", model.ResourceProject
		}
	}

	// SBOM endpoints
	if strings.HasPrefix(path, "/sbom") {
		resourceType = model.ResourceSBOM
		switch method {
		case "POST":
			return model.ActionSBOMUploaded, model.ResourceSBOM
		case "DELETE":
			return model.ActionSBOMDeleted, model.ResourceSBOM
		case "GET":
			return "sbom.viewed", model.ResourceSBOM
		}
	}

	// VEX endpoints
	if strings.HasPrefix(path, "/vex") || strings.Contains(path, "/vex") {
		resourceType = model.ResourceVEX
		switch method {
		case "POST":
			return model.ActionVEXCreated, model.ResourceVEX
		case "PUT", "PATCH":
			return model.ActionVEXUpdated, model.ResourceVEX
		case "DELETE":
			return model.ActionVEXDeleted, model.ResourceVEX
		case "GET":
			return "vex.viewed", model.ResourceVEX
		}
	}

	// API key endpoints
	if strings.HasPrefix(path, "/api-keys") {
		resourceType = model.ResourceAPIKey
		switch method {
		case "POST":
			return model.ActionAPIKeyCreated, model.ResourceAPIKey
		case "DELETE":
			return model.ActionAPIKeyDeleted, model.ResourceAPIKey
		case "GET":
			return "apikey.viewed", model.ResourceAPIKey
		}
	}

	// Settings endpoints
	if strings.HasPrefix(path, "/settings") {
		resourceType = model.ResourceSettings
		switch method {
		case "PUT", "PATCH", "POST":
			return model.ActionSettingsUpdated, model.ResourceSettings
		case "GET":
			return "settings.viewed", model.ResourceSettings
		}
	}

	// User endpoints
	if strings.HasPrefix(path, "/users") || strings.HasPrefix(path, "/members") {
		resourceType = model.ResourceUser
		switch method {
		case "POST":
			if strings.Contains(path, "/invite") {
				return model.ActionUserInvited, model.ResourceUser
			}
			return model.ActionUserCreated, model.ResourceUser
		case "PUT", "PATCH":
			if strings.Contains(path, "/role") {
				return model.ActionUserRoleChanged, model.ResourceUser
			}
			return model.ActionUserUpdated, model.ResourceUser
		case "DELETE":
			return model.ActionUserDeleted, model.ResourceUser
		case "GET":
			return "user.viewed", model.ResourceUser
		}
	}

	// Subscription endpoints
	if strings.HasPrefix(path, "/subscription") || strings.HasPrefix(path, "/billing") {
		resourceType = model.ResourceSubscription
		switch method {
		case "POST":
			return model.ActionSubscriptionCreated, model.ResourceSubscription
		case "PUT", "PATCH":
			return model.ActionSubscriptionUpdated, model.ResourceSubscription
		case "DELETE":
			return model.ActionSubscriptionCancelled, model.ResourceSubscription
		case "GET":
			return "subscription.viewed", model.ResourceSubscription
		}
	}

	// Reports endpoints
	if strings.HasPrefix(path, "/reports") {
		resourceType = "report"
		switch method {
		case "POST":
			return "report.generated", "report"
		case "GET":
			return "report.viewed", "report"
		}
	}

	// Compliance endpoints
	if strings.HasPrefix(path, "/compliance") || strings.Contains(path, "/compliance") {
		resourceType = "compliance"
		switch method {
		case "GET":
			return "compliance.checked", "compliance"
		}
	}

	// Analytics endpoints
	if strings.HasPrefix(path, "/analytics") {
		resourceType = "analytics"
		switch method {
		case "GET":
			return "analytics.viewed", "analytics"
		}
	}

	// Integrations endpoints
	if strings.HasPrefix(path, "/integrations") {
		resourceType = "integration"
		switch method {
		case "POST":
			return "integration.created", "integration"
		case "PUT", "PATCH":
			return "integration.updated", "integration"
		case "DELETE":
			return "integration.deleted", "integration"
		case "GET":
			return "integration.viewed", "integration"
		}
	}

	// Default: log as generic resource access
	if method == "GET" {
		return "resource.viewed", "unknown"
	}
	if method == "POST" {
		return "resource.created", "unknown"
	}
	if method == "PUT" || method == "PATCH" {
		return "resource.updated", "unknown"
	}
	if method == "DELETE" {
		return "resource.deleted", "unknown"
	}

	return "", ""
}

// extractResourceID extracts the resource ID from path parameters.
func extractResourceID(c echo.Context) *uuid.UUID {
	// Try common parameter names
	for _, param := range []string{"id", "project_id", "sbom_id", "vulnerability_id"} {
		if idStr := c.Param(param); idStr != "" {
			if id, err := uuid.Parse(idStr); err == nil {
				return &id
			}
		}
	}
	return nil
}
