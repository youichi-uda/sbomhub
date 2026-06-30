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
	// Normalize path: strip the API group prefix. We have to gate the
	// two TrimPrefix calls on a leading "/" after the prefix, otherwise
	// the second call eats the "/api" head of a real resource name —
	// e.g. "/api/v1/apikeys" trims to "/apikeys" then to "pikeys",
	// which broke api-key classification (F176 root cause).
	switch {
	case strings.HasPrefix(path, "/api/v1/"):
		path = strings.TrimPrefix(path, "/api/v1")
	case path == "/api/v1":
		path = ""
	case strings.HasPrefix(path, "/api/"):
		path = strings.TrimPrefix(path, "/api")
	case path == "/api":
		path = ""
	}

	// Skip certain paths
	if strings.HasPrefix(path, "/health") ||
		strings.HasPrefix(path, "/metrics") ||
		strings.HasPrefix(path, "/audit-logs") { // Avoid recursive logging
		return "", ""
	}

	// API key endpoints (must run BEFORE the /projects branch so that
	// project-scoped routes such as /projects/:id/apikeys are classified
	// as apikey, not as a generic project resource. F176: previously the
	// branch used "/api-keys" (with a hyphen) which never matched the
	// real routes "/apikeys" / "/projects/:id/apikeys", so apikey audit
	// actions were dead code and project-scoped key ops were mislogged
	// as project.created / project.deleted.
	if strings.Contains(path, "/apikeys") {
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

	// Search endpoints
	if strings.HasPrefix(path, "/search") {
		resourceType = "search"
		if method == "GET" {
			if strings.Contains(path, "/cve") {
				return "search.cve", "search"
			}
			if strings.Contains(path, "/component") {
				return "search.component", "search"
			}
			return "search.executed", "search"
		}
	}

	// Dashboard endpoints
	if strings.HasPrefix(path, "/dashboard") {
		resourceType = "dashboard"
		if method == "GET" {
			return "dashboard.viewed", "dashboard"
		}
	}

	// Vulnerability endpoints
	if strings.HasPrefix(path, "/vulnerabilities") || strings.Contains(path, "/vulnerabilities") {
		resourceType = "vulnerability"
		switch method {
		case "POST":
			if strings.Contains(path, "/scan") {
				return "vulnerability.scanned", "vulnerability"
			}
			return "vulnerability.created", "vulnerability"
		case "PUT", "PATCH":
			return "vulnerability.updated", "vulnerability"
		case "GET":
			return "vulnerability.viewed", "vulnerability"
		}
	}

	// MCP endpoints
	if strings.HasPrefix(path, "/mcp") {
		resourceType = "mcp"
		if method == "GET" {
			return "mcp.accessed", "mcp"
		}
		if method == "POST" {
			return "mcp.action", "mcp"
		}
	}

	// CLI endpoints
	if strings.HasPrefix(path, "/cli") {
		resourceType = "cli"
		switch method {
		case "POST":
			if strings.Contains(path, "/upload") {
				return "cli.upload", "cli"
			}
			if strings.Contains(path, "/check") {
				return "cli.check", "cli"
			}
			return "cli.action", "cli"
		case "GET":
			return "cli.accessed", "cli"
		}
	}

	// Scan endpoints
	if strings.Contains(path, "/scan") {
		resourceType = "scan"
		if method == "POST" {
			return "scan.started", "scan"
		}
		if method == "GET" {
			return "scan.status", "scan"
		}
	}

	// Notifications endpoints
	if strings.HasPrefix(path, "/notifications") || strings.Contains(path, "/notifications") {
		resourceType = "notification"
		switch method {
		case "POST":
			return "notification.created", "notification"
		case "PUT", "PATCH":
			return "notification.updated", "notification"
		case "DELETE":
			return "notification.deleted", "notification"
		case "GET":
			return "notification.viewed", "notification"
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

// resourceIDParamPriority lists path param names ordered from path-tail
// (most specific resource) to path-head (least specific). The audit row's
// resource_id should always point at the most specific resource the request
// operates on, so when both ":id" (parent) and ":key_id" (child) are bound
// — e.g. DELETE /projects/:id/apikeys/:key_id — the child wins.
//
// F186 root cause: the original list iterated only
// {"id","project_id","sbom_id","vulnerability_id"} in arbitrary order. For
// DELETE /projects/:id/apikeys/:key_id, "id" matched first and the audit
// row recorded the project UUID instead of the apikey UUID. For tenant-
// scoped DELETE /apikeys/:key_id, none of the four names matched at all
// and resource_id silently dropped to NULL. F176 fix corrected action
// classification (apikey.deleted vs project.deleted) but the companion
// extractResourceID was never adjusted, so the join key between
// audit_logs.resource_id and api_keys.id was broken for every apikey
// delete logged after the F176 deploy.
//
// Same gap also affected :vex_id, :draft_id, :report_id, :criterion_id,
// :policy_id, :assessment_id and :vuln_id — every route-specific resource
// param that lives under a /projects/:id parent.
var resourceIDParamPriority = []string{
	// Path-tail params first. Order within this block is grouped by
	// feature area but the actual ordering only matters when more than
	// one of these is bound on a single route, which Echo route tree
	// does not currently do.
	"vuln_id",
	"assessment_id",
	"policy_id",
	"criterion_id",
	"report_id",
	"draft_id",
	"vex_id",
	"key_id",
	// Mid-tier params used for nested-but-not-leaf resources.
	"sbom_id",
	"vulnerability_id",
	"project_id",
	// Generic :id last — only matched if no specific param above is bound.
	"id",
}

// extractResourceID extracts the resource ID from path parameters.
//
// Strategy (F186 hybrid):
//  1. Iterate resourceIDParamPriority in declaration order. The first
//     param bound on the request whose value parses as a UUID wins. The
//     list is explicit so a reader can grep audit.go to answer "which
//     path param becomes resource_id on route X?". Specific names (e.g.
//     :key_id) come before generic ":id" so child resources are not
//     shadowed by their parent.
//  2. Fallback: if nothing in the priority list matches, walk
//     c.ParamNames() from tail to head and accept the first UUID-
//     parseable value. This is the future-proof path — when a new route
//     introduces a novel `:<thing>_id` we still record the most specific
//     UUID instead of silently dropping resource_id to NULL until
//     someone notices and edits the priority list.
//  3. Non-UUID values (slugs such as :checkId for checklist response
//     keys) are intentionally skipped so they never pollute resource_id.
//     This includes :cve_id (CVE identifiers such as "CVE-2021-44228"
//     are not UUIDs by spec — see F196). The only currently-known route
//     binding :cve_id is /projects/:id/ssvc/cve/:cve_id, where the
//     parent :id rescues the audit row with the project UUID; standalone
//     CVE-keyed routes will record resource_id = NULL by design.
//
// Known limitation — create-route resource_id is NULL (F190, M13 Phase D):
//
//	extractResourceID is invoked AFTER `next(c)` returns, but it only
//	reads path params bound on the route pattern. POST/create routes
//	such as:
//
//	  POST /projects            (newly-minted project UUID in body)
//	  POST /apikeys             (newly-minted apikey UUID in body)
//	  POST /projects/:id/cra-reports   (parent :id present, but the
//	                                    NEW cra_report UUID lives in
//	                                    the response body)
//	  POST /projects/:id/vex    (same — new VEX UUID is in body, only
//	                             the parent project :id is in the path)
//
//	have no path param carrying the newly-minted UUID, so the audit row
//	for every project.created / apikey.created / cra_report.created /
//	vex.created records resource_id = NULL (or the parent project's
//	UUID, which is misleading — joining audit_logs.resource_id onto
//	the newly-created table's primary key on those rows will silently
//	drop them or join onto the wrong subject).
//
//	The F186 commit message implied "create paths covered"; that was
//	for the action+resource_type classification (which IS correct for
//	POST routes), not for resource_id (which is not). We are choosing
//	to document the limitation here rather than reshape the handler
//	contract — the eventual fix (M14 candidate) requires every create
//	handler to call c.Set("audit_resource_id", newID) after a
//	successful create, with extractResourceID falling back to that
//	context value when no UUID path param resolves. That touches every
//	create handler and is out of scope for M13 Phase D.
//
//	Operational consequence today: forensic queries that join
//	audit_logs on (resource_type='project' AND action='project.created')
//	must use details->>'path' + (tenant_id, created_at) heuristics to
//	correlate to projects.id; resource_id is unreliable for the row.
func extractResourceID(c echo.Context) *uuid.UUID {
	// 1) Explicit priority list.
	for _, name := range resourceIDParamPriority {
		if idStr := c.Param(name); idStr != "" {
			if id, err := uuid.Parse(idStr); err == nil {
				return &id
			}
		}
	}

	// 2) Fallback: path-tail UUID. We walk ParamNames in reverse so the
	//    most specific param on the route wins, mirroring the priority
	//    list's "child before parent" rule.
	names := c.ParamNames()
	for i := len(names) - 1; i >= 0; i-- {
		if idStr := c.Param(names[i]); idStr != "" {
			if id, err := uuid.Parse(idStr); err == nil {
				return &id
			}
		}
	}

	return nil
}
