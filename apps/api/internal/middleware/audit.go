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

// pathHasChildResource reports whether path contains "/<name>" as a
// COMPLETE path segment — i.e. it ends with "/<name>" or contains
// "/<name>/". Substring-only matching (the old
// `strings.Contains(path, "/<name>")` pattern) over-trips on routes
// that share <name> as a prefix of a longer segment:
//
//   - F202 latent: /integrations/apikeys-sync would have false-matched
//     strings.Contains(path, "/apikeys") and been classified as apikey.
//     The COMPLETE-segment match rules it out.
//
// The helper is the building block of the F188 (M13 Phase D round 3)
// project-nested resource hoist below. See its head comment in
// determineActionAndResource for the full rationale.
func pathHasChildResource(path, name string) bool {
	seg := "/" + name
	return strings.HasSuffix(path, seg) || strings.Contains(path, seg+"/")
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

	// ========================================================================
	// F188 (M13 Phase D round 3) project-nested child-resource hoist.
	//
	// Routes shaped like /projects/:id/<child>(/:sub_id(/<verb>)) must be
	// classified by <child> BEFORE the /projects branch swallows them all
	// into project.<verb>. F176 originally hoisted /apikeys only; this
	// block generalises the same pattern to every /projects/:id/<child>
	// family — there are 18+ at the time of this fix (vex, vex-drafts,
	// cra-reports, triage, scan, compliance, notifications, diff, ssvc,
	// meti, licenses, evidence-pack, checklist, visualization,
	// public-links, kev, eol-*, sboms, vulnerabilities). Pre-F188, every
	// one of them was logged as project.viewed / project.created /
	// project.deleted, which broke the audit_logs.(resource_type,
	// resource_id) join key for the CRA / VEX / METI evidence layer.
	//
	// Each branch uses pathHasChildResource so the match is segment-exact:
	//   * `/projects/:id/vex` matches "vex" but NOT "vex-drafts"
	//   * `/projects/:id/apikeys` matches "apikeys" but NOT a hypothetical
	//     /integrations/apikeys-sync (F202: the older
	//     strings.Contains(path, "/apikeys") was a latent false-positive)
	//
	// /apikeys is the only segment that has a tenant-level counterpart we
	// still want to catch (tenant POST /apikeys is the SBOM-CLI auth
	// bootstrap path from F176), so it sits outside the
	// HasPrefix("/projects/") guard. Every other family in this block is
	// gated by that prefix so tenant-level paths re-using the same
	// segment name (e.g. /settings/scan, /sbom/diff) still fall through
	// to the tenant-level branches below.
	// ========================================================================

	// /apikeys: tenant-level (POST/GET /apikeys, DELETE /apikeys/:key_id)
	// AND project-level (/projects/:id/apikeys[/:key_id]).
	if pathHasChildResource(path, "apikeys") {
		switch method {
		case "POST":
			return model.ActionAPIKeyCreated, model.ResourceAPIKey
		case "DELETE":
			return model.ActionAPIKeyDeleted, model.ResourceAPIKey
		case "GET":
			return "apikey.viewed", model.ResourceAPIKey
		default:
			// F201: PUT/PATCH on apikey routes is not used today, but
			// the bare switch above would otherwise fall through to the
			// /projects branch on a future PUT route. Pin the resource
			// here so any new PUT lands as apikey, not as project.
			return "apikey.updated", model.ResourceAPIKey
		}
	}

	// Project-nested child resource families. Guarded by
	// HasPrefix("/projects/") so the segment match never collides with
	// tenant-level paths that happen to contain the same word
	// (e.g. /settings/scan, /sbom/diff).
	if strings.HasPrefix(path, "/projects/") {
		// CRA reports (Wave M2-4 / issue #36).
		if pathHasChildResource(path, "cra-reports") {
			switch method {
			case "POST":
				if strings.HasSuffix(path, "/reanalyse") {
					return model.ActionCRAReportReanalysed, model.ResourceCRAReport
				}
				return model.ActionCRAReportRun, model.ResourceCRAReport
			case "PUT", "PATCH":
				return model.ActionCRAReportDecisionUpdated, model.ResourceCRAReport
			case "GET":
				if strings.HasSuffix(path, "/cra-reports") {
					return model.ActionCRAReportListed, model.ResourceCRAReport
				}
				return model.ActionCRAReportViewed, model.ResourceCRAReport
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin the
				// resource here so a future DELETE / OPTIONS / etc.
				// route on /projects/:id/cra-reports lands as
				// cra_report.* and not as project.<verb>.
				return "cra_report.updated", model.ResourceCRAReport
			}
		}
		// VEX drafts (Wave M1-5). Segment-distinct from /vex so order
		// against the /vex branch does not matter.
		if pathHasChildResource(path, "vex-drafts") {
			switch method {
			case "POST":
				return model.ActionVEXDraftReanalysed, model.ResourceVEXDraft
			case "PUT", "PATCH":
				return model.ActionVEXDraftDecisionUpdated, model.ResourceVEXDraft
			case "GET":
				if strings.HasSuffix(path, "/vex-drafts") {
					return model.ActionVEXDraftListed, model.ResourceVEXDraft
				}
				return model.ActionVEXDraftViewed, model.ResourceVEXDraft
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin the
				// resource here so a future DELETE / OPTIONS / etc.
				// route on /projects/:id/vex-drafts lands as
				// vex_draft.* and not as project.<verb>.
				return "vex_draft.updated", model.ResourceVEXDraft
			}
		}
		// Triage runs (Wave M1-4).
		if pathHasChildResource(path, "triage") {
			return model.ActionTriageRun, model.ResourceTriage
		}
		// VEX statements.
		if pathHasChildResource(path, "vex") {
			switch method {
			case "POST":
				return model.ActionVEXCreated, model.ResourceVEX
			case "PUT", "PATCH":
				return model.ActionVEXUpdated, model.ResourceVEX
			case "DELETE":
				return model.ActionVEXDeleted, model.ResourceVEX
			case "GET":
				if strings.HasSuffix(path, "/vex") {
					return model.ActionVEXListed, model.ResourceVEX
				}
				return "vex.viewed", model.ResourceVEX
			default:
				// F206 (anti-pattern 48 symmetric to F201): the four
				// arms above cover the current CRUD surface, but a
				// future OPTIONS / HEAD route would otherwise fall
				// through to the /projects branch and re-introduce
				// F188 mass-misclassification for /projects/:id/vex.
				return model.ActionVEXUpdated, model.ResourceVEX
			}
		}
		// Vulnerability scan trigger (POST /projects/:id/scan).
		if pathHasChildResource(path, "scan") {
			if method == "POST" {
				return model.ActionScanStarted, model.ResourceScan
			}
			return model.ActionScanViewed, model.ResourceScan
		}
		// Compliance.
		if pathHasChildResource(path, "compliance") {
			return model.ActionComplianceChecked, model.ResourceCompliance
		}
		// Notification settings.
		if pathHasChildResource(path, "notifications") {
			switch method {
			case "POST":
				return model.ActionNotificationCreated, model.ResourceNotification
			case "PUT", "PATCH":
				return model.ActionNotificationUpdated, model.ResourceNotification
			case "DELETE":
				return model.ActionNotificationDeleted, model.ResourceNotification
			case "GET":
				if strings.HasSuffix(path, "/notifications") {
					return model.ActionNotificationListed, model.ResourceNotification
				}
				return model.ActionNotificationViewed, model.ResourceNotification
			default:
				// F206 (anti-pattern 48 symmetric to F201): future
				// non-CRUD method (OPTIONS / HEAD) must stay on the
				// notification family rather than falling through to
				// the /projects branch as project.<verb>.
				return model.ActionNotificationUpdated, model.ResourceNotification
			}
		}
		// Diff (M10-6 / M11-4 / M12-3). /diff.csv and /diff.pdf are not
		// segment-shaped, so we accept them explicitly.
		if pathHasChildResource(path, "diff") ||
			strings.HasSuffix(path, "/diff.csv") ||
			strings.HasSuffix(path, "/diff.pdf") {
			if method == "POST" {
				return model.ActionDiffSummary, model.ResourceDiff
			}
			if strings.HasSuffix(path, "/graph") {
				return model.ActionDiffGraphViewed, model.ResourceDiff
			}
			return model.ActionDiffViewed, model.ResourceDiff
		}
		// SSVC. Must come before the /vulnerabilities check below so
		// /projects/:id/vulnerabilities/:vuln_id/ssvc lands as SSVC,
		// not as a vulnerability list.
		if pathHasChildResource(path, "ssvc") {
			switch method {
			case "POST", "PUT", "PATCH":
				return model.ActionSSVCAssessed, model.ResourceSSVC
			case "DELETE":
				return model.ActionSSVCDeleted, model.ResourceSSVC
			case "GET":
				return model.ActionSSVCViewed, model.ResourceSSVC
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin SSVC
				// resource on any future method so it does not fall
				// through to project.<verb>.
				return model.ActionSSVCAssessed, model.ResourceSSVC
			}
		}
		// METI self-assessment (Wave M3-4).
		if pathHasChildResource(path, "meti") {
			switch method {
			case "POST":
				return model.ActionMETIRefreshed, model.ResourceMETI
			case "PUT", "PATCH":
				return model.ActionMETIOverridden, model.ResourceMETI
			case "DELETE":
				return model.ActionMETIOverridden, model.ResourceMETI
			case "GET":
				return model.ActionMETIViewed, model.ResourceMETI
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin METI
				// resource on any future method so it does not fall
				// through to project.<verb>.
				return model.ActionMETIOverridden, model.ResourceMETI
			}
		}
		// License policies.
		if pathHasChildResource(path, "licenses") {
			switch method {
			case "POST":
				return model.ActionLicensePolicyCreated, model.ResourceLicensePolicy
			case "PUT", "PATCH":
				return model.ActionLicensePolicyUpdated, model.ResourceLicensePolicy
			case "DELETE":
				return model.ActionLicensePolicyDeleted, model.ResourceLicensePolicy
			case "GET":
				if strings.HasSuffix(path, "/licenses") {
					return model.ActionLicensePolicyListed, model.ResourceLicensePolicy
				}
				return model.ActionLicensePolicyViewed, model.ResourceLicensePolicy
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin
				// license_policy resource on any future method so it
				// does not fall through to project.<verb>.
				return model.ActionLicensePolicyUpdated, model.ResourceLicensePolicy
			}
		}
		// Evidence pack (Wave M2-6).
		if pathHasChildResource(path, "evidence-pack") {
			return model.ActionEvidencePackBuilt, model.ResourceEvidencePack
		}
		// METI checklist.
		if pathHasChildResource(path, "checklist") {
			switch method {
			case "PUT", "PATCH":
				return model.ActionChecklistUpdated, model.ResourceChecklist
			case "DELETE":
				return model.ActionChecklistDeleted, model.ResourceChecklist
			case "GET":
				return model.ActionChecklistViewed, model.ResourceChecklist
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin
				// checklist resource on any future method (e.g. POST,
				// OPTIONS) so it does not fall through to
				// project.<verb>.
				return model.ActionChecklistUpdated, model.ResourceChecklist
			}
		}
		// Visualization framework.
		if pathHasChildResource(path, "visualization") {
			switch method {
			case "PUT", "PATCH":
				return model.ActionVisualizationUpdated, model.ResourceVisualization
			case "DELETE":
				return model.ActionVisualizationDeleted, model.ResourceVisualization
			case "GET":
				return model.ActionVisualizationViewed, model.ResourceVisualization
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin
				// visualization resource on any future method (e.g.
				// POST, OPTIONS) so it does not fall through to
				// project.<verb>.
				return model.ActionVisualizationUpdated, model.ResourceVisualization
			}
		}
		// Public links.
		if pathHasChildResource(path, "public-links") {
			switch method {
			case "POST":
				return model.ActionPublicLinkCreated, model.ResourcePublicLink
			case "PUT", "PATCH":
				return model.ActionPublicLinkUpdated, model.ResourcePublicLink
			case "DELETE":
				return model.ActionPublicLinkDeleted, model.ResourcePublicLink
			case "GET":
				return model.ActionPublicLinkViewed, model.ResourcePublicLink
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin
				// public_link resource on any future method so it does
				// not fall through to project.<verb>.
				return model.ActionPublicLinkUpdated, model.ResourcePublicLink
			}
		}
		// KEV (project-scoped /projects/:id/kev). Tenant-level /kev/* and
		// /vulnerabilities/:cve_id/kev fall through to the tenant branches
		// below because of the HasPrefix("/projects/") guard.
		if pathHasChildResource(path, "kev") {
			return model.ActionKEVViewed, model.ResourceKEV
		}
		// EOL (project-scoped /eol-summary, /eol-check). These are not
		// /-separated segments — they're suffix tokens hanging off the
		// project root — so we match them explicitly.
		if pathHasChildResource(path, "eol-summary") || pathHasChildResource(path, "eol-check") {
			if method == "POST" {
				return model.ActionEOLChecked, model.ResourceEOL
			}
			return model.ActionEOLViewed, model.ResourceEOL
		}
		// SBOM (nested /sbom — upload + read-back — and /sboms — list +
		// /sboms/:sbom_id/scan-status). POST /projects/:id/sbom keeps the
		// existing sbom.uploaded verb (matches the legacy branch the
		// /projects swallow used to redirect to via Contains("/sbom")).
		if pathHasChildResource(path, "sbom") || pathHasChildResource(path, "sboms") {
			switch method {
			case "POST":
				return model.ActionSBOMUploaded, model.ResourceSBOM
			case "DELETE":
				return model.ActionSBOMDeleted, model.ResourceSBOM
			case "GET":
				return model.ActionSBOMViewed, model.ResourceSBOM
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin SBOM
				// resource on any future method (PUT/PATCH replace,
				// OPTIONS preflight) so it does not fall through to
				// project.<verb>.
				return "sbom.updated", model.ResourceSBOM
			}
		}
		// Vulnerabilities (project-nested). Must come AFTER the /ssvc
		// branch above so /projects/:id/vulnerabilities/:vuln_id/ssvc
		// is classified by /ssvc, not by /vulnerabilities.
		if pathHasChildResource(path, "vulnerabilities") {
			switch method {
			case "POST":
				if strings.Contains(path, "/scan") {
					return "vulnerability.scanned", model.ResourceVulnerability
				}
				return "vulnerability.created", model.ResourceVulnerability
			case "PUT", "PATCH":
				return "vulnerability.updated", model.ResourceVulnerability
			case "GET":
				if strings.HasSuffix(path, "/vulnerabilities") {
					return model.ActionVulnerabilityListed, model.ResourceVulnerability
				}
				return model.ActionVulnerabilityViewed, model.ResourceVulnerability
			default:
				// F206 (anti-pattern 48 symmetric to F201): pin
				// vulnerability resource on any future method (DELETE,
				// OPTIONS) so it does not fall through to
				// project.<verb>.
				return "vulnerability.updated", model.ResourceVulnerability
			}
		}
	}

	// Project endpoints — bare /projects (list, create) and
	// /projects/:id (get, update, delete) with no child resource
	// segment. The F188 hoist above already handled every nested case,
	// so the legacy /sbom branches inside this switch are intentionally
	// absent; keeping them would shadow the hoisted classification for
	// any /sbom subpath that slipped through and re-introduce the F188
	// bug.
	if strings.HasPrefix(path, "/projects") {
		switch method {
		case "POST":
			return model.ActionProjectCreated, model.ResourceProject
		case "PUT", "PATCH":
			return model.ActionProjectUpdated, model.ResourceProject
		case "DELETE":
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

	// VEX endpoints — tenant-level only. The Contains(/vex) arm that
	// used to live on this branch caught /projects/:id/vex etc., but
	// only after the /projects branch had already returned project.*
	// for the same path, so it was dead code. F188 hoist now classifies
	// nested /vex above; F198 removes the dead arm here.
	if strings.HasPrefix(path, "/vex") {
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

	// Compliance endpoints — tenant-level only (project-nested classified
	// by the F188 hoist above). F198 removes the dead Contains arm.
	if strings.HasPrefix(path, "/compliance") {
		switch method {
		case "GET":
			return model.ActionComplianceChecked, model.ResourceCompliance
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

	// Vulnerability endpoints — tenant-level only (project-nested
	// classified by the F188 hoist above). F198 removes the dead Contains
	// arm. /vulnerabilities/sync-epss, /vulnerabilities/epss/:cve_id,
	// /vulnerabilities/:cve_id/ipa, /vulnerabilities/:vuln_id/ticket(s)
	// and /vulnerabilities/:id/remediation all start with /vulnerabilities
	// so HasPrefix is sufficient.
	if strings.HasPrefix(path, "/vulnerabilities") {
		switch method {
		case "POST":
			if strings.Contains(path, "/scan") {
				return "vulnerability.scanned", model.ResourceVulnerability
			}
			return "vulnerability.created", model.ResourceVulnerability
		case "PUT", "PATCH":
			return "vulnerability.updated", model.ResourceVulnerability
		case "GET":
			return model.ActionVulnerabilityViewed, model.ResourceVulnerability
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

	// Notifications endpoints — tenant-level only (project-nested
	// classified by the F188 hoist above). F198 removes the dead Contains
	// arm.
	if strings.HasPrefix(path, "/notifications") {
		switch method {
		case "POST":
			return model.ActionNotificationCreated, model.ResourceNotification
		case "PUT", "PATCH":
			return model.ActionNotificationUpdated, model.ResourceNotification
		case "DELETE":
			return model.ActionNotificationDeleted, model.ResourceNotification
		case "GET":
			return model.ActionNotificationViewed, model.ResourceNotification
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
