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
//
// Dual-path audit design (F227, M14 Phase D round 2 fix — explicit
// closure of a recurring review false-positive):
//
// sbomhub has TWO audit write paths with intentionally different error
// contracts. Confusing them is a recurring review failure mode (Codex
// Round 2 flagged the `_ = auditRepo.Log(...)` below as an F168
// audit-or-nothing violation; it is not, because F168 governs a
// different path entirely). The two paths and the rationale for the
// asymmetry are pinned here:
//
//  1. MIDDLEWARE-LEVEL AUDIT (this function). Cross-cutting concern
//     that records one row per authenticated HTTP request as a generic
//     forensic trail: path, method, status, latency, IP, UA, plus the
//     classifier's (action, resource_type, resource_id) join key.
//     This path is BY-DESIGN BEST-EFFORT — the Log() return value is
//     intentionally swallowed (`_ = auditRepo.Log(...)`). The reason is
//     blast-radius: an audit-log INSERT failure during a DB outage,
//     RLS bug, or schema drift would otherwise translate to a 500 on
//     EVERY authenticated request, taking the whole product down to
//     preserve forensic completeness on requests that already failed.
//     We accept the trade-off — a small fraction of requests may be
//     missing from audit_logs during a DB incident — because middleware
//     audit is the trail, not the source of truth, for any specific
//     business event.
//
//  2. HANDLER-LEVEL AUDIT_PAIR (F168 audit-or-nothing). Specific
//     handlers that MUST emit an audit row as part of a multi-row
//     business contract — the canonical example is sbom.go::
//     runDiffWebhookAutoTrigger / writeAutoFiredAudit (the M12-4
//     diff-webhook auto-trigger), where a webhook firing without a
//     matching diff_webhook_auto_fired audit row would orphan the
//     webhook in the dashboard's audit timeline. Those call sites
//     PROPAGATE the audit Log error (do NOT use `_ = audit.Log(...)`)
//     so a failed audit write fails the whole pair atomically: either
//     both the webhook and the audit row land, or neither does.
//     "Audit-or-nothing" is the name for that contract.
//
// A future contributor reviewing this file MUST keep the two paths
// separate. Promoting the middleware-level swallow to F168 audit-or-
// nothing would re-introduce the 500-storm failure mode above; demoting
// a handler-level audit_pair to best-effort would silently corrupt the
// business invariant the audit_pair was added to guarantee.
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

			// F214 / M14-4 (closes F196 NULL-by-design pin): record every
			// non-UUID path param value under its param name so forensic
			// queries can join on identifiers like :cve_id ("CVE-2021-44228")
			// or :checkId (slug-style checklist response key) without the
			// audit middleware needing to grow a "non-UUID resource_id"
			// slot. UUID-shaped params already flow through resource_id
			// (extractResourceID) and are not duplicated here.
			//
			// Pre-F214 only "path"/"method"/"status"/"latency_ms"/"query"
			// lived in details — a row for GET /projects/:id/ssvc/cve/:cve_id
			// could rescue resource_id from the project :id but the CVE
			// identifier itself was unrecoverable from the audit row, so
			// "show me every audit row touching CVE-2021-44228" required
			// re-parsing path strings.
			//
			// (anti-pattern 48 anchor: F196 had only a doc-only NULL-by-
			// design pin for :cve_id specifically; this fix covers every
			// current and future non-UUID path param in one place.)
			for name, val := range collectNonUUIDPathParams(c) {
				details[name] = val
			}

			var tenantIDPtr *uuid.UUID
			var userIDPtr *uuid.UUID
			if hasTenant {
				tenantIDPtr = &tenantID
			}
			if hasUser {
				userIDPtr = &userID
			}

			// F227 (M14 Phase D round 2 fix, dual-path audit design
			// pin): the Log error is INTENTIONALLY discarded here.
			// This is the middleware-level best-effort path; failing
			// the request on an audit-log INSERT failure would convert
			// a DB-side audit_logs outage into a 500 on every
			// authenticated request and take the whole product down.
			// F168 audit-or-nothing applies to HANDLER-level audit_pair
			// call sites (e.g. handler/sbom.go::writeAutoFiredAudit /
			// runDiffWebhookAutoTrigger) where the audit row is part of
			// a multi-row business contract; those handlers PROPAGATE
			// the Log error and do NOT use this swallow pattern. See
			// the Audit() head comment above for the full two-path
			// rationale.
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

// sensitiveAuditParamNames lists path-param names whose VALUE we must
// never copy into audit_logs.details, even if the value parses as a
// non-UUID string. The current sbomhub route table does NOT use any of
// these names in an authenticated route (the only one in use today is
// :token on the unauthenticated /public/:token route, which bypasses
// the audit middleware via the `if !hasTenant { return err }` guard),
// but the filter is defensive: a future authenticated route that
// inadvertently binds e.g. :api_key in the path would otherwise leak
// the secret into audit forensics with no warning.
//
// Names are matched lower-case; collectNonUUIDPathParams lower-cases
// the candidate before consulting this set so casing variants
// (:apiKey vs :api_key vs :APIKey) cannot bypass it.
var sensitiveAuditParamNames = map[string]struct{}{
	"token":       {},
	"secret":      {},
	"password":    {},
	"passwd":      {},
	"api_key":     {},
	"apikey":      {},
	"access_key":  {},
	"private_key": {},
	"session":     {},
	// F222 (M14 Phase D round 1 fix, anti-pattern 48 universal closure
	// supplement): forward-defensive additions covering auth header
	// shapes, CSRF / replay protection tokens, message-integrity
	// signatures, and raw HTTP cookies. None of these names are bound
	// by any current authenticated sbomhub route, so the additions are
	// strict-superset and cannot change today's behaviour; they exist
	// so a future route that inadvertently surfaces e.g. :bearer or
	// :jwt as a path param does not silently leak the value into
	// audit_logs.details under that name. Match is case-insensitive
	// via collectNonUUIDPathParams's strings.ToLower call.
	"bearer":     {},
	"jwt":        {},
	"csrf":       {},
	"csrf_token": {},
	"nonce":      {},
	"signature":  {},
	"hmac":       {},
	"cookie":     {},
}

// collectNonUUIDPathParams walks c.ParamNames() and returns name=value
// pairs for every path param whose value is non-empty, does NOT parse as
// a UUID (UUID-shaped params already flow through resource_id), and is
// not on the sensitive-name deny-list. The result is merged into the
// audit_logs.details map (F214 / M14-4) so forensic queries can join on
// identifiers like :cve_id ("CVE-2021-44228") and :checkId (slug-style
// checklist response keys).
//
// Returns nil when the route binds no path params or every bound param
// is empty / UUID / sensitive, so callers can iterate with `for k, v :=
// range collectNonUUIDPathParams(c)` without a length guard. The map
// keys are the raw Echo param names (e.g. "cve_id", "checkId") so the
// audit row matches the route declaration — a reader can grep the
// route table to find the originating endpoint.
//
// (anti-pattern 48: this captures the WHOLE class of non-UUID path
// params, not just the visible :cve_id case that motivated F196. A new
// route binding e.g. :purl is picked up automatically without an audit
// middleware edit.)
func collectNonUUIDPathParams(c echo.Context) map[string]string {
	names := c.ParamNames()
	if len(names) == 0 {
		return nil
	}
	var out map[string]string
	for _, name := range names {
		val := c.Param(name)
		if val == "" {
			continue
		}
		if _, err := uuid.Parse(val); err == nil {
			// UUID — already captured via resource_id.
			continue
		}
		if _, sensitive := sensitiveAuditParamNames[strings.ToLower(name)]; sensitive {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(names))
		}
		out[name] = val
	}
	return out
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
		// Triage runs (Wave M1-4). POST /projects/:id/triage/run mints a
		// fresh vex_draft row (the RunTriage handler publishes the new
		// draft UUID via SetAuditResourceID(c, res.Draft.ID) F208 path).
		//
		// F218 (M14 Phase D round 1 fix): pre-F218 this branch returned
		// model.ActionTriageRun / model.ResourceTriage, but no `triage`
		// table exists — audit_logs.(resource_type, resource_id) had no
		// joinable target. Combined with the F208 handler override that
		// sets resource_id to the new draft UUID, the audit row carried
		// (resource_type="triage", resource_id=<vex_draft UUID>), which
		// joined onto NEITHER vex_drafts (wrong resource_type) NOR a
		// triage table (does not exist). Reclassifying to
		// vex_draft.created closes the join contract.
		if pathHasChildResource(path, "triage") {
			return model.ActionVEXDraftCreated, model.ResourceVEXDraft
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
			// F237 (M15 Phase D round 1 fix, anti-pattern 53 dual-path
			// audit resolution — symmetric to the F236 evidence-pack
			// resolution above). The /diff/graph sub-path is
			// INTENTIONALLY skipped here so the outer Audit() middleware
			// does not emit a per-request audit row for GET
			// /projects/:id/diff/graph. Pre-F237 the branch returned
			// (model.ActionDiffGraphViewed = "diff.graph.view",
			// model.ResourceDiff = "diff") AND DiffHandler.ProjectDiffGraph
			// ALSO emitted its own handler-level audit_pair row (F168
			// audit-or-nothing semantics) with the IDENTICAL action
			// string ("diff.graph.view", via a local handler constant
			// AuditActionDiffGraphView) but a DIFFERENT resource_type
			// ("sbom_diff" via diff_summary.ResourceTypeSbomDiff) —
			// forensic `SELECT COUNT(*) FROM audit_logs WHERE
			// action='diff.graph.view'` double-counted every render, and
			// the two rows joined onto different tables. The handler side
			// is the source of truth: it fails the request 500 and rolls
			// back the TenantTx on audit write failure (F168) and carries
			// the rich details map (node_count / edge_count / added /
			// removed / changed / from_sbom_id / to_sbom_id) that the
			// middleware path cannot reconstruct. Option A resolution
			// (chosen for symmetry with F236): middleware skips, handler
			// audit_pair remains sole emit path. The local
			// AuditActionDiffGraphView constant is removed and the handler
			// now references model.ActionDiffGraphViewed directly so the
			// action string is defined in exactly one place. See
			// docs/operations/evidence-pack-audit-migration.md for the
			// operator-facing rationale (the same doc covers the F236 +
			// F237 pattern — both are middleware-vs-handler dual-path
			// resolutions to the single-row invariant).
			//
			// Regression pins:
			//   - TestDetermineActionAndResource_DiffGraphSkipped_F237
			//     (middleware/audit_test.go) asserts ("", "") return for
			//     the diff/graph path × method matrix.
			//   - TestDiffGraphHandler_Build_EmitsSingleAuditRow_F237
			//     (handler/diff_test.go) asserts the handler emits exactly
			//     one audit row with action="diff.graph.view" and
			//     resource_type="sbom_diff".
			if strings.HasSuffix(path, "/graph") {
				return "", ""
			}
			if method == "POST" {
				return model.ActionDiffSummary, model.ResourceDiff
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
		//
		// F236 (M15-4 fix, anti-pattern 53 dual-path audit resolution):
		// this branch INTENTIONALLY returns ("", "") so the outer
		// Audit() middleware skips its per-request audit row for every
		// POST /projects/:id/evidence-pack/build request. Pre-F236 the
		// branch returned (model.ActionEvidencePackBuilt,
		// model.ResourceEvidencePack) and EvidencePackHandler.Build ALSO
		// emitted its own handler-level audit_pair row (F168 audit-or-
		// nothing semantics) — the same request wrote TWO audit_logs
		// rows: one from here (action="evidence_pack.built" dotted) and
		// one from the handler (action="evidence_pack_built" underscore
		// per the local handler constant). Forensic queries that
		// GROUP BY action double-counted every evidence pack build.
		//
		// Option A resolution (chosen by user, M15-4 kickoff): the
		// handler-level audit_pair is the source of truth for the
		// evidence_pack.built business event — it fails the request on
		// audit write failure (F5 fail-closed) and carries the rich
		// details map (vex_approved_count / cra_approved_count /
		// meti_row_count / filename / built_at) that the middleware
		// path cannot reconstruct. The middleware-level generic row
		// added nothing the handler row was not already writing, only
		// noise. Skipping here keeps the F168 audit-or-nothing contract
		// intact on the handler side while eliminating the duplicate.
		//
		// The action string was ALSO unified to the dotted form
		// (model.ActionEvidencePackBuilt = "evidence_pack.built") in the
		// same M15-4 wave — pre-F236 the handler emitted the underscore
		// form via a local const AuditActionEvidencePackBuilt =
		// "evidence_pack_built"; that constant is removed and the
		// handler now references model.ActionEvidencePackBuilt so the
		// dotted form is the ONLY action string emitted for evidence
		// pack builds. Operators querying legacy audit_logs rows
		// produced before this deploy should filter
		// `action IN ('evidence_pack.built', 'evidence_pack_built')`;
		// new rows will only ever carry the dotted form. See
		// docs/operations/evidence-pack-audit-migration.md for the full
		// migration note.
		//
		// Regression pins:
		//   - TestDetermineActionAndResource_EvidencePackSkipped_F236
		//     (this file's test suite) asserts ("", "") return for the
		//     evidence-pack path × method matrix.
		//   - TestEvidencePackHandler_Build_HappyPath_EmitsSingleAuditRow_F236
		//     (handler/evidence_pack_test.go) asserts the handler emits
		//     exactly one audit row with action="evidence_pack.built".
		if pathHasChildResource(path, "evidence-pack") {
			return "", ""
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

	// F217 (M14 Phase D round 1 fix): issue-tracker ticket routes.
	//
	// Pre-F217, the four ticket endpoints
	//
	//   POST   /vulnerabilities/:vuln_id/ticket  (mint new ticket row)
	//   GET    /vulnerabilities/:vuln_id/tickets (list per-vuln)
	//   GET    /tickets                          (list tenant-wide)
	//   POST   /tickets/:id/sync                 (sync existing ticket)
	//
	// were classified by the tenant /vulnerabilities branch (for the
	// /vulnerabilities-prefixed two) as vulnerability.* and by the
	// default "unknown" bucket (for the /tickets-prefixed two). The
	// CreateTicket handler additionally publishes ticket.ID via
	// SetAuditResourceID (F208 path), so the resulting audit row carried
	// (resource_type="vulnerability", resource_id=<ticket UUID>) — a
	// JOIN onto vulnerabilities.id silently dropped (ticket UUID is not
	// a vulnerabilities PK) and a JOIN onto vulnerability_tickets.id
	// (the physical table — see migrations/015_issue_tracker.up.sql)
	// matched only by coincidence (resource_type filter excluded it).
	// F223 (M14 Phase D round 2 fix) corrected this docstring's prior
	// reference to a non-existent integration-prefixed ticket table.
	//
	// This branch must come BEFORE the /vulnerabilities tenant branch
	// below so the /vulnerabilities-prefixed ticket routes are caught
	// here first. The two pathHasChildResource calls match the segment-
	// exact suffix "/ticket" (singular create) and "/tickets" (plural
	// list / nested sync), respecting F202 discipline so a hypothetical
	// "/tickets-archive" route would not false-match.
	if pathHasChildResource(path, "ticket") || pathHasChildResource(path, "tickets") {
		switch method {
		case "POST":
			if strings.HasSuffix(path, "/sync") {
				return model.ActionTicketSynced, model.ResourceTicket
			}
			return model.ActionTicketCreated, model.ResourceTicket
		case "GET":
			// Plural /tickets suffix is a list operation; everything
			// else (no current GET route, but future :id GET) is a
			// per-item view.
			if strings.HasSuffix(path, "/tickets") {
				return model.ActionTicketListed, model.ResourceTicket
			}
			return model.ActionTicketViewed, model.ResourceTicket
		case "PUT", "PATCH":
			// F225 (M14 Phase D round 2 fix): the inline "ticket.updated"
			// literal is replaced by the named constant so a typo cannot
			// silently drift between the middleware emit site and the
			// service-layer dropdown that filters on the same string.
			return model.ActionTicketUpdated, model.ResourceTicket
		case "DELETE":
			// F225 (M14 Phase D round 2 fix): see PUT/PATCH note above.
			return model.ActionTicketDeleted, model.ResourceTicket
		default:
			// F206 (anti-pattern 48 symmetric to F201): pin the resource
			// here so a future OPTIONS / HEAD route on the ticket family
			// does not fall through to the /vulnerabilities tenant
			// branch below and re-introduce the F217 mass-misclassification.
			// F225 promotes the literal to the named constant.
			return model.ActionTicketUpdated, model.ResourceTicket
		}
	}

	// Vulnerability endpoints — tenant-level only (project-nested
	// classified by the F188 hoist above). F198 removes the dead Contains
	// arm. /vulnerabilities/sync-epss, /vulnerabilities/epss/:cve_id,
	// /vulnerabilities/:cve_id/ipa, /vulnerabilities/:vuln_id/ticket(s)
	// and /vulnerabilities/:id/remediation all start with /vulnerabilities
	// so HasPrefix is sufficient. (F217 hoists the ticket sub-paths
	// above; this branch now only sees non-ticket vulnerability routes.)
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

	// CLI endpoints.
	//
	// F233 (M15-1 fix, anti-pattern 48/51/52 universal closure for CLI
	// family): the pre-F233 branch classified every /cli/* POST as
	// cli.upload / cli.action / cli.check with resource_type="cli",
	// which meant the audit row for POST /cli/upload (mints a new sbom
	// UUID via CLIService.UploadSBOM) and POST /cli/projects (mints a
	// new project UUID via CLIService.GetOrCreateProject) had:
	//
	//   * resource_type = "cli"  (no `cli` table exists to join onto)
	//   * resource_id   = NULL   (extractResourceID had no path UUID
	//                             to pick up, and F208 handler override
	//                             was not published from cli.go)
	//
	// Post-F233 the CLI upload + project-create routes classify by the
	// UNDERLYING resource (sbom.uploaded / sbom, project.created /
	// project) so audit_logs.(resource_type, resource_id) matches the
	// tenant /api/v1/projects and /api/v1/projects/:id/sbom routes.
	// Combined with the handler-side SetAuditResourceID calls (cli.go
	// Upload publishes the new sbom UUID; CreateProject publishes the
	// new project UUID), the F208 override-first strategy lands the
	// created row's UUID in resource_id — forensic joins onto
	// sboms.id / projects.id now work whether the row was created via
	// /api/v1/... or /cli/... .
	//
	// /cli/check keeps cli.check / cli because it is a transient
	// vulnerability check (no UUID minted, nothing to join onto).
	// GET /cli/* keeps cli.accessed / cli for the same reason.
	//
	// The default arm at the bottom (F206 discipline: pin the family
	// on any future method — PUT/PATCH/DELETE/OPTIONS/HEAD — so a
	// future CLI route addition does not fall through to the tenant
	// branches or to the "unknown" default at the very bottom of the
	// classifier).
	if strings.HasPrefix(path, "/cli") {
		switch method {
		case "POST":
			if strings.Contains(path, "/upload") {
				// POST /cli/upload — sbom UUID minted in the handler
				// and published via SetAuditResourceID(c, sbom.ID).
				return model.ActionSBOMUploaded, model.ResourceSBOM
			}
			if strings.Contains(path, "/check") {
				// Transient vulnerability check, no UUID minted.
				return "cli.check", "cli"
			}
			if strings.Contains(path, "/projects") {
				// POST /cli/projects — project UUID minted in the
				// handler and published via SetAuditResourceID(c,
				// project.ID). Even when GetOrCreateProject returns
				// an EXISTING project (created=false), the handler
				// still publishes the project UUID so the audit row
				// joins on projects.id.
				return model.ActionProjectCreated, model.ResourceProject
			}
			return "cli.action", "cli"
		case "GET":
			return "cli.accessed", "cli"
		default:
			// F206 (anti-pattern 48 symmetric to F201): pin the CLI
			// family on any future method (PUT/PATCH/DELETE/OPTIONS/
			// HEAD) so it does not fall through to the tenant
			// branches below (or to the generic "unknown" default).
			return "cli.action", "cli"
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

// ContextKeyAuditResourceID is the echo.Context key handlers use to
// publish a newly-minted resource UUID for the audit middleware to
// consume as resource_id (F208).
//
// Handlers MUST call SetAuditResourceID(c, id) AFTER a successful
// create-style operation so the (post-`next(c)`) middleware sees the
// value during extractResourceID's first (override) strategy path —
// this OVERRIDES the priority-list / ParamNames fallback paths even
// when a parent :id UUID is present, which is required to close the
// F190 join-key corruption (parent :id would otherwise win and the
// audit row would point at the wrong subject). F231 (M14 Phase D
// round 6) corrected this docstring from the older 'fallback-only'
// wording to match the override-first implementation pinned by
// TestExtractResourceID_PostSuccessContextKey_F208 project-nested
// cases. See extractResourceID head doc for the full strategy.
//
// The key is exported so handler/_test files can assert on it without
// re-typing the literal; the literal value ("audit_resource_id") is
// the contract documented in the F190 limitation paragraph the M14-1
// fix closes.
const ContextKeyAuditResourceID = "audit_resource_id"

// SetAuditResourceID publishes id on the echo.Context so the audit
// middleware records audit_logs.resource_id = id with override-first
// semantics — the published id wins over the priority-list /
// ParamNames-fallback paths even when a parent :id UUID is bound on
// the route (F208, M14-1; F231 docstring correction).
//
// Convenience wrapper around c.Set(ContextKeyAuditResourceID, id) —
// kept in middleware/ so the contract (key name, accepted types)
// lives next to the consumer (extractResourceID). Handlers may call
// this with either uuid.UUID or *uuid.UUID; the consumer accepts both.
//
// Call site convention (F208):
//   - POST/create handlers: invoke immediately BEFORE the success
//     return (`return c.JSON(http.StatusCreated, obj)`), passing the
//     newly-minted object's primary key UUID.
//   - For POST routes that act on an existing resource and mint a
//     NEW row (e.g. /cra-reports/run, /reports/generate, /ssvc/cve
//     /:cve_id), call with the NEW row's UUID — not the parent :id.
//     The middleware's priority list would otherwise pick up the
//     parent path param and the audit row would point at the wrong
//     subject for forensic joins (the original F190 failure mode).
//
// Pass a typed-nil pointer (no-op-safe) when the handler decides
// post-flight that no resource was actually created; the middleware
// then falls back to the path-param strategy as if Set had not been
// called.
func SetAuditResourceID(c echo.Context, id uuid.UUID) {
	if id == uuid.Nil {
		return
	}
	c.Set(ContextKeyAuditResourceID, id)
}

// extractResourceID extracts the resource ID from path parameters
// and the post-success handler context-key override.
//
// Strategy (F186 hybrid + F208 explicit-handler-override):
//  1. Explicit handler override (F208 / M14-1): handlers that mint a
//     new UUID inside the request body — typical of every create-style
//     POST — call SetAuditResourceID(c, id) (or c.Set(
//     ContextKeyAuditResourceID, id) directly) right before the
//     success return. Because the audit middleware runs AFTER `next(c)`
//     returns, that value is available here AND it takes precedence
//     over path-param inference. This is what makes the F208 fix work
//     for project-nested create routes such as POST /projects/:id/vex
//     and POST /projects/:id/cra-reports/run — without override-first
//     semantics, the priority list below would still pick up the
//     parent `:id` and the audit row would point at the project UUID
//     (the original F190 failure mode). We accept both uuid.UUID and
//     *uuid.UUID type assertions so handler call sites that already
//     hold a pointer to a service-returned *Model do not need to
//     dereference at the call boundary.
//  2. Iterate resourceIDParamPriority in declaration order. The first
//     param bound on the request whose value parses as a UUID wins. The
//     list is explicit so a reader can grep audit.go to answer "which
//     path param becomes resource_id on route X?". Specific names (e.g.
//     :key_id) come before generic ":id" so child resources are not
//     shadowed by their parent.
//  3. Fallback: if nothing in the priority list matches, walk
//     c.ParamNames() from tail to head and accept the first UUID-
//     parseable value. This is the future-proof path — when a new route
//     introduces a novel `:<thing>_id` we still record the most specific
//     UUID instead of silently dropping resource_id to NULL until
//     someone notices and edits the priority list.
//
// Non-UUID values (slugs such as :checkId for checklist response keys)
// are intentionally skipped on paths 2 + 3 so they never pollute
// resource_id. This includes :cve_id (CVE identifiers such as
// "CVE-2021-44228" are not UUIDs by spec — see F196). The only
// currently-known route binding :cve_id is /projects/:id/ssvc/cve/
// :cve_id, where the parent :id rescues the audit row with the project
// UUID; the ssvc handlers that mint a new assessment row on POST also
// publish that UUID via path 1 so the audit row reflects the
// assessment, not the parent project.
//
// F214 / M14-4 (closes F196): non-UUID path param VALUES (cve_id,
// checkId, ...) are now recorded under their param name inside
// audit_logs.details by the Audit() middleware itself (see
// collectNonUUIDPathParams). resource_id remains nil for those values
// by design — UUIDs only — but forensic queries can now reach the CVE
// identifier via details->>'cve_id' instead of re-parsing path strings.
// The NULL-by-design pin documented above is still true for resource_id,
// but the forensic gap it described is closed at the details layer.
//
// Why explicit handler override is path 1 (anti-pattern 48 anchor,
// M14-1 closure of F190): the F190 docstring catalogued a class of
// create routes where the newly-minted UUID lives in the response body
// and the path carries only the PARENT resource's UUID. Examples
// include POST /projects/:id/cra-reports (new cra_report UUID, parent
// :id in path) and POST /projects/:id/vex (new VEX UUID, parent :id in
// path). If the handler override were merely a last-resort fallback
// (i.e. only consulted when paths 2+3 returned nil), those routes
// would still record the parent's project UUID — the exact failure
// the F190 docstring warned about. Putting the handler override
// FIRST closes the limitation universally: every create handler can
// authoritatively declare "the audit row points at THIS row".
//
// Handlers that opted into the F208 contract are pinned by the
// TestExtractResourceID_PostSuccessContextKey_F208 meta-test in
// audit_test.go; additions to that coverage table flag every future
// create handler that forgets to call SetAuditResourceID.
//
// Historical limitation (F190, M13 Phase D — RESOLVED by F208 / M14-1):
//
//	Before path 1 existed, POST/create routes such as
//
//	  POST /projects            (newly-minted project UUID in body)
//	  POST /apikeys             (newly-minted apikey UUID in body)
//	  POST /projects/:id/cra-reports   (parent :id present, but the
//	                                    NEW cra_report UUID lives in
//	                                    the response body)
//	  POST /projects/:id/vex    (same — new VEX UUID is in body, only
//	                             the parent project :id is in the path)
//
//	had no path param carrying the newly-minted UUID, so the audit
//	row for every project.created / apikey.created / cra_report.created
//	/ vex.created recorded resource_id = NULL (or the parent project's
//	UUID, which is misleading — joining audit_logs.resource_id onto
//	the newly-created table's primary key on those rows would silently
//	drop them or join onto the wrong subject). M14-1 (F208) closes the
//	limitation by adding path 1 here (and inserting SetAuditResourceID
//	calls in every create handler — apikey/cra_reports/issue_tracker/
//	license/project/public_link/report/sbom/ssvc/vex). Forensic
//	queries that join audit_logs.resource_id onto the created table's
//	primary key are now reliable for those rows.
func extractResourceID(c echo.Context) *uuid.UUID {
	// 1) Explicit handler override (F208 / M14-1). Accept both
	//    uuid.UUID and *uuid.UUID so handler call sites that already
	//    hold a pointer to a service-returned *Model do not need to
	//    dereference at the call boundary. uuid.Nil is treated as
	//    "no value" so a default-initialised zero UUID does not
	//    silently poison forensic joins.
	if v := c.Get(ContextKeyAuditResourceID); v != nil {
		switch id := v.(type) {
		case uuid.UUID:
			if id != uuid.Nil {
				out := id
				return &out
			}
		case *uuid.UUID:
			if id != nil && *id != uuid.Nil {
				out := *id
				return &out
			}
		}
	}

	// 2) Explicit priority list.
	for _, name := range resourceIDParamPriority {
		if idStr := c.Param(name); idStr != "" {
			if id, err := uuid.Parse(idStr); err == nil {
				return &id
			}
		}
	}

	// 3) Fallback: path-tail UUID. We walk ParamNames in reverse so the
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
