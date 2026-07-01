package model

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// AuditLog represents an audit trail entry
type AuditLog struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	TenantID     *uuid.UUID             `json:"tenant_id,omitempty" db:"tenant_id"`
	UserID       *uuid.UUID             `json:"user_id,omitempty" db:"user_id"`
	Action       string                 `json:"action" db:"action"`
	ResourceType string                 `json:"resource_type" db:"resource_type"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty" db:"resource_id"`
	Details      map[string]interface{} `json:"details,omitempty" db:"details"`
	IPAddress    net.IP                 `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent    string                 `json:"user_agent,omitempty" db:"user_agent"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

// Audit action constants
const (
	// User actions
	ActionUserSignIn      = "user.sign_in"
	ActionUserSignOut     = "user.sign_out"
	ActionUserCreated     = "user.created"
	ActionUserUpdated     = "user.updated"
	ActionUserDeleted     = "user.deleted"
	ActionUserInvited     = "user.invited"
	ActionUserRoleChanged = "user.role_changed"

	// Tenant actions
	ActionTenantCreated = "tenant.created"
	ActionTenantUpdated = "tenant.updated"
	ActionTenantDeleted = "tenant.deleted"

	// Project actions
	ActionProjectCreated = "project.created"
	ActionProjectUpdated = "project.updated"
	ActionProjectDeleted = "project.deleted"
	// F242 (M16-1 fix, anti-pattern 48/51/52 CLI GET reclassify): named
	// constant for the "project.viewed" dot verb that the audit middleware
	// emits for GET /projects[/:id] (tenant) and, post-F242, for
	// GET /cli/projects[/:id] (CLI family). Pre-F242 the value existed
	// only as an inline string literal at two sites (middleware /projects
	// GET arm at audit.go L745; service/audit.go dropdown row at L295) so
	// a typo at either site was compile-time invisible. Extracting the
	// constant here lets the /cli GET reclassify reference the same value
	// via model.ActionProjectViewed and keeps the tenant/CLI parity
	// enforceable at compile time. The dot form is intentional — matches
	// every other <resource>.viewed verb in this file (sbom.viewed,
	// vex_draft.viewed, cra_report.viewed, scan.viewed, meti.viewed,
	// ssvc.viewed, kev.viewed, eol.viewed, ticket.viewed, notification.viewed,
	// license_policy.viewed, checklist.viewed, visualization.viewed,
	// public_link.viewed, vulnerability.viewed, diff.viewed).
	ActionProjectViewed = "project.viewed"

	// SBOM actions
	ActionSBOMUploaded = "sbom.uploaded"
	ActionSBOMDeleted  = "sbom.deleted"
	ActionSBOMScanned  = "sbom.scanned"

	// VEX actions
	ActionVEXCreated = "vex.created"
	ActionVEXUpdated = "vex.updated"
	ActionVEXDeleted = "vex.deleted"

	// API Key actions
	ActionAPIKeyCreated = "apikey.created"
	ActionAPIKeyDeleted = "apikey.deleted"
	ActionAPIKeyUsed    = "apikey.used"

	// Subscription actions
	ActionSubscriptionCreated   = "subscription.created"
	ActionSubscriptionUpdated   = "subscription.updated"
	ActionSubscriptionCancelled = "subscription.cancelled"
	ActionSubscriptionRenewed   = "subscription.renewed"

	// Settings actions
	ActionSettingsUpdated = "settings.updated"

	// LLM / BYOK actions (issue #22). The key itself is NEVER logged —
	// only the action verb and provider name. See
	// internal/handler/settings_llm.go for the call sites.
	ActionLLMKeySet     = "llm_key_set"
	ActionLLMKeyRotated = "llm_key_rotated"
	ActionLLMKeyCleared = "llm_key_cleared"

	// F188 (M13 Phase D round 3): action verbs for the project-nested
	// child resource families that the audit middleware now classifies
	// before the /projects branch swallows them. Before F188, every
	// /projects/:id/<child> request was logged as project.<verb>; this
	// list, paired with the matching Resource* constants below, gives
	// each family its own (action, resource_type) pair so audit_logs
	// joins onto the family's own table actually work.

	// VEX statement listing — GET /projects/:id/vex is a list operation;
	// keep "vex.viewed" for the per-statement GET so existing audit rows
	// stay readable.
	ActionVEXListed = "vex.listed"

	// VEX draft (AI triage) actions. The runner emits its own domain-
	// level vex_draft_ai_generated / vex_draft_ai_disabled etc. rows
	// inside the Stage 3 write tx; the middleware records the request-
	// level path/method/latency view with these verbs.
	ActionVEXDraftListed          = "vex_draft.listed"
	ActionVEXDraftViewed          = "vex_draft.viewed"
	ActionVEXDraftDecisionUpdated = "vex_draft.decision_updated"
	ActionVEXDraftReanalysed      = "vex_draft.reanalysed"
	// F218 (M14 Phase D round 1 fix): POST /projects/:id/triage/run mints
	// a fresh vex_draft row. Pre-F218 the middleware classified it as
	// "triage.run" / "triage" but no `triage` table exists, so
	// audit_logs.(resource_type, resource_id) had no joinable target —
	// the handler-published resource_id (the new draft UUID) collided
	// with resource_type="triage". The branch is reclassified to
	// vex_draft.created so the audit row joins on vex_drafts.id.
	ActionVEXDraftCreated = "vex_draft.created"

	// Triage runs (Wave M1-5).
	//
	// F218 (M14 Phase D round 1 fix): No longer emitted by the audit
	// middleware (the /triage branch is reclassified to vex_draft.created
	// because triage runs mint vex_draft rows and there is no `triage`
	// table to join onto). The constant is retained so existing dropdown
	// filters can still match legacy audit_logs rows produced before the
	// reclassification.
	ActionTriageRun = "triage.run"

	// CRA report drafting (Wave M2-4 / issue #36).
	ActionCRAReportRun             = "cra_report.run"
	ActionCRAReportListed          = "cra_report.listed"
	ActionCRAReportViewed          = "cra_report.viewed"
	ActionCRAReportDecisionUpdated = "cra_report.decision_updated"
	ActionCRAReportReanalysed      = "cra_report.reanalysed"

	// Scheduled / on-demand vulnerability scans.
	ActionScanStarted = "scan.started"
	ActionScanViewed  = "scan.viewed"

	// Compliance checks (METI dashboard, /compliance).
	ActionComplianceChecked = "compliance.checked"

	// Notification settings.
	ActionNotificationListed  = "notification.listed"
	ActionNotificationCreated = "notification.created"
	ActionNotificationUpdated = "notification.updated"
	ActionNotificationDeleted = "notification.deleted"
	ActionNotificationViewed  = "notification.viewed"

	// SBOM-diff observability (M10-6 / M11-4 / M12-3).
	ActionDiffViewed      = "diff.viewed"
	ActionDiffSummary     = "diff.summary"
	ActionDiffGraphViewed = "diff.graph.view"

	// SSVC.
	ActionSSVCViewed   = "ssvc.viewed"
	ActionSSVCAssessed = "ssvc.assessed"
	ActionSSVCDeleted  = "ssvc.deleted"

	// METI self-assessment (Wave M3-4).
	ActionMETIViewed     = "meti.viewed"
	ActionMETIRefreshed  = "meti.refreshed"
	ActionMETIOverridden = "meti.overridden"

	// License policy.
	ActionLicensePolicyListed  = "license_policy.listed"
	ActionLicensePolicyViewed  = "license_policy.viewed"
	ActionLicensePolicyCreated = "license_policy.created"
	ActionLicensePolicyUpdated = "license_policy.updated"
	ActionLicensePolicyDeleted = "license_policy.deleted"

	// Evidence pack (Wave M2-6).
	ActionEvidencePackBuilt = "evidence_pack.built"

	// METI checklist.
	ActionChecklistViewed  = "checklist.viewed"
	ActionChecklistUpdated = "checklist.updated"
	ActionChecklistDeleted = "checklist.deleted"

	// Visualization framework.
	ActionVisualizationViewed  = "visualization.viewed"
	ActionVisualizationUpdated = "visualization.updated"
	ActionVisualizationDeleted = "visualization.deleted"

	// Public links.
	ActionPublicLinkCreated = "public_link.created"
	ActionPublicLinkViewed  = "public_link.viewed"
	ActionPublicLinkUpdated = "public_link.updated"
	ActionPublicLinkDeleted = "public_link.deleted"

	// KEV (project-scoped lookup).
	ActionKEVViewed = "kev.viewed"

	// EOL (project-scoped /eol-summary, /eol-check).
	ActionEOLViewed  = "eol.viewed"
	ActionEOLChecked = "eol.checked"

	// SBOM viewed (per-project GET /sbom, GET /sboms, scan-status).
	ActionSBOMViewed = "sbom.viewed"

	// Vulnerability listing.
	ActionVulnerabilityListed = "vulnerability.listed"
	ActionVulnerabilityViewed = "vulnerability.viewed"

	// F217 (M14 Phase D round 1 fix): Issue-tracker ticket actions for
	// POST /vulnerabilities/:vuln_id/ticket (mints new ticket row),
	// POST /tickets/:id/sync (re-syncs an existing ticket), and the
	// GET /vulnerabilities/:vuln_id/tickets list / GET /tickets list
	// endpoints. Pre-F217 these requests were classified as
	// vulnerability.* (the /vulnerabilities branch swallowed the suffix
	// segment) and the SetAuditResourceID(c, ticket.ID) override in the
	// CreateTicket handler poisoned audit_logs with
	// (resource_type="vulnerability", resource_id=<ticket UUID>) — a
	// row that joined onto NEITHER table.
	ActionTicketCreated = "ticket.created"
	ActionTicketSynced  = "ticket.synced"
	ActionTicketListed  = "ticket.listed"
	ActionTicketViewed  = "ticket.viewed"

	// F225 (M14 Phase D round 2 fix, anti-pattern 48 symmetric closure):
	// the F217 middleware ticket branch emits PUT/PATCH and DELETE+default
	// arms returning "ticket.updated" and "ticket.deleted" as inline
	// string literals, with no named constant counterpart and no entry in
	// the service-layer dropdown registry. No PUT/PATCH or DELETE ticket
	// route exists today, so the gap was latent — but a future ticket
	// route landing on either arm would produce audit_logs rows that the
	// UI filter dropdown could not select. Adding the constants here +
	// dropdown entries in service/audit.go closes the symmetric gap so the
	// four ticket.created/synced/listed/viewed entries (F217) and the
	// future ticket.updated/deleted entries share the same registration
	// discipline. The middleware now references these constants instead
	// of the raw literals so a typo at the literal site fails to compile.
	ActionTicketUpdated = "ticket.updated"
	ActionTicketDeleted = "ticket.deleted"

	// F256 (M17-1, anti-pattern 48 universal closure): named constants
	// for the remaining <resource>.viewed dot verbs that the audit
	// middleware still emitted as inline string literals across the
	// tenant-level and default-arm branches. Pre-F256 twelve
	// determineActionAndResource sites returned raw strings such as
	// "apikey.viewed", "user.viewed", "resource.viewed", so a typo at
	// any single site (e.g. "aipkey.viewed") was compile-time invisible
	// — the audit_logs row would carry the misspelled verb and the UI
	// dropdown filter (service/audit.go registry) would never surface
	// it. F242 (project.viewed) + F245 (dedupe /projects GET arm) had
	// already established the pattern; F256 extends the same discipline
	// to every remaining .viewed literal so a rename cascades at compile
	// time and typos surface as build errors, not silent audit drift.
	// The middleware audit_test.go cases at the same verbs are also
	// swapped to reference these constants so a test-side rename tracks
	// the code-side rename in lockstep.
	ActionAPIKeyViewed       = "apikey.viewed"
	ActionVEXViewed          = "vex.viewed"
	ActionSettingsViewed     = "settings.viewed"
	ActionUserViewed         = "user.viewed"
	ActionSubscriptionViewed = "subscription.viewed"
	ActionReportViewed       = "report.viewed"
	ActionAnalyticsViewed    = "analytics.viewed"
	ActionIntegrationViewed  = "integration.viewed"
	ActionDashboardViewed    = "dashboard.viewed"
	ActionResourceViewed     = "resource.viewed"

	// F267 (M18-1, anti-pattern 48 universe universal closure completion):
	// named constants for the remaining 23 dot-verb inline literals that
	// audit middleware still emitted across the F201/F206 default-arm
	// pins, the /vulnerabilities/scan+create/update arms, the tenant-level
	// /reports, /integrations, /search, /mcp, /cli, /scan, and generic
	// "unknown" default arms. F256 (M17-1) closed the `.viewed` universe
	// (10 constants + 12 middleware sites + 6 test sites) and F259
	// (M17-1 R2) swapped the single `scan.started` inline literal to
	// model.ActionScanStarted; the 22 verb-family cases below (28
	// middleware sites, unique 23 verbs, plus 6 audit_test.go sites) were
	// deferred to M18 because they needed new model.* constants added
	// first. Extracting them here lets every audit-emitting middleware
	// site reference a single symbol so a typo fails at compile time —
	// audit universe reaches inline-literal residual 0 for code emit
	// (comment explanations at F225 promoted literal notes remain, per
	// F225 discipline). The UI dropdown filter (service/audit.go
	// GetAvailableActions) registration is not done here — the 23 symbols
	// below are registered by companion wave F270 (M18-1 Phase D R2) in
	// service/audit.go, and F271 (M18-1 Phase D R2, anti-pattern 58
	// candidate) is the emit ↔ registry parity meta-test that keeps the
	// two lists synchronized so future drift fails CI, not silently
	// hides in the audit_logs table.
	ActionAPIKeyUpdated        = "apikey.updated"
	ActionCRAReportUpdated     = "cra_report.updated"
	ActionVEXDraftUpdated      = "vex_draft.updated"
	ActionSBOMUpdated          = "sbom.updated"
	ActionVulnerabilityScanned = "vulnerability.scanned"
	ActionVulnerabilityCreated = "vulnerability.created"
	ActionVulnerabilityUpdated = "vulnerability.updated"
	ActionReportGenerated      = "report.generated"
	ActionIntegrationCreated   = "integration.created"
	ActionIntegrationUpdated   = "integration.updated"
	ActionIntegrationDeleted   = "integration.deleted"
	ActionSearchCVE            = "search.cve"
	ActionSearchComponent      = "search.component"
	ActionSearchExecuted       = "search.executed"
	ActionMCPAccessed          = "mcp.accessed"
	ActionMCPAction            = "mcp.action"
	ActionCLICheck             = "cli.check"
	ActionCLIAction            = "cli.action"
	ActionCLIAccessed          = "cli.accessed"
	ActionScanStatus           = "scan.status"
	ActionResourceCreated      = "resource.created"
	ActionResourceUpdated      = "resource.updated"
	ActionResourceDeleted      = "resource.deleted"
)

// Resource type constants
const (
	ResourceUser         = "user"
	ResourceTenant       = "tenant"
	ResourceProject      = "project"
	ResourceSBOM         = "sbom"
	ResourceVEX          = "vex"
	ResourceAPIKey       = "apikey"
	ResourceSubscription = "subscription"
	ResourceSettings     = "settings"
	ResourceLLMConfig    = "llm_config"

	// F188 (M13 Phase D round 3): resource_type constants for the
	// project-nested child resource families that the audit middleware
	// now distinguishes. audit_logs (resource_type, resource_id) joins
	// onto the per-family domain table — keeping these as named constants
	// catches typos at compile time. See internal/middleware/audit.go
	// determineActionAndResource for the path-classification map.
	ResourceCRAReport     = "cra_report"
	ResourceVEXDraft      = "vex_draft"
	ResourceTriage        = "triage"
	ResourceScan          = "scan"
	ResourceCompliance    = "compliance"
	ResourceNotification  = "notification"
	ResourceDiff          = "diff"
	ResourceSSVC          = "ssvc"
	ResourceMETI          = "meti"
	ResourceLicensePolicy = "license_policy"
	ResourceEvidencePack  = "evidence_pack"
	ResourceChecklist     = "checklist"
	ResourceVisualization = "visualization"
	ResourcePublicLink    = "public_link"
	ResourceKEV           = "kev"
	ResourceEOL           = "eol"
	ResourceVulnerability = "vulnerability"

	// F217 (M14 Phase D round 1 fix): issue-tracker ticket resource_type
	// for /vulnerabilities/:vuln_id/ticket(s) and /tickets[/...]. Pinned
	// here so audit_logs.(resource_type, resource_id) joins onto the
	// vulnerability_tickets table cleanly (the physical table — see
	// migrations/015_issue_tracker.up.sql and repository/issue_tracker.go).
	// Pre-F217 the row carried resource_type="vulnerability" but
	// resource_id=<ticket UUID> (handler SetAuditResourceID) which
	// joined onto NEITHER table. F223 (M14 Phase D round 2 fix)
	// corrected this docstring's prior integration-prefixed ticket
	// table reference, which never existed in any migration.
	ResourceTicket = "ticket"

	// F272 (M18-1 Phase D R2, anti-pattern 48 symmetric closure): named
	// constant for the "unknown" resource_type that the audit middleware's
	// default arm returns when no branch above matches. Pre-F272 the four
	// default arms (middleware/audit.go GET/POST/PUT+PATCH/DELETE) returned
	// the "unknown" string literal alongside model.ActionResource*
	// constants — an asymmetric pattern where a typo ("unkown") at any
	// of the four sites would silently ship to audit_logs and the UI
	// filter dropdown could never surface it. Extracting the constant
	// here mirrors the F242 (project.viewed) / F256 (.viewed universe) /
	// F267 (action verb universe) discipline: every audit-emitted
	// resource_type value must be a compile-time-checked symbol so a
	// rename cascades and a typo fails to build. See middleware/audit.go
	// four default arms — the model.ActionResourceViewed +
	// model.ActionResource{Created,Updated,Deleted} arms — for the emit
	// sites that reference this constant.
	ResourceUnknown = "unknown"

	// F282 (M19-3 Phase D R1, anti-pattern 58 horizontal replication —
	// Resource dimension): named constants for the tenant-branch resource
	// types that audit middleware still emitted as inline string literals
	// across the /reports, /analytics, /integrations, /search, /dashboard,
	// /mcp, /cli, and /scan branches. Pre-F282 the middleware returned
	// raw strings like "report", "integration", "cli" alongside
	// model.Action* constants — an asymmetric pattern where a typo
	// ("reoprt") would silently ship to audit_logs and the service-layer
	// GetAvailableResourceTypes registry (which itself carried the same
	// three literal-only entries "report" / "analytics" / "integration")
	// could not detect the drift at compile time. F282 mirrors the F272
	// discipline for the "unknown" default arm to the eight tenant-branch
	// resource families, closing the anti-pattern 48 residual on the
	// Resource dimension exactly as F267 closed it on the Action dimension.
	// F283 (M19-3 sibling) swaps the emit-side literals to reference these
	// constants; F281 (M19-3 sibling) pins the emit ↔ registry parity so
	// future drift fails CI here.
	ResourceReport      = "report"
	ResourceAnalytics   = "analytics"
	ResourceIntegration = "integration"
	ResourceSearch      = "search"
	ResourceDashboard   = "dashboard"
	ResourceMCP         = "mcp"
	ResourceCLI         = "cli"

	// F296 (M20-1 Phase D R1, anti-pattern 58 3-axis full coverage —
	// handler-side ResourceType* orphan closure): named constants for
	// the three handler / service-layer emit sites that pre-F296 lived
	// as package-local `ResourceType*` string constants outside the
	// model.Resource* universe. Pre-F296:
	//
	//   * handler/meti.go carried `ResourceTypeMetiAssessment = "meti_assessment"`
	//     used by /refresh, /override, and /override-cleared audit rows
	//     (three handler emit sites: L487, L692, L896).
	//   * service/diff_summary/diff_summary.go carried
	//     `ResourceTypeSbomDiff = "sbom_diff"` used by the AI-generated /
	//     AI-failed audit rows (two service emit sites) plus one handler
	//     reference in handler/diff.go (the /diff/graph audit_pair, F237
	//     dual-path resolution).
	//   * model/diff_webhook.go carried `ResourceTypeDiffWebhook = "diff_webhook"`
	//     used by settings_diff_webhook.go (/settings PUT), handler/sbom.go
	//     (auto-fire path), and service/diff_webhook/diff_webhook.go
	//     (delivery worker).
	//
	// F281 (M19-3) direction-2 parity contract keys on the model.Resource*
	// symbol universe, so these three orphan constants were a documented
	// scope-limitation gap tracked as F286 M20+ candidate — the F281
	// meta-test could not catch a rename / typo at any of the six emit
	// sites because the strings lived outside the symbol universe it
	// scans. F296 closes the third axis of anti-pattern 58 coverage:
	//
	//   axis 1 (Action dimension, Action*)           = F271 (M18)
	//   axis 2 (Resource dimension, middleware-side) = F281 (M19)
	//   axis 3 (Resource dimension, handler-side)    = F296 (M20-1, THIS)
	//
	// The handler-side emit sites are swapped to reference these
	// constants; the orphan `ResourceType*` package-locals are removed
	// (single source of truth = model.Resource*), the corresponding
	// GetAvailableResourceTypes() rows are added, and the F281
	// expectedEmit set expands to include the three symbols so
	// direction-1 parity is enforced at CI time.
	ResourceMETIAssessment = "meti_assessment"
	ResourceSBOMDiff       = "sbom_diff"
	ResourceDiffWebhook    = "diff_webhook"
)

// CreateAuditLogInput is the input for creating an audit log
type CreateAuditLogInput struct {
	TenantID     *uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Details      map[string]interface{}
	IPAddress    string
	UserAgent    string
}
