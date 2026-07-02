package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// AuditService provides audit log operations
type AuditService struct {
	auditRepo *repository.AuditRepository
	userRepo  *repository.UserRepository
}

// NewAuditService creates a new AuditService
func NewAuditService(auditRepo *repository.AuditRepository, userRepo *repository.UserRepository) *AuditService {
	return &AuditService{
		auditRepo: auditRepo,
		userRepo:  userRepo,
	}
}

// AuditListResponse represents a paginated list of audit logs
type AuditListResponse struct {
	Logs       []AuditLogWithUser `json:"logs"`
	Total      int                `json:"total"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	TotalPages int                `json:"total_pages"`
}

// AuditLogWithUser extends AuditLog with user information
type AuditLogWithUser struct {
	model.AuditLog
	UserEmail string `json:"user_email,omitempty"`
	UserName  string `json:"user_name,omitempty"`
}

// AuditFilter defines filter options for listing audit logs
type AuditFilter struct {
	Action       string     `json:"action,omitempty"`
	ResourceType string     `json:"resource_type,omitempty"`
	UserID       *uuid.UUID `json:"user_id,omitempty"`
	StartDate    *time.Time `json:"start_date,omitempty"`
	EndDate      *time.Time `json:"end_date,omitempty"`
	Page         int        `json:"page"`
	Limit        int        `json:"limit"`
}

// List returns a paginated list of audit logs with filtering
func (s *AuditService) List(ctx context.Context, tenantID uuid.UUID, filter AuditFilter) (*AuditListResponse, error) {
	// Set defaults
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	offset := (filter.Page - 1) * filter.Limit

	// Convert to repository filter
	repoFilter := repository.AuditFilter{
		Action:       filter.Action,
		ResourceType: filter.ResourceType,
		UserID:       filter.UserID,
		StartDate:    filter.StartDate,
		EndDate:      filter.EndDate,
		Limit:        filter.Limit,
		Offset:       offset,
	}

	logs, total, err := s.auditRepo.ListWithFilter(ctx, tenantID, repoFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}

	// Collect unique user IDs for enrichment
	userIDs := make(map[uuid.UUID]bool)
	for _, log := range logs {
		if log.UserID != nil {
			userIDs[*log.UserID] = true
		}
	}

	// Fetch user information
	userMap := make(map[uuid.UUID]*model.User)
	for userID := range userIDs {
		user, err := s.userRepo.GetByID(ctx, userID)
		if err == nil && user != nil {
			userMap[userID] = user
		}
	}

	// Enrich logs with user information
	enrichedLogs := make([]AuditLogWithUser, len(logs))
	for i, log := range logs {
		enrichedLogs[i] = AuditLogWithUser{
			AuditLog: log,
		}
		if log.UserID != nil {
			if user, ok := userMap[*log.UserID]; ok {
				enrichedLogs[i].UserEmail = user.Email
				enrichedLogs[i].UserName = user.Name
			}
		}
	}

	totalPages := total / filter.Limit
	if total%filter.Limit > 0 {
		totalPages++
	}

	return &AuditListResponse{
		Logs:       enrichedLogs,
		Total:      total,
		Page:       filter.Page,
		Limit:      filter.Limit,
		TotalPages: totalPages,
	}, nil
}

// ExportCSV exports audit logs as CSV
func (s *AuditService) ExportCSV(ctx context.Context, tenantID uuid.UUID, filter AuditFilter) ([]byte, error) {
	// For export, get all matching logs (up to 10000)
	filter.Limit = 10000
	filter.Page = 1

	offset := 0
	repoFilter := repository.AuditFilter{
		Action:       filter.Action,
		ResourceType: filter.ResourceType,
		UserID:       filter.UserID,
		StartDate:    filter.StartDate,
		EndDate:      filter.EndDate,
		Limit:        filter.Limit,
		Offset:       offset,
	}

	logs, _, err := s.auditRepo.ListWithFilter(ctx, tenantID, repoFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}

	// Collect unique user IDs for enrichment
	userIDs := make(map[uuid.UUID]bool)
	for _, log := range logs {
		if log.UserID != nil {
			userIDs[*log.UserID] = true
		}
	}

	// Fetch user information
	userMap := make(map[uuid.UUID]*model.User)
	for userID := range userIDs {
		user, err := s.userRepo.GetByID(ctx, userID)
		if err == nil && user != nil {
			userMap[userID] = user
		}
	}

	// Generate CSV
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write BOM for Excel compatibility
	buf.Write([]byte{0xEF, 0xBB, 0xBF})

	// Write header
	header := []string{
		"ID",
		"Timestamp",
		"Action",
		"Resource Type",
		"Resource ID",
		"User ID",
		"User Email",
		"User Name",
		"IP Address",
		"User Agent",
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write rows
	for _, log := range logs {
		userEmail := ""
		userName := ""
		if log.UserID != nil {
			if user, ok := userMap[*log.UserID]; ok {
				userEmail = user.Email
				userName = user.Name
			}
		}

		resourceID := ""
		if log.ResourceID != nil {
			resourceID = log.ResourceID.String()
		}

		userID := ""
		if log.UserID != nil {
			userID = log.UserID.String()
		}

		ipAddress := ""
		if log.IPAddress != nil {
			ipAddress = log.IPAddress.String()
		}

		row := []string{
			log.ID.String(),
			log.CreatedAt.Format(time.RFC3339),
			log.Action,
			log.ResourceType,
			resourceID,
			userID,
			userEmail,
			userName,
			ipAddress,
			log.UserAgent,
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("failed to flush CSV: %w", err)
	}

	return buf.Bytes(), nil
}

// GetStatistics returns audit log statistics
func (s *AuditService) GetStatistics(ctx context.Context, tenantID uuid.UUID, days int) (*AuditStatistics, error) {
	if days <= 0 {
		days = 30
	}

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	actionCounts, err := s.auditRepo.GetActionCounts(ctx, tenantID, start, now)
	if err != nil {
		return nil, fmt.Errorf("failed to get action counts: %w", err)
	}

	dailyCounts, err := s.auditRepo.GetDailyActionCounts(ctx, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily counts: %w", err)
	}

	return &AuditStatistics{
		Period:       days,
		ActionCounts: actionCounts,
		DailyCounts:  dailyCounts,
	}, nil
}

// AuditStatistics represents audit log statistics
type AuditStatistics struct {
	Period       int                      `json:"period"`
	ActionCounts []repository.ActionCount `json:"action_counts"`
	DailyCounts  []map[string]interface{} `json:"daily_counts"`
}

// GetAvailableActions returns list of available action types for filtering
func (s *AuditService) GetAvailableActions() []ActionInfo {
	return []ActionInfo{
		// User actions
		{Action: model.ActionUserSignIn, Label: "User Sign In", Category: "user"},
		{Action: model.ActionUserSignOut, Label: "User Sign Out", Category: "user"},
		{Action: model.ActionUserCreated, Label: "User Created", Category: "user"},
		{Action: model.ActionUserUpdated, Label: "User Updated", Category: "user"},
		{Action: model.ActionUserDeleted, Label: "User Deleted", Category: "user"},
		{Action: model.ActionUserInvited, Label: "User Invited", Category: "user"},
		{Action: model.ActionUserRoleChanged, Label: "User Role Changed", Category: "user"},

		// Project actions
		{Action: model.ActionProjectCreated, Label: "Project Created", Category: "project"},
		{Action: model.ActionProjectUpdated, Label: "Project Updated", Category: "project"},
		{Action: model.ActionProjectDeleted, Label: "Project Deleted", Category: "project"},
		// F242 (M16-1 fix, anti-pattern 48/51/52 CLI GET reclassify): the
		// dropdown row now references the model.ActionProjectViewed
		// constant instead of the inline "project.viewed" literal — a
		// typo at either the middleware /projects GET arm (audit.go
		// L745) or the /cli GET reclassify (audit.go /cli branch) would
		// otherwise silently desync from this dropdown. See
		// model/audit.go ActionProjectViewed head comment for the two
		// emit sites F242 unifies.
		{Action: model.ActionProjectViewed, Label: "Project Viewed", Category: "project"},

		// SBOM actions
		{Action: model.ActionSBOMUploaded, Label: "SBOM Uploaded", Category: "sbom"},
		{Action: model.ActionSBOMDeleted, Label: "SBOM Deleted", Category: "sbom"},
		{Action: model.ActionSBOMScanned, Label: "SBOM Scanned", Category: "sbom"},
		{Action: model.ActionSBOMViewed, Label: "SBOM Viewed", Category: "sbom"},

		// VEX actions
		{Action: model.ActionVEXCreated, Label: "VEX Created", Category: "vex"},
		{Action: model.ActionVEXUpdated, Label: "VEX Updated", Category: "vex"},
		{Action: model.ActionVEXDeleted, Label: "VEX Deleted", Category: "vex"},
		{Action: model.ActionVEXListed, Label: "VEX Listed", Category: "vex"},

		// API Key actions
		{Action: model.ActionAPIKeyCreated, Label: "API Key Created", Category: "apikey"},
		{Action: model.ActionAPIKeyDeleted, Label: "API Key Deleted", Category: "apikey"},
		{Action: model.ActionAPIKeyUsed, Label: "API Key Used", Category: "apikey"},

		// Settings actions
		{Action: model.ActionSettingsUpdated, Label: "Settings Updated", Category: "settings"},

		// F188 (M13 Phase D round 3): project-nested child-resource actions
		// surfaced by the audit middleware hoist. Each family ships at
		// minimum the verbs the middleware emits today; the UI filter
		// dropdown follows the registry.

		// CRA report actions (Wave M2-4 / issue #36).
		{Action: model.ActionCRAReportRun, Label: "CRA Report Run", Category: "cra_report"},
		{Action: model.ActionCRAReportListed, Label: "CRA Report Listed", Category: "cra_report"},
		{Action: model.ActionCRAReportViewed, Label: "CRA Report Viewed", Category: "cra_report"},
		{Action: model.ActionCRAReportDecisionUpdated, Label: "CRA Report Decision Updated", Category: "cra_report"},
		{Action: model.ActionCRAReportReanalysed, Label: "CRA Report Reanalysed", Category: "cra_report"},

		// VEX draft actions (Wave M1-5).
		{Action: model.ActionVEXDraftListed, Label: "VEX Draft Listed", Category: "vex_draft"},
		{Action: model.ActionVEXDraftViewed, Label: "VEX Draft Viewed", Category: "vex_draft"},
		{Action: model.ActionVEXDraftDecisionUpdated, Label: "VEX Draft Decision Updated", Category: "vex_draft"},
		{Action: model.ActionVEXDraftReanalysed, Label: "VEX Draft Reanalysed", Category: "vex_draft"},
		// F218 (M14 Phase D round 1 fix): triage/run now classifies as
		// vex_draft.created (see middleware/audit.go::determineActionAndResource).
		{Action: model.ActionVEXDraftCreated, Label: "VEX Draft Created", Category: "vex_draft"},

		// Triage actions.
		//
		// F218 (M14 Phase D round 1 fix): no longer emitted by the
		// audit middleware (reclassified to vex_draft.created). Kept
		// in the dropdown so historical audit_logs rows produced
		// before the reclassification remain filterable.
		{Action: model.ActionTriageRun, Label: "Triage Run", Category: "triage"},

		// Scan actions.
		{Action: model.ActionScanStarted, Label: "Scan Started", Category: "scan"},
		{Action: model.ActionScanViewed, Label: "Scan Status Viewed", Category: "scan"},

		// Compliance.
		{Action: model.ActionComplianceChecked, Label: "Compliance Checked", Category: "compliance"},

		// Notifications.
		{Action: model.ActionNotificationListed, Label: "Notification Listed", Category: "notification"},
		{Action: model.ActionNotificationCreated, Label: "Notification Created", Category: "notification"},
		{Action: model.ActionNotificationUpdated, Label: "Notification Updated", Category: "notification"},
		{Action: model.ActionNotificationDeleted, Label: "Notification Deleted", Category: "notification"},
		{Action: model.ActionNotificationViewed, Label: "Notification Viewed", Category: "notification"},

		// Diff observability.
		{Action: model.ActionDiffViewed, Label: "Diff Viewed", Category: "diff"},
		{Action: model.ActionDiffSummary, Label: "Diff Summary", Category: "diff"},
		{Action: model.ActionDiffGraphViewed, Label: "Diff Graph Viewed", Category: "diff"},

		// SSVC.
		{Action: model.ActionSSVCViewed, Label: "SSVC Viewed", Category: "ssvc"},
		{Action: model.ActionSSVCAssessed, Label: "SSVC Assessed", Category: "ssvc"},
		{Action: model.ActionSSVCDeleted, Label: "SSVC Deleted", Category: "ssvc"},

		// METI self-assessment.
		{Action: model.ActionMETIViewed, Label: "METI Viewed", Category: "meti"},
		{Action: model.ActionMETIRefreshed, Label: "METI Refreshed", Category: "meti"},
		{Action: model.ActionMETIOverridden, Label: "METI Overridden", Category: "meti"},

		// License policy.
		{Action: model.ActionLicensePolicyListed, Label: "License Policy Listed", Category: "license_policy"},
		{Action: model.ActionLicensePolicyViewed, Label: "License Policy Viewed", Category: "license_policy"},
		{Action: model.ActionLicensePolicyCreated, Label: "License Policy Created", Category: "license_policy"},
		{Action: model.ActionLicensePolicyUpdated, Label: "License Policy Updated", Category: "license_policy"},
		{Action: model.ActionLicensePolicyDeleted, Label: "License Policy Deleted", Category: "license_policy"},

		// Evidence pack.
		{Action: model.ActionEvidencePackBuilt, Label: "Evidence Pack Built", Category: "evidence_pack"},

		// METI checklist.
		{Action: model.ActionChecklistViewed, Label: "Checklist Viewed", Category: "checklist"},
		{Action: model.ActionChecklistUpdated, Label: "Checklist Updated", Category: "checklist"},
		{Action: model.ActionChecklistDeleted, Label: "Checklist Deleted", Category: "checklist"},

		// Visualization framework.
		{Action: model.ActionVisualizationViewed, Label: "Visualization Viewed", Category: "visualization"},
		{Action: model.ActionVisualizationUpdated, Label: "Visualization Updated", Category: "visualization"},
		{Action: model.ActionVisualizationDeleted, Label: "Visualization Deleted", Category: "visualization"},

		// Public links.
		{Action: model.ActionPublicLinkCreated, Label: "Public Link Created", Category: "public_link"},
		{Action: model.ActionPublicLinkViewed, Label: "Public Link Viewed", Category: "public_link"},
		{Action: model.ActionPublicLinkUpdated, Label: "Public Link Updated", Category: "public_link"},
		{Action: model.ActionPublicLinkDeleted, Label: "Public Link Deleted", Category: "public_link"},

		// KEV / EOL.
		{Action: model.ActionKEVViewed, Label: "KEV Viewed", Category: "kev"},
		{Action: model.ActionEOLViewed, Label: "EOL Viewed", Category: "eol"},
		{Action: model.ActionEOLChecked, Label: "EOL Checked", Category: "eol"},

		// Vulnerability listing.
		{Action: model.ActionVulnerabilityListed, Label: "Vulnerability Listed", Category: "vulnerability"},
		{Action: model.ActionVulnerabilityViewed, Label: "Vulnerability Viewed", Category: "vulnerability"},

		// F217 (M14 Phase D round 1 fix): issue-tracker ticket actions.
		// audit_logs.(resource_type="ticket", resource_id=<ticket UUID>)
		// joins onto vulnerability_tickets.id (the physical table name —
		// see apps/api/migrations/015_issue_tracker.up.sql and
		// repository/issue_tracker.go). F223 (M14 Phase D round 2 fix):
		// renamed from a prior integration-prefixed docstring reference,
		// which never existed in any migration and would have sent
		// forensic-join readers grepping for a phantom table.
		{Action: model.ActionTicketCreated, Label: "Ticket Created", Category: "ticket"},
		{Action: model.ActionTicketSynced, Label: "Ticket Synced", Category: "ticket"},
		{Action: model.ActionTicketListed, Label: "Ticket Listed", Category: "ticket"},
		{Action: model.ActionTicketViewed, Label: "Ticket Viewed", Category: "ticket"},
		// F225 (M14 Phase D round 2 fix, anti-pattern 48 symmetric
		// closure): the middleware emits ticket.updated on PUT/PATCH +
		// OPTIONS/HEAD default arm and ticket.deleted on DELETE. No
		// PUT/PATCH or DELETE ticket route exists at the router today,
		// so today these emit only on hypothetical future routes — but
		// registering the dropdown entries now keeps the F217 ticket
		// family symmetric with every other audit family (each verb the
		// middleware can emit has a matching UI filter entry).
		{Action: model.ActionTicketUpdated, Label: "Ticket Updated", Category: "ticket"},
		{Action: model.ActionTicketDeleted, Label: "Ticket Deleted", Category: "ticket"},

		// F270 (M18-1 Phase D R2, anti-pattern 48 registry-side closure):
		// register the 23 F267 emit symbols in the UI filter dropdown.
		// F267 (M18-1) extracted 23 new model.Action* constants for the
		// remaining inline dot-verb literals across audit middleware
		// (apikey/cra_report/vex_draft/sbom/vulnerability/report/
		// integration/search/mcp/cli/scan/resource families) and swapped
		// 28 emit sites to reference them. That closed the classifier-
		// side typo gap at compile time but left the registry-side
		// dropdown blind to those 23 verbs — a UI filter that could not
		// select any audit_logs row produced by the middleware's F267
		// arms. F270 completes the closure by registering each of the
		// 23 F267 verbs here so the UI can filter them. F271 (M18-1
		// Phase D R2, anti-pattern 58 candidate) is the emit ↔ registry
		// parity meta-test that keeps future dual-list drift from
		// re-opening the same gap silently.
		{Action: model.ActionAPIKeyUpdated, Label: "API Key Updated", Category: "apikey"},
		{Action: model.ActionCRAReportUpdated, Label: "CRA Report Updated", Category: "cra_report"},
		{Action: model.ActionVEXDraftUpdated, Label: "VEX Draft Updated", Category: "vex_draft"},
		{Action: model.ActionSBOMUpdated, Label: "SBOM Updated", Category: "sbom"},
		{Action: model.ActionVulnerabilityScanned, Label: "Vulnerability Scanned", Category: "vulnerability"},
		{Action: model.ActionVulnerabilityCreated, Label: "Vulnerability Created", Category: "vulnerability"},
		{Action: model.ActionVulnerabilityUpdated, Label: "Vulnerability Updated", Category: "vulnerability"},
		{Action: model.ActionReportGenerated, Label: "Report Generated", Category: "report"},
		{Action: model.ActionIntegrationCreated, Label: "Integration Created", Category: "integration"},
		{Action: model.ActionIntegrationUpdated, Label: "Integration Updated", Category: "integration"},
		{Action: model.ActionIntegrationDeleted, Label: "Integration Deleted", Category: "integration"},
		{Action: model.ActionSearchCVE, Label: "Search CVE", Category: "search"},
		{Action: model.ActionSearchComponent, Label: "Search Component", Category: "search"},
		{Action: model.ActionSearchExecuted, Label: "Search Executed", Category: "search"},
		{Action: model.ActionMCPAccessed, Label: "MCP Accessed", Category: "mcp"},
		{Action: model.ActionMCPAction, Label: "MCP Action", Category: "mcp"},
		{Action: model.ActionCLICheck, Label: "CLI Check", Category: "cli"},
		{Action: model.ActionCLIAction, Label: "CLI Action", Category: "cli"},
		{Action: model.ActionCLIAccessed, Label: "CLI Accessed", Category: "cli"},
		{Action: model.ActionScanStatus, Label: "Scan Status", Category: "scan"},
		{Action: model.ActionResourceCreated, Label: "Resource Created", Category: "resource"},
		{Action: model.ActionResourceUpdated, Label: "Resource Updated", Category: "resource"},
		{Action: model.ActionResourceDeleted, Label: "Resource Deleted", Category: "resource"},
		// F270 (M18-1 Phase D R2): resource.viewed is F256-era rather
		// than F267, but the middleware's default-arm GET emits it as
		// a family sibling of the three F267 resource.{created,updated,
		// deleted} verbs above. Registering it here keeps the resource
		// default-arm family complete rather than splitting one family
		// across two waves, and is the minimum extension required for
		// F271's emit ↔ registry parity direction 1 to close (F272's
		// four default-arm emit sites cover all four resource verbs).
		{Action: model.ActionResourceViewed, Label: "Resource Viewed", Category: "resource"},

		// F280 (M19-2 Phase D R1, anti-pattern 58 formalize + horizontal
		// completion): register the 12 remaining emit symbols that F271
		// (M18-1 Phase D R2) had documented as F275+ candidates in the
		// knownEmitNotRegistered allowlist. F270 closed the 23 F267
		// symbols but deferred two clusters — the F256-era .viewed
		// residuals across nine tenant-branch resources and the three
		// subscription verbs — to a future M19+ wave. F280 completes
		// that wave: every emit site the audit middleware can produce
		// now has a matching UI filter entry, and the F271 allowlist
		// shrinks 12 → 0 (Action dimension parity completeness). F281
		// (M19-3 sibling) replicates the same discipline to the
		// Resource dimension so the dual-list system's parity contract
		// is enforced in both directions.
		{Action: model.ActionAPIKeyViewed, Label: "API Key Viewed", Category: "apikey"},
		{Action: model.ActionVEXViewed, Label: "VEX Viewed", Category: "vex"},
		{Action: model.ActionSettingsViewed, Label: "Settings Viewed", Category: "settings"},
		{Action: model.ActionUserViewed, Label: "User Viewed", Category: "user"},

		// Subscription family. The tenant-branch middleware arm at
		// audit.go /subscription emits four verbs (created/updated/
		// cancelled/viewed); F280 registers all four so the UI filter
		// can surface any audit_logs row the middleware produces.
		// A fifth "renewed" verb once existed as a model constant with
		// no emit site (no middleware classifier branch returned it and
		// the LemonSqueezy webhook event switch has no renewal event);
		// F333 (M22-2) deleted that dead constant rather than register
		// it here, because a registry entry without an emit counterpart
		// would violate the F271 direction-1 parity by injecting a
		// UI-selectable action that no branch can produce (F280
		// discipline).
		{Action: model.ActionSubscriptionCreated, Label: "Subscription Created", Category: "subscription"},
		{Action: model.ActionSubscriptionUpdated, Label: "Subscription Updated", Category: "subscription"},
		{Action: model.ActionSubscriptionCancelled, Label: "Subscription Cancelled", Category: "subscription"},
		{Action: model.ActionSubscriptionViewed, Label: "Subscription Viewed", Category: "subscription"},

		// Report / analytics / integration / dashboard tenant-branch
		// .viewed residuals. F270 registered the F267 non-.viewed
		// counterparts (ReportGenerated, IntegrationCreated/Updated/
		// Deleted) but the .viewed sibling in each family was deferred
		// to F275+; F280 closes the deferral so the tenant-branch
		// families are symmetric with the F267 completion.
		{Action: model.ActionReportViewed, Label: "Report Viewed", Category: "report"},
		{Action: model.ActionAnalyticsViewed, Label: "Analytics Viewed", Category: "analytics"},
		{Action: model.ActionIntegrationViewed, Label: "Integration Viewed", Category: "integration"},
		{Action: model.ActionDashboardViewed, Label: "Dashboard Viewed", Category: "dashboard"},

		// F319 (M21-2 Phase D, anti-pattern 58 adjacent gap closure —
		// handler / service-side Action dimension parity): the four
		// AuditActionDiffWebhook* constants in model/diff_webhook.go
		// (settings_updated / fired / failed / auto_fired) are emitted
		// from handler/settings_diff_webhook.go (Updated), handler/
		// sbom.go auto-fire path (AutoFired), and service/diff_webhook/
		// diff_webhook.go delivery worker (Fired / Failed). Pre-F319
		// none of the four were listed in GetAvailableActions() so the
		// UI filter dropdown could not surface any audit_logs row
		// produced by the DiffWebhook delivery pipeline — the same
		// silent forensic gap F270/F280 closed for the middleware-emit
		// verbs. F319 registers the four handler / service-side verbs
		// here so the dropdown is symmetric with the Resource dimension
		// (model.ResourceDiffWebhook, registered by F296 in
		// GetAvailableResourceTypes()) and closes the last M20 Action
		// dimension residual. The middleware-emit parity meta-test
		// (F271) does not exercise these four because they are not
		// middleware-classifier outputs; F319 companion test in
		// middleware/audit_test.go asserts registry presence via the
		// same GetAvailableActions() surface so a future rename /
		// removal trips CI.
		{Action: model.AuditActionDiffWebhookUpdated, Label: "Diff Webhook Updated", Category: "diff_webhook"},
		{Action: model.AuditActionDiffWebhookFired, Label: "Diff Webhook Fired", Category: "diff_webhook"},
		{Action: model.AuditActionDiffWebhookFailed, Label: "Diff Webhook Failed", Category: "diff_webhook"},
		{Action: model.AuditActionDiffWebhookAutoFired, Label: "Diff Webhook Auto-Fired", Category: "diff_webhook"},

		// F322 (M21 Phase D R2, anti-pattern 48 residual pattern closure —
		// handler-side Action orphans): five more model.Action* constants
		// emitted from handler code (not middleware classifier) but never
		// registered pre-F322 — a residual of the same M20 F302 pattern
		// F319 documented itself as closing. The R1 review of F319 caught
		// the overclaim: "closes the last M20 defer pool residual on the
		// Action dimension" was factually incomplete because an anti-
		// pattern 48 universal scan of `model.Action[A-Z]` across
		// apps/api/internal/handler/ + apps/api/internal/service/ found
		// five more orphans — three ActionTenant* from
		// handler/webhook_clerk.go (Clerk lifecycle webhook: Created L274 /
		// Updated L250 / Deleted L153) and two ActionLLMKey* from
		// handler/settings_llm.go (BYOK provisioning: Set L257 / Rotated
		// L259). F322 registers all five here so the UI filter dropdown
		// can surface any audit_logs row the tenant lifecycle webhook or
		// LLM key provisioning handler produces, and the F271 direction-1
		// parity assertion is expanded in the same wave (audit_test.go
		// F322 expectedEmit additions) so a future removal from either
		// side trips CI. See F276 factuality lineage on overclaim risk.
		//
		// Note (F333, M22-2 close): the two dead model constants this
		// note previously tracked as M22+ wire-up-or-delete candidates
		// (an LLM key "cleared" verb and a subscription "renewed" verb,
		// both defined in model/audit.go with zero emit sites) were
		// DELETED in F333 rather than wired up. Survey evidence:
		// settings_llm.go's Update handler treats a nil EncryptedAPIKey
		// as preserve-existing (no key-clearance business path exists),
		// and webhook_lemonsqueezy.go's event switch handles created/
		// updated/cancelled/resumed/expired/paused/unpaused with no
		// renewal event. Per the F280 discipline (registering a
		// UI-selectable action with no emit site would violate the F271
		// direction-1 parity), delete was the correct close; a wave
		// that adds either business path must re-introduce the
		// constant, its emit site, and the registry entry here in the
		// same change.
		{Action: model.ActionTenantCreated, Label: "Tenant Created", Category: "tenant"},
		{Action: model.ActionTenantUpdated, Label: "Tenant Updated", Category: "tenant"},
		{Action: model.ActionTenantDeleted, Label: "Tenant Deleted", Category: "tenant"},
		{Action: model.ActionLLMKeySet, Label: "LLM Key Set", Category: "llm"},
		{Action: model.ActionLLMKeyRotated, Label: "LLM Key Rotated", Category: "llm"},
	}
}

// ActionInfo represents information about an audit action
type ActionInfo struct {
	Action   string `json:"action"`
	Label    string `json:"label"`
	Category string `json:"category"`
}

// GetAvailableResourceTypes returns list of available resource types for filtering
func (s *AuditService) GetAvailableResourceTypes() []ResourceTypeInfo {
	return []ResourceTypeInfo{
		// F298 (M20-1 Phase D R1, anti-pattern 58 dual-list parity
		// completeness — Category structural symmetry): every entry
		// below carries a non-empty Category string so the F281
		// direction-2 meta-test can enforce Category presence in
		// lockstep with the F271 (Action dimension) direction-2
		// contract. Pre-F298 ResourceTypeInfo carried only Type +
		// Label — a structural asymmetry with ActionInfo whose
		// Category field the F271 direction-2 loop asserts non-empty.
		// Categories mirror the Action-side groupings so the two
		// dropdowns render with matching taxonomy in the UI.
		{Type: model.ResourceUser, Label: "User", Category: "user"},
		{Type: model.ResourceTenant, Label: "Tenant", Category: "tenant"},
		{Type: model.ResourceProject, Label: "Project", Category: "project"},
		{Type: model.ResourceSBOM, Label: "SBOM", Category: "sbom"},
		{Type: model.ResourceVEX, Label: "VEX", Category: "vex"},
		{Type: model.ResourceAPIKey, Label: "API Key", Category: "apikey"},
		{Type: model.ResourceSubscription, Label: "Subscription", Category: "subscription"},
		{Type: model.ResourceSettings, Label: "Settings", Category: "settings"},

		// F282 (M19-3 Phase D R1, anti-pattern 58 horizontal replication
		// — Resource dimension): the three registry rows below previously
		// carried inline "report" / "analytics" / "integration" string
		// literals with no model.Resource* const backing. Pre-F282 a
		// rename on the middleware side (e.g. changing an /integrations
		// return to a new symbol) would have silently desynced from
		// these dropdown rows because the compiler could not link them.
		// F282 adds the missing model.Resource{Report,Analytics,
		// Integration} constants and swaps the registry entries to
		// symbol references so a typo at either the emit site or the
		// registry side fails at build time. F281 (sibling meta-test)
		// pins the parity so future drift fails CI, not silently.
		{Type: model.ResourceReport, Label: "Report", Category: "report"},
		{Type: model.ResourceAnalytics, Label: "Analytics", Category: "analytics"},
		{Type: model.ResourceIntegration, Label: "Integration", Category: "integration"},

		// F282 (M19-3 Phase D R1) new tenant-branch resource types.
		// Pre-F282 the middleware's /search, /dashboard, /mcp, /cli
		// branches emitted resource_type as inline "search" /
		// "dashboard" / "mcp" / "cli" literals but the service-layer
		// registry never listed them at all — a silent gap where a
		// forensic operator filtering audit_logs by resource_type
		// could not select rows the middleware produced. Registering
		// them here closes the F281 direction-1 parity gap for these
		// four families in the same wave that closes the direction-2
		// literal-only entries above.
		{Type: model.ResourceSearch, Label: "Search", Category: "search"},
		{Type: model.ResourceDashboard, Label: "Dashboard", Category: "dashboard"},
		{Type: model.ResourceMCP, Label: "MCP", Category: "mcp"},
		{Type: model.ResourceCLI, Label: "CLI", Category: "cli"},

		// F282 (M19-3 Phase D R1) LLM config resource type. The
		// constant existed pre-F282 (model.ResourceLLMConfig, backing
		// the handler/settings_llm.go audit emit at h.auditRepo.Log)
		// but was never registered in the dropdown, so an admin
		// filtering audit_logs.resource_type by "llm_config" via the
		// UI could not select the LLM key set / rotated / cleared
		// audit rows. Adding the entry here closes the silent
		// registry gap and completes the F281 direction-1 parity for
		// the handler-emitted (rather than middleware-emitted) LLM
		// resource family.
		{Type: model.ResourceLLMConfig, Label: "LLM Config", Category: "llm"},

		// F188 (M13 Phase D round 3): per-family resource types the
		// hoisted audit middleware now distinguishes for
		// /projects/:id/<child> routes. Previously every nested route
		// was logged as the bare "project" type, collapsing the
		// (resource_type, resource_id) join key for the evidence layer.
		{Type: model.ResourceCRAReport, Label: "CRA Report", Category: "cra_report"},
		{Type: model.ResourceVEXDraft, Label: "VEX Draft", Category: "vex_draft"},
		{Type: model.ResourceTriage, Label: "Triage", Category: "triage"},
		{Type: model.ResourceScan, Label: "Scan", Category: "scan"},
		{Type: model.ResourceCompliance, Label: "Compliance", Category: "compliance"},
		{Type: model.ResourceNotification, Label: "Notification", Category: "notification"},
		{Type: model.ResourceDiff, Label: "Diff", Category: "diff"},
		{Type: model.ResourceSSVC, Label: "SSVC", Category: "ssvc"},
		{Type: model.ResourceMETI, Label: "METI", Category: "meti"},
		{Type: model.ResourceLicensePolicy, Label: "License Policy", Category: "license_policy"},
		{Type: model.ResourceEvidencePack, Label: "Evidence Pack", Category: "evidence_pack"},
		{Type: model.ResourceChecklist, Label: "Checklist", Category: "checklist"},
		{Type: model.ResourceVisualization, Label: "Visualization", Category: "visualization"},
		{Type: model.ResourcePublicLink, Label: "Public Link", Category: "public_link"},
		{Type: model.ResourceKEV, Label: "KEV", Category: "kev"},
		{Type: model.ResourceEOL, Label: "EOL", Category: "eol"},
		{Type: model.ResourceVulnerability, Label: "Vulnerability", Category: "vulnerability"},

		// F217 (M14 Phase D round 1 fix): issue-tracker ticket
		// resource_type. Pre-F217 ticket rows were misfiled under
		// resource_type="vulnerability" with resource_id pointing at
		// a ticket UUID, breaking forensic joins onto either table.
		{Type: model.ResourceTicket, Label: "Ticket", Category: "ticket"},

		// F296 (M20-1 Phase D R1, anti-pattern 58 3-axis full coverage
		// — handler-side ResourceType* orphan closure): the three rows
		// below register the newly-promoted model.Resource{METIAssessment,
		// SBOMDiff,DiffWebhook} constants (F296 promoted them from
		// three pre-M20 orphan `ResourceType*` package-locals in
		// handler/meti.go, service/diff_summary/diff_summary.go, and
		// model/diff_webhook.go). Registering them here closes the F281
		// direction-1 parity gap on the third axis — the handler-side
		// emit dimension the pre-M20 F286 scope-limitation block in
		// audit_test.go documented as a known gap. Category values
		// mirror the sibling model.Resource{METI,Diff} entries above
		// so the UI dropdown groups them alongside the domain family
		// they belong to.
		{Type: model.ResourceMETIAssessment, Label: "METI Assessment", Category: "meti"},
		{Type: model.ResourceSBOMDiff, Label: "SBOM Diff", Category: "diff"},
		{Type: model.ResourceDiffWebhook, Label: "Diff Webhook", Category: "integration"},
	}
}

// ResourceTypeInfo represents information about a resource type.
//
// F298 (M20-1 Phase D R1, anti-pattern 58 dual-list parity completeness
// — Category structural symmetry): the Category field is added to
// mirror the ActionInfo structure so the F281 (M19-3) direction-2
// meta-test can assert Category non-emptiness in lockstep with the
// F271 (M18-1) Action-dimension contract. Pre-F298 ResourceTypeInfo
// carried only Type + Label, which was a structural asymmetry with
// ActionInfo (Action + Label + Category) — the audit dropdown in the
// UI could render Action rows grouped by Category but Resource rows
// could not, and the F281 direction-2 loop could not enforce Category
// presence at CI time. F298 closes that asymmetry: every entry in
// GetAvailableResourceTypes must now carry a non-empty Category the
// UI can key its dropdown grouping off, and any future entry that
// forgets to supply one fails the F281 direction-2 assertion.
type ResourceTypeInfo struct {
	Type     string `json:"type"`
	Label    string `json:"label"`
	Category string `json:"category"`
}
