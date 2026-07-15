package cra

// runner.go (Wave M2-3, issue #31) — CRA report generation runner.
//
// This file orchestrates the AI-assisted CRA Article 14 report drafting
// pipeline end-to-end:
//
//   1. Stage 1 (short read tx via TxManager.RunRead): resolves the
//      per-tenant LLM provider (BYOK decrypt) + the authoritative cve_id
//      for the supplied vulnerability_id (F12) + the source vex_draft
//      (either the caller-supplied id or the latest approved row for the
//      (project, cve) pair) + advisory_excerpts + reachability_results.
//      Commits before Stage 2 so the Postgres connection is released
//      during the slow upstream LLM call (F19).
//   2. Stage 2 (no tx, bounded ctx): builds the system + user prompt
//      from the source VEX draft + advisory + reachability evidence,
//      calls Provider.Complete with a configurable timeout (default
//      DefaultLLMTimeout seconds, overridable via SBOMHUB_LLM_TIMEOUT_SECONDS
//      — shared with M1 triage to keep operator-facing knobs unified),
//      parses the structured JSON response into a craLLMFields struct.
//      AI-disabled providers skip this stage entirely.
//   3. Stage 3 (short write tx via TxManager.RunWrite): re-validates the
//      authoritative cve_id (TOCTOU — the vulnerabilities row could have
//      been replaced while the LLM was running), renders the template
//      with the merged deterministic + AI fields, writes the llm_calls
//      audit row, the cra_reports row, and the `cra_report_ai_generated`
//      audit log entry. All atomic; an audit failure rolls back the
//      cra_report INSERT per the M1 F5 contract (§8.5 audit-or-nothing).
//
// AI-disabled path (M1 F4 pattern):
//   When the resolver returns *llm.DisabledProvider the runner skips
//   Stage 2 and renders the template directly from deterministic fields.
//   It then writes a cra_reports row with provider="disabled", model=""
//   and evidence=[{"kind":"ai_disabled", "source":"system"}], plus an
//   audit row with action `cra_report_ai_disabled` so compliance
//   reviewers can distinguish "AI rendered something" from "AI was not
//   called at all" — same discipline M1 triage established for
//   vex_drafts.
//
// M1 fix patterns applied (see runner_test.go for the regression
// coverage):
//   F1   tenant_llm_config RLS  ← TxManager binds SET LOCAL automatically
//   F2   per-tenant provider     ← ProviderResolver closure (Stage 1)
//   F4   AI-disabled draft path  ← runAIDisabled + cra_report_ai_disabled audit
//   F5   audit-or-nothing        ← writeAudit returns error inside Stage 3 tx
//   F7/F8/F9 cross-project source vex_draft scope ← Stage 1 ProjectID check
//   F10  generic error body      ← sentinel errors with no tenant-specific data
//   F12  cve_id server validate  ← resolveAuthoritativeCVEID (Stage 1 + Stage 3)
//   F13  redact LLM provider err ← llm.RedactProviderError on Stage 2 failure
//   F19  connection-pool hygiene ← 2-stage tx + bounded LLM ctx
//   F25  fan-out cap N/A         ← 1 request = 1 (vuln,type,lang) → 1 draft
//   F26  pagination N/A          ← runner is single-row writer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/advisorytext"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

// ----------------------------------------------------------------------------
// Audit / purpose constants
// ----------------------------------------------------------------------------

const (
	// The audit_logs.resource_type wire value for every cra_reports
	// lifecycle event lives in package model as model.ResourceCRAReport
	// (the anti-pattern 58 dual-list system single source of truth). This
	// package used to declare a sibling `ResourceTypeCRAReport = "cra_report"`
	// duplicate; M20 R2 F302 promoted the 3 use sites to model.ResourceCRAReport
	// and removed the orphan constant so a future rename of the wire value
	// cannot desync silently through a stale package-local copy.

	// AuditActionCRAReportAIGenerated is the audit_logs.action emitted
	// when the LLM successfully drafted a CRA report.
	AuditActionCRAReportAIGenerated = "cra_report_ai_generated"

	// AuditActionCRAReportAIDisabled is the audit_logs.action emitted
	// when the runner persists a placeholder draft because no provider
	// is configured for this tenant (M1 F4 analogue for CRA).
	AuditActionCRAReportAIDisabled = "cra_report_ai_disabled"

	// LLMCallPurposeCRADraft tags llm_calls rows produced by this runner.
	// Matches the SBOMHUB CLAUDE.md "LLM Provider Policy" purpose list
	// (vex_triage / cra_draft / meti_prefill / embed).
	LLMCallPurposeCRADraft = "cra_draft"
)

// ----------------------------------------------------------------------------
// Sentinel errors
// ----------------------------------------------------------------------------

var (
	// ErrCVEIDMismatch mirrors triage.ErrCVEIDMismatch (M1 F12): the
	// caller-supplied CVEID disagrees with the cve_id stored on the
	// vulnerabilities row identified by VulnerabilityID. The handler maps
	// this to a generic 400 ("CRA report target invalid") that does not
	// disclose which of vulnerability_id / cve_id was at fault.
	ErrCVEIDMismatch = errors.New("cra: cve_id does not match vulnerability_id")

	// ErrSourceVEXDraftNotFound is returned when the caller supplies a
	// SourceVEXDraftID that cannot be loaded for this tenant. Mapped to
	// 404 by the handler.
	ErrSourceVEXDraftNotFound = errors.New("cra: source vex_draft not found")

	// ErrSourceVEXDraftCrossProject is returned when a caller-supplied
	// (or auto-resolved) source vex_draft belongs to a project that does
	// NOT match RunInput.ProjectID. Cross-project linkage would let a
	// caller smuggle evidence from project A into a CRA report scoped to
	// project B (M1 F7/F8/F9 scope-check pattern adapted to CRA). Mapped
	// to 404 by the handler — same generic body as the unknown-source
	// case so the response cannot be used as an oracle.
	ErrSourceVEXDraftCrossProject = errors.New("cra: source vex_draft does not belong to the target project")

	// ErrSourceVEXDraftCVEMismatch is returned when a caller-supplied
	// (or auto-resolved) source vex_draft carries a non-empty CVE id
	// that does NOT match RunInput.CVEID. Without this guard a caller
	// could draft a CRA report for one CVE while attaching an approved
	// VEX draft for a DIFFERENT CVE in the same project — the rendered
	// regulatory submission would then claim evidence ("approved triage
	// for CVE-Y") that does not in fact cover the CVE being reported
	// (CVE-X). Mapped to 409 by the handler so the operator must either
	// approve a VEX draft for the correct CVE or correct the request.
	// M3 may relax this with a validated alias mapping; until then the
	// rule is "strict reject" (M2 Codex review #F30, was warn-only).
	ErrSourceVEXDraftCVEMismatch = errors.New("cra: source vex_draft cve_id does not match input cve_id")

	// ErrNoApprovedVEXDraft is returned when SourceVEXDraftID is nil and
	// no approved vex_draft exists for the (project, cve) pair. The
	// handler maps this to 409 (the operator must approve a VEX draft
	// first) so the UI surfaces a "triage this CVE first" call-to-action
	// rather than letting an unsourced CRA report land.
	// TODO(cra): 409 vs 422 is an open UX preference — verified
	// 2026-07-02 (M24-3 F359): handler/cra_reports.go mapCRARunnerError
	// maps this sentinel to 409 today. Either way the CRA report cannot
	// be drafted without an approved triage decision per
	// PRODUCT_REBOOT_PLAN §7.2, so only the status code is in question.
	ErrNoApprovedVEXDraft = errors.New("cra: no approved vex_draft available for this (project, cve)")
)

// ----------------------------------------------------------------------------
// Persistence interfaces
// ----------------------------------------------------------------------------
//
// The runner is wired against narrow interfaces rather than concrete
// repository types so that runner_test.go can supply in-memory fakes
// without spinning up Postgres. *repository.VEXDraftsRepository /
// *repository.AdvisoryExcerptsRepository / *repository.ReachabilityResultsRepository
// / *repository.CRAReportsRepository / *repository.LLMCallsRepository
// / *repository.VulnerabilityRepository all satisfy these interfaces
// by construction (see signatures in apps/api/internal/repository/).

// VEXDraftReader is the subset of *repository.VEXDraftsRepository the
// runner needs. ListByProject is consulted only when SourceVEXDraftID
// is nil so the runner can auto-pick the latest approved draft.
type VEXDraftReader interface {
	Get(ctx context.Context, tenantID, draftID uuid.UUID) (*repository.VEXDraft, error)
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.VEXDraftListFilter) ([]repository.VEXDraft, error)
}

// AdvisoryExcerptReader is the subset of *repository.AdvisoryExcerptsRepository
// the runner needs.
type AdvisoryExcerptReader interface {
	GetByCVE(ctx context.Context, tenantID uuid.UUID, cveID string) ([]repository.AdvisoryExcerpt, error)
}

// ReachabilityReader is the subset of *repository.ReachabilityResultsRepository
// the runner needs.
type ReachabilityReader interface {
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.ReachabilityResultListFilter) ([]repository.ReachabilityResult, error)
}

// CRAReportWriter is the subset of *repository.CRAReportsRepository
// the runner needs.
type CRAReportWriter interface {
	Insert(ctx context.Context, c *repository.CRAReport) error
}

// LLMCallWriter is the subset of *repository.LLMCallsRepository the
// runner needs. Reused across M1 triage and M2 CRA so the audit table
// has a single shape; the cra_report_id column on llm_calls is what
// joins this row back to the cra_reports row.
type LLMCallWriter interface {
	Insert(ctx context.Context, c *repository.LLMCall) error
}

// VulnerabilityCVELookup mirrors triage.VulnerabilityCVELookup so the
// production wiring can pass *repository.VulnerabilityRepository to
// both runners. F12 server-side cve_id re-resolve.
type VulnerabilityCVELookup interface {
	GetCVEIDByID(ctx context.Context, vulnerabilityID uuid.UUID) (string, error)
}

// AuditLogWriter mirrors triage.AuditLogWriter; satisfied by
// *repository.AuditRepository.
type AuditLogWriter interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// ProviderResolver returns the LLM provider to use for one CRA report
// run. M1 F2 closure pattern: the runner consults this on every Run()
// so /settings/llm BYOK config drives the call, not the server-startup
// env default. Returning (nil, nil) is treated as "use defaultProvider";
// if defaultProvider is also nil the runner falls back to
// *llm.DisabledProvider and triggers the AI-disabled draft path (F4).
type ProviderResolver func(ctx context.Context, tenantID uuid.UUID) (llm.Provider, error)

// TxManager mirrors triage.TxManager so production wiring can pass the
// same *triage.DBTxManager instance to both runners (structural Go
// interface match — no shared type required, no import cycle risk).
// PassthroughTxManager below is the unit-test default; production
// callers MUST pass a *triage.DBTxManager so the F19 DB-pool fix
// actually takes effect for CRA generation too.
type TxManager interface {
	RunRead(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error
	RunWrite(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error
}

// PassthroughTxManager is the no-op TxManager used by tests and as the
// runner default when RunnerConfig.TxManager is nil. Matches
// triage.PassthroughTxManager semantics.
type PassthroughTxManager struct{}

// RunRead implements TxManager.
func (PassthroughTxManager) RunRead(ctx context.Context, _ uuid.UUID, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// RunWrite implements TxManager.
func (PassthroughTxManager) RunWrite(ctx context.Context, _ uuid.UUID, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// ----------------------------------------------------------------------------
// Runner
// ----------------------------------------------------------------------------

// Runner orchestrates CRA report drafting. See file header for the
// Stage 1 / Stage 2 / Stage 3 contract.
type Runner struct {
	vexDrafts           VEXDraftReader
	advisoryExcerpts    AdvisoryExcerptReader
	reachabilityResults ReachabilityReader
	craReports          CRAReportWriter
	llmCalls            LLMCallWriter
	vulnCVE             VulnerabilityCVELookup
	audit               AuditLogWriter

	defaultProvider  llm.Provider
	providerResolver ProviderResolver

	txManager  TxManager
	llmTimeout time.Duration
	clock      func() time.Time

	// generatedBy is the {{.GeneratedBy}} string the templates render in
	// the legal-notice footer. Defaults to "SBOMHub/cra" if unset;
	// production wiring should pass something more descriptive such as
	// "SBOMHub vX.Y.Z (LLM: anthropic/claude-opus-4-7)".
	generatedBy string
}

// RunnerConfig is the constructor input for NewRunner.
type RunnerConfig struct {
	VEXDrafts           VEXDraftReader
	AdvisoryExcerpts    AdvisoryExcerptReader
	ReachabilityResults ReachabilityReader
	CRAReports          CRAReportWriter
	LLMCalls            LLMCallWriter
	VulnerabilityCVE    VulnerabilityCVELookup
	Audit               AuditLogWriter

	Provider         llm.Provider
	ProviderResolver ProviderResolver

	TxManager   TxManager
	LLMTimeout  time.Duration
	Clock       func() time.Time
	GeneratedBy string
}

// NewRunner constructs a Runner. Required fields (VEXDrafts /
// AdvisoryExcerpts / ReachabilityResults / CRAReports / LLMCalls /
// Audit / Provider) are validated; nil values panic at construction so
// misconfiguration surfaces immediately instead of at first call —
// matches triage.NewRunner discipline.
func NewRunner(cfg RunnerConfig) *Runner {
	if cfg.VEXDrafts == nil {
		panic("cra.NewRunner: VEXDrafts is required")
	}
	if cfg.AdvisoryExcerpts == nil {
		panic("cra.NewRunner: AdvisoryExcerpts is required")
	}
	if cfg.ReachabilityResults == nil {
		panic("cra.NewRunner: ReachabilityResults is required")
	}
	if cfg.CRAReports == nil {
		panic("cra.NewRunner: CRAReports is required")
	}
	if cfg.LLMCalls == nil {
		panic("cra.NewRunner: LLMCalls is required")
	}
	if cfg.Audit == nil {
		panic("cra.NewRunner: Audit is required")
	}
	if cfg.Provider == nil {
		panic("cra.NewRunner: Provider is required")
	}

	txMgr := cfg.TxManager
	if txMgr == nil {
		// Tests + legacy wiring fall through to no-op; production wires
		// *triage.DBTxManager explicitly via cmd/server/main.go (Wave M2-4).
		txMgr = PassthroughTxManager{}
	}
	llmTimeout := cfg.LLMTimeout
	if llmTimeout <= 0 {
		// Reuses the M1 triage timeout so operator-facing tuning via
		// SBOMHUB_LLM_TIMEOUT_SECONDS works for both runners uniformly.
		llmTimeout = triage.LLMTimeoutFromEnv()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	generatedBy := cfg.GeneratedBy
	if generatedBy == "" {
		generatedBy = "SBOMHub/cra"
	}

	return &Runner{
		vexDrafts:           cfg.VEXDrafts,
		advisoryExcerpts:    cfg.AdvisoryExcerpts,
		reachabilityResults: cfg.ReachabilityResults,
		craReports:          cfg.CRAReports,
		llmCalls:            cfg.LLMCalls,
		vulnCVE:             cfg.VulnerabilityCVE,
		audit:               cfg.Audit,
		defaultProvider:     cfg.Provider,
		providerResolver:    cfg.ProviderResolver,
		txManager:           txMgr,
		llmTimeout:          llmTimeout,
		clock:               clock,
		generatedBy:         generatedBy,
	}
}

// ----------------------------------------------------------------------------
// Request / response DTOs
// ----------------------------------------------------------------------------

// RunInput is the request payload for Run.
//
// TenantID / ProjectID / VulnerabilityID / CVEID are required. The
// runner validates VulnerabilityID + CVEID server-side (F12) so a
// caller cannot pair an in-scope vulnerability_id with a stranger CVE.
//
// SourceVEXDraftID is optional: when nil the runner picks the latest
// approved vex_drafts row for (project, cve). Cross-project source
// drafts are rejected (F7/F8/F9 scope-check pattern adapted to CRA).
//
// ReportType + Lang select the template; both are validated against
// the templates package's SupportedReportTypes / SupportedLangs lists.
//
// The trailing Reporter / Contact / Awareness fields are pass-through
// to the template data and are NOT generated by the LLM (compliance
// data is operator-supplied and must not be hallucinated).
type RunInput struct {
	TenantID         uuid.UUID
	ProjectID        uuid.UUID
	VulnerabilityID  uuid.UUID
	CVEID            string
	SourceVEXDraftID *uuid.UUID
	ReportType       ReportType
	Lang             Lang
	UserID           *uuid.UUID

	// Pass-through fields rendered verbatim by the template.
	ProductName    string
	ProductVersion string
	VendorName     string
	ReporterName   string
	ReporterRole   string
	ContactEmail   string
	ContactPhone   string
	AwarenessTime  string // ISO-8601 UTC, start of the 24h / 72h clock
	ReportID       string // internal tracking ID

	IPAddress string
	UserAgent string
}

// RunResult is what Run returns to its caller.
type RunResult struct {
	Report    *repository.CRAReport
	LLMCallID *uuid.UUID // nil on the AI-disabled path (no LLM call was made)
	// AIDisabled reports whether the runner skipped the LLM call because
	// no provider was configured (BYOK absent). The handler / CLI uses
	// this flag to surface the "APIキー未設定" hint.
	AIDisabled bool
}

// ----------------------------------------------------------------------------
// LLM JSON contract
// ----------------------------------------------------------------------------

// craLLMFields is the JSON shape the LLM emits. Every field is optional
// from the parser's perspective: the template's `{{if}}` guards render
// placeholders for missing values. We deliberately do NOT require the
// LLM to produce all fields for every report type — the 24h early
// warning legitimately leaves Final-Report-only fields like
// PermanentRemediation empty.
type craLLMFields struct {
	VulnerabilitySummary    string   `json:"vulnerability_summary,omitempty"`
	VulnerabilityDetail     string   `json:"vulnerability_detail,omitempty"`
	RootCause               string   `json:"root_cause,omitempty"`
	ExploitationStatus      string   `json:"exploitation_status,omitempty"`
	ExploitationEvidence    string   `json:"exploitation_evidence,omitempty"`
	PreliminaryImpactScope  string   `json:"preliminary_impact_scope,omitempty"`
	ImmediateMitigations    string   `json:"immediate_mitigations,omitempty"`
	MitigationSteps         []string `json:"mitigation_steps,omitempty"`
	RemediationPlan         string   `json:"remediation_plan,omitempty"`
	PermanentRemediation    string   `json:"permanent_remediation,omitempty"`
	PreventionMeasures      []string `json:"prevention_measures,omitempty"`
	UserNotificationSummary string   `json:"user_notification_summary,omitempty"`
}

// ----------------------------------------------------------------------------
// Run — the public entry point
// ----------------------------------------------------------------------------

// Run executes one CRA report drafting cycle for the supplied
// (vulnerability, report_type, lang) tuple. See the file header for
// the 2-stage architecture and F-series fix patterns.
//
// Error contract:
//   - input validation failures              → returns a plain error
//     (caller maps to 400)
//   - ErrCVEIDMismatch                       → caller maps to 400 (F12)
//   - ErrSourceVEXDraftNotFound              → caller maps to 404
//   - ErrSourceVEXDraftCrossProject          → caller maps to 404 (F7/F8/F9)
//   - ErrNoApprovedVEXDraft                  → caller maps to 409
//   - ErrUnknownTemplate                     → caller maps to 400
//   - non-Disabled llm.Provider failure      → wrapped (caller maps 5xx)
//   - LLM bounded-context timeout            → wrapped (caller maps 5xx)
//   - persistence failures                    → wrapped (caller maps 500)
func (r *Runner) Run(ctx context.Context, in RunInput) (*RunResult, error) {
	// ---- Input validation (cheap, before any DB / LLM I/O) ----
	if in.TenantID == uuid.Nil {
		return nil, errors.New("cra.Run: tenant_id is required")
	}
	if in.ProjectID == uuid.Nil {
		return nil, errors.New("cra.Run: project_id is required")
	}
	if in.VulnerabilityID == uuid.Nil {
		return nil, errors.New("cra.Run: vulnerability_id is required")
	}
	if in.CVEID == "" {
		return nil, errors.New("cra.Run: cve_id is required")
	}
	if !isValidReportType(in.ReportType) {
		return nil, fmt.Errorf("cra.Run: report_type %q is not in the allowlist", string(in.ReportType))
	}
	if !isValidLang(in.Lang) {
		return nil, fmt.Errorf("cra.Run: lang %q is not in the allowlist", string(in.Lang))
	}

	// Parse the operator-attested awareness instant ONCE (M34-A / F423)
	// so both the LLM path and the AI-disabled path persist the same
	// *time.Time on cra_reports.awareness_time. A malformed value fails
	// the whole drafting cycle here, before any DB / LLM I/O, so a
	// mistyped clock start surfaces loudly instead of silently dropping.
	awarenessTime, err := parseAwarenessTime(in.AwarenessTime)
	if err != nil {
		return nil, err
	}

	// ----------------------------------------------------------------
	// Stage 1 — short read tx.
	// ----------------------------------------------------------------
	var (
		provider   llm.Provider
		sourceVEX  *repository.VEXDraft
		advisories []repository.AdvisoryExcerpt
		reachRows  []repository.ReachabilityResult
	)
	if err := r.txManager.RunRead(ctx, in.TenantID, func(ctx context.Context) error {
		var err error
		// F2: per-tenant provider.
		provider, err = r.resolveProvider(ctx, in.TenantID)
		if err != nil {
			return fmt.Errorf("cra.Run: resolve provider: %w", err)
		}

		// F12: server-side cve_id re-resolve.
		resolvedCVE, err := r.resolveAuthoritativeCVEID(ctx, in.VulnerabilityID, in.CVEID)
		if err != nil {
			return err
		}
		in.CVEID = resolvedCVE

		// Resolve source VEX draft (caller-supplied or latest approved).
		sourceVEX, err = r.resolveSourceVEXDraft(ctx, in)
		if err != nil {
			return err
		}

		// AI-disabled providers skip advisory / reachability fetches —
		// runAIDisabled handles its own persistence inside Stage 3.
		if _, isDisabled := provider.(*llm.DisabledProvider); isDisabled {
			return nil
		}

		advisories, err = r.advisoryExcerpts.GetByCVE(ctx, in.TenantID, in.CVEID)
		if err != nil {
			return fmt.Errorf("cra.Run: load advisory excerpts: %w", err)
		}
		// M43 Phase D R2 finding 2: drop content-free negative-tombstone
		// rows at the load edge, before either consumer (buildCRAUserPrompt
		// and buildEvidence) sees them. See dropContentFreeExcerpts for the
		// tombstone provenance.
		advisories = dropContentFreeExcerpts(advisories)
		reachRows, err = r.reachabilityResults.ListByProject(ctx, in.TenantID, in.ProjectID, repository.ReachabilityResultListFilter{
			CVEID: in.CVEID,
		})
		if err != nil {
			return fmt.Errorf("cra.Run: load reachability results: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// AI-disabled fork — skips Stage 2 (no LLM call).
	if _, ok := provider.(*llm.DisabledProvider); ok {
		return r.runAIDisabled(ctx, in, provider, sourceVEX, awarenessTime)
	}

	// ----------------------------------------------------------------
	// Stage 2 — LLM call with bounded context. NO Postgres tx is held.
	// ----------------------------------------------------------------
	systemPrompt := buildCRASystemPrompt(in.ReportType, in.Lang)
	userPrompt := buildCRAUserPrompt(in, sourceVEX, advisories, reachRows)

	completeReq := llm.CompleteRequest{
		System:      systemPrompt,
		Messages:    []llm.Message{{Role: llm.RoleUser, Content: userPrompt}},
		Temperature: 0.0,
		JSONMode:    true,
		TenantID:    in.TenantID.String(),
		Purpose:     LLMCallPurposeCRADraft,
	}
	if in.UserID != nil {
		completeReq.UserID = in.UserID.String()
	}

	llmCtx, cancel := context.WithTimeout(ctx, r.llmTimeout)
	defer cancel()
	llmStart := r.clock()
	resp, llmErr := provider.Complete(llmCtx, completeReq)
	llmDuration := r.clock().Sub(llmStart)

	// Build the llm_calls record up-front so success and failure paths
	// share a single source of truth.
	llmCallID := uuid.New()
	callRecord := &repository.LLMCall{
		ID:              llmCallID,
		TenantID:        in.TenantID,
		UserID:          in.UserID,
		Purpose:         LLMCallPurposeCRADraft,
		Provider:        provider.Name(),
		Model:           provider.Model(),
		PromptHash:      sha256Hex(userPrompt),
		PromptPreview:   preview(userPrompt, 256),
		DurationMs:      int(llmDuration.Milliseconds()),
		TriageTargetCVE: in.CVEID,
	}
	if resp != nil {
		callRecord.ResponseHash = sha256Hex(resp.Content)
		callRecord.ResponsePreview = preview(resp.Content, 256)
		callRecord.ResponseBody = resp.Content
		callRecord.InputTokens = resp.InputTokens
		callRecord.OutputTokens = resp.OutputTokens
		callRecord.CostUSD = resp.CostUSD
		callRecord.FinishReason = resp.FinishReason
	}
	if llmErr != nil {
		// F13: redact API-key-shaped material before persistence + return.
		llmErr = llm.RedactProviderError(llmErr)
		callRecord.ErrorMessage = llmErr.Error()

		// Persist the failed llm_calls record in its own short write tx
		// so operators can trace failed cycles even when no cra_report
		// landed. Matches triage Run() pattern.
		if persistErr := r.txManager.RunWrite(ctx, in.TenantID, func(ctx context.Context) error {
			return r.llmCalls.Insert(ctx, callRecord)
		}); persistErr != nil {
			slog.Warn("cra.Run: persist llm_calls failed",
				"tenant_id", in.TenantID, "cve_id", in.CVEID, "error", persistErr)
		}
		return nil, fmt.Errorf("cra.Run: llm provider failed: %w", llmErr)
	}

	// Parse LLM JSON. On parse failure we degrade gracefully to empty
	// AI fields (the template renders placeholders) — a CRA draft with
	// the deterministic VEX context is still useful to the operator,
	// and we record the parse error in the evidence trail so the audit
	// log makes the degradation visible.
	aiFields, parseErr := parseCRALLMResponse(resp.Content)
	if parseErr != nil {
		slog.Warn("cra.Run: LLM JSON parse failed; falling back to template placeholders",
			"tenant_id", in.TenantID, "cve_id", in.CVEID, "error", parseErr)
		aiFields = &craLLMFields{}
	}

	// Build template data + render.
	data := buildTemplateData(in, sourceVEX, advisories, reachRows, aiFields, r.generatedBy, r.clock(), provider)
	rendered, err := Render(in.ReportType, in.Lang, data)
	if err != nil {
		return nil, fmt.Errorf("cra.Run: render template: %w", err)
	}

	// Build evidence array. The cra_reports schema requires at least
	// one entry; the source vex_draft pointer is always present (Stage 1
	// guarantees a non-nil sourceVEX) so the array is never empty even
	// when advisory / reachability data is missing.
	evidence := buildEvidence(sourceVEX, advisories, reachRows, in.ReportType, in.Lang, parseErr)
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("cra.Run: marshal evidence: %w", err)
	}

	sourceVEXID := sourceVEX.ID
	llmFK := llmCallID
	reportID := uuid.New()
	report := &repository.CRAReport{
		ID:               reportID,
		TenantID:         in.TenantID,
		ProjectID:        in.ProjectID,
		VulnerabilityID:  in.VulnerabilityID,
		CVEID:            in.CVEID,
		ReportType:       string(in.ReportType),
		Lang:             string(in.Lang),
		State:            "draft",
		DraftText:        rendered,
		Provider:         provider.Name(),
		Model:            provider.Model(),
		PromptHash:       callRecord.PromptHash,
		ResponseHash:     callRecord.ResponseHash,
		Evidence:         json.RawMessage(evidenceJSON),
		SourceVEXDraftID: &sourceVEXID,
		LLMCallID:        &llmFK,
		Decision:         "pending",
		CreatedBy:        in.UserID,
		AwarenessTime:    awarenessTime,
	}
	// Link llm_calls.cra_report_id so the audit table joins back to the
	// CRA report row this call produced.
	callRecord.CRAReportID = &reportID

	// ----------------------------------------------------------------
	// Stage 3 — short write tx with TOCTOU re-validate + audit-or-nothing.
	// ----------------------------------------------------------------
	if err := r.txManager.RunWrite(ctx, in.TenantID, func(ctx context.Context) error {
		// TOCTOU: re-resolve the cve_id from the vulnerabilities row.
		// If the vulnerability disappeared (resolver returns sql.ErrNoRows)
		// or its cve_id changed during Stage 2, surface the error so we
		// never persist a CRA report pointing at a stale target.
		resolvedCVE, err := r.resolveAuthoritativeCVEID(ctx, in.VulnerabilityID, in.CVEID)
		if err != nil {
			return err
		}
		if resolvedCVE != in.CVEID {
			// Defense in depth: resolveAuthoritativeCVEID already returns
			// ErrCVEIDMismatch for the disagreement case, but in case it
			// ever returns a different resolved id (e.g. CVE rename), we
			// reject explicitly here too.
			return fmt.Errorf("cra.Run: %w (stage 3 revalidation)", ErrCVEIDMismatch)
		}

		// Persist llm_calls first so the audit row exists even when the
		// downstream INSERT trips a constraint. Matches triage F19 Stage 3
		// ordering: llm_calls.Insert failure is slog.Warn (we keep the
		// cra_report landing) — only cra_reports.Insert and the audit row
		// are load-bearing for the rollback contract.
		if err := r.llmCalls.Insert(ctx, callRecord); err != nil {
			slog.Warn("cra.Run: persist llm_calls failed (continuing — cra_report still inserts)",
				"tenant_id", in.TenantID, "cve_id", in.CVEID, "error", err)
		}

		// Persist cra_reports.
		if err := r.craReports.Insert(ctx, report); err != nil {
			return fmt.Errorf("cra.Run: persist cra_report: %w", err)
		}

		// F5: audit-or-nothing. writeAudit returns the error so a failure
		// rolls back the cra_report INSERT above.
		if err := r.writeAudit(ctx, in, report.ID, AuditActionCRAReportAIGenerated, map[string]interface{}{
			"cve_id":              in.CVEID,
			"vulnerability_id":    in.VulnerabilityID.String(),
			"project_id":          in.ProjectID.String(),
			"report_type":         string(in.ReportType),
			"lang":                string(in.Lang),
			"source_vex_draft_id": sourceVEX.ID.String(),
			"llm_provider":        provider.Name(),
			"llm_model":           provider.Model(),
			"llm_call_id":         llmCallID.String(),
			"ai_disabled":         false,
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	llmFKReturn := llmCallID
	return &RunResult{
		Report:    report,
		LLMCallID: &llmFKReturn,
	}, nil
}

// ----------------------------------------------------------------------------
// AI-disabled path (F4)
// ----------------------------------------------------------------------------

// runAIDisabled implements the F4 analogue for CRA: when no provider is
// configured for the tenant, the runner still renders the template using
// the deterministic VEX context (no LLM fields are populated) and
// persists a cra_reports row tagged with provider="disabled" plus a
// distinct `cra_report_ai_disabled` audit action.
//
// No LLM call is attempted and no llm_calls row is written — there was
// no call to record. The handler returns the report to the CLI which
// surfaces the "APIキー未設定" hint without inventing a counter-only
// fallback path.
//
// Wrapped in a single TxManager.RunWrite so the AI-disabled path gets
// the same connection-pool hygiene as the LLM-enabled path. TOCTOU
// re-validate (cve_id re-resolve) runs at the top of the write tx.
func (r *Runner) runAIDisabled(ctx context.Context, in RunInput, provider llm.Provider, sourceVEX *repository.VEXDraft, awarenessTime *time.Time) (*RunResult, error) {
	reason := "BYOK key not configured"
	if dp, ok := provider.(*llm.DisabledProvider); ok && dp.Reason != "" {
		reason = dp.Reason
	}

	// Build template data with empty AI fields — the template's `{{if}}`
	// guards render placeholders. Deterministic fields (ProductName,
	// CVEID, ReporterName, etc.) still flow through from RunInput.
	data := buildTemplateData(in, sourceVEX, nil, nil, &craLLMFields{}, r.generatedBy, r.clock(), provider)
	rendered, err := Render(in.ReportType, in.Lang, data)
	if err != nil {
		return nil, fmt.Errorf("cra.runAIDisabled: render template: %w", err)
	}

	// Synthetic evidence — schema requires ≥1 entry, and ai_disabled is
	// the marker the UI / compliance auditor uses to distinguish "AI
	// rendered nothing" from "AI rendered a real draft".
	evidence := []evidenceEntry{
		{
			Kind:        "ai_disabled",
			Source:      "system",
			Description: "AI CRA drafting skipped: " + reason,
			Note:        "BYOK key not configured for this tenant; draft auto-created with template placeholders",
		},
		{
			Kind: "vex_draft",
			Ref:  sourceVEX.ID.String(),
		},
		{
			Kind: "template",
			Ref:  string(in.ReportType) + "_" + string(in.Lang),
		},
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("cra.runAIDisabled: marshal evidence: %w", err)
	}

	sourceVEXID := sourceVEX.ID
	reportID := uuid.New()
	report := &repository.CRAReport{
		ID:               reportID,
		TenantID:         in.TenantID,
		ProjectID:        in.ProjectID,
		VulnerabilityID:  in.VulnerabilityID,
		CVEID:            in.CVEID,
		ReportType:       string(in.ReportType),
		Lang:             string(in.Lang),
		State:            "draft",
		DraftText:        rendered,
		Provider:         provider.Name(), // "disabled"
		Model:            provider.Model(),
		Evidence:         json.RawMessage(evidenceJSON),
		SourceVEXDraftID: &sourceVEXID,
		Decision:         "pending",
		CreatedBy:        in.UserID,
		AwarenessTime:    awarenessTime,
	}

	if err := r.txManager.RunWrite(ctx, in.TenantID, func(ctx context.Context) error {
		// TOCTOU re-validate (cve_id) — same defence as the LLM-enabled path.
		resolvedCVE, err := r.resolveAuthoritativeCVEID(ctx, in.VulnerabilityID, in.CVEID)
		if err != nil {
			return err
		}
		if resolvedCVE != in.CVEID {
			return fmt.Errorf("cra.runAIDisabled: %w (stage 3 revalidation)", ErrCVEIDMismatch)
		}

		if err := r.craReports.Insert(ctx, report); err != nil {
			return fmt.Errorf("cra.runAIDisabled: persist cra_report: %w", err)
		}

		if err := r.writeAudit(ctx, in, report.ID, AuditActionCRAReportAIDisabled, map[string]interface{}{
			"cve_id":              in.CVEID,
			"vulnerability_id":    in.VulnerabilityID.String(),
			"project_id":          in.ProjectID.String(),
			"report_type":         string(in.ReportType),
			"lang":                string(in.Lang),
			"source_vex_draft_id": sourceVEX.ID.String(),
			"reason":              reason,
			"provider":            provider.Name(),
			"ai_disabled":         true,
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &RunResult{
		Report:     report,
		AIDisabled: true,
	}, nil
}

// ----------------------------------------------------------------------------
// Resolver helpers
// ----------------------------------------------------------------------------

// resolveProvider mirrors triage.Runner.resolveProvider (F2):
// resolver → defaultProvider → DisabledProvider.
func (r *Runner) resolveProvider(ctx context.Context, tenantID uuid.UUID) (llm.Provider, error) {
	if r.providerResolver != nil {
		p, err := r.providerResolver(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
	}
	if r.defaultProvider != nil {
		return r.defaultProvider, nil
	}
	return &llm.DisabledProvider{Reason: "no LLM provider configured (set tenant_llm_config or SBOMHUB_LLM_PROVIDER env)"}, nil
}

// resolveAuthoritativeCVEID re-resolves the canonical cve_id for the
// supplied vulnerability_id and rejects requests where the caller's
// CVEID disagrees (F12). Fail-closed when the lookup is not wired so a
// production misconfig surfaces loudly as a 400 instead of letting an
// unscoped draft persist.
func (r *Runner) resolveAuthoritativeCVEID(ctx context.Context, vulnID uuid.UUID, suppliedCVEID string) (string, error) {
	if r.vulnCVE == nil {
		return "", errors.New("cra.Run: vulnerability cve lookup is required (no VulnerabilityCVELookup wired)")
	}
	resolved, err := r.vulnCVE.GetCVEIDByID(ctx, vulnID)
	if err != nil {
		// Caller maps this to 5xx via mapRunnerError's default branch.
		// We deliberately do NOT fold this into ErrCVEIDMismatch: the
		// failure mode is server-side (data integrity / TOCTOU), not
		// caller-supplied.
		return "", fmt.Errorf("cra.Run: resolve cve_id for vulnerability_id: %w", err)
	}
	if resolved == "" {
		return "", fmt.Errorf("cra.Run: vulnerability_id %s has empty cve_id (corrupt vulnerabilities row)", vulnID)
	}
	if resolved != suppliedCVEID {
		// F10: do NOT include the resolved CVE id in the error message —
		// the handler maps this to a generic 400 body, and we log the
		// precise mismatch via slog.Warn at the handler boundary.
		return "", fmt.Errorf("cra.Run: %w", ErrCVEIDMismatch)
	}
	return resolved, nil
}

// resolveSourceVEXDraft loads the source vex_draft for this CRA report.
//
// When SourceVEXDraftID is set the runner loads that specific draft and
// verifies it belongs to RunInput.ProjectID (F7/F8/F9 cross-project
// rejection — without this check a caller could smuggle approved
// evidence from project A into a CRA report scoped to project B,
// silently inheriting that triage decision into a different product's
// regulatory submission).
//
// When SourceVEXDraftID is nil the runner picks the most recent
// approved vex_drafts row for (project, cve). Empty result returns
// ErrNoApprovedVEXDraft so the handler can prompt the operator to
// triage the CVE first.
func (r *Runner) resolveSourceVEXDraft(ctx context.Context, in RunInput) (*repository.VEXDraft, error) {
	if in.SourceVEXDraftID != nil && *in.SourceVEXDraftID != uuid.Nil {
		draft, err := r.vexDrafts.Get(ctx, in.TenantID, *in.SourceVEXDraftID)
		if err != nil {
			return nil, fmt.Errorf("cra.Run: load source vex_draft: %w", err)
		}
		if draft == nil {
			return nil, fmt.Errorf("cra.Run: %w", ErrSourceVEXDraftNotFound)
		}
		// F7/F8/F9 scope check: the source draft MUST belong to the same
		// project as the CRA report we are drafting. Cross-project
		// linkage would let a caller smuggle in evidence from a sister
		// project (tenants are unchanged by the load — RLS already
		// guarantees the tenant boundary — but vex_drafts only filters
		// on (tenant, id) in Get(), so project membership is the runner's
		// to enforce).
		if draft.ProjectID != in.ProjectID {
			return nil, fmt.Errorf("cra.Run: %w", ErrSourceVEXDraftCrossProject)
		}
		// Hard reject when the source draft's CVE id disagrees with the
		// CRA report's CVE id. The earlier (warn-only) version let a
		// caller draft a CRA report for CVE-X while attaching an
		// approved VEX draft for CVE-Y in the same project — the
		// rendered submission would then claim evidence ("approved
		// triage for CVE-Y") that does not in fact cover CVE-X. We log
		// the precise mismatch via slog at the warn level (so probe
		// alarms still fire) and surface the generic
		// ErrSourceVEXDraftCVEMismatch sentinel to the handler.
		// TODO(cra): a validated CVE alias mapping could relax this —
		// verified 2026-07-02 (M24-3 F359): no alias resolver exists
		// anywhere in service/cra or service/triage, and PM has not
		// signed off on a mapping shape, so the rule stays strict
		// reject (M2 Codex review #F30) unconditionally.
		if draft.CVEID != "" && draft.CVEID != in.CVEID {
			slog.Warn("cra.Run: source vex_draft cve_id does not match input cve_id (rejected)",
				"tenant_id", in.TenantID, "draft_cve", draft.CVEID, "input_cve", in.CVEID)
			return nil, fmt.Errorf("cra.Run: %w", ErrSourceVEXDraftCVEMismatch)
		}
		return draft, nil
	}

	// Auto-pick: list approved drafts for (project, cve) and take the
	// most recent. ListByProject orders by created_at DESC so index 0
	// is the latest. We do NOT widen the search beyond approved status
	// — drafting a CRA report from a pending / rejected VEX would
	// violate PRODUCT_REBOOT_PLAN §7.2 ("approved な vex_drafts から取得").
	drafts, err := r.vexDrafts.ListByProject(ctx, in.TenantID, in.ProjectID, repository.VEXDraftListFilter{
		CVEID:    in.CVEID,
		Decision: triage.DecisionApproved,
		Limit:    1,
	})
	if err != nil {
		return nil, fmt.Errorf("cra.Run: list approved vex_drafts: %w", err)
	}
	if len(drafts) == 0 {
		return nil, fmt.Errorf("cra.Run: %w", ErrNoApprovedVEXDraft)
	}
	picked := drafts[0]
	return &picked, nil
}

// ----------------------------------------------------------------------------
// Audit helper (F5)
// ----------------------------------------------------------------------------

// writeAudit emits one audit_logs row. Failures are returned so the
// surrounding Stage 3 tx rolls back the cra_reports INSERT — F5
// audit-or-nothing contract.
func (r *Runner) writeAudit(ctx context.Context, in RunInput, resourceID uuid.UUID, action string, details map[string]interface{}) error {
	rid := resourceID
	tenantID := in.TenantID
	input := &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       in.UserID,
		Action:       action,
		ResourceType: model.ResourceCRAReport,
		ResourceID:   &rid,
		Details:      details,
		IPAddress:    in.IPAddress,
		UserAgent:    in.UserAgent,
	}
	if err := r.audit.Log(ctx, input); err != nil {
		slog.Warn("cra.writeAudit: audit log failed",
			"tenant_id", in.TenantID, "action", action, "resource_id", resourceID, "error", err)
		return fmt.Errorf("cra.writeAudit: persist audit_logs row (action=%s): %w", action, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Prompt construction
// ----------------------------------------------------------------------------

// buildCRASystemPrompt returns the system prompt steering the LLM
// toward the strict JSON contract craLLMFields expects.
//
// The prompt is intentionally bilingual-aware: it tells the model to
// write field values in the requested target language so the rendered
// template body reads naturally for Japanese authorities (ENISA / EU
// CSIRT prefer the operator's national language for the 24h window).
//
// Unknown-ReportType posture (F359, M24-3): in the production Run()
// path this function only ever sees registered report types — Run()
// rejects anything outside SupportedReportTypes() via isValidReportType
// BEFORE Stage 2 reaches this builder, and Render() independently
// rejects an unknown (reportType, lang) pair with ErrUnknownTemplate.
// The default arm below therefore exists for the drift case those
// gates do not cover: a NEW ReportType const registered in
// SupportedReportTypes() without this switch being extended (or a
// future direct caller bypassing Run's validation). Pre-F359 the
// switch had no default arm, so that drift silently dropped the
// report-type sentence from the prompt; now the raw wire value is
// embedded loudly in the prompt text instead, where golden/prompt
// review and the F359 unit test can see it.
func buildCRASystemPrompt(reportType ReportType, lang Lang) string {
	var b strings.Builder
	b.WriteString("You are SBOMHub's CRA (EU Cyber Resilience Act) report drafting assistant. ")
	b.WriteString("You produce structured JSON for an EU Article 14 ")
	switch reportType {
	case ReportTypeEarlyWarning:
		b.WriteString("24-hour early warning report. ")
	case ReportTypeDetailedNotification:
		b.WriteString("72-hour detailed notification report. ")
	case ReportTypeFinalReport:
		b.WriteString("post-remediation final report. ")
	default:
		// Loud fallback (F359): name the unregistered type verbatim so
		// a truncated prompt can never masquerade as a registered one.
		fmt.Fprintf(&b, "report of the unregistered type %q. ", string(reportType))
	}
	if lang == LangJA {
		b.WriteString("Write all field values in Japanese (日本語). ")
	} else {
		b.WriteString("Write all field values in English. ")
	}

	b.WriteString(`

You MUST reply with a single JSON object on the schema below. Do not
include prose outside the JSON. Do not invent facts — every field must
be grounded in the supplied advisory excerpt, reachability evidence,
or approved VEX draft context.

{
  "vulnerability_summary": "one-sentence layman summary suitable for the report header",
  "vulnerability_detail": "longer technical description (detailed/final reports)",
  "root_cause": "root-cause analysis (detailed/final reports)",
  "exploitation_status": "actively exploited | PoC available | no known exploitation",
  "exploitation_evidence": "citation / quote supporting the status",
  "preliminary_impact_scope": "early-warning narrative on impact scope",
  "immediate_mitigations": "24h-window quick mitigations operators can apply now",
  "mitigation_steps": ["numbered mitigation step 1", "step 2"],
  "remediation_plan": "72h-window remediation plan narrative",
  "permanent_remediation": "final-report permanent remediation narrative",
  "prevention_measures": ["recurrence prevention measure 1", "measure 2"],
  "user_notification_summary": "final-report user-notification summary"
}

Leave fields empty (omit or "") when the report type does not call for
them (e.g. PermanentRemediation is final-report only). Never claim
exploitation that the supplied evidence does not support.`)

	return b.String()
}

// buildCRAUserPrompt assembles the user-turn body from the approved VEX
// draft + advisory excerpts + reachability rows. We render the
// supporting evidence as compact JSON so the LLM can reason about it
// without us pretty-printing every field.
func buildCRAUserPrompt(in RunInput, sourceVEX *repository.VEXDraft, advisories []repository.AdvisoryExcerpt, reach []repository.ReachabilityResult) string {
	var b strings.Builder
	b.WriteString("CVE: ")
	b.WriteString(in.CVEID)
	b.WriteString("\nReport type: ")
	b.WriteString(string(in.ReportType))
	b.WriteString("\nLanguage: ")
	b.WriteString(string(in.Lang))
	if in.ProductName != "" {
		b.WriteString("\nProduct: ")
		b.WriteString(in.ProductName)
		if in.ProductVersion != "" {
			b.WriteString(" ")
			b.WriteString(in.ProductVersion)
		}
	}
	b.WriteString("\n\nApproved VEX draft context:\n")
	if sourceVEX != nil {
		fmt.Fprintf(&b, "  id=%s\n  state=%s\n  justification=%s\n",
			sourceVEX.ID, sourceVEX.State, sourceVEX.Justification)
		if sourceVEX.Detail != "" {
			fmt.Fprintf(&b, "  detail=%s\n", advisorytext.Truncate(sourceVEX.Detail, 600))
		}
		if sourceVEX.Confidence != nil {
			fmt.Fprintf(&b, "  confidence=%.2f\n", *sourceVEX.Confidence)
		}
	} else {
		b.WriteString("  (none — defensive; resolver should have rejected this)\n")
	}

	b.WriteString("\nAdvisory excerpts:\n")
	if len(advisories) == 0 {
		b.WriteString("  (none — advisory parser has no data for this CVE)\n")
	} else {
		for i, a := range advisories {
			fmt.Fprintf(&b, "  [%d] id=%s source=%s\n", i, a.ID, a.Source)
			if a.RawExcerpt != "" {
				fmt.Fprintf(&b, "      excerpt: %s\n", advisorytext.Truncate(a.RawExcerpt, 600))
			}
			if len(a.VulnFuncs) > 0 && string(a.VulnFuncs) != "[]" {
				// M43 Phase D R2 finding 2: same whole-element budget as
				// the triage prompt — an OSV / Go vulndb union of hundreds
				// of symbols must not bloat the CRA prompt either.
				fmt.Fprintf(&b, "      vuln_funcs: %s\n", advisorytext.RenderVulnFuncs(a.VulnFuncs, advisorytext.VulnFuncsPromptBudget))
			}
		}
	}

	b.WriteString("\nReachability results (per component):\n")
	if len(reach) == 0 {
		b.WriteString("  (none — reachability analyser has no data for this (project, cve))\n")
	} else {
		for i, rr := range reach {
			conf := "n/a"
			if rr.Confidence != nil {
				conf = fmt.Sprintf("%.2f", *rr.Confidence)
			}
			fmt.Fprintf(&b, "  [%d] id=%s component=%s ecosystem=%s status=%s confidence=%s\n",
				i, rr.ID, rr.ComponentID, rr.Ecosystem, rr.Status, conf)
		}
	}

	b.WriteString("\nProduce the CRA report JSON now (target language: ")
	if in.Lang == LangJA {
		b.WriteString("Japanese")
	} else {
		b.WriteString("English")
	}
	b.WriteString(").")
	return b.String()
}

// parseCRALLMResponse parses the LLM's JSON response into a craLLMFields
// struct. Failure returns (nil, err) — caller is expected to fall back
// to empty fields rather than aborting the draft (the template renders
// placeholders for missing values).
func parseCRALLMResponse(jsonStr string) (*craLLMFields, error) {
	if jsonStr == "" {
		return nil, errors.New("empty LLM response")
	}
	var f craLLMFields
	if err := json.Unmarshal([]byte(jsonStr), &f); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}
	return &f, nil
}

// ----------------------------------------------------------------------------
// Template data construction
// ----------------------------------------------------------------------------

// buildTemplateData merges deterministic fields (from RunInput +
// sourceVEX) with LLM-generated fields (from aiFields) into the
// CRATemplateData struct the template engine consumes.
//
// Discipline:
//   - LLM fields take precedence ONLY for the natural-language slots
//     templates leave to the model (vulnerability_summary, root_cause,
//     mitigation narrative, etc.).
//   - Operator-supplied identifiers (ProductName, ReporterName,
//     ContactEmail, etc.) ALWAYS come from RunInput so the LLM cannot
//     hallucinate compliance identifiers.
//   - SubmittedAt / GeneratedAt come from the runner clock so the
//     audit trail timestamps are deterministic.
func buildTemplateData(
	in RunInput,
	sourceVEX *repository.VEXDraft,
	advisories []repository.AdvisoryExcerpt,
	reach []repository.ReachabilityResult,
	aiFields *craLLMFields,
	generatedBy string,
	now time.Time,
	provider llm.Provider,
) CRATemplateData {
	// TODO(cra): advisories / reach are deliberately unused in
	// template-data construction — verified 2026-07-02 (M24-3 F359):
	// both feed only the LLM prompt (buildCRAUserPrompt renders them as
	// indexed context rows), never the rendered template. Future
	// expansion may surface advisory pointers (e.g. an NVD link table)
	// or a per-component reachability table in the template body;
	// AffectedComponents stays operator-supplied (M2-4 enrichment)
	// until then.
	_ = advisories
	_ = reach

	data := CRATemplateData{
		ProductName:    in.ProductName,
		ProductVersion: in.ProductVersion,
		VendorName:     in.VendorName,

		CVEID: in.CVEID,

		// AI-generated narrative fields (empty when LLM disabled or
		// JSON parse failed).
		VulnerabilitySummary: aiFields.VulnerabilitySummary,
		VulnerabilityDetail:  aiFields.VulnerabilityDetail,
		RootCause:            aiFields.RootCause,

		ExploitationStatus:   aiFields.ExploitationStatus,
		ExploitationEvidence: aiFields.ExploitationEvidence,

		PreliminaryImpactScope: aiFields.PreliminaryImpactScope,

		ImmediateMitigations: aiFields.ImmediateMitigations,
		MitigationSteps:      aiFields.MitigationSteps,
		RemediationPlan:      aiFields.RemediationPlan,

		PermanentRemediation:    aiFields.PermanentRemediation,
		PreventionMeasures:      aiFields.PreventionMeasures,
		UserNotificationSummary: aiFields.UserNotificationSummary,

		ReporterName: in.ReporterName,
		ReporterRole: in.ReporterRole,
		ContactEmail: in.ContactEmail,
		ContactPhone: in.ContactPhone,

		SubmittedAt:   now.UTC().Format(time.RFC3339),
		AwarenessTime: in.AwarenessTime,
		ReportID:      in.ReportID,

		GeneratedBy: generatedBy + " (LLM: " + provider.Name() + "/" + provider.Model() + ")",
		GeneratedAt: now.UTC().Format(time.RFC3339),
	}

	// CycloneDX VEX 1.5 justification → CRA report field bridge.
	// When the source VEX draft carries a justification, we surface it
	// as a short prepended note on ImmediateMitigations so the operator
	// sees the triage rationale directly in the 24h report. The LLM
	// fields stay authoritative; this is a deterministic fallback when
	// the LLM left ImmediateMitigations empty.
	if sourceVEX != nil && data.ImmediateMitigations == "" {
		data.ImmediateMitigations = vexJustificationToCRAImmediateMitigations(sourceVEX, in.Lang)
	}

	return data
}

// vexJustificationToCRAImmediateMitigations is the deterministic
// fallback used when the LLM leaves ImmediateMitigations empty. It
// translates the VEX 1.5 justification + state into a brief operator-
// facing note.
func vexJustificationToCRAImmediateMitigations(d *repository.VEXDraft, lang Lang) string {
	if d == nil {
		return ""
	}
	// Lookup tables keyed by justification.
	jaJust := map[string]string{
		"code_not_present":                 "脆弱なコードは本製品に含まれていない (VEX 判定: code_not_present)",
		"code_not_reachable":               "脆弱なコードは含まれるが到達不可能な経路にあり、悪用は確認されていない (VEX 判定: code_not_reachable)",
		"requires_configuration":           "特定の構成設定下でのみ顕在化する (VEX 判定: requires_configuration)",
		"requires_dependency":              "特定の依存ライブラリ構成下でのみ顕在化する (VEX 判定: requires_dependency)",
		"requires_environment":             "特定の実行環境下でのみ顕在化する (VEX 判定: requires_environment)",
		"protected_by_compiler":            "コンパイラ層の保護により悪用を抑止 (VEX 判定: protected_by_compiler)",
		"protected_at_perimeter":           "境界防御により悪用を抑止 (VEX 判定: protected_at_perimeter)",
		"protected_at_runtime":             "実行時保護により悪用を抑止 (VEX 判定: protected_at_runtime)",
		"inline_mitigations_already_exist": "本製品内に組み込みの緩和策が既に存在する (VEX 判定: inline_mitigations_already_exist)",
	}
	enJust := map[string]string{
		"code_not_present":                 "Vulnerable code is not present in this product (VEX: code_not_present)",
		"code_not_reachable":               "Vulnerable code is present but not reachable (VEX: code_not_reachable)",
		"requires_configuration":           "Only exploitable under specific configurations (VEX: requires_configuration)",
		"requires_dependency":              "Only exploitable under specific dependency profiles (VEX: requires_dependency)",
		"requires_environment":             "Only exploitable under specific runtime environments (VEX: requires_environment)",
		"protected_by_compiler":            "Compiler-level protections mitigate exploitation (VEX: protected_by_compiler)",
		"protected_at_perimeter":           "Perimeter defences mitigate exploitation (VEX: protected_at_perimeter)",
		"protected_at_runtime":             "Runtime protections mitigate exploitation (VEX: protected_at_runtime)",
		"inline_mitigations_already_exist": "Inline mitigations already exist within the product (VEX: inline_mitigations_already_exist)",
	}
	table := enJust
	if lang == LangJA {
		table = jaJust
	}
	if note, ok := table[d.Justification]; ok {
		return note
	}
	// Unknown / empty justification — fall back to the verbatim Detail
	// field on the VEX draft (operator wrote that during triage approval).
	return d.Detail
}

// ----------------------------------------------------------------------------
// Evidence construction
// ----------------------------------------------------------------------------

// evidenceEntry is the {kind, ref, ...} shape persisted in
// cra_reports.evidence. Kept compact so the JSONB column stays small
// and the UI can render the citation chain without extra joins.
type evidenceEntry struct {
	Kind        string `json:"kind"`
	Ref         string `json:"ref,omitempty"`
	Source      string `json:"source,omitempty"`
	Description string `json:"description,omitempty"`
	Note        string `json:"note,omitempty"`
}

// buildEvidence assembles the cra_reports.evidence JSONB array.
//
// The array always carries at least:
//   - one "vex_draft" pointer (source)
//   - one "template" pointer (which template was used)
//
// plus optional "advisory_excerpt" and "reachability_result" entries.
// On LLM JSON parse failure an "llm_rationale" entry with note
// "parse_error" is appended so the audit trail records the degradation.
func buildEvidence(
	sourceVEX *repository.VEXDraft,
	advisories []repository.AdvisoryExcerpt,
	reach []repository.ReachabilityResult,
	reportType ReportType,
	lang Lang,
	llmParseErr error,
) []evidenceEntry {
	entries := make([]evidenceEntry, 0, 4+len(advisories)+len(reach))
	if sourceVEX != nil {
		entries = append(entries, evidenceEntry{
			Kind: "vex_draft",
			Ref:  sourceVEX.ID.String(),
		})
	}
	entries = append(entries, evidenceEntry{
		Kind: "template",
		Ref:  string(reportType) + "_" + string(lang),
	})
	for _, a := range advisories {
		entries = append(entries, evidenceEntry{
			Kind:   "advisory_excerpt",
			Ref:    a.ID.String(),
			Source: a.Source,
		})
	}
	for _, rr := range reach {
		// F11 analogue: include EVERY reachability row touching this
		// vulnerability, not just one per component, so the audit trail
		// captures the full reachability picture.
		entries = append(entries, evidenceEntry{
			Kind:        "reachability_result",
			Ref:         rr.ID.String(),
			Source:      rr.Ecosystem,
			Description: rr.Status,
		})
	}
	if llmParseErr != nil {
		entries = append(entries, evidenceEntry{
			Kind:        "llm_rationale",
			Source:      "llm",
			Description: llmParseErr.Error(),
			Note:        "parse_error",
		})
	}
	return entries
}

// ----------------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------------

func isValidReportType(t ReportType) bool {
	for _, supported := range SupportedReportTypes() {
		if supported == t {
			return true
		}
	}
	return false
}

func isValidLang(l Lang) bool {
	for _, supported := range SupportedLangs() {
		if supported == l {
			return true
		}
	}
	return false
}

// parseAwarenessTime parses the operator-attested awareness instant
// (RunInput.AwarenessTime) into a *time.Time for persistence on
// cra_reports.awareness_time (M34-A / F423). It is called ONCE in Run()
// so both the LLM and the AI-disabled path persist the same value.
//
// Contract:
//   - empty / whitespace-only  → (nil, nil): awareness is optional; a
//     nil column is treated by the read-time deadline computation as
//     not_applicable (no Art.14 clock can start without an attested
//     instant).
//   - non-empty, valid RFC3339 → (&instant, nil), normalised to UTC so
//     the persisted instant is timezone-canonical.
//   - non-empty, malformed     → (nil, error): a mistyped clock start
//     must fail the drafting cycle loudly, not silently drop.
func parseAwarenessTime(raw string) (*time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("cra.Run: awareness_time %q is not a valid RFC3339 timestamp: %w", raw, err)
	}
	u := t.UTC()
	return &u, nil
}

// ----------------------------------------------------------------------------
// Tiny helpers (mirrors triage runner helpers; intentionally duplicated
// rather than imported to keep the cra package free of cross-service
// implementation imports — types stay easier to reason about and we do
// not couple cra's prompt construction to triage's encoding choices).
// ----------------------------------------------------------------------------

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func preview(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// dropContentFreeExcerpts filters out advisory rows that carry no usable
// content: RawExcerpt empty AND every structured array (VulnFuncs /
// AffectedPaths / RequiredConfig / RequiredEnv) empty. Such rows exist by
// design: the M43 OSV vuln_funcs sync (scheduler/cve_sync.go) writes a
// negative TOMBSTONE row (source='osv', vuln_funcs '[]', raw_excerpt NULL)
// for a definitive upstream miss so the freshness window can negative-cache
// it. In the CRA runner a tombstone would otherwise render as a
// content-free advisory line in the LLM prompt AND land as an
// advisory_excerpt entry in the cra_reports.evidence citation chain
// (buildEvidence cites every loaded row) — a compliance artefact must not
// cite a row with nothing in it. Filtering at the load edge covers both
// consumers at once (M43 Phase D R2 finding 2).
//
// The content-free classification itself is advisorytext.ContentFree,
// shared byte-for-byte with the triage runner (M45 Wave 2 C3); only this
// row-type-specific loop stays local because repository.AdvisoryExcerpt
// and triage's AdvisoryExcerptRow differ.
func dropContentFreeExcerpts(advisories []repository.AdvisoryExcerpt) []repository.AdvisoryExcerpt {
	out := make([]repository.AdvisoryExcerpt, 0, len(advisories))
	for _, a := range advisories {
		if advisorytext.ContentFree(a.RawExcerpt, a.VulnFuncs, a.AffectedPaths, a.RequiredConfig, a.RequiredEnv) {
			continue
		}
		out = append(out, a)
	}
	return out
}
