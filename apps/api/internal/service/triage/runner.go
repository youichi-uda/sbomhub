package triage

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
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// ----------------------------------------------------------------------------
// Persistence interfaces (parallel-agent boundary)
// ----------------------------------------------------------------------------
//
// The runner is wired against narrow interfaces rather than the concrete
// repository types because agent A (issue #28) owns the vex_drafts
// repository file in parallel with this PR. The repository types below
// already exist in the repo (advisory_excerpts / reachability_results /
// llm_calls / audit / vex), so the runner can compile against them
// directly. For VexDraft persistence we keep an interface so that:
//
//   - this package builds and tests on its own (mock store in
//     runner_test.go),
//   - agent A's `*repository.VexDraftsRepository` can be plugged in
//     verbatim once it lands (the methods below match the agreed
//     surface from the M1-5 prompt).
//
// ※要確認: method names / parameter order are the agreed contract with
// agent A. If A renames Insert→Create or InsertDecision instead of
// UpdateDecision, the orchestrator should refactor in lock-step.

// VexDraftStore is the persistence contract for vex_drafts that the
// runner depends on. *repository.VEXDraftsRepository satisfies this
// interface by construction (its methods are the four below).
//
// Why an interface rather than the concrete struct: it lets
// runner_test.go supply an in-memory fake (no Postgres) and isolates
// the runner from future repository surface changes.
type VexDraftStore interface {
	Insert(ctx context.Context, draft *repository.VEXDraft) error
	Get(ctx context.Context, tenantID, draftID uuid.UUID) (*repository.VEXDraft, error)
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.VEXDraftListFilter) ([]repository.VEXDraft, error)
	UpdateDecision(ctx context.Context, tenantID, draftID uuid.UUID, update repository.VEXDraftDecisionUpdate) error
}

// AdvisoryExcerptReader is satisfied by *repository.AdvisoryExcerptsRepository.
// Kept as an interface so the unit test can supply a fixture without
// spinning up Postgres.
type AdvisoryExcerptReader interface {
	GetByCVE(ctx context.Context, tenantID uuid.UUID, cveID string) ([]AdvisoryExcerptRow, error)
}

// ReachabilityReader is satisfied by *repository.ReachabilityResultsRepository.
type ReachabilityReader interface {
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter ReachabilityFilter) ([]ReachabilityRow, error)
}

// LLMCallWriter is satisfied by *repository.LLMCallsRepository.
type LLMCallWriter interface {
	Insert(ctx context.Context, call *LLMCallRecord) error
}

// AuditLogWriter is satisfied by *repository.AuditRepository (via its
// Log method, wrapped by the runner to translate to this narrower
// surface).
type AuditLogWriter interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// VEXStatementSync is the subset of *service.VEXService the runner
// touches when an AI draft is approved: it must mirror the confirmed
// decision into the existing vex_statements table so that
// CycloneDX export, MCP read access, and the public link surfaces all
// see the human-approved verdict without a new code path.
//
// ※要確認: the prompt allows either calling VEXService.CreateStatement
// or writing directly to VEXRepository. The interface below is the
// service-level shape, which keeps validation rules (status allowlist,
// duplicate-detection) in one place.
type VEXStatementSync interface {
	CreateStatement(ctx context.Context, input VEXStatementSyncInput) error
}

// ProviderResolver returns the LLM provider to use for one triage run.
// M1 Codex review #F2: the runner consults this on every Run() so that
// /settings/llm BYOK config (tenant_llm_config) actually drives the call
// rather than the server-startup env default.
//
// Implementations are typically:
//
//	func(ctx, tenantID) {
//	    cfg, err := tenantLLMConfigRepo.Get(ctx, tenantID)
//	    if errors.Is(err, ErrTenantLLMConfigNotFound) || !cfg.HasAPIKey() {
//	        return defaultProvider, nil // env-configured fallback
//	    }
//	    plaintext, _ := llm.Decrypt(cfg.EncryptedAPIKey, masterKey)
//	    return llm.NewProviderFromConfig(cfg.Provider, cfg.Model, string(plaintext))
//	}
//
// The resolver MUST run inside the request-scoped TenantTx so the
// tenant_llm_config SELECT obeys RLS. Returning (nil, nil) is treated as
// "no provider available" and falls back to the runner's defaultProvider;
// if that is also nil the runner uses *llm.DisabledProvider which
// triggers the AI-disabled draft path (#F4).
type ProviderResolver func(ctx context.Context, tenantID uuid.UUID) (llm.Provider, error)

// ComponentVulnerabilityResolver resolves (tenant, project, vulnerability)
// → []component_id. M1 Codex review #F3: the CLI cannot supply
// component_id from /vulnerabilities (which has no projection of the
// component join), so the server resolves it. A zero-length result
// means "this vulnerability does not affect any component in the
// tenant's project" → runner returns ErrVulnerabilityNotInTenant.
//
// Satisfied by *repository.ComponentRepository via
// ListIDsByVulnerability.
type ComponentVulnerabilityResolver interface {
	ListIDsByVulnerability(ctx context.Context, tenantID, projectID, vulnerabilityID uuid.UUID) ([]uuid.UUID, error)
}

// VulnerabilityCVELookup returns the authoritative cve_id for a
// vulnerabilities.id row. M1 Codex review #F12: RunInput accepts both
// VulnerabilityID and CVEID from the request — the former gets scoped
// against the (tenant, project) graph via ComponentVulnerabilityResolver
// (#F3 / #F6), but CVEID was previously trusted blindly. Without a
// server-side cross-check a caller could pair a valid VulnerabilityID
// with an arbitrary CVEID and have the runner fetch advisory_excerpts /
// reachability_results for the stranger CVE, then persist a draft whose
// vulnerability_id and evidence point at different vulnerabilities.
// This lookup closes that gap.
//
// Satisfied by *repository.VulnerabilityRepository via GetCVEIDByID.
// Returns sql.ErrNoRows when the vulnerabilities row does not exist
// (the runner treats that as an internal data-integrity error since
// componentVulns has already vouched for tenant scope by the time the
// lookup fires).
type VulnerabilityCVELookup interface {
	GetCVEIDByID(ctx context.Context, vulnerabilityID uuid.UUID) (string, error)
}

// ----------------------------------------------------------------------------
// Pass-through DTOs
// ----------------------------------------------------------------------------
//
// The DTOs below let the runner depend on interfaces rather than on
// concrete repository structs (which would create an import cycle once
// agent A's repository imports this package for its own helpers). Each
// concrete repository row is wrapped in a *Row DTO by a thin adapter
// declared in adapters.go (see end of this file).

// AdvisoryExcerptRow is the runner-facing view of one
// advisory_excerpts row.
type AdvisoryExcerptRow struct {
	ID             uuid.UUID
	CVEID          string
	Source         string
	VulnFuncs      json.RawMessage
	AffectedPaths  json.RawMessage
	RequiredConfig json.RawMessage
	RequiredEnv    json.RawMessage
	RawExcerpt     string
}

// ReachabilityFilter narrows ReachabilityReader.ListByProject. Empty
// fields mean "do not filter".
type ReachabilityFilter struct {
	CVEID       string
	ComponentID *uuid.UUID
	Status      string
}

// ReachabilityRow is the runner-facing view of one reachability_results
// row.
type ReachabilityRow struct {
	ID          uuid.UUID
	ComponentID uuid.UUID
	CVEID       string
	Ecosystem   string
	Status      string
	Confidence  *float64
	Evidence    json.RawMessage
}

// LLMCallRecord is the runner-facing view of one llm_calls row.
// Mirrors agent X's repository.LLMCall (Wave M1-1) but kept narrow.
type LLMCallRecord struct {
	ID                      uuid.UUID
	TenantID                uuid.UUID
	UserID                  *uuid.UUID
	Purpose                 string
	Provider                string
	Model                   string
	PromptHash              string
	PromptPreview           string
	ResponseHash            string
	ResponsePreview         string
	ResponseBody            string
	InputTokens             int
	OutputTokens            int
	CostUSD                 float64
	DurationMs              int
	FinishReason            string
	ErrorMessage            string
	TriageTargetCVE         string
	TriageTargetComponentID *uuid.UUID
}

// VEXStatementSyncInput is the payload the runner hands to
// VEXStatementSync.CreateStatement when a draft is approved.
type VEXStatementSyncInput struct {
	ProjectID       uuid.UUID
	VulnerabilityID uuid.UUID
	ComponentID     *uuid.UUID
	Status          model.VEXStatus
	Justification   model.VEXJustification
	ActionStatement string
	ImpactStatement string
	CreatedBy       string
}

// ----------------------------------------------------------------------------
// Audit constants
// ----------------------------------------------------------------------------

// Audit action constants for the vex_drafts lifecycle.
// PRODUCT_REBOOT_PLAN.md §8.5: "承認者、 変更前後、 時刻を監査ログに残す".
const (
	AuditActionVexDraftAIGenerated = "vex_draft_ai_generated"
	AuditActionVexDraftApproved    = "vex_draft_approved"
	AuditActionVexDraftEdited      = "vex_draft_edited"
	AuditActionVexDraftRejected    = "vex_draft_rejected"
	AuditActionVexDraftReanalysed  = "vex_draft_reanalysed"

	// ResourceTypeVexDraft is the audit_logs.resource_type for any
	// vex_draft-related row.
	ResourceTypeVexDraft = "vex_draft"
)

// LLMCallPurposeVexTriage tags llm_calls rows produced by this runner.
const LLMCallPurposeVexTriage = "vex_triage"

// AuditActionVexDraftAIDisabled is the audit_logs.action emitted when the
// runner persists an under_investigation draft because BYOK is not
// configured (no tenant_llm_config + no env default). M1 Codex review #F4:
// the operator-side audit trail MUST distinguish "AI rendered an
// under_investigation verdict" (vex_draft_ai_generated) from "AI was not
// even called because no provider is configured" (vex_draft_ai_disabled).
const AuditActionVexDraftAIDisabled = "vex_draft_ai_disabled"

// ErrVulnerabilityNotInTenant is returned by Run when component_id is not
// supplied AND the ComponentVulnerabilityResolver reports no matching
// (tenant, project, vulnerability) link. The handler translates this to
// 404 "vulnerability not found in tenant scope" (M1 Codex review #F3).
var ErrVulnerabilityNotInTenant = errors.New("triage: vulnerability not found in tenant scope")

// ErrComponentNotInVulnerabilityScope is returned by Run when the caller
// supplies a ComponentID that is NOT among the resolved
// (tenant, project, vulnerability) → []component_id set. M1 Codex review
// #F6: vex_drafts soft-references component_id / vulnerability_id (no
// composite FK), so the runner MUST cross-check the caller-supplied id
// against the server-resolved set or a stranger component from a
// neighbouring project could be persisted into a draft. The handler
// maps this to 404 "component not in vulnerability scope".
var ErrComponentNotInVulnerabilityScope = errors.New("triage: component not in vulnerability scope")

// ErrCVEIDMismatch is returned by Run when the caller-supplied CVEID
// disagrees with the cve_id stored on the vulnerabilities row identified
// by VulnerabilityID. M1 Codex review #F12: previously the runner
// validated VulnerabilityID against the (tenant, project) graph via
// ComponentVulnerabilityResolver but treated CVEID as caller-trusted —
// advisory_excerpts and reachability_results were both fetched by CVEID,
// so an attacker who knew an in-scope vulnerability_id could swap in any
// CVE-XXXX-YYYY string and have the runner build prompts / persist
// drafts using mismatched evidence. The handler maps this to a generic
// 400 ("triage target invalid") that does not disclose which of
// vulnerability_id / cve_id was at fault.
var ErrCVEIDMismatch = errors.New("triage: cve_id does not match vulnerability_id")

// ----------------------------------------------------------------------------
// Runner
// ----------------------------------------------------------------------------

// Runner orchestrates AI VEX triage end-to-end:
//
//  1. read advisory_excerpts + reachability_results for the (project, cve)
//  2. build prompt + call llm.Provider.Complete
//  3. parse the response via guards.ParseLLMResponse
//  4. apply ApplyConfidenceThreshold + ValidateEvidence (guards.go)
//  5. INSERT vex_drafts + llm_calls + audit_logs (vex_draft_ai_generated)
//
// All persistence runs against the caller's context, which is expected
// to be inside a TenantTx (see middleware/tx.go) so RLS GUC is bound.
type Runner struct {
	drafts         VexDraftStore
	advisories     AdvisoryExcerptReader
	reachability   ReachabilityReader
	llmCalls       LLMCallWriter
	audit          AuditLogWriter
	vexSync        VEXStatementSync
	componentVulns ComponentVulnerabilityResolver
	vulnCVE        VulnerabilityCVELookup

	// defaultProvider is the env-configured Provider used when no
	// ProviderResolver is wired or the resolver returns nil. In OSS this
	// is whatever SBOMHUB_LLM_PROVIDER + SBOMHUB_LLM_API_KEY produced at
	// startup (via llm.NewProviderFromEnv). In SaaS — when the
	// ProviderResolver is wired — this is the fallback for tenants
	// without their own BYOK row.
	defaultProvider  llm.Provider
	providerResolver ProviderResolver

	threshold float64
	clock     func() time.Time
}

// RunnerConfig is the constructor input for NewRunner.
type RunnerConfig struct {
	Drafts       VexDraftStore
	Advisories   AdvisoryExcerptReader
	Reachability ReachabilityReader
	LLMCalls     LLMCallWriter
	Audit        AuditLogWriter
	VEXSync      VEXStatementSync

	// Provider is the default (server-startup env) LLM provider used
	// when ProviderResolver is nil or returns nil. Existing tests pass
	// this directly; production wiring passes the env-resolved provider
	// as Provider and the tenant-aware closure as ProviderResolver.
	Provider llm.Provider

	// ProviderResolver lets the runner pick a per-tenant Provider for
	// each Run() request (M1 Codex review #F2). Wired in production
	// from cmd/server/main.go; left nil in unit tests that only need
	// the default provider path.
	ProviderResolver ProviderResolver

	// ComponentVulnerabilities resolves vulnerability_id →
	// []component_id when the caller omits ComponentID (M1 Codex
	// review #F3). Production wiring passes
	// *repository.ComponentRepository; tests may pass a fake.
	ComponentVulnerabilities ComponentVulnerabilityResolver

	// VulnerabilityCVE re-resolves the authoritative cve_id from a
	// vulnerabilities row so the runner can reject mismatched
	// caller-supplied CVEIDs (M1 Codex review #F12). Production wiring
	// passes *repository.VulnerabilityRepository; tests that exercise
	// Run() must pass a fake (UpdateDecision-only tests can leave it nil
	// because the CVE check is gated on the Run() path).
	VulnerabilityCVE VulnerabilityCVELookup

	// Threshold defaults to ConfidenceThresholdFromEnv() when zero.
	Threshold float64
	// Clock is overrideable for tests; defaults to time.Now.
	Clock func() time.Time
}

// NewRunner constructs a Runner. Required fields (Drafts, Advisories,
// Reachability, LLMCalls, Audit, Provider) are validated; nil values
// panic at construction so misconfiguration surfaces immediately
// instead of at first call.
func NewRunner(cfg RunnerConfig) *Runner {
	if cfg.Drafts == nil {
		panic("triage.NewRunner: Drafts is required")
	}
	if cfg.Advisories == nil {
		panic("triage.NewRunner: Advisories is required")
	}
	if cfg.Reachability == nil {
		panic("triage.NewRunner: Reachability is required")
	}
	if cfg.LLMCalls == nil {
		panic("triage.NewRunner: LLMCalls is required")
	}
	if cfg.Audit == nil {
		panic("triage.NewRunner: Audit is required")
	}
	if cfg.Provider == nil {
		panic("triage.NewRunner: Provider is required")
	}
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = ConfidenceThresholdFromEnv()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Runner{
		drafts:           cfg.Drafts,
		advisories:       cfg.Advisories,
		reachability:     cfg.Reachability,
		llmCalls:         cfg.LLMCalls,
		audit:            cfg.Audit,
		vexSync:          cfg.VEXSync,
		componentVulns:   cfg.ComponentVulnerabilities,
		vulnCVE:          cfg.VulnerabilityCVE,
		defaultProvider:  cfg.Provider,
		providerResolver: cfg.ProviderResolver,
		threshold:        threshold,
		clock:            clock,
	}
}

// RunInput is the request payload for Run / Reanalyse.
type RunInput struct {
	TenantID  uuid.UUID
	ProjectID uuid.UUID
	UserID    *uuid.UUID // nil for system-triggered runs

	// Required: one or both of the two targeting fields below must be
	// populated. The runner does NOT iterate "every vuln in the project"
	// in M1 — that fan-out belongs in a caller (CLI `sbomhub triage` or
	// the web UI's bulk action) so a single failure does not stall the
	// whole project.
	VulnerabilityID uuid.UUID
	CVEID           string

	// ComponentID is optional. When supplied the reachability row is
	// scoped to that component; otherwise the runner picks the most
	// pessimistic verdict across components for the CVE.
	ComponentID *uuid.UUID

	// IPAddress / UserAgent are forwarded into audit_logs.
	IPAddress string
	UserAgent string

	// Reanalyse marks the run as a re-triage of an existing draft so
	// the audit row is `vex_draft_reanalysed`. The original draft is
	// not mutated — a fresh row is inserted.
	Reanalyse          bool
	ReanalyseFromDraft *uuid.UUID
}

// RunResult is what Run returns to its caller.
//
// When a single vulnerability fans out across multiple components (M1
// Codex review #F3), the runner persists one draft per (component,
// vuln) pair and returns them in Drafts. Draft remains the first entry
// for backward compatibility with handlers that render a single draft.
type RunResult struct {
	Draft  *repository.VEXDraft   // primary draft (== Drafts[0])
	Drafts []*repository.VEXDraft // all drafts persisted in this run
	Parsed *ParsedDecision
	// LLMCallID is the persisted llm_calls.id so the handler can return
	// it to clients that want to audit. uuid.Nil when AI was disabled.
	LLMCallID uuid.UUID
	// Clamped reports whether ApplyConfidenceThreshold forced the state
	// to under_investigation. Carried out-of-band on the result since
	// agent A's vex_drafts schema does not include the column.
	Clamped bool
	// Threshold records the confidence threshold in effect at draft
	// generation time. Same out-of-band note as Clamped.
	Threshold float64
	// AIDisabled reports whether the runner skipped the LLM call because
	// no provider was configured (BYOK absent) and instead persisted an
	// under_investigation draft. M1 Codex review #F4: the CLI uses this
	// flag to surface the "APIキー未設定" hint without inventing a
	// counter-only fallback path.
	AIDisabled bool
}

// Run executes one triage cycle for (TenantID, ProjectID, CVEID).
//
// Per-request flow (M1 Codex review #F2 / #F3 / #F4):
//
//  1. Resolve the LLM provider via ProviderResolver (tenant_llm_config →
//     decrypt → llm.NewProviderFromConfig). Falls back to defaultProvider
//     (env-resolved at startup), then to DisabledProvider.
//  2. Resolve component_id(s) — caller-supplied ComponentID wins;
//     otherwise the ComponentVulnerabilityResolver enumerates every
//     component in (tenant, project) linked to the vulnerability. Zero
//     matches → ErrVulnerabilityNotInTenant (caller maps to 404).
//  3. If the resolved provider is *llm.DisabledProvider, skip the LLM
//     call and persist one under_investigation draft per component +
//     `vex_draft_ai_disabled` audit row. AIDisabled=true on the result.
//  4. Otherwise call provider.Complete once, then fan out one draft per
//     component sharing the same parsed decision / evidence / llm_call.
//
// Error contract:
//   - input validation failures              → returns a sentinel input
//     error (caller maps to 400)
//   - ErrVulnerabilityNotInTenant            → caller maps to 404
//   - ErrComponentNotInVulnerabilityScope    → caller maps to 404
//   - ErrCVEIDMismatch                       → caller maps to 400 (#F12)
//   - non-Disabled llm.Provider failure      → wrapped (caller maps 5xx)
//   - ValidateEvidence ErrEmptyEvidence      → wrapped (caller maps 422)
//   - persistence failures                    → wrapped (caller maps 500)
func (r *Runner) Run(ctx context.Context, in RunInput) (*RunResult, error) {
	if in.TenantID == uuid.Nil {
		return nil, errors.New("triage.Run: tenant_id is required")
	}
	if in.ProjectID == uuid.Nil {
		return nil, errors.New("triage.Run: project_id is required")
	}
	if in.CVEID == "" {
		return nil, errors.New("triage.Run: cve_id is required")
	}
	if in.VulnerabilityID == uuid.Nil {
		return nil, errors.New("triage.Run: vulnerability_id is required")
	}

	// Step 0a: resolve the per-request LLM provider (#F2). Resolver wins;
	// fall back to the env-resolved default; final fallback is a
	// DisabledProvider so the #F4 AI-disabled path can fire.
	provider, err := r.resolveProvider(ctx, in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("triage.Run: resolve provider: %w", err)
	}

	// Step 0b: resolve component IDs (#F3). The CLI omits ComponentID
	// because /vulnerabilities does not project the component join; the
	// server resolves it here. Caller-supplied wins; otherwise the
	// resolver enumerates every (component, vuln) pair in tenant scope.
	componentIDs, err := r.resolveComponentIDs(ctx, in)
	if err != nil {
		return nil, err
	}

	// Step 0c: re-resolve the CVEID server-side from the vulnerabilities
	// row (#F12). RunInput accepts both VulnerabilityID and CVEID from
	// the request, and VulnerabilityID has just been validated against
	// the (tenant, project) graph by resolveComponentIDs — but the
	// downstream advisory / reachability fetches both index by CVEID,
	// so without this cross-check a caller could pair an in-scope
	// VulnerabilityID with an arbitrary CVE-XXXX-YYYY string and have
	// the runner build prompts + persist drafts using stranger evidence.
	// We rebind in.CVEID to the resolved value so every later step
	// (prompt, advisory_excerpts fetch, reachability fetch, draft, audit,
	// llm_calls row) sees the same authoritative CVE id.
	resolvedCVEID, err := r.resolveAuthoritativeCVEID(ctx, in.VulnerabilityID, in.CVEID)
	if err != nil {
		return nil, err
	}
	in.CVEID = resolvedCVEID

	// Step 0d: if the resolved provider is disabled, branch into the
	// AI-disabled persistence path (#F4). No advisory / reachability
	// fetch and no LLM call.
	if _, ok := provider.(*llm.DisabledProvider); ok {
		return r.runAIDisabled(ctx, in, provider, componentIDs)
	}

	// Step 1: gather context.
	advisories, err := r.advisories.GetByCVE(ctx, in.TenantID, in.CVEID)
	if err != nil {
		return nil, fmt.Errorf("triage.Run: load advisory excerpts: %w", err)
	}
	reachFilter := ReachabilityFilter{
		CVEID: in.CVEID,
		// When fanning out we leave ComponentID nil so reachability rows
		// across all affected components are visible to the LLM; per-
		// component filtering happens at draft persistence time. When
		// the caller supplied an explicit component_id we still scope
		// the reachability fetch to that component (backward compat).
		ComponentID: in.ComponentID,
	}
	reach, err := r.reachability.ListByProject(ctx, in.TenantID, in.ProjectID, reachFilter)
	if err != nil {
		return nil, fmt.Errorf("triage.Run: load reachability results: %w", err)
	}

	// Step 2: build LLM prompt + call provider.
	prompt := buildPrompt(in.CVEID, advisories, reach)
	completeReq := llm.CompleteRequest{
		System:      vexTriageSystemPrompt,
		Messages:    []llm.Message{{Role: llm.RoleUser, Content: prompt}},
		Temperature: 0.0,
		JSONMode:    true,
		TenantID:    in.TenantID.String(),
		Purpose:     LLMCallPurposeVexTriage,
	}
	if in.UserID != nil {
		completeReq.UserID = in.UserID.String()
	}

	llmStart := r.clock()
	resp, llmErr := r.provider_Complete(ctx, provider, completeReq)
	llmDuration := r.clock().Sub(llmStart)

	// Persist the llm_calls row whether the call succeeded or failed,
	// so the audit trail captures transient-failure cases. NOTE: the
	// AI-disabled case has its own path (runAIDisabled) and does not
	// reach here, so r.provider here is always a real provider.
	llmCallID := uuid.New()
	// For audit purposes record the first component (or nil) — the
	// llm_calls row predates fan-out. If we want per-component
	// attribution, that lives on vex_drafts.component_id directly.
	var llmTargetComponent *uuid.UUID
	if len(componentIDs) > 0 {
		c := componentIDs[0]
		llmTargetComponent = &c
	}
	callRecord := &LLMCallRecord{
		ID:                      llmCallID,
		TenantID:                in.TenantID,
		UserID:                  in.UserID,
		Purpose:                 LLMCallPurposeVexTriage,
		Provider:                provider.Name(),
		Model:                   provider.Model(),
		PromptHash:              sha256Hex(prompt),
		PromptPreview:           preview(prompt, 256),
		DurationMs:              int(llmDuration.Milliseconds()),
		TriageTargetCVE:         in.CVEID,
		TriageTargetComponentID: llmTargetComponent,
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
		callRecord.ErrorMessage = llmErr.Error()
	}
	if persistErr := r.llmCalls.Insert(ctx, callRecord); persistErr != nil {
		// Surfaceable but not fatal — we still want to propagate the
		// underlying llmErr if there was one, but logging makes ops
		// aware of audit-write failures.
		slog.Warn("triage.Run: persist llm_calls failed",
			"tenant_id", in.TenantID, "cve_id", in.CVEID, "error", persistErr)
	}

	if llmErr != nil {
		return nil, fmt.Errorf("triage.Run: llm provider failed: %w", llmErr)
	}

	// Step 3: parse + guard.
	parsed, _ := ParseLLMResponse(resp.Content)
	if parsed == nil {
		// ParseLLMResponse contract: never returns nil + nil. Defensive.
		return nil, fmt.Errorf("triage.Run: nil parsed decision (provider=%s)", provider.Name())
	}
	finalState, clamped := ApplyConfidenceThreshold(string(parsed.State), parsed.Confidence, r.threshold)

	// Step 4: validate evidence. If the LLM emitted no evidence, the
	// fallback path in ParseLLMResponse always tacks on an llm_rationale
	// pointer, but real success-path responses with empty evidence are
	// 422 per the issue spec.
	if err := ValidateEvidence(parsed.Evidence); err != nil {
		return nil, fmt.Errorf("triage.Run: %w", err)
	}

	evidenceJSON, err := json.Marshal(parsed.Evidence)
	if err != nil {
		return nil, fmt.Errorf("triage.Run: marshal evidence: %w", err)
	}
	// Optional FK pointers into advisory_excerpts / llm_calls. We
	// populate AdvisoryExcerptID with the first matching row id so the
	// UI can drill back without scanning the evidence array; advisory
	// rows are per-(tenant, cve) so the same FK is correct for every
	// fan-out component.
	var advisoryFK *uuid.UUID
	if len(advisories) > 0 {
		v := advisories[0].ID
		advisoryFK = &v
	}
	// M1 Codex review #F11: reachability_results rows are per-component
	// (one per (component, cve) pair). The previous version sampled
	// reach[0].ID once before the fan-out loop and reused it for every
	// draft, which pointed component B / C / ...'s drafts at component
	// A's reachability evidence — the draft viewer then surfaced the
	// wrong "imported but unreachable from main()" rationale on the
	// other components. We now index by component_id and look up the
	// FK per fan-out iteration; components without a matching
	// reachability row get a nil FK (NOT a stranger row).
	reachByComponent := make(map[uuid.UUID]uuid.UUID, len(reach))
	for _, rr := range reach {
		if rr.ComponentID == uuid.Nil {
			// Defensive — reachability_results.component_id is NOT NULL
			// at the DB layer (migration 034), so a zero UUID here is
			// either a fixture bug or a future schema drift. Skip rather
			// than seeding the map with a zero key that would silently
			// collide across components.
			continue
		}
		// First write wins. If multiple reachability rows exist for the
		// same component (e.g. multiple analyser runs), the UI drill-back
		// only renders one — picking the first observed keeps draft
		// behaviour deterministic. The full set is still visible via
		// the reachability_results endpoint.
		if _, exists := reachByComponent[rr.ComponentID]; !exists {
			reachByComponent[rr.ComponentID] = rr.ID
		}
	}
	llmFK := llmCallID

	// Step 5: persist one vex_drafts row per (component, vuln) pair —
	// the fan-out from #F3. Each draft carries the same parsed decision
	// / evidence / llm_call FK; ComponentID, ReachabilityResultID, and
	// the audit row's resource_id differ per component (#F11).
	conf := parsed.Confidence
	drafts := make([]*repository.VEXDraft, 0, len(componentIDs))
	action := AuditActionVexDraftAIGenerated
	if in.Reanalyse {
		action = AuditActionVexDraftReanalysed
	}
	for _, compID := range componentIDs {
		var reachFK *uuid.UUID
		if rid, ok := reachByComponent[compID]; ok {
			v := rid
			reachFK = &v
		}
		draft := &repository.VEXDraft{
			ID:                   uuid.New(),
			TenantID:             in.TenantID,
			ProjectID:            in.ProjectID,
			ComponentID:          compID,
			VulnerabilityID:      in.VulnerabilityID,
			CVEID:                in.CVEID,
			State:                finalState,
			Justification:        string(parsed.Justification),
			Detail:               parsed.Detail,
			Confidence:           &conf,
			Provider:             provider.Name(),
			Model:                provider.Model(),
			PromptHash:           callRecord.PromptHash,
			ResponseHash:         callRecord.ResponseHash,
			Evidence:             evidenceJSON,
			AdvisoryExcerptID:    advisoryFK,
			ReachabilityResultID: reachFK,
			LLMCallID:            &llmFK,
			Decision:             DecisionPending,
			CreatedBy:            in.UserID,
		}
		if err := r.drafts.Insert(ctx, draft); err != nil {
			return nil, fmt.Errorf("triage.Run: persist vex_draft: %w", err)
		}
		// Step 6: audit log — one row per draft so compliance reviewers
		// can trace the AI verdict on each (component, vuln) pair.
		if err := r.writeAudit(ctx, in.TenantID, in.UserID, action, draft.ID, map[string]interface{}{
			"cve_id":               in.CVEID,
			"vulnerability_id":     in.VulnerabilityID.String(),
			"project_id":           in.ProjectID.String(),
			"component_id":         compID.String(),
			"llm_provider":         provider.Name(),
			"llm_model":            provider.Model(),
			"llm_call_id":          llmCallID.String(),
			"confidence":           parsed.Confidence,
			"confidence_threshold": r.threshold,
			"clamped":              clamped,
			"state":                finalState,
			"justification":        string(parsed.Justification),
			"reanalyse_from":       uuidStringOrEmpty(in.ReanalyseFromDraft),
		}, in.IPAddress, in.UserAgent); err != nil {
			return nil, fmt.Errorf("triage.Run: %w", err)
		}
		drafts = append(drafts, draft)
	}

	return &RunResult{
		Draft:     drafts[0],
		Drafts:    drafts,
		Parsed:    parsed,
		LLMCallID: llmCallID,
		Clamped:   clamped,
		Threshold: r.threshold,
	}, nil
}

// resolveProvider implements the per-request provider lookup contract
// (M1 Codex review #F2): resolver → defaultProvider → DisabledProvider.
// A resolver that returns (nil, nil) is treated as "use the default".
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

// resolveComponentIDs implements the component_id resolution contract
// (M1 Codex review #F3 + #F6). The resolver always enumerates the
// authoritative (tenant, project, vulnerability) → []component_id set
// via componentVulns.ListIDsByVulnerability. Behaviour then forks:
//
//   - No ComponentID supplied: the full resolved set is returned and the
//     runner fans out one draft per (component, vuln) pair (#F3). Zero
//     matches → ErrVulnerabilityNotInTenant.
//   - ComponentID supplied: the caller-supplied id MUST be a member of
//     the resolved set, otherwise ErrComponentNotInVulnerabilityScope
//     (#F6). vex_drafts has no composite FK over (project_id,
//     component_id, vulnerability_id), so without this check a caller
//     could persist a draft pointing at a component from a neighbouring
//     project / vulnerability — silently bypassing project membership.
//
// When the production wiring is missing a ComponentVulnerabilityResolver
// the runner still refuses to fabricate an ID. Without a resolver we
// cannot perform the #F6 membership check either, so a caller-supplied
// ComponentID is also rejected in that mode — surfacing the misconfig
// loudly is preferable to a silently unscoped draft.
func (r *Runner) resolveComponentIDs(ctx context.Context, in RunInput) ([]uuid.UUID, error) {
	if r.componentVulns == nil {
		// Maintains the original #F3 contract: handler-fixable misconfig
		// reads as a 400 ("is required ...") via mapRunnerError.
		return nil, errors.New("triage.Run: component_id resolver is required (no ComponentVulnerabilityResolver wired)")
	}
	ids, err := r.componentVulns.ListIDsByVulnerability(ctx, in.TenantID, in.ProjectID, in.VulnerabilityID)
	if err != nil {
		return nil, fmt.Errorf("triage.Run: resolve component_ids: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("triage.Run: %w", ErrVulnerabilityNotInTenant)
	}
	// F6: validate caller-supplied component_id against the resolved
	// set. We compare uuid values directly — the ID set is small (one
	// per affected component in this project) so a linear scan is fine.
	if in.ComponentID != nil && *in.ComponentID != uuid.Nil {
		want := *in.ComponentID
		for _, id := range ids {
			if id == want {
				return []uuid.UUID{want}, nil
			}
		}
		return nil, fmt.Errorf("triage.Run: %w", ErrComponentNotInVulnerabilityScope)
	}
	return ids, nil
}

// resolveAuthoritativeCVEID looks up the canonical cve_id for the
// supplied vulnerability_id and rejects requests where the caller's
// CVEID disagrees (M1 Codex review #F12). It MUST run after
// resolveComponentIDs so the tenant-scope check (which goes through the
// RLS-protected components / sboms join) fires first — the
// vulnerabilities table is a global NVD/EPSS cache with no RLS of its
// own, so the join-based (tenant, project, vuln) membership check is
// what makes the lookup safe to perform here.
//
// Returns the resolved CVEID on success. On mismatch returns a wrapped
// ErrCVEIDMismatch which the handler folds into a generic 400 body
// ("triage target invalid") so a probe caller cannot distinguish
// "mismatched cve_id" from "unknown vulnerability_id" via the response.
//
// When the lookup itself is not wired (vulnCVE == nil) the runner
// refuses to fabricate trust in the caller-supplied CVEID — mirroring
// the resolveComponentIDs misconfig contract. Production wiring always
// supplies *repository.VulnerabilityRepository.
func (r *Runner) resolveAuthoritativeCVEID(ctx context.Context, vulnID uuid.UUID, suppliedCVEID string) (string, error) {
	if r.vulnCVE == nil {
		// Fail closed — same posture as resolveComponentIDs when
		// componentVulns is missing. The handler maps "is required ..." to
		// 400, which surfaces the misconfig loudly without persisting an
		// unscoped draft.
		return "", errors.New("triage.Run: vulnerability cve lookup is required (no VulnerabilityCVELookup wired)")
	}
	resolved, err := r.vulnCVE.GetCVEIDByID(ctx, vulnID)
	if err != nil {
		// componentVulns has just vouched for (tenant, project, vuln)
		// membership, so a missing vulnerabilities row here is a
		// data-integrity issue (caller maps to 5xx via mapRunnerError's
		// default branch). We deliberately do NOT fold this into the
		// ErrCVEIDMismatch path: the failure mode is server-side, not
		// caller-supplied.
		return "", fmt.Errorf("triage.Run: resolve cve_id for vulnerability_id: %w", err)
	}
	if resolved == "" {
		return "", fmt.Errorf("triage.Run: vulnerability_id %s has empty cve_id (corrupt vulnerabilities row)", vulnID)
	}
	if resolved != suppliedCVEID {
		// Intentional: do NOT include the resolved CVE id in the error
		// message. The handler maps this to a generic 400 body, and we
		// log the precise mismatch in server logs (mapRunnerError +
		// slog.Warn). Leaking the resolved CVE here would defeat the
		// generic-body discipline (#F10 / #F12).
		return "", fmt.Errorf("triage.Run: %w", ErrCVEIDMismatch)
	}
	return resolved, nil
}

// provider_Complete is a tiny indirection that lets us swap the bound
// provider per request without touching the rest of the Run() body. The
// odd name avoids collision with the `provider` interface field that
// used to live on the receiver.
func (r *Runner) provider_Complete(ctx context.Context, p llm.Provider, req llm.CompleteRequest) (*llm.CompleteResponse, error) {
	return p.Complete(ctx, req)
}

// runAIDisabled implements the F4 AI-disabled draft path. For every
// component in scope:
//
//   - inserts a vex_drafts row with state=under_investigation,
//     confidence=0.0, evidence=[{kind:"ai_disabled", ...}]
//   - emits a `vex_draft_ai_disabled` audit_logs row
//
// No LLM call is attempted and no llm_calls row is written — there was
// no call to record. The handler returns the drafts to the CLI which
// surfaces the "APIキー未設定" hint and increments the
// under_investigation counter (UX kept; persistence is now on the
// server, not invented locally on the CLI).
func (r *Runner) runAIDisabled(ctx context.Context, in RunInput, provider llm.Provider, componentIDs []uuid.UUID) (*RunResult, error) {
	reason := "BYOK key not configured"
	if dp, ok := provider.(*llm.DisabledProvider); ok && dp.Reason != "" {
		reason = dp.Reason
	}

	// Synthetic evidence — the schema requires at least one entry, and
	// "ai_disabled" gives the UI / compliance auditor a clear marker
	// that this draft was NOT a real AI verdict.
	evidence := []EvidencePointer{{
		Kind:        "ai_disabled",
		Source:      "system",
		Description: "AI triage skipped: " + reason,
		Note:        "BYOK key not configured for this tenant; draft auto-created as under_investigation",
	}}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("triage.runAIDisabled: marshal evidence: %w", err)
	}

	zeroConf := 0.0
	drafts := make([]*repository.VEXDraft, 0, len(componentIDs))
	action := AuditActionVexDraftAIDisabled
	for _, compID := range componentIDs {
		draft := &repository.VEXDraft{
			ID:              uuid.New(),
			TenantID:        in.TenantID,
			ProjectID:       in.ProjectID,
			ComponentID:     compID,
			VulnerabilityID: in.VulnerabilityID,
			CVEID:           in.CVEID,
			State:           string(StateUnderInvestigation),
			// No justification — under_investigation does not need one
			// per CycloneDX 1.5 (justification is allowlisted to
			// not_affected variants).
			Detail:     "AI triage skipped: " + reason,
			Confidence: &zeroConf,
			Provider:   provider.Name(),
			Model:      provider.Model(),
			Evidence:   evidenceJSON,
			Decision:   DecisionPending,
			CreatedBy:  in.UserID,
		}
		if err := r.drafts.Insert(ctx, draft); err != nil {
			return nil, fmt.Errorf("triage.runAIDisabled: persist vex_draft: %w", err)
		}
		if err := r.writeAudit(ctx, in.TenantID, in.UserID, action, draft.ID, map[string]interface{}{
			"cve_id":           in.CVEID,
			"vulnerability_id": in.VulnerabilityID.String(),
			"project_id":       in.ProjectID.String(),
			"component_id":     compID.String(),
			"reason":           reason,
			"provider":         provider.Name(),
			"state":            string(StateUnderInvestigation),
		}, in.IPAddress, in.UserAgent); err != nil {
			return nil, fmt.Errorf("triage.runAIDisabled: %w", err)
		}
		drafts = append(drafts, draft)
	}

	return &RunResult{
		Draft:      drafts[0],
		Drafts:     drafts,
		Threshold:  r.threshold,
		AIDisabled: true,
	}, nil
}

// GetDraft returns one draft scoped to tenant.
func (r *Runner) GetDraft(ctx context.Context, tenantID, draftID uuid.UUID) (*repository.VEXDraft, error) {
	if tenantID == uuid.Nil {
		return nil, errors.New("triage.GetDraft: tenant_id is required")
	}
	if draftID == uuid.Nil {
		return nil, errors.New("triage.GetDraft: draft_id is required")
	}
	return r.drafts.Get(ctx, tenantID, draftID)
}

// ListDrafts returns drafts for a project, scoped to tenant.
func (r *Runner) ListDrafts(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.VEXDraftListFilter) ([]repository.VEXDraft, error) {
	if tenantID == uuid.Nil {
		return nil, errors.New("triage.ListDrafts: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, errors.New("triage.ListDrafts: project_id is required")
	}
	return r.drafts.ListByProject(ctx, tenantID, projectID, filter)
}

// DecisionInput is the payload for UpdateDecision (Approve / Edit / Reject).
// Decision is a plain string matching agent A's repository.VEXDraftDecisionUpdate
// allowlist (`approved` | `edited` | `rejected`); the runner validates
// before persistence so a bad caller never reaches the DB.
type DecisionInput struct {
	TenantID            uuid.UUID
	DraftID             uuid.UUID
	UserID              *uuid.UUID
	Decision            string
	EditedState         string
	EditedJustification string
	EditedDetail        string
	Note                string
	IPAddress           string
	UserAgent           string
}

// UpdateDecision applies a human approve / edit / reject decision and:
//
//   - updates vex_drafts.decision (+ edited_* / decided_by / decided_at),
//   - on approve, mirrors the confirmed verdict into vex_statements via
//     VEXStatementSync so the existing CycloneDX export and MCP surfaces
//     pick it up,
//   - writes the matching audit_logs row (vex_draft_approved / _edited /
//     _rejected).
//
// Edit transitions require EditedState (and EditedJustification when
// EditedState is not_affected) — the spec is intentionally strict so an
// AI-flagged not_affected cannot be quietly edited into "affected" with
// no justification.
func (r *Runner) UpdateDecision(ctx context.Context, in DecisionInput) (*repository.VEXDraft, error) {
	if in.TenantID == uuid.Nil {
		return nil, errors.New("triage.UpdateDecision: tenant_id is required")
	}
	if in.DraftID == uuid.Nil {
		return nil, errors.New("triage.UpdateDecision: draft_id is required")
	}
	if in.UserID == nil || *in.UserID == uuid.Nil {
		return nil, errors.New("triage.UpdateDecision: user_id is required (audit trail; agent A repo also requires it)")
	}
	switch in.Decision {
	case DecisionApproved, DecisionRejected:
		// OK — no extra fields required.
	case DecisionEdited:
		if in.EditedState == "" {
			return nil, errors.New("triage.UpdateDecision: edited_state is required for `edited` decisions")
		}
		if !IsValidState(in.EditedState) {
			return nil, fmt.Errorf("triage.UpdateDecision: edited_state %q is not in allowlist", in.EditedState)
		}
		if !IsValidJustification(in.EditedJustification) {
			return nil, fmt.Errorf("triage.UpdateDecision: edited_justification %q is not in allowlist", in.EditedJustification)
		}
		if in.EditedState == string(StateNotAffected) && in.EditedJustification == "" {
			return nil, errors.New("triage.UpdateDecision: edited_justification is required when edited_state is `not_affected`")
		}
	default:
		return nil, fmt.Errorf("triage.UpdateDecision: decision %q is not in allowlist (expected approved|edited|rejected)", in.Decision)
	}

	now := r.clock().UTC()
	update := repository.VEXDraftDecisionUpdate{
		Decision:     in.Decision,
		DecisionBy:   *in.UserID,
		DecisionAt:   now,
		DecisionNote: in.Note,
	}
	// For edits, pass the new values as non-nil pointers so agent A's
	// COALESCE-based UPDATE overwrites in-place. Empty-string is
	// preserved as a real edit (matches A's "do not change vs set to
	// empty" contract documented on VEXDraftDecisionUpdate).
	if in.Decision == DecisionEdited {
		es := in.EditedState
		update.EditedState = &es
		ej := in.EditedJustification
		update.EditedJustification = &ej
		ed := in.EditedDetail
		update.EditedDetail = &ed
	}
	if err := r.drafts.UpdateDecision(ctx, in.TenantID, in.DraftID, update); err != nil {
		return nil, fmt.Errorf("triage.UpdateDecision: persist decision: %w", err)
	}

	// Re-fetch the updated row so downstream sync + audit + caller see
	// the post-update state (agent A's UpdateDecision returns only
	// `error`).
	updated, err := r.drafts.Get(ctx, in.TenantID, in.DraftID)
	if err != nil {
		return nil, fmt.Errorf("triage.UpdateDecision: refetch after update: %w", err)
	}
	if updated == nil {
		return nil, fmt.Errorf("triage.UpdateDecision: draft %s not found after update", in.DraftID)
	}

	// Mirror approved / edited drafts into vex_statements so existing
	// surfaces (export, MCP, public link) see the confirmed verdict.
	// updated.State / Justification / Detail already carry the edited
	// values when Decision="edited" because UpdateDecision applied the
	// COALESCE overwrite in the same statement.
	if (in.Decision == DecisionApproved || in.Decision == DecisionEdited) && r.vexSync != nil {
		if err := r.syncToVEXStatements(ctx, updated, in.UserID); err != nil {
			// Audit + return — failing the sync should not silently
			// hide the failure, but we already persisted the
			// decision, so the caller can retry.
			slog.Error("triage.UpdateDecision: vex_statements sync failed",
				"tenant_id", in.TenantID, "draft_id", in.DraftID, "error", err)
			return updated, fmt.Errorf("triage.UpdateDecision: sync to vex_statements: %w", err)
		}
	}

	// Audit row.
	action := decisionAuditAction(in.Decision)
	if err := r.writeAudit(ctx, in.TenantID, in.UserID, action, in.DraftID, map[string]interface{}{
		"cve_id":               updated.CVEID,
		"vulnerability_id":     updated.VulnerabilityID.String(),
		"project_id":           updated.ProjectID.String(),
		"draft_state":          updated.State,
		"draft_justification":  updated.Justification,
		"edited_state":         in.EditedState,
		"edited_justification": in.EditedJustification,
		"edited_detail":        in.EditedDetail,
		"note":                 in.Note,
	}, in.IPAddress, in.UserAgent); err != nil {
		// Audit write failed — propagate so TenantTx rolls back the
		// vex_drafts UPDATE and any vex_statements INSERT performed
		// above. PRODUCT_REBOOT_PLAN.md §8.5 requires the audit row to
		// land with the decision change or neither persists. We return
		// `updated` alongside the error so debugging the failure does
		// not lose the would-be state, but the handler maps the error
		// to 5xx and the client never sees `updated`.
		return updated, fmt.Errorf("triage.UpdateDecision: %w", err)
	}

	return updated, nil
}

// syncToVEXStatements mirrors an approved / edited draft into the
// existing vex_statements table via VEXStatementSync. Translation of
// allowlist values (M1 triage uses CycloneDX VEX 1.5 names, the
// existing model.VEXJustification enum uses the 1.4 names) is the
// responsibility of mapTriageJustification.
//
// Agent A's vex_drafts schema stores ComponentID as a non-nullable
// column, so we wrap it as a pointer to match VEXStatementSync's
// optional-component contract (existing vex_statements.component_id
// is nullable).
func (r *Runner) syncToVEXStatements(ctx context.Context, draft *repository.VEXDraft, userID *uuid.UUID) error {
	createdBy := "ai-triage"
	if userID != nil {
		createdBy = userID.String()
	}
	compID := draft.ComponentID
	input := VEXStatementSyncInput{
		ProjectID:       draft.ProjectID,
		VulnerabilityID: draft.VulnerabilityID,
		ComponentID:     &compID,
		Status:          mapTriageStateToVEXStatus(draft.State),
		Justification:   mapTriageJustification(draft.Justification),
		ImpactStatement: draft.Detail,
		CreatedBy:       createdBy,
	}
	return r.vexSync.CreateStatement(ctx, input)
}

// writeAudit emits one audit_logs row carrying details about the draft
// lifecycle event. Failures are returned to the caller so the surrounding
// TenantTx (apps/api/internal/middleware/tx.go) rolls back the draft
// INSERT / decision UPDATE alongside the would-be audit row.
//
// Codex M1 round 1 #F5: previously this swallowed errors with a slog.Warn,
// which let Run / UpdateDecision commit a VEX-draft mutation while its
// audit row silently failed — a §8.5 violation (the compliance reviewer
// could not see who approved what). We now fail-closed: any audit_logs
// write failure aborts the request, the handler maps it to 5xx, and
// TenantTx drops everything written on the request-bound transaction.
func (r *Runner) writeAudit(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, action string, resourceID uuid.UUID, details map[string]interface{}, ipAddress, userAgent string) error {
	rid := resourceID
	input := &model.CreateAuditLogInput{
		TenantID:     uuidPtr(tenantID),
		UserID:       userID,
		Action:       action,
		ResourceType: ResourceTypeVexDraft,
		ResourceID:   &rid,
		Details:      details,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	}
	if err := r.audit.Log(ctx, input); err != nil {
		// slog.Warn keeps the operator-visible signal for the
		// dashboards that already alarm on this string; the returned
		// error is what drives rollback.
		slog.Warn("triage.writeAudit: audit log failed",
			"tenant_id", tenantID, "action", action, "resource_id", resourceID, "error", err)
		return fmt.Errorf("triage.writeAudit: persist audit_logs row (action=%s): %w", action, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// LLM prompt construction
// ----------------------------------------------------------------------------

// vexTriageSystemPrompt steers the LLM toward the strict JSON contract
// the parser expects. We intentionally bake the allowlist into the
// system prompt so the model has the schema in-context.
//
// ※要確認: prompt wording may need iteration once the M1-4 eval set
// lands. Keep prompt changes Tracked so prompt_hash analytics stay
// meaningful (any prompt edit invalidates historical equality joins).
const vexTriageSystemPrompt = `You are SBOMHub's AI VEX triage assistant.

Your job: given an advisory excerpt and ecosystem reachability evidence,
decide whether the cited CVE is exploitable in the user's project.

You MUST reply with a single JSON object on the schema below. Do not
include prose outside the JSON. Do not invent evidence — every
"evidence" entry MUST refer to a fact present in the supplied context.

{
  "state": "not_affected | affected | under_investigation | resolved",
  "justification": "code_not_present | code_not_reachable | requires_configuration | requires_dependency | requires_environment | protected_by_compiler | protected_at_perimeter | protected_at_runtime | inline_mitigations_already_exist",
  "detail": "one or two sentences for a human reviewer",
  "confidence": 0.0 - 1.0,
  "evidence": [
    { "kind": "import_path" | "symbol_ref" | "advisory_excerpt" | "llm_rationale",
      "import_path": "...", "symbol": "...", "raw_snippet": "...",
      "description": "...", "source": "reachability|advisory_parser|llm",
      "note": "..." }
  ]
}

When evidence is thin or contradictory, prefer state="under_investigation"
with confidence reflecting your uncertainty. Never set state="not_affected"
without at least one evidence pointer.`

// buildPrompt constructs the user-turn prompt body. The advisory +
// reachability data is rendered as compact JSON so the LLM can address
// individual rows by index in its evidence list.
func buildPrompt(cveID string, advisories []AdvisoryExcerptRow, reach []ReachabilityRow) string {
	var b strings.Builder
	b.WriteString("CVE: ")
	b.WriteString(cveID)
	b.WriteString("\n\nAdvisory excerpts:\n")
	if len(advisories) == 0 {
		b.WriteString("  (none — advisory parsing has no data for this CVE)\n")
	} else {
		for i, a := range advisories {
			fmt.Fprintf(&b, "  [%d] id=%s source=%s\n", i, a.ID, a.Source)
			if a.RawExcerpt != "" {
				fmt.Fprintf(&b, "      excerpt: %s\n", truncate(a.RawExcerpt, 600))
			}
			if len(a.VulnFuncs) > 0 && string(a.VulnFuncs) != "[]" {
				fmt.Fprintf(&b, "      vuln_funcs: %s\n", string(a.VulnFuncs))
			}
			if len(a.AffectedPaths) > 0 && string(a.AffectedPaths) != "[]" {
				fmt.Fprintf(&b, "      affected_paths: %s\n", string(a.AffectedPaths))
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
			if len(rr.Evidence) > 0 && string(rr.Evidence) != "{}" {
				fmt.Fprintf(&b, "      evidence: %s\n", truncate(string(rr.Evidence), 400))
			}
		}
	}
	b.WriteString("\nProduce the VEX JSON now.")
	return b.String()
}

// ----------------------------------------------------------------------------
// Mapping helpers
// ----------------------------------------------------------------------------

// mapTriageStateToVEXStatus maps the M1 triage state names onto the
// existing model.VEXStatus enum.
//
// Notes:
//   - StateResolved maps to VEXStatusFixed because the existing CycloneDX
//     export already serialises VEXStatusFixed as "resolved" (see
//     service/vex.go::mapStatusToCycloneDX), so the round-trip is lossless.
//   - Unknown / empty input collapses to under_investigation rather than
//     leaving the caller with an invalid VEXStatus that would be rejected
//     by VEXService.CreateStatement.
func mapTriageStateToVEXStatus(s string) model.VEXStatus {
	switch State(s) {
	case StateNotAffected:
		return model.VEXStatusNotAffected
	case StateAffected:
		return model.VEXStatusAffected
	case StateResolved:
		return model.VEXStatusFixed
	case StateUnderInvestigation:
		return model.VEXStatusUnderInvestigation
	default:
		return model.VEXStatusUnderInvestigation
	}
}

// mapTriageJustification translates from the CycloneDX VEX 1.5
// justification names used in M1 triage onto the older 1.4 names that
// model.VEXJustification still uses.
//
// ※要確認: types.go documents that the existing model uses 1.4 names;
// when we migrate model.VEXJustification to 1.5 (post-M1) this mapping
// becomes the identity. Until then this is the conversion point.
func mapTriageJustification(j string) model.VEXJustification {
	switch Justification(j) {
	case JustificationCodeNotPresent:
		return model.VEXJustificationVulnerableCodeNotPresent
	case JustificationCodeNotReachable:
		return model.VEXJustificationVulnerableCodeNotInExecutePath
	case JustificationRequiresConfiguration,
		JustificationRequiresDependency,
		JustificationRequiresEnvironment:
		// No exact 1.4 equivalent — closest match is "cannot be controlled
		// by adversary" because all three of these states require attacker
		// access to a non-standard knob.
		return model.VEXJustificationVulnerableCodeCannotBeControlled
	case JustificationProtectedByCompiler,
		JustificationProtectedAtPerimeter,
		JustificationProtectedAtRuntime,
		JustificationInlineMitigationsAlreadyExist:
		return model.VEXJustificationInlineMitigationsAlreadyExist
	default:
		return ""
	}
}

// decisionAuditAction maps a decision string to its audit_logs action.
func decisionAuditAction(d string) string {
	switch d {
	case DecisionApproved:
		return AuditActionVexDraftApproved
	case DecisionEdited:
		return AuditActionVexDraftEdited
	case DecisionRejected:
		return AuditActionVexDraftRejected
	default:
		// Should not be reached — UpdateDecision validates the
		// decision allowlist up front. Falls back to the generic
		// "edited" action so the audit row is never lost.
		return AuditActionVexDraftEdited
	}
}

// ----------------------------------------------------------------------------
// Small helpers
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

func uuidPtr(u uuid.UUID) *uuid.UUID {
	if u == uuid.Nil {
		return nil
	}
	v := u
	return &v
}

func uuidStringOrEmpty(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}
