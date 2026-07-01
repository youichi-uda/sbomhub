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

	// The audit_logs.resource_type wire value for every vex_draft
	// lifecycle event lives in package model as model.ResourceVEXDraft
	// (the anti-pattern 58 dual-list system single source of truth).
	// This package used to declare a sibling `ResourceTypeVexDraft =
	// "vex_draft"` duplicate; M20 R2 F302 promoted the 2 use sites to
	// model.ResourceVEXDraft and removed the orphan constant so a
	// future rename of the wire value cannot desync silently through a
	// stale package-local copy.
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

// ErrFanOutExceeded is returned by Run when the caller omits ComponentID
// AND the (tenant, project, vulnerability) → []component_id resolver
// returns more components than r.maxFanOut. The handler maps this to
// 413 with an "supply component_id" hint. M1 Codex review #F25: without
// this cap, a write-scoped API-key caller could trigger a single triage
// run that persists one vex_drafts + one audit_logs row per affected
// component inside a single transaction — DoS by widely-used CVE.
//
// Bypass: callers with a legitimate need to triage one specific
// (component, vuln) pair from a high-fan-out CVE supply ComponentID
// explicitly; that path skips the cap because it persists exactly one
// draft regardless of how many components the resolver knows about.
var ErrFanOutExceeded = errors.New("triage: fan-out exceeds configured cap (supply component_id to triage one pair)")

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

	// txManager opens short-lived per-tenant transactions for the 2-stage
	// Run() flow. M1 Codex review #F19: previously the runner ran inside
	// the request-scoped TenantTx, so a slow Provider.Complete pinned a
	// Postgres connection from the 25-slot pool for up to 60s while doing
	// no DB work. The runner now drives its own tx lifecycle via this
	// field — Stage 1 read tx → commit → LLM call (no tx) → Stage 3 write
	// tx with re-validation → commit. Defaults to PassthroughTxManager
	// (no-op) for unit tests so the in-memory fakes stay simple.
	txManager TxManager

	// llmTimeout bounds each Provider.Complete call (M1 Codex review #F19
	// part 3). Default DefaultLLMTimeout seconds, overridable via
	// SBOMHUB_LLM_TIMEOUT_SECONDS (LLMTimeoutFromEnv).
	llmTimeout time.Duration

	// maxFanOut caps how many components a single ComponentID-less triage
	// request may fan out across (M1 Codex review #F25). Default
	// DefaultMaxFanOut, overridable via SBOMHUB_TRIAGE_MAX_FANOUT
	// (MaxFanOutFromEnv). Caller-supplied ComponentID bypasses the cap
	// (always exactly 1 draft regardless of the resolver's full set size).
	maxFanOut int
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

	// TxManager drives Stage 1 / Stage 3 transaction lifecycle (M1 Codex
	// review #F19). Production wiring MUST pass *DBTxManager so the
	// connection-pool fix takes effect; nil defaults to
	// PassthroughTxManager which is unit-test only.
	TxManager TxManager

	// LLMTimeout bounds Provider.Complete during Stage 2 (M1 Codex review
	// #F19 part 3). Zero falls back to LLMTimeoutFromEnv() (default
	// DefaultLLMTimeout seconds, overridable via
	// SBOMHUB_LLM_TIMEOUT_SECONDS).
	LLMTimeout time.Duration

	// MaxFanOut caps how many components a single ComponentID-less triage
	// request may fan out across (M1 Codex review #F25). Zero falls back to
	// MaxFanOutFromEnv() (default DefaultMaxFanOut, overridable via
	// SBOMHUB_TRIAGE_MAX_FANOUT). Caller-supplied ComponentID bypasses the
	// cap (single-pair triage is always allowed).
	MaxFanOut int
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
	txMgr := cfg.TxManager
	if txMgr == nil {
		// Tests + legacy wiring fall through to no-op; production wires
		// *DBTxManager explicitly (see cmd/server/main.go).
		txMgr = PassthroughTxManager{}
	}
	llmTimeout := cfg.LLMTimeout
	if llmTimeout <= 0 {
		llmTimeout = LLMTimeoutFromEnv()
	}
	maxFanOut := cfg.MaxFanOut
	if maxFanOut <= 0 {
		maxFanOut = MaxFanOutFromEnv()
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
		txManager:        txMgr,
		llmTimeout:       llmTimeout,
		maxFanOut:        maxFanOut,
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
// 2-stage architecture (M1 Codex review #F19):
//
//  1. Stage 1 — short read tx via TxManager.RunRead. Resolves the LLM
//     provider (tenant_llm_config BYOK decrypt), component_id(s),
//     authoritative cve_id, advisory_excerpts, reachability_results.
//     Commits before Stage 2 so the Postgres connection is released
//     during the slow upstream call.
//  2. Stage 2 — Provider.Complete with a bounded context (default
//     DefaultLLMTimeout seconds, env-overridable). NO Postgres
//     transaction is held during this step. AI-disabled providers skip
//     this stage entirely.
//  3. Stage 3 — short write tx via TxManager.RunWrite. Re-validates
//     component scope + cve_id (TOCTOU defense — a component could
//     have been deleted between Stage 1 and Stage 3) then persists
//     llm_calls, fans out one vex_drafts row per (component, vuln)
//     pair, and emits the per-draft audit_logs rows. All atomic.
//
// Connection-pool hygiene contract: at no point does the runner hold a
// Postgres connection across the Stage 2 LLM call. The previous
// architecture pinned the request's TenantTx connection for up to 60s
// while waiting for the upstream, allowing 25 concurrent triage
// requests to exhaust the entire pool and block unrelated DB-backed
// routes. See cmd/server/main.go for the route-level concurrency
// limiter that complements this fix.
//
// Error contract:
//   - input validation failures              → returns a sentinel input
//     error (caller maps to 400)
//   - ErrVulnerabilityNotInTenant            → caller maps to 404
//   - ErrComponentNotInVulnerabilityScope    → caller maps to 404
//   - ErrCVEIDMismatch                       → caller maps to 400 (#F12)
//   - non-Disabled llm.Provider failure      → wrapped (caller maps 5xx)
//   - LLM bounded-context timeout            → wrapped (caller maps 5xx)
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

	// ----------------------------------------------------------------
	// Stage 1: short read tx — resolve provider + componentIDs +
	// authoritative cve_id + advisory_excerpts + reachability_results.
	// ----------------------------------------------------------------
	var (
		provider     llm.Provider
		componentIDs []uuid.UUID
		advisories   []AdvisoryExcerptRow
		reach        []ReachabilityRow
	)
	if err := r.txManager.RunRead(ctx, in.TenantID, func(ctx context.Context) error {
		var err error
		// Step 0a: resolve the per-request LLM provider (#F2).
		provider, err = r.resolveProvider(ctx, in.TenantID)
		if err != nil {
			return fmt.Errorf("triage.Run: resolve provider: %w", err)
		}

		// Step 0b: resolve component IDs (#F3 / #F6).
		componentIDs, err = r.resolveComponentIDs(ctx, in)
		if err != nil {
			return err
		}

		// Step 0c: re-resolve the authoritative cve_id (#F12).
		resolvedCVEID, err := r.resolveAuthoritativeCVEID(ctx, in.VulnerabilityID, in.CVEID)
		if err != nil {
			return err
		}
		in.CVEID = resolvedCVEID

		// Step 0d: AI-disabled providers do not need advisory /
		// reachability reads — runAIDisabled handles its own
		// persistence inside Stage 3. Skip the extra queries.
		if _, isDisabled := provider.(*llm.DisabledProvider); isDisabled {
			return nil
		}

		// Step 1: gather context (advisory + reachability reads).
		advisories, err = r.advisories.GetByCVE(ctx, in.TenantID, in.CVEID)
		if err != nil {
			return fmt.Errorf("triage.Run: load advisory excerpts: %w", err)
		}
		reachFilter := ReachabilityFilter{
			CVEID:       in.CVEID,
			ComponentID: in.ComponentID,
		}
		reach, err = r.reachability.ListByProject(ctx, in.TenantID, in.ProjectID, reachFilter)
		if err != nil {
			return fmt.Errorf("triage.Run: load reachability results: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// AI-disabled path: skip Stage 2 entirely; Stage 3 is a write tx
	// that re-validates scope + persists under_investigation drafts.
	if _, ok := provider.(*llm.DisabledProvider); ok {
		return r.runAIDisabled(ctx, in, provider, componentIDs)
	}

	// ----------------------------------------------------------------
	// Stage 2: LLM call with bounded context. NO Postgres tx is held.
	// ----------------------------------------------------------------
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

	llmCtx, cancel := context.WithTimeout(ctx, r.llmTimeout)
	defer cancel()
	llmStart := r.clock()
	resp, llmErr := r.provider_Complete(llmCtx, provider, completeReq)
	llmDuration := r.clock().Sub(llmStart)

	// Build the llm_calls record up-front so success and failure paths
	// share a single source of truth for the audit row.
	llmCallID := uuid.New()
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
		// M1 Codex review #F13: scrub auth-shaped material from any
		// provider error before persistence + wrapped return.
		llmErr = llm.RedactProviderError(llmErr)
		callRecord.ErrorMessage = llmErr.Error()
	}

	// On LLM failure: persist the llm_calls audit row in its own short
	// write tx (so operators can trace failed cycles), then surface the
	// error. No drafts, no per-draft audit row.
	if llmErr != nil {
		if persistErr := r.txManager.RunWrite(ctx, in.TenantID, func(ctx context.Context) error {
			return r.llmCalls.Insert(ctx, callRecord)
		}); persistErr != nil {
			slog.Warn("triage.Run: persist llm_calls failed",
				"tenant_id", in.TenantID, "cve_id", in.CVEID, "error", persistErr)
		}
		return nil, fmt.Errorf("triage.Run: llm provider failed: %w", llmErr)
	}

	// Step 3: parse + guard (no tx needed — pure CPU).
	parsed, _ := ParseLLMResponse(resp.Content)
	if parsed == nil {
		return nil, fmt.Errorf("triage.Run: nil parsed decision (provider=%s)", provider.Name())
	}
	finalState, clamped := ApplyConfidenceThreshold(string(parsed.State), parsed.Confidence, r.threshold)

	// Step 4: validate evidence (no tx needed). On rejection we still
	// persist the llm_calls audit row so the failed parse is traceable.
	if err := ValidateEvidence(parsed.Evidence); err != nil {
		if persistErr := r.txManager.RunWrite(ctx, in.TenantID, func(ctx context.Context) error {
			return r.llmCalls.Insert(ctx, callRecord)
		}); persistErr != nil {
			slog.Warn("triage.Run: persist llm_calls failed",
				"tenant_id", in.TenantID, "cve_id", in.CVEID, "error", persistErr)
		}
		return nil, fmt.Errorf("triage.Run: %w", err)
	}

	evidenceJSON, err := json.Marshal(parsed.Evidence)
	if err != nil {
		return nil, fmt.Errorf("triage.Run: marshal evidence: %w", err)
	}
	var advisoryFK *uuid.UUID
	if len(advisories) > 0 {
		v := advisories[0].ID
		advisoryFK = &v
	}
	reachByComponent := make(map[uuid.UUID]uuid.UUID, len(reach))
	for _, rr := range reach {
		if rr.ComponentID == uuid.Nil {
			continue
		}
		if _, exists := reachByComponent[rr.ComponentID]; !exists {
			reachByComponent[rr.ComponentID] = rr.ID
		}
	}
	llmFK := llmCallID
	conf := parsed.Confidence
	action := AuditActionVexDraftAIGenerated
	if in.Reanalyse {
		action = AuditActionVexDraftReanalysed
	}

	// ----------------------------------------------------------------
	// Stage 3: short write tx — re-validate scope (TOCTOU) + persist
	// llm_calls + fan out drafts + per-draft audit rows. All atomic.
	// ----------------------------------------------------------------
	var drafts []*repository.VEXDraft
	if err := r.txManager.RunWrite(ctx, in.TenantID, func(ctx context.Context) error {
		// Re-validate component scope. Between Stage 1 and Stage 3 a
		// component (or the whole vulnerability link) could have been
		// deleted — silently persisting drafts pointing at gone rows
		// would corrupt the audit trail. We intersect the freshly
		// resolved set with the Stage 1 ids so we never grow the
		// fan-out beyond what the LLM was asked about.
		revalidatedIDs, err := r.revalidateComponentIDs(ctx, in, componentIDs)
		if err != nil {
			return err
		}

		// Persist the llm_calls audit row first so it commits even if
		// a downstream draft INSERT fails for a different reason.
		if err := r.llmCalls.Insert(ctx, callRecord); err != nil {
			slog.Warn("triage.Run: persist llm_calls failed",
				"tenant_id", in.TenantID, "cve_id", in.CVEID, "error", err)
			// Audit-row failure is not fatal — keep the lifecycle
			// drafts going so the user gets their verdict.
		}

		drafts = make([]*repository.VEXDraft, 0, len(revalidatedIDs))
		for _, compID := range revalidatedIDs {
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
				return fmt.Errorf("triage.Run: persist vex_draft: %w", err)
			}
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
				return fmt.Errorf("triage.Run: %w", err)
			}
			drafts = append(drafts, draft)
		}
		return nil
	}); err != nil {
		return nil, err
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
	//
	// F25: caller-supplied ComponentID intentionally bypasses the
	// maxFanOut cap. The cap exists to protect against unbounded fan-out
	// of (component, vuln) drafts in a single transaction; a request
	// pinned to one component creates exactly one draft regardless of
	// how widely the CVE spreads in the project, so the operator opt-in
	// of supplying ComponentID is the documented escape hatch.
	if in.ComponentID != nil && *in.ComponentID != uuid.Nil {
		want := *in.ComponentID
		for _, id := range ids {
			if id == want {
				return []uuid.UUID{want}, nil
			}
		}
		return nil, fmt.Errorf("triage.Run: %w", ErrComponentNotInVulnerabilityScope)
	}
	// F25: reject fan-out when the resolver returns more components than
	// the configured cap. We do NOT silently truncate the slice — a
	// partial fan-out would leave the operator uncertain about which
	// components were triaged and which were skipped. The caller is
	// expected to retry with an explicit ComponentID for each pair.
	if r.maxFanOut > 0 && len(ids) > r.maxFanOut {
		return nil, fmt.Errorf("triage.Run: %w (resolved %d components, cap is %d)",
			ErrFanOutExceeded, len(ids), r.maxFanOut)
	}
	return ids, nil
}

// revalidateComponentIDs re-runs the componentVulns resolver inside the
// Stage 3 write tx and intersects the result with the Stage 1 set so the
// runner never persists drafts for components that disappeared during
// the LLM call (M1 Codex review #F19 TOCTOU defense).
//
// Behaviour:
//   - Caller-supplied ComponentID path: if the supplied id is still in
//     the resolver's set the result is [id]; otherwise the call returns
//     ErrComponentNotInVulnerabilityScope.
//   - Fan-out path: returns the intersection of the freshly resolved
//     set with stage1IDs. An empty intersection returns
//     ErrVulnerabilityNotInTenant — the same sentinel Stage 1 would
//     have returned had the deletion happened earlier — so the handler
//     surfaces a 404 the caller already knows how to handle (mapped to
//     the generic "triage target not found" body by mapRunnerError).
//   - When the resolver is not wired (legacy/unit-test path) we trust
//     stage1IDs verbatim since there is no authoritative source to
//     re-check against. This matches the original resolveComponentIDs
//     fail-closed contract for the WHOLE call (handler maps 400).
func (r *Runner) revalidateComponentIDs(ctx context.Context, in RunInput, stage1IDs []uuid.UUID) ([]uuid.UUID, error) {
	if r.componentVulns == nil {
		return stage1IDs, nil
	}
	resolved, err := r.componentVulns.ListIDsByVulnerability(ctx, in.TenantID, in.ProjectID, in.VulnerabilityID)
	if err != nil {
		return nil, fmt.Errorf("triage.Run: revalidate component_ids: %w", err)
	}
	resolvedSet := make(map[uuid.UUID]struct{}, len(resolved))
	for _, id := range resolved {
		resolvedSet[id] = struct{}{}
	}
	// Caller-supplied component path: stage1IDs is [supplied], must still
	// be in the resolver set.
	if in.ComponentID != nil && *in.ComponentID != uuid.Nil {
		want := *in.ComponentID
		if _, ok := resolvedSet[want]; !ok {
			return nil, fmt.Errorf("triage.Run: %w", ErrComponentNotInVulnerabilityScope)
		}
		return []uuid.UUID{want}, nil
	}
	// Fan-out path: intersect stage1 set with the freshly resolved set.
	out := make([]uuid.UUID, 0, len(stage1IDs))
	for _, id := range stage1IDs {
		if _, ok := resolvedSet[id]; ok {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("triage.Run: %w", ErrVulnerabilityNotInTenant)
	}
	return out, nil
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
//
// F19: wrapped in a single TxManager.RunWrite so the AI-disabled path
// gets the same connection-pool discipline as the LLM-enabled path —
// it re-validates component scope (TOCTOU defense) then persists in
// one short write tx.
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
	var drafts []*repository.VEXDraft
	action := AuditActionVexDraftAIDisabled

	if err := r.txManager.RunWrite(ctx, in.TenantID, func(ctx context.Context) error {
		// F19 TOCTOU: re-validate componentIDs in the write tx so a
		// deletion between Stage 1 and Stage 3 is caught.
		revalidatedIDs, err := r.revalidateComponentIDs(ctx, in, componentIDs)
		if err != nil {
			return err
		}
		drafts = make([]*repository.VEXDraft, 0, len(revalidatedIDs))
		for _, compID := range revalidatedIDs {
			draft := &repository.VEXDraft{
				ID:              uuid.New(),
				TenantID:        in.TenantID,
				ProjectID:       in.ProjectID,
				ComponentID:     compID,
				VulnerabilityID: in.VulnerabilityID,
				CVEID:           in.CVEID,
				State:           string(StateUnderInvestigation),
				Detail:          "AI triage skipped: " + reason,
				Confidence:      &zeroConf,
				Provider:        provider.Name(),
				Model:           provider.Model(),
				Evidence:        evidenceJSON,
				Decision:        DecisionPending,
				CreatedBy:       in.UserID,
			}
			if err := r.drafts.Insert(ctx, draft); err != nil {
				return fmt.Errorf("triage.runAIDisabled: persist vex_draft: %w", err)
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
				return fmt.Errorf("triage.runAIDisabled: %w", err)
			}
			drafts = append(drafts, draft)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &RunResult{
		Draft:      drafts[0],
		Drafts:     drafts,
		Threshold:  r.threshold,
		AIDisabled: true,
	}, nil
}

// GetDraft returns one draft scoped to tenant.
//
// F19: wrapped in TxManager.RunRead so the call works without an ambient
// TenantTx — required because /triage/run and /vex-drafts/:id/reanalyse
// have TenantTx stripped (the runner manages its own tx lifecycle to
// release the Postgres connection during the slow Stage 2 LLM call).
// When an ambient tx already exists on ctx (other vex-drafts routes
// still wrap in TenantTx), the TxManager detects it and reuses — no
// nested tx is opened.
func (r *Runner) GetDraft(ctx context.Context, tenantID, draftID uuid.UUID) (*repository.VEXDraft, error) {
	if tenantID == uuid.Nil {
		return nil, errors.New("triage.GetDraft: tenant_id is required")
	}
	if draftID == uuid.Nil {
		return nil, errors.New("triage.GetDraft: draft_id is required")
	}
	var draft *repository.VEXDraft
	if err := r.txManager.RunRead(ctx, tenantID, func(ctx context.Context) error {
		d, err := r.drafts.Get(ctx, tenantID, draftID)
		if err != nil {
			return err
		}
		draft = d
		return nil
	}); err != nil {
		return nil, err
	}
	return draft, nil
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
		ResourceType: model.ResourceVEXDraft,
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

// VEXTriageSystemPrompt steers the LLM toward the strict JSON contract
// the parser expects. We intentionally bake the allowlist into the
// system prompt so the model has the schema in-context.
//
// M4-3 (※要確認): exported so the apps/api/cmd/llm-bench harness can
// reuse the *exact* runtime prompt rather than maintaining a drifted
// copy that would invalidate prompt_hash analytics. The original
// unexported name remains as a const alias below so unit tests inside
// this package keep compiling without rename churn.
//
// ※要確認: prompt wording may need iteration once the M1-4 eval set
// lands. Keep prompt changes Tracked so prompt_hash analytics stay
// meaningful (any prompt edit invalidates historical equality joins).
const VEXTriageSystemPrompt = `You are SBOMHub's AI VEX triage assistant.

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

// vexTriageSystemPrompt is the legacy unexported alias kept so the
// runner body (and any in-package tests) compile unchanged after the
// M4-3 export rename. New callers (e.g. cmd/llm-bench) should use
// VEXTriageSystemPrompt directly.
const vexTriageSystemPrompt = VEXTriageSystemPrompt

// BuildPrompt constructs the user-turn prompt body. The advisory +
// reachability data is rendered as compact JSON so the LLM can address
// individual rows by index in its evidence list.
//
// M4-3 (※要確認): exported so cmd/llm-bench can render the *exact*
// runtime prompt. The original unexported name remains as a thin
// wrapper below so existing in-package callers (Run() at line 659)
// compile without churn.
func BuildPrompt(cveID string, advisories []AdvisoryExcerptRow, reach []ReachabilityRow) string {
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

// buildPrompt is the legacy unexported alias retained so the runner
// body compiles unchanged after the M4-3 export. New callers should
// use BuildPrompt directly.
func buildPrompt(cveID string, advisories []AdvisoryExcerptRow, reach []ReachabilityRow) string {
	return BuildPrompt(cveID, advisories, reach)
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
