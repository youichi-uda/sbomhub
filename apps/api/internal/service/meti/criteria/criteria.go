// Package criteria holds the per-criterion evaluation logic for the
// METI self-assessment catalog (apps/api/internal/service/meti/catalog.yaml,
// 32 criteria across env_setup / sbom_creation / sbom_operation phases
// after M8-1, issue #62 reached IPA 32-item full coverage).
//
// Layering (M3-2, issue #40 / M8-1, issue #62):
//
//   - criteria.go        — Deps interface, Result type, Func signature,
//     shared evidence / status helpers.
//   - env_setup.go       — 11 per-criterion functions (phase 1; +3 in M8-1).
//   - sbom_creation.go   — 10 per-criterion functions (phase 2; +1 in M8-1).
//   - sbom_operation.go  — 11 per-criterion functions (phase 3; +1 in M8-1).
//   - registry.go        — Registry map criterion_id -> Func, the single
//     dispatch surface consumed by service/meti
//     .Evaluator.
//
// Why a separate package: the parent service/meti package owns the
// catalog (LoadCatalog / GetCriterion / ListByPhase) and the Evaluator
// orchestration. Keeping per-criterion logic in a child package lets
// the orchestration import the criteria functions without forming a
// cycle, and lets unit tests pass a fake Deps without standing up
// concrete repositories.
//
// Design discipline:
//
//   - All functions are pure: they read through Deps, do not write, do
//     not mutate global state. The Upsert into meti_assessments is the
//     M3-4 handler's responsibility, not this package's.
//   - No LLM. M3 is explicitly AI-free (PRODUCT_REBOOT_PLAN.md §13).
//   - Status mapping is a small closed set:
//     achieved        — auto-signal confirms.
//     not_achieved    — auto-signal confirms the requirement is
//     NOT met (e.g. SBOM tool selected but zero
//     sboms uploaded).
//     needs_review    — auto-signal cannot resolve; operator must
//     attest manually via the M3-4 override path.
//     not_applicable  — the criterion legitimately does not apply
//     to this project (used sparingly; M3-4
//     handler / operator override is the dominant
//     source).
//   - Evidence is always a JSON array (json.RawMessage). Empty `[]` is
//     legitimate for needs_review / not_applicable rows; the
//     meti_assessments DB CHECK accepts that.
//   - ImprovementAction is a short Japanese sentence aligned with the
//     catalog description_ja; UI surfaces it as the operator's "next
//     step". For achieved rows it is empty.
package criteria

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Status enumerates the four meti_assessments.status allow-list values.
// Defined as untyped string constants so callers can compose them with
// the repository struct (which carries a plain string) without an
// explicit cast.
const (
	StatusAchieved      = "achieved"
	StatusNotAchieved   = "not_achieved"
	StatusNeedsReview   = "needs_review"
	StatusNotApplicable = "not_applicable"
)

// Result is the per-criterion verdict returned by an evaluator
// function. It intentionally omits CriterionID — the caller (registry
// dispatcher) holds the id and stamps it into the higher-level
// CriterionResult.
//
// Evidence is always a JSON array; helpers below guarantee that
// invariant so per-criterion authors do not have to remember to call
// json.Marshal explicitly.
type Result struct {
	Status            string
	Evidence          json.RawMessage
	ImprovementAction string
}

// Func is the per-criterion evaluator signature. tenantID and
// projectID come from the M3-4 handler; both are validated upstream
// (must be non-zero UUIDs). Returning an error is reserved for
// underlying storage failures — a "no data found" condition should
// resolve to needs_review with empty evidence rather than an error,
// so the dashboard can still render a row for every criterion.
type Func func(ctx context.Context, deps Deps, tenantID, projectID uuid.UUID) (Result, error)

// Deps is the narrow read-only interface the per-criterion functions
// see. It is intentionally a single interface (not one per criterion)
// so:
//
//   - the production wiring in service/meti/evaluator.go can supply
//     one *repoDeps adapter that satisfies the whole surface in one
//     place;
//   - unit tests in this package can compose a single fakeDeps struct
//     with field-per-call hooks rather than juggling N tiny mocks.
//
// Every method here is read-only. Writes (meti_assessments Upsert /
// override) live in the M3-4 handler, not in criteria functions.
type Deps interface {
	// --- SBOM + components -------------------------------------------------

	// GetLatestSbom returns the most recent SBOM for the project or
	// (nil, nil) if no SBOM has been uploaded. The repository surface
	// returns sql.ErrNoRows on miss; the adapter MUST normalise that
	// to (nil, nil) so per-criterion logic does not have to import
	// database/sql.
	GetLatestSbom(ctx context.Context, projectID uuid.UUID) (*model.Sbom, error)

	// ListSbomsByProject returns every SBOM ever uploaded for the
	// project, ordered by created_at DESC. Used for cadence checks
	// (sbom_creation.01 / .08 / sbom_operation.09).
	ListSbomsByProject(ctx context.Context, projectID uuid.UUID) ([]model.Sbom, error)

	// ListComponentsBySbom returns the parsed components of a single
	// SBOM. Used for ecosystem-coverage (env_setup.02), component
	// presence (sbom_creation.03), unknown-version detection
	// (sbom_creation.04) and minimum-elements (sbom_creation.06).
	ListComponentsBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.Component, error)

	// --- Vulnerabilities ---------------------------------------------------

	// ListVulnerabilitiesByProject returns the project's matched
	// vulnerabilities (NVD/JVN scan output). Used for the vulnerability-
	// monitoring (.01) and prioritisation (.03) criteria.
	ListVulnerabilitiesByProject(ctx context.Context, projectID uuid.UUID) ([]model.Vulnerability, error)

	// --- VEX drafts --------------------------------------------------------

	// ListVEXDraftsByProject returns the project's VEX drafts (incl.
	// AI-drafted ones). Used by sbom_operation.04 to check whether a
	// human decision has been recorded.
	ListVEXDraftsByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]repository.VEXDraft, error)

	// --- CRA reports -------------------------------------------------------

	// ListCRAReportsByProject returns the project's CRA reports. Used
	// by sbom_operation.08 (incident response process) and as an
	// auto-augment signal for env_setup.04 (EU CRA scope confirmed
	// when at least one CRA report exists).
	ListCRAReportsByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]repository.CRAReport, error)

	// --- Public links ------------------------------------------------------

	// ListPublicLinksByProject returns the project's public sharing
	// links. Used by sbom_creation.07 (sharing channel established)
	// and as an auto-augment signal for env_setup.05.
	ListPublicLinksByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.PublicLink, error)

	// --- License -----------------------------------------------------------

	// ListLicensePoliciesByProject returns the project's license
	// policies. Used by sbom_operation.05.
	ListLicensePoliciesByProject(ctx context.Context, projectID uuid.UUID) ([]model.LicensePolicy, error)

	// --- EOL ---------------------------------------------------------------

	// GetEOLSummary returns the EOL coverage stats for the project.
	// May return (nil, nil) when no EOL analysis has been performed.
	GetEOLSummary(ctx context.Context, projectID uuid.UUID) (*model.EOLSummary, error)

	// --- KEV sync (global, tenant-agnostic) --------------------------------

	// GetKEVSyncSettings returns the singleton KEV sync settings row
	// or (nil, nil) when the row has never been initialised. Used by
	// sbom_operation.02 to confirm a vulnerability-source feed is wired
	// in. ※要確認: NVD / JVN sync also has settings tables (model.NVD…,
	// model.JVN…); current evaluator scopes the freshness check to KEV
	// only, which is the most commonly-configured feed. Adding NVD/JVN
	// parity is a follow-up — track via a needs_review path when the
	// KEV row is missing.
	GetKEVSyncSettings(ctx context.Context) (*model.KEVSyncSettings, error)

	// --- Audit log ---------------------------------------------------------

	// CountAuditLogsForTenant returns the total count of audit_logs
	// rows for the tenant. Used by sbom_operation.07 (retention
	// activity exists) and .10 (audit log presence).
	CountAuditLogsForTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
}

// emptyEvidence returns the canonical empty JSONB array. needs_review
// and not_applicable rows commonly use this when there is literally no
// auto-signal to cite (the operator will fill in evidence via the
// M3-4 override flow).
func emptyEvidence() json.RawMessage {
	return json.RawMessage(`[]`)
}

// mustEvidence marshals a slice of evidence entries to JSON and panics
// on error. Panic is acceptable here because every call site builds the
// slice from typed Go values (string / int / bool) that json.Marshal
// cannot fail on; a panic would indicate a programmer error not a
// runtime data condition.
func mustEvidence(entries []map[string]any) json.RawMessage {
	if len(entries) == 0 {
		return emptyEvidence()
	}
	b, err := json.Marshal(entries)
	if err != nil {
		// Programmer error: every entry value is a Go primitive that
		// must marshal. Fall back to empty array so the caller still
		// gets a valid JSONB shape rather than nil.
		return emptyEvidence()
	}
	return b
}

// evidenceEntry is a tiny constructor that keeps evaluator code
// readable — `evidenceEntry("kind", "value")` instead of an inline
// map literal at every call site.
func evidenceEntry(kind string, value any) map[string]any {
	return map[string]any{"kind": kind, "value": value}
}
