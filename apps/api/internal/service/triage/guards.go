package triage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvLLMTimeoutSeconds is the env var consulted by LLMTimeoutFromEnv.
const EnvLLMTimeoutSeconds = "SBOMHUB_LLM_TIMEOUT_SECONDS"

// LLMTimeoutFromEnv returns the operator-configured LLM call timeout,
// falling back to DefaultLLMTimeout seconds when the env var is unset
// or unparseable. Negative / zero values are rejected so a misconfigured
// operator cannot silently disable the bound by setting 0.
//
// M1 Codex review #F19 (part 3): every triage Provider.Complete is
// wrapped in context.WithTimeout(ctx, LLMTimeoutFromEnv()) so a slow /
// hanging upstream LLM cannot pin a goroutine forever.
func LLMTimeoutFromEnv() time.Duration {
	raw := os.Getenv(EnvLLMTimeoutSeconds)
	if raw == "" {
		return time.Duration(DefaultLLMTimeout) * time.Second
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return time.Duration(DefaultLLMTimeout) * time.Second
	}
	return time.Duration(v) * time.Second
}

// DefaultConfidenceThreshold is the M1 default below which any LLM
// decision is clamped to under_investigation. Calibrated against the
// MVP eval set; operators can override via SBOMHUB_AI_CONFIDENCE_THRESHOLD.
//
// ※要確認: 0.7 is a placeholder; the M1-4 LLM evaluation set should
// confirm/adjust before GA. See PRODUCT_REBOOT_PLAN.md §8.5.
const DefaultConfidenceThreshold = 0.7

// EnvConfidenceThreshold is the env var consulted by ConfidenceThresholdFromEnv.
const EnvConfidenceThreshold = "SBOMHUB_AI_CONFIDENCE_THRESHOLD"

// DefaultLLMTimeout bounds Provider.Complete during triage so a hanging
// upstream cannot block a request forever. Configurable per-deployment via
// SBOMHUB_LLM_TIMEOUT_SECONDS. 90s is the M1 default — most LLM providers
// cap at 60s of model think-time and we keep a 30s margin for TLS / first
// byte / response decoding. M1 Codex review #F19 (part 3).
const DefaultLLMTimeout = 90

// DefaultMaxFanOut bounds the number of (component, vuln) drafts a single
// triage request may create when the caller omits ComponentID. M1 Codex
// review #F25: without this cap a write-scoped API key could target a CVE
// linked to thousands of components in the project and force the runner
// to persist one vex_drafts row + one audit_logs row per component inside
// a single transaction — a single-request DoS that bloats both the
// response body and the audit table. Operators with legitimate large
// fan-outs override via SBOMHUB_TRIAGE_MAX_FANOUT.
//
// ※要確認: 20 is a conservative default; once we have real-world data on
// triage fan-out distribution this can be tuned. The cap is intentionally
// low enough that a single accidentally over-broad CVE (e.g. an OpenSSL
// transitive used by every container) cannot fill the response body / audit
// table without an explicit operator opt-in.
const DefaultMaxFanOut = 20

// EnvMaxFanOut is the env var consulted by MaxFanOutFromEnv.
const EnvMaxFanOut = "SBOMHUB_TRIAGE_MAX_FANOUT"

// MaxFanOutFromEnv returns the operator-configured fan-out cap, falling
// back to DefaultMaxFanOut when the env var is unset or unparseable.
// Negative / zero values are rejected so a misconfigured operator cannot
// silently disable the cap by setting 0.
//
// M1 Codex review #F25: the runner consults this once at construction
// time (NewRunner) to fill Runner.maxFanOut. Callers that need a fixed
// cap for tests pass RunnerConfig.MaxFanOut explicitly.
func MaxFanOutFromEnv() int {
	raw := os.Getenv(EnvMaxFanOut)
	if raw == "" {
		return DefaultMaxFanOut
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return DefaultMaxFanOut
	}
	return v
}

// Sentinel errors returned by the guards layer. The runner converts them
// to the appropriate HTTP status (422 for ErrEmptyEvidence, 400 for the
// allowlist errors).
var (
	// ErrEmptyEvidence is returned by ValidateEvidence when the evidence
	// slice is nil or zero-length. PRODUCT_REBOOT_PLAN.md §8.5: "evidence
	// なしの出力は保存しない".
	ErrEmptyEvidence = errors.New("triage: evidence is required (no evidence pointers supplied)")

	// ErrInvalidEvidence is returned when an EvidencePointer is structurally
	// unusable (e.g. unknown Kind, or Kind=symbol_ref with no symbol).
	ErrInvalidEvidence = errors.New("triage: evidence pointer is invalid")
)

// ConfidenceThresholdFromEnv returns the operator-configured threshold,
// falling back to DefaultConfidenceThreshold when the env var is unset
// or unparseable. Out-of-range values ([0,1]) are also rejected so that
// a misconfigured operator cannot silently disable the guard by setting
// e.g. -1 or 99.
//
// The function never panics and never returns an error: a bad env value
// is treated as "use the default" because this code is on the hot path
// of every triage decision and we prefer safe-by-default to crashing.
func ConfidenceThresholdFromEnv() float64 {
	raw := os.Getenv(EnvConfidenceThreshold)
	if raw == "" {
		return DefaultConfidenceThreshold
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return DefaultConfidenceThreshold
	}
	if v < 0.0 || v > 1.0 {
		return DefaultConfidenceThreshold
	}
	return v
}

// ApplyConfidenceThreshold enforces the §8.5 safety valve: if confidence
// is strictly less than threshold, the returned state is forced to
// under_investigation regardless of what the LLM proposed. The boolean
// return tells the runner whether a clamp happened (so it can log it).
//
// NaN confidence is treated as "below threshold" — that is, NaN always
// clamps. This matches the §8.5 intent ("低確信は under_investigation
// に倒す") rather than the IEEE-754 default of any comparison-against-NaN
// being false (which would otherwise let NaN slip through).
//
// If the input state is empty or not in the allowlist, the result is
// also forced to under_investigation. This double-duties as a final
// safety net for callers that forgot to run IsValidState first.
//
// Threshold is clamped to [0,1] for defence-in-depth; values outside
// that range are treated as the nearest endpoint.
func ApplyConfidenceThreshold(state string, confidence float64, threshold float64) (newState string, clamped bool) {
	// Clamp the threshold itself defensively so a caller passing -1 or 99
	// (e.g. from a misparsed config) cannot silently disable / over-trigger.
	if threshold < 0.0 {
		threshold = 0.0
	}
	if threshold > 1.0 {
		threshold = 1.0
	}

	// NaN-safe: !(confidence >= threshold) covers NaN (always clamps).
	belowThreshold := !(confidence >= threshold)

	if belowThreshold {
		return string(StateUnderInvestigation), true
	}

	// Confidence is OK; still gate on a valid state.
	if !IsValidState(state) {
		return string(StateUnderInvestigation), true
	}
	return state, false
}

// ValidateEvidence returns ErrEmptyEvidence when evidence is nil/empty,
// and ErrInvalidEvidence (wrapped with index + reason) when any pointer
// is structurally unusable.
//
// "Structurally unusable" intentionally errs on the strict side:
//
//   - Kind must be non-empty and in the enum.
//   - symbol_ref must carry Symbol (so the UI has something to render).
//   - import_path must carry ImportPath.
//   - advisory_excerpt must carry RawSnippet OR Description.
//   - analyzer_error / llm_rationale must carry Description.
//
// Looser rules are tempting but encourage LLMs to emit `{"kind":"..."}`
// stubs that pass evidence-required checks while carrying zero signal.
// The runner (#29 agent B) calls this before persisting any vex_draft.
func ValidateEvidence(evidence []EvidencePointer) error {
	if len(evidence) == 0 {
		return ErrEmptyEvidence
	}
	for i, ev := range evidence {
		if err := validateOnePointer(ev); err != nil {
			return fmt.Errorf("%w: evidence[%d]: %v", ErrInvalidEvidence, i, err)
		}
	}
	return nil
}

func validateOnePointer(ev EvidencePointer) error {
	switch ev.Kind {
	case EvidenceKindImportPath:
		if ev.ImportPath == "" {
			return errors.New("import_path evidence requires ImportPath")
		}
	case EvidenceKindSymbolRef:
		if ev.Symbol == "" {
			return errors.New("symbol_ref evidence requires Symbol")
		}
	case EvidenceKindAdvisoryExcerpt:
		if ev.RawSnippet == "" && ev.Description == "" {
			return errors.New("advisory_excerpt evidence requires RawSnippet or Description")
		}
	case EvidenceKindLLMRationale:
		if ev.Description == "" {
			return errors.New("llm_rationale evidence requires Description")
		}
	case EvidenceKindAnalyzerError:
		if ev.Description == "" {
			return errors.New("analyzer_error evidence requires Description")
		}
	case "":
		return errors.New("evidence Kind must be set")
	default:
		return fmt.Errorf("unknown evidence Kind %q", ev.Kind)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Grounding guard (M32 Wave B, P2)
// ----------------------------------------------------------------------------
//
// ValidateEvidence above only validates the SHAPE of the LLM's
// self-reported evidence: an advisory_excerpt pointer passes on a
// Description the model wrote itself, with nothing tying it to the advisory
// / reachability rows the runner actually loaded. In production those
// tables are frequently empty, so the LLM fabricates evidence pointers that
// pass ValidateEvidence and flow straight through to the human approver as a
// confident, fabricated-evidence VEX.
//
// The helpers below let the runner harden that gap in two tiers:
//
//   - Tier 1 (IsUngrounded + UngroundedNote + UngroundedConfidenceCeiling):
//     a zero-grounding clamp. When NO grounding data was loaded at all, a
//     confident non-under_investigation verdict cannot be trusted; the
//     runner forces under_investigation, clamps confidence below threshold,
//     and appends an honest synthetic note preserving the AI's proposal.
//
//   - Tier 2 (ValidateGrounding): a per-pointer cross-check. Each
//     grounded-kind pointer is matched (case-insensitive substring) against
//     the loaded rows; unmatched ones are FLAGGED (never dropped, never
//     hard-reject) so a legitimate paraphrase is not lost, while a fabricated
//     citation gets marked unverified and the draft's confidence is clamped.
//
// Both tiers reuse the existing under_investigation state + a synthetic
// note + a confidence clamp as the "requires human verification" signal —
// no new draft field or DB column is introduced.

const (
	// UngroundedNoteTag marks the synthetic evidence pointer appended by
	// UngroundedNote so the web layer / audit consumers can detect a
	// Tier-1-clamped draft without parsing free text.
	UngroundedNoteTag = "ungrounded"

	// UnverifiedGroundingTag marks a grounded-kind evidence pointer that
	// ValidateGrounding could not match against any loaded advisory /
	// reachability row. It is appended to the pointer's Note in place; the
	// pointer is retained (lenient — flag, never drop).
	UnverifiedGroundingTag = "unverified_grounding"
)

// GroundingResult summarises a ValidateGrounding pass.
type GroundingResult struct {
	// GroundedKinds counts pointers of a grounded kind (advisory_excerpt /
	// symbol_ref / import_path) that were cross-checked.
	GroundedKinds int
	// Matched counts grounded-kind pointers that matched a loaded row.
	Matched int
	// Unverified counts grounded-kind pointers that matched nothing and were
	// flagged in place.
	Unverified int
	// Exempt counts self-referential pointers (llm_rationale / analyzer_error)
	// that are never cross-checked — this is REQUIRED so fallbackDecision
	// drafts and the Tier-1 synthetic note are never flagged.
	Exempt int
}

// IsUngrounded reports whether NO grounding data was loaded for a triage
// cycle — neither an advisory excerpt nor a reachability row. When true, any
// grounded-kind evidence the LLM cited is unbacked by retrieved data and a
// confident verdict must be clamped (Tier 1).
func IsUngrounded(advisories []AdvisoryExcerptRow, reach []ReachabilityRow) bool {
	return len(advisories) == 0 && len(reach) == 0
}

// UngroundedConfidenceCeiling maps an auto-approve threshold to the
// confidence an ungrounded / unverified draft is clamped to. It is always
// strictly below the threshold (so a clamped draft can never re-present as
// high-confidence) while staying non-negative. Half the threshold keeps a
// small honest "low confidence" signal without implying near-approval.
func UngroundedConfidenceCeiling(threshold float64) float64 {
	if threshold <= 0 {
		return 0
	}
	if threshold > 1 {
		threshold = 1
	}
	return threshold / 2
}

// UngroundedNote builds the synthetic evidence pointer appended to an
// ungrounded draft (Tier 1). It records HONESTLY that no advisory /
// reachability evidence backed the verdict, preserving the AI's original
// proposal (state@confidence) inside the Description so the human approver
// can see what the model claimed before the clamp. Its kind is
// analyzer_error, which ValidateGrounding treats as exempt, so re-running
// the guard never flags this note.
func UngroundedNote(origState string, origConfidence float64) EvidencePointer {
	return EvidencePointer{
		Kind:   EvidenceKindAnalyzerError,
		Source: "grounding_guard",
		Note:   UngroundedNoteTag,
		Description: fmt.Sprintf(
			"ungrounded: no advisory excerpt or reachability evidence was available for this (project, CVE); AI proposed %s@%.2f but the draft is ungrounded and requires human verification",
			origState, origConfidence,
		),
	}
}

// ValidateGrounding cross-checks each evidence pointer against the loaded
// advisory / reachability rows and marks unmatched grounded-kind pointers
// unverified IN PLACE (mutating evidence[i].Note). It NEVER deletes a
// pointer and NEVER returns an error — the lenient contract avoids
// false-negatives when the LLM legitimately paraphrases. The runner reads
// the returned GroundingResult to decide whether to clamp confidence.
//
// Matching rules:
//   - advisory_excerpt: RawSnippet (else Description) must be a
//     case-insensitive substring of some advisory's RawExcerpt, or appear in
//     one of its structured JSON fields (VulnFuncs / AffectedPaths / ...).
//   - symbol_ref / import_path: Symbol / ImportPath (else Description) must
//     appear in some reachability row's Evidence JSON.
//   - llm_rationale / analyzer_error: EXEMPT (self-referential). Never
//     flagged — this keeps fallbackDecision drafts and the Tier-1 synthetic
//     note clean.
func ValidateGrounding(evidence []EvidencePointer, advisories []AdvisoryExcerptRow, reach []ReachabilityRow) GroundingResult {
	var res GroundingResult
	for i := range evidence {
		ev := &evidence[i]
		switch ev.Kind {
		case EvidenceKindAdvisoryExcerpt:
			res.GroundedKinds++
			if advisoryPointerGrounded(*ev, advisories) {
				res.Matched++
			} else {
				res.Unverified++
				markUnverifiedGrounding(ev)
			}
		case EvidenceKindSymbolRef, EvidenceKindImportPath:
			res.GroundedKinds++
			if reachPointerGrounded(*ev, reach) {
				res.Matched++
			} else {
				res.Unverified++
				markUnverifiedGrounding(ev)
			}
		case EvidenceKindLLMRationale, EvidenceKindAnalyzerError:
			// EXEMPT — self-referential kinds are never cross-checked.
			res.Exempt++
		default:
			// Unknown kinds are already rejected by ValidateEvidence; ignore.
		}
	}
	return res
}

// advisoryPointerGrounded reports whether an advisory_excerpt pointer's
// quoted text appears (case-insensitively) in some loaded advisory row.
func advisoryPointerGrounded(ev EvidencePointer, advisories []AdvisoryExcerptRow) bool {
	needle := firstNonEmpty(ev.RawSnippet, ev.Description)
	if needle == "" {
		return false
	}
	nlow := strings.ToLower(strings.TrimSpace(needle))
	if nlow == "" {
		return false
	}
	for _, a := range advisories {
		if a.RawExcerpt != "" && strings.Contains(strings.ToLower(a.RawExcerpt), nlow) {
			return true
		}
		if jsonRawContainsFold(a.VulnFuncs, nlow) ||
			jsonRawContainsFold(a.AffectedPaths, nlow) ||
			jsonRawContainsFold(a.RequiredConfig, nlow) ||
			jsonRawContainsFold(a.RequiredEnv, nlow) {
			return true
		}
	}
	return false
}

// reachPointerGrounded reports whether a symbol_ref / import_path pointer's
// symbol/path appears (case-insensitively) in some loaded reachability row's
// Evidence JSON.
func reachPointerGrounded(ev EvidencePointer, reach []ReachabilityRow) bool {
	needle := firstNonEmpty(ev.Symbol, ev.ImportPath, ev.Description)
	if needle == "" {
		return false
	}
	nlow := strings.ToLower(strings.TrimSpace(needle))
	if nlow == "" {
		return false
	}
	for _, rr := range reach {
		if jsonRawContainsFold(rr.Evidence, nlow) {
			return true
		}
	}
	return false
}

// markUnverifiedGrounding appends UnverifiedGroundingTag to a pointer's Note
// without clobbering existing Note content (e.g. the LLM's per-pointer
// rationale). Idempotent: a pointer is tagged at most once.
func markUnverifiedGrounding(ev *EvidencePointer) {
	if strings.Contains(ev.Note, UnverifiedGroundingTag) {
		return
	}
	if ev.Note == "" {
		ev.Note = UnverifiedGroundingTag
		return
	}
	ev.Note = ev.Note + "; " + UnverifiedGroundingTag
}

// jsonRawContainsFold reports whether the lowercased raw JSON bytes contain
// needleLower (already lowercased). Heuristic substring match — see the
// package-level caveat about paraphrase false-negatives.
func jsonRawContainsFold(raw json.RawMessage, needleLower string) bool {
	if len(raw) == 0 || needleLower == "" {
		return false
	}
	return strings.Contains(strings.ToLower(string(raw)), needleLower)
}

// firstNonEmpty returns the first non-empty (after trimming) argument.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// IsValidState reports whether s is in the CycloneDX VEX 1.5 state
// allowlist as used by M1. Empty string is rejected.
func IsValidState(s string) bool {
	switch State(s) {
	case StateNotAffected,
		StateAffected,
		StateUnderInvestigation,
		StateResolved:
		return true
	default:
		return false
	}
}

// IsValidJustification reports whether j is in the CycloneDX VEX 1.5
// justification allowlist. The empty string is accepted so callers do
// not have to special-case states that legitimately carry no
// justification (state=affected, state=under_investigation).
func IsValidJustification(j string) bool {
	if j == "" {
		return true
	}
	switch Justification(j) {
	case JustificationCodeNotPresent,
		JustificationCodeNotReachable,
		JustificationRequiresConfiguration,
		JustificationRequiresDependency,
		JustificationRequiresEnvironment,
		JustificationProtectedByCompiler,
		JustificationProtectedAtPerimeter,
		JustificationProtectedAtRuntime,
		JustificationInlineMitigationsAlreadyExist:
		return true
	default:
		return false
	}
}

// llmResponseDTO is the on-the-wire shape we ask the LLM to emit. We
// keep it separate from ParsedDecision so ParseLLMResponse can clamp
// out-of-allowlist values (state="maybe" → under_investigation) instead
// of failing strict json.Unmarshal.
type llmResponseDTO struct {
	State         string            `json:"state"`
	Justification string            `json:"justification,omitempty"`
	Detail        string            `json:"detail,omitempty"`
	Confidence    float64           `json:"confidence"`
	Evidence      []EvidencePointer `json:"evidence,omitempty"`
}

// ParseLLMResponse parses a raw LLM JSON response into a ParsedDecision.
//
// Failure policy (§8.5 fallback): any parse / structural failure returns
// a synthetic ParsedDecision with state=under_investigation, confidence=0,
// and a single llm_rationale evidence pointer carrying the raw response
// + parse error. Critically, the returned error is always nil — the
// runner must never lose a draft because the LLM emitted bad JSON.
// Callers that care about parse-failure-vs-success can look at the
// presence of the llm_rationale "parse_error" Note.
//
// Allowlist enforcement happens here too: an unknown state collapses
// to under_investigation; an unknown justification is cleared (so the
// runner can re-prompt or surface the raw value via Detail). Confidence
// is clamped to [0,1]; NaN / Inf are treated as 0.
func ParseLLMResponse(jsonStr string) (*ParsedDecision, error) {
	dto := llmResponseDTO{}
	if err := json.Unmarshal([]byte(jsonStr), &dto); err != nil {
		return fallbackDecision(jsonStr, fmt.Sprintf("json unmarshal failed: %v", err)), nil
	}

	// State allowlist (collapse unknown to under_investigation).
	state := State(dto.State)
	if !IsValidState(string(state)) {
		state = StateUnderInvestigation
	}

	// Justification allowlist (clear unknowns so the runner can surface
	// the bad value via Detail rather than persist garbage).
	just := Justification(dto.Justification)
	if !IsValidJustification(string(just)) {
		just = ""
	}

	// Confidence: clamp range, treat NaN/Inf as 0 for safety.
	conf := dto.Confidence
	if conf != conf { // NaN check (NaN != NaN by IEEE-754).
		conf = 0
	}
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}

	return &ParsedDecision{
		State:         state,
		Justification: just,
		Detail:        dto.Detail,
		Confidence:    conf,
		Evidence:      dto.Evidence,
		RawResponse:   jsonStr,
	}, nil
}

// fallbackDecision builds the synthetic under_investigation result used
// when ParseLLMResponse cannot trust the LLM output. It always carries
// at least one evidence pointer (llm_rationale) so that downstream
// ValidateEvidence does not also reject it — fallback drafts are
// supposed to be saved-and-flagged, not dropped.
func fallbackDecision(raw, reason string) *ParsedDecision {
	return &ParsedDecision{
		State:      StateUnderInvestigation,
		Confidence: 0,
		Detail:     "LLM response could not be parsed; defaulted to under_investigation.",
		Evidence: []EvidencePointer{{
			Kind:        EvidenceKindLLMRationale,
			Source:      "llm",
			Description: reason,
			Note:        "parse_error",
			RawSnippet:  raw,
		}},
		RawResponse: raw,
	}
}
