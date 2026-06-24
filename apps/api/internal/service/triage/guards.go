package triage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
)

// DefaultConfidenceThreshold is the M1 default below which any LLM
// decision is clamped to under_investigation. Calibrated against the
// MVP eval set; operators can override via SBOMHUB_AI_CONFIDENCE_THRESHOLD.
//
// ※要確認: 0.7 is a placeholder; the M1-4 LLM evaluation set should
// confirm/adjust before GA. See PRODUCT_REBOOT_PLAN.md §8.5.
const DefaultConfidenceThreshold = 0.7

// EnvConfidenceThreshold is the env var consulted by ConfidenceThresholdFromEnv.
const EnvConfidenceThreshold = "SBOMHUB_AI_CONFIDENCE_THRESHOLD"

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
