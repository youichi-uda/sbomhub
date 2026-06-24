// Package triage implements the AI VEX triage pipeline for M1
// (GitHub issues #27, #28, #29; PRODUCT_REBOOT_PLAN.md §7.1).
//
// The package layers as follows:
//
//   - types.go    — value types (State, Justification, EvidencePointer,
//                   ParsedDecision) consumed by guards and the runner.
//   - guards.go   — pure validation / clamping helpers (this issue, #29).
//   - runner.go   — orchestrates advisory → reachability → LLM → draft
//                   (agent B, separate issue).
//
// The guards layer deliberately stays pure (no DB / HTTP / file I/O) so
// it can be exhaustively unit-tested in isolation. The runner (Wave M1-5)
// is responsible for wiring guards onto persistence and the LLM client.
//
// State / Justification allowlists follow the CycloneDX VEX 1.5 spec
// (see PRODUCT_REBOOT_PLAN.md §7.1 "VEX出力" and LLM_PROVIDER_DESIGN.md
// §7.4). ※要確認: internal/model/vex.go currently encodes the older
// CycloneDX 1.4 justification names (e.g. "vulnerable_code_not_present");
// the M1 triage pipeline uses the 1.5 names ("code_not_present" etc.) per
// the issue spec. The runner (#29 agent B) is expected to translate
// between the two when persisting via the existing vex_drafts repository.
package triage

// State is a CycloneDX VEX 1.5 `analysis.state` value.
//
// Only the four values in the M1 allowlist are accepted by IsValidState.
// `fixed` from CycloneDX 1.4 is intentionally not in the allowlist for
// M1 — drafts that would have been `fixed` are mapped to `resolved`
// per PRODUCT_REBOOT_PLAN.md §7.1.
type State string

const (
	StateNotAffected        State = "not_affected"
	StateAffected           State = "affected"
	StateUnderInvestigation State = "under_investigation"
	StateResolved           State = "resolved"
)

// Justification is a CycloneDX VEX 1.5 `analysis.justification` value.
//
// The allowlist is intentionally limited to the nine names enumerated in
// PRODUCT_REBOOT_PLAN.md §7.1. Bare `""` is also accepted by callers that
// have no justification to emit (e.g. state=affected); IsValidJustification
// returns true for the empty string so the runner does not have to special
// case it.
type Justification string

const (
	JustificationCodeNotPresent             Justification = "code_not_present"
	JustificationCodeNotReachable           Justification = "code_not_reachable"
	JustificationRequiresConfiguration      Justification = "requires_configuration"
	JustificationRequiresDependency         Justification = "requires_dependency"
	JustificationRequiresEnvironment        Justification = "requires_environment"
	JustificationProtectedByCompiler        Justification = "protected_by_compiler"
	JustificationProtectedAtPerimeter       Justification = "protected_at_perimeter"
	JustificationProtectedAtRuntime         Justification = "protected_at_runtime"
	JustificationInlineMitigationsAlreadyExist Justification = "inline_mitigations_already_exist"
)

// EvidenceKind classifies how a piece of evidence was obtained.
//
// The triage package keeps a *local* copy of the EvidencePointer family
// (vs. importing internal/service/reachability) so that this package can
// build and ship before the runner (Wave M1-5) wires the two together,
// and so that LLM-supplied evidence (advisory excerpts, LLM rationale
// quotes) has somewhere to live that does not depend on the analyzer
// package. The M1-5 runner is the conversion point.
//
// ※要確認: once the runner stabilises we may collapse this onto
// reachability.EvidencePointer or extract a shared package; for now the
// duplication keeps the package boundary clean.
type EvidenceKind string

const (
	// EvidenceKindImportPath captures a module path discovered in the
	// transitive import closure (parity with reachability package).
	EvidenceKindImportPath EvidenceKind = "import_path"

	// EvidenceKindSymbolRef captures a source-level symbol reference.
	EvidenceKindSymbolRef EvidenceKind = "symbol_ref"

	// EvidenceKindAdvisoryExcerpt captures a quoted span from the
	// advisory body (NVD / GHSA / JVN) cited by the LLM.
	EvidenceKindAdvisoryExcerpt EvidenceKind = "advisory_excerpt"

	// EvidenceKindLLMRationale captures the LLM's own free-text rationale
	// (always paired with a model+prompt_hash by the runner).
	EvidenceKindLLMRationale EvidenceKind = "llm_rationale"

	// EvidenceKindAnalyzerError captures a non-fatal analyzer error that
	// downgraded the result (mirrors the reachability constant).
	EvidenceKindAnalyzerError EvidenceKind = "analyzer_error"
)

// EvidencePointer is a single justification for a triage decision.
//
// Field names mirror reachability.EvidencePointer so the runner can
// convert in either direction with no field renaming. Source / Note are
// triage-specific extensions: Source records who produced the evidence
// ("reachability" / "advisory_parser" / "llm"), Note carries free text
// (e.g. the LLM's one-line rationale per evidence pointer).
type EvidencePointer struct {
	Kind        EvidenceKind `json:"kind"`
	FilePath    string       `json:"file_path,omitempty"`
	Line        int          `json:"line,omitempty"`
	Column      int          `json:"column,omitempty"`
	Symbol      string       `json:"symbol,omitempty"`
	ImportPath  string       `json:"import_path,omitempty"`
	Description string       `json:"description,omitempty"`
	RawSnippet  string       `json:"raw_snippet,omitempty"`
	Source      string       `json:"source,omitempty"`
	Note        string       `json:"note,omitempty"`
}

// ParsedDecision is the structured view of an LLM triage response.
//
// Confidence is in [0.0, 1.0]; values outside this range are clamped by
// ApplyConfidenceThreshold for safety. Evidence may be empty at parse
// time; ValidateEvidence is invoked separately by the runner so that
// callers can decide whether to retry the LLM call or fall back to
// under_investigation with a synthetic evidence pointer.
//
// RawResponse retains the original LLM JSON (or the unparsed string on
// fallback) so the audit log can hash it verbatim — never mutate this
// field after ParseLLMResponse returns.
type ParsedDecision struct {
	State         State             `json:"state"`
	Justification Justification     `json:"justification,omitempty"`
	Detail        string            `json:"detail,omitempty"`
	Confidence    float64           `json:"confidence"`
	Evidence      []EvidencePointer `json:"evidence,omitempty"`
	RawResponse   string            `json:"-"`
}
