// Package reachability implements language-specific static reachability
// heuristics for AI VEX triage (M1 Wave M1-3, GitHub issue #25).
//
// Design reference: sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §7.1
// (処理ステップ 2: 言語別の静的解析で到達性を一次判定).
//
// MVP scope (M1):
//
//   - Go (M1): see go_analyzer.go for the entry point. npm (M44 Wave 1,
//     F469): see npm_analyzer.go — same contract, implemented as a
//     lockfile-graph + comment-stripping regex source scanner.
//   - Heuristic 2-stage decision: (1) import path presence in module graph,
//     (2) symbol-name reference in source tree via go/packages AST walk.
//   - Full call-graph analysis (golang.org/x/vuln equivalent) is out of scope:
//     it is expensive and produces brittle results on partial source trees.
//     M1 deliberately stops at "is the symbol referenced anywhere" — the LLM
//     judgement stage (M1-4, issue #27) takes it from there.
//
// Output is consumed by the triage runner (M1-5) which combines reachability
// with the parsed advisory and LLM judgement into a CycloneDX VEX draft.
package reachability

import "time"

// Status is the coarse-grained reachability verdict emitted by an analyzer.
//
// The four values are deliberately ordered from "least concerning" to
// "most concerning"; the triage runner uses Status (plus Confidence) to
// decide whether to short-circuit LLM evaluation. unknown is the catch-all
// for analyzer failures: M1-4 must surface "reachability unknown" to the
// LLM rather than silently assuming not_present.
type Status string

const (
	// StatusNotPresent means the vulnerable module is not imported (directly
	// or transitively) by the target project. Safe to surface as
	// not_affected after LLM confirmation.
	StatusNotPresent Status = "not_present"

	// StatusImportOnly means the vulnerable module IS imported transitively,
	// but no reference to any vulnerable symbol was found in the project's
	// source tree. Candidate for not_affected/vulnerable_code_not_in_execute_path
	// pending LLM review.
	StatusImportOnly Status = "import_only"

	// StatusReachable means the vulnerable module is imported AND at least
	// one vulnerable symbol is referenced in the source tree. Candidate for
	// affected/under_investigation pending LLM review.
	StatusReachable Status = "reachable"

	// StatusUnknown means the analyzer failed (parse error, missing go.mod,
	// permission denied, etc). Evidence must include the failure reason so
	// M1-4 can pass "reachability unknown" to the LLM.
	StatusUnknown Status = "unknown"
)

// EvidenceKind classifies how a piece of evidence was obtained, so the UI
// can render it appropriately (link to source file vs. show CLI output).
type EvidenceKind string

const (
	// EvidenceKindImportPath captures a module path discovered in the
	// transitive import closure (go.mod / module graph).
	EvidenceKindImportPath EvidenceKind = "import_path"

	// EvidenceKindSymbolRef captures a source-level symbol reference
	// (function call, method receiver, qualified identifier).
	EvidenceKindSymbolRef EvidenceKind = "symbol_ref"

	// EvidenceKindAnalyzerError captures a non-fatal error that downgraded
	// the result to unknown (e.g. go.mod missing, packages.Load failed).
	EvidenceKindAnalyzerError EvidenceKind = "analyzer_error"
)

// EvidencePointer is a single justification for the reported Status.
//
// All paths are relative to the analysis root (ProjectPath) so the UI can
// link to them inside the repository view without leaking absolute host
// paths into audit logs. Line/Column are 1-indexed when populated; zero
// values mean "not applicable" (e.g. import-path evidence has no line).
type EvidencePointer struct {
	Kind        EvidenceKind `json:"kind"`
	FilePath    string       `json:"file_path,omitempty"`
	Line        int          `json:"line,omitempty"`
	Column      int          `json:"column,omitempty"`
	Symbol      string       `json:"symbol,omitempty"`      // e.g. "yaml.Unmarshal"
	ImportPath  string       `json:"import_path,omitempty"` // e.g. "gopkg.in/yaml.v2"
	Description string       `json:"description,omitempty"` // human-readable context
	RawSnippet  string       `json:"raw_snippet,omitempty"` // optional source excerpt
}

// ReachabilityResult is the analyzer output consumed by the M1-4 LLM stage
// and the M1-5 triage runner. Confidence is in [0.0, 1.0]; the triage
// runner treats below-threshold results as "under_investigation".
//
// Confidence convention (heuristic, may evolve as we observe LLM behaviour):
//
//   - reachable with multiple symbol hits: 0.85
//   - reachable with a single symbol hit:  0.70
//   - import_only:                         0.60
//   - not_present (no import in graph):    0.90
//   - unknown:                             0.00
//
// ※要確認: thresholds above are placeholder and should be calibrated
// against the M1-4 LLM evaluation set before GA.
type ReachabilityResult struct {
	Status       Status            `json:"status"`
	Confidence   float64           `json:"confidence"`
	Evidence     []EvidencePointer `json:"evidence"`
	Ecosystem    string            `json:"ecosystem"` // "go" (M1) or "npm" (M44)
	AnalyzedAt   time.Time         `json:"analyzed_at"`
	AnalyzerName string            `json:"analyzer_name"` // e.g. "go_analyzer/v1"
	DurationMS   int64             `json:"duration_ms"`
}

// ReachabilityInput is the analyzer-facing view of an advisory. It is
// intentionally decoupled from internal/service/advisory.ParsedAdvisory so
// this package can build and ship before the advisory parser (issue #23,
// agent Y) lands. The M1-5 triage runner is responsible for projecting
// ParsedAdvisory into ReachabilityInput.
//
// ※要確認: once advisory.ParsedAdvisory stabilises (#23), add a thin
// adapter (e.g. reachability.FromParsedAdvisory) so call sites don't have
// to know about the projection. Keep the struct decoupled either way —
// the analyzer must not import the advisory package, to avoid a build
// cycle with the triage runner.
type ReachabilityInput struct {
	// AdvisoryID is the upstream identifier (GHSA-xxxx, CVE-YYYY-NNNN).
	// Used only for evidence labelling, not for matching.
	AdvisoryID string

	// Ecosystem selects the analyzer: "go" (GoAnalyzer) or "npm"
	// (NpmAnalyzer, M44 Wave 1, F469). An analyzer handed any other value
	// returns StatusUnknown with an analyzer_error evidence entry.
	Ecosystem string

	// VulnerableModules is the set of import paths that are considered
	// vulnerable. Matching is performed against the project's transitive
	// module graph; prefix matches are NOT performed (the caller must
	// supply exact module paths as published in OSV / GHSA, e.g.
	// "github.com/jackc/pgx/v5", not "github.com/jackc/pgx").
	//
	// For npm the entries are registry package names (scoped names like
	// "@scope/name" included, NOT purl-encoded); matching is exact but
	// case-insensitive, against package.json plus any lockfile, so
	// transitive dependencies count as present.
	VulnerableModules []string

	// VulnerableSymbols is the set of fully-qualified symbol names to grep
	// for in the project's source tree. Accepted forms:
	//
	//   - "Package.Function"      (e.g. "yaml.Unmarshal")
	//   - "Package.Type.Method"   (e.g. "sql.DB.Exec")
	//
	// Bare function names (no package qualifier) are rejected to avoid
	// false positives across packages. ※要確認: this may be too strict
	// for advisories that only publish bare symbol names; revisit after
	// the M1-4 evaluation set.
	//
	// For npm (M44) the server-normalised selector forms are 1..3
	// dot-separated JavaScript identifiers ("$" allowed):
	//
	//   - "defaultsDeep"          (bare export name — the most common form)
	//   - "pkg.method" / "a.b.c"  (receiver.method / call chain)
	//
	// The npm analyzer matches them binding-aware, only inside files that
	// import the vulnerable package, and skips malformed entries
	// INDIVIDUALLY instead of rejecting the whole set.
	VulnerableSymbols []string
}

// AffectedVersionRange is reserved for future use: semver-aware matching
// against the resolved module version. The analyzers currently treat any
// presence in the module graph as a match, leaving version-range filtering
// to the advisory parser / LLM stage (not yet implemented).
//
// ※要確認: kept here so the eventual ParsedAdvisory adapter has a clear
// projection target; remove if version-range filtering ends up living in
// the advisory parser instead.
type AffectedVersionRange struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}
