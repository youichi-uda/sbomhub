package reachability

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

// GoAnalyzer is the Go-only analyzer. npm reachability shipped separately
// as npm_analyzer.go (NpmAnalyzer, M44 Wave 1, F469); ecosystem dispatch is
// the caller's responsibility (the triage runner picks the analyzer per
// advisory ecosystem). See PRODUCT_REBOOT_PLAN.md §7.1 and issue #25.

// GoAnalyzer implements the two-stage heuristic reachability check for
// Go projects described in the package doc.
//
// The zero value is a usable analyzer; the optional fields below are for
// tests (overriding packages.Load) and operational tuning.
type GoAnalyzer struct {
	// LoadConfig overrides the default packages.Config used for AST walking.
	// Tests use this to set GOFLAGS=-mod=mod or to inject a Logf hook.
	// Nil means: use defaultGoLoadConfig().
	LoadConfig *packages.Config

	// SkipPackagesLoad disables the AST walk entirely and decides only
	// based on the module graph. Intended for unit tests that don't have
	// a vendored toolchain; callers in production should leave this false.
	SkipPackagesLoad bool
}

// analyzerName is recorded in ReachabilityResult.AnalyzerName so audit
// log consumers can tell which analyzer version produced a verdict.
const analyzerName = "go_analyzer/v1"

// Analyze runs the two-stage reachability heuristic.
//
//	stage 1: parse go.mod + require()s for module-path presence
//	stage 2: AST-walk the source tree for symbol references
//
// Failure modes that are user-actionable (no go.mod, wrong ecosystem,
// empty input) return StatusUnknown with a descriptive analyzer_error
// evidence entry rather than a Go error, so the triage runner can still
// hand the result to the LLM. A returned error is reserved for truly
// unexpected conditions (context cancelled, OS-level failure).
func (a *GoAnalyzer) Analyze(ctx context.Context, projectPath string, input ReachabilityInput) (*ReachabilityResult, error) {
	start := time.Now()

	if ctx == nil {
		return nil, errors.New("reachability: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	result := &ReachabilityResult{
		Ecosystem:    "go",
		AnalyzedAt:   start.UTC(),
		AnalyzerName: analyzerName,
	}
	defer func() {
		result.DurationMS = time.Since(start).Milliseconds()
	}()

	// ---- input validation (downgrades to unknown, not Go error) ----
	if strings.TrimSpace(projectPath) == "" {
		return unknownResult(result, "empty project path"), nil
	}
	if input.Ecosystem != "" && input.Ecosystem != "go" {
		return unknownResult(result,
			fmt.Sprintf("unsupported ecosystem %q (GoAnalyzer handles go only; use the npm analyzer for npm)",
				input.Ecosystem)), nil
	}
	if len(input.VulnerableModules) == 0 {
		return unknownResult(result, "no vulnerable modules supplied"), nil
	}

	// ---- stage 1: module graph ----
	graph, err := loadModuleGraph(projectPath)
	if err != nil {
		return unknownResult(result, fmt.Sprintf("module graph load failed: %v", err)), nil
	}

	importHits := matchModules(graph, input.VulnerableModules)
	if len(importHits) == 0 {
		// not_present is a positive result, not a failure.
		result.Status = StatusNotPresent
		result.Confidence = 0.90
		result.Evidence = []EvidencePointer{{
			Kind:        EvidenceKindAnalyzerError, // re-used as informational
			Description: "no vulnerable module in transitive import closure",
		}}
		return result, nil
	}

	for _, hit := range importHits {
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind:        EvidenceKindImportPath,
			ImportPath:  hit,
			Description: "module present in transitive import closure (go.mod require)",
		})
	}

	// ---- stage 2: symbol grep via AST ----
	if a.SkipPackagesLoad || len(input.VulnerableSymbols) == 0 {
		// Either tests asked us to stop, or the advisory didn't publish
		// any symbol names; we can't go beyond import_only.
		result.Status = StatusImportOnly
		result.Confidence = 0.60
		if len(input.VulnerableSymbols) == 0 {
			result.Evidence = append(result.Evidence, EvidencePointer{
				Kind:        EvidenceKindAnalyzerError,
				Description: "advisory did not publish vulnerable symbol names; symbol matching skipped",
			})
		}
		return result, nil
	}

	symbolHits, symErr := a.walkSymbols(ctx, projectPath, input.VulnerableSymbols)
	if symErr != nil {
		// Symbol walk failed but we already have a module match; surface as
		// import_only with the error appended, not unknown. The LLM stage
		// can still make a useful call from the import evidence alone.
		result.Status = StatusImportOnly
		result.Confidence = 0.50 // lower than clean import_only — degraded path
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind:        EvidenceKindAnalyzerError,
			Description: fmt.Sprintf("symbol AST walk failed: %v", symErr),
		})
		return result, nil
	}

	if len(symbolHits) == 0 {
		result.Status = StatusImportOnly
		result.Confidence = 0.60
		return result, nil
	}

	result.Status = StatusReachable
	switch {
	case len(symbolHits) >= 2:
		result.Confidence = 0.85
	default:
		result.Confidence = 0.70
	}
	result.Evidence = append(result.Evidence, symbolHits...)
	return result, nil
}

// unknownResult is a helper to build the StatusUnknown variant with an
// analyzer_error evidence entry.
func unknownResult(r *ReachabilityResult, reason string) *ReachabilityResult {
	r.Status = StatusUnknown
	r.Confidence = 0.0
	r.Evidence = append(r.Evidence, EvidencePointer{
		Kind:        EvidenceKindAnalyzerError,
		Description: reason,
	})
	return r
}

// loadModuleGraph parses the project's go.mod and returns the set of
// module paths present in require() blocks (direct + indirect).
//
// We deliberately do not shell out to `go list -m -json all` here:
//
//   - It needs a network if the module cache is cold, which is hostile to
//     unit tests and to air-gapped self-host installs.
//   - For the M1 import-presence check, go.mod require lines are
//     sufficient. False negatives from missing tidy can occur but the
//     LLM stage compensates.
//
// ※要確認: if false-negative rate is high in real-world projects, switch
// to `go mod graph` (offline-safe) for transitive closure. Out of M1 scope.
func loadModuleGraph(projectPath string) (map[string]struct{}, error) {
	modPath := filepath.Join(projectPath, "go.mod")
	data, err := os.ReadFile(modPath)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}
	mf, err := modfile.Parse(modPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}
	out := make(map[string]struct{}, len(mf.Require))
	for _, req := range mf.Require {
		if req == nil || req.Mod.Path == "" {
			continue
		}
		out[req.Mod.Path] = struct{}{}
	}
	return out, nil
}

// matchModules returns the subset of wanted module paths that are present
// in the project's module graph. Matching is exact (no prefix matching)
// per the contract documented on ReachabilityInput.
func matchModules(graph map[string]struct{}, wanted []string) []string {
	var hits []string
	for _, w := range wanted {
		if _, ok := graph[w]; ok {
			hits = append(hits, w)
		}
	}
	return hits
}

// walkSymbols loads the project's Go packages and looks for any reference
// to the supplied fully-qualified symbol names. Returns evidence entries
// (one per distinct file/symbol pair, deduped). Errors are returned
// verbatim — Analyze decides whether they downgrade to import_only or
// unknown.
func (a *GoAnalyzer) walkSymbols(ctx context.Context, projectPath string, symbols []string) ([]EvidencePointer, error) {
	wanted, err := parseSymbolSelectors(symbols)
	if err != nil {
		return nil, err
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	cfg := a.LoadConfig
	if cfg == nil {
		cfg = defaultGoLoadConfig(ctx, projectPath)
	} else {
		// Honour caller overrides but always re-pin the project dir and ctx.
		clone := *cfg
		clone.Dir = projectPath
		clone.Context = ctx
		cfg = &clone
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("packages.Load: %w", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		// PrintErrors writes to stderr — we don't treat package errors as
		// fatal because partial source trees are common (vendored deps,
		// generated files, missing build tags). We just continue with what
		// loaded successfully.
		_ = n
	}

	seen := make(map[string]struct{})
	var out []EvidencePointer
	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			if file == nil {
				continue
			}
			var fileName string
			if i < len(pkg.GoFiles) {
				fileName = pkg.GoFiles[i]
			}
			rel := relPath(projectPath, fileName)
			out = append(out, inspectFileForSelectors(pkg.Fset, file, rel, wanted, seen)...)
		}
	}
	return out, nil
}

// inspectFileForSelectors walks a single parsed Go file for SelectorExpr
// nodes that match any of the wanted symbols, returning evidence entries.
// seen is shared across files so the same (file, symbol, position) is not
// emitted twice — relevant when packages.Load surfaces test variants of a
// package.
//
// Exposed as a package-private helper so tests can exercise the AST logic
// without paying the cost (and offline-hostility) of packages.Load.
func inspectFileForSelectors(
	fset *token.FileSet,
	file *ast.File,
	relFile string,
	wanted []symbolSelector,
	seen map[string]struct{},
) []EvidencePointer {
	var out []EvidencePointer
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgName := ident.Name
		method := sel.Sel.Name
		for _, want := range wanted {
			if !matchSelector(pkgName, method, want) {
				continue
			}
			key := relFile + ":" + want.canonical() + ":" + posKey(fset, sel.Pos())
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			pos := fset.Position(sel.Pos())
			out = append(out, EvidencePointer{
				Kind:        EvidenceKindSymbolRef,
				FilePath:    relFile,
				Line:        pos.Line,
				Column:      pos.Column,
				Symbol:      want.canonical(),
				Description: fmt.Sprintf("source reference to vulnerable symbol %s", want.canonical()),
			})
		}
		return true
	})
	return out
}

// defaultGoLoadConfig builds the packages.Config used when callers don't
// supply one. NeedName/NeedFiles/NeedSyntax is sufficient for AST walking
// without paying for type checking — symbol matching is name-based.
//
// ※要確認: name-based matching cannot distinguish two packages with the
// same short name (e.g. two `yaml` packages from different modules). This
// will produce false positives. Upgrading to NeedTypes + types.Info would
// fix it but is too slow for projects with many dependencies. Acceptable
// for M1 (heuristic); revisit when calibrating against M1-4 eval set.
func defaultGoLoadConfig(ctx context.Context, projectPath string) *packages.Config {
	return &packages.Config{
		Context: ctx,
		Dir:     projectPath,
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedSyntax |
			packages.NeedCompiledGoFiles,
		Tests: false,
	}
}

// symbolSelector is the parsed form of a fully-qualified symbol name from
// the advisory. We only retain pkg+leaf (the last identifier on the dotted
// path) because Go's surface syntax for both function calls and method
// calls is uniformly `pkg.Ident` once you strip the receiver.
type symbolSelector struct {
	pkg  string
	leaf string
	full string // original form, e.g. "sql.DB.Exec"
}

func (s symbolSelector) canonical() string { return s.full }

// parseSymbolSelectors accepts "Package.Function" or "Package.Type.Method"
// forms. Anything else is rejected (per ReachabilityInput contract).
func parseSymbolSelectors(in []string) ([]symbolSelector, error) {
	out := make([]symbolSelector, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		parts := strings.Split(s, ".")
		switch len(parts) {
		case 2:
			out = append(out, symbolSelector{pkg: parts[0], leaf: parts[1], full: s})
		case 3:
			// Package.Type.Method — match on pkg + Method (the AST surface
			// is `receiver.Method`, and the receiver's package matches the
			// declaring package).
			out = append(out, symbolSelector{pkg: parts[0], leaf: parts[2], full: s})
		default:
			return nil, fmt.Errorf("invalid symbol selector %q: expected Package.Function or Package.Type.Method", raw)
		}
	}
	return out, nil
}

func matchSelector(pkg, method string, want symbolSelector) bool {
	if method != want.leaf {
		return false
	}
	// pkg-name match. For Package.Type.Method we still match on pkg
	// because the receiver variable's package equals the declaring pkg.
	return pkg == want.pkg
}

func posKey(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return fmt.Sprintf("%d:%d", p.Line, p.Column)
}

func relPath(root, abs string) string {
	if abs == "" {
		return ""
	}
	if rel, err := filepath.Rel(root, abs); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(abs)
}
