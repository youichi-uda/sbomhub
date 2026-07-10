package reachability

// npm reachability analyzer (M44 Wave 1, F469). Backend copy is the source
// of truth; the CLI carries a vendored copy under
// sbomhub-cli/internal/reachability/npm_analyzer.go (see types.go there).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// NpmAnalyzer implements the heuristic reachability check for npm/JavaScript
// projects. It mirrors the GoAnalyzer contract (same Status enum, confidence
// convention, and evidence kinds) but replaces the AST walk with a
// line/regex source scanner, because (a) there is no stdlib JS parser, and
// (b) the CLI binary is built with CGO_ENABLED=0 and a zero-new-dependency
// policy, which rules out cgo tree-sitter and third-party JS parsers.
//
// Three stages:
//
//	stage 1: dependency-graph presence — package.json (dependencies /
//	         devDependencies / optionalDependencies) plus a lockfile
//	         (package-lock.json v1/v2/v3, npm-shrinkwrap.json,
//	         pnpm-lock.yaml, yarn.lock). Lockfile hits cover TRANSITIVE
//	         dependencies; without a lockfile only direct dependencies are
//	         visible and confidence is reduced.
//	stage 2: import-level scan — walk first-party sources (.js/.mjs/.cjs/
//	         .jsx/.ts/.tsx, excluding node_modules/dist/build/hidden dirs)
//	         for require()/import/export-from/dynamic-import of the
//	         vulnerable packages (subpath specifiers like "pkg/sub" are
//	         attributed to "pkg"; "@scope/name" is supported).
//	stage 3: symbol-level match, confined to files that import the
//	         vulnerable package (binding-aware; a bare grep of symbol names
//	         across the whole tree is deliberately NOT performed — names
//	         like "merge" or "get" would destroy precision).
//
// Like the Go analyzer, this is a conservative static heuristic, not a call
// graph: comment AND string/template-literal stripping (see stripJSCode)
// plus statement-shaped regexes err on the side of skipping constructs they
// cannot classify (multi-line trickery, computed require targets, re-export
// chains, aliased phantom bindings), so results lean towards false
// NEGATIVES and the LLM judgement / human approval stages own the final
// call. The zero value is a usable analyzer.
type NpmAnalyzer struct {
	// SkipSourceScan disables stages 2 and 3 and decides only from the
	// dependency graph (mirrors GoAnalyzer.SkipPackagesLoad). Intended for
	// unit tests; production callers should leave this false.
	SkipSourceScan bool
}

// npmAnalyzerName is recorded in ReachabilityResult.AnalyzerName so audit
// log consumers can tell which analyzer version produced a verdict.
const npmAnalyzerName = "npm_analyzer/v1"

// Operational caps. The Go analyzer bounds its work via packages.Load; the
// npm scanner walks arbitrary user trees, so it needs explicit ceilings.
// Hitting a cap never fails the analysis — the scan reports what it saw and
// appends an informational evidence entry (false-negative direction).
const (
	// npmMaxSourceFiles is the maximum number of candidate source files
	// inspected in one Analyze call; the walk stops (deterministically —
	// filepath.WalkDir is lexical) once the budget is spent.
	npmMaxSourceFiles = 10000

	// npmMaxFileSizeBytes skips files larger than this (likely bundles or
	// generated code, which would also be a false-positive hazard).
	npmMaxFileSizeBytes = 1 << 20 // 1 MiB

	// npmMaxSourceEvidence caps import_path + symbol_ref evidence entries
	// collected from the source scan. Hit tracking continues past the cap,
	// so the verdict is unaffected.
	npmMaxSourceEvidence = 50

	// npmMaxGraphEvidence caps stage-1 dependency-graph evidence entries.
	npmMaxGraphEvidence = 20
)

// Analyze runs the npm reachability heuristic. The error contract matches
// GoAnalyzer.Analyze: user-actionable failures (no package.json/lockfile,
// wrong ecosystem, empty input) downgrade to StatusUnknown with an
// analyzer_error evidence entry; a returned Go error is reserved for truly
// unexpected conditions (nil/cancelled context, OS-level failure).
func (a *NpmAnalyzer) Analyze(ctx context.Context, projectPath string, input ReachabilityInput) (*ReachabilityResult, error) {
	start := time.Now()

	if ctx == nil {
		return nil, errors.New("reachability: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	result := &ReachabilityResult{
		Ecosystem:    "npm",
		AnalyzedAt:   start.UTC(),
		AnalyzerName: npmAnalyzerName,
	}
	defer func() {
		result.DurationMS = time.Since(start).Milliseconds()
	}()

	// ---- input validation (downgrades to unknown, not Go error) ----
	if strings.TrimSpace(projectPath) == "" {
		return unknownResult(result, "empty project path"), nil
	}
	if input.Ecosystem != "" && input.Ecosystem != "npm" {
		return unknownResult(result,
			fmt.Sprintf("unsupported ecosystem %q (npm analyzer handles npm only)",
				input.Ecosystem)), nil
	}
	if len(input.VulnerableModules) == 0 {
		return unknownResult(result, "no vulnerable packages supplied"), nil
	}

	// ---- stage 1: dependency graph ----
	graph, err := loadNpmDependencyGraph(projectPath)
	if err != nil {
		return unknownResult(result, fmt.Sprintf("dependency graph load failed: %v", err)), nil
	}

	hits := matchNpmPackages(graph, input.VulnerableModules)
	if len(hits) == 0 {
		// not_present is a positive result, not a failure.
		result.Status = StatusNotPresent
		if graph.lockfile != "" {
			result.Confidence = 0.90
			result.Evidence = []EvidencePointer{{
				Kind:        EvidenceKindAnalyzerError, // re-used as informational
				Description: "no vulnerable package in the dependency graph (package.json + " + graph.lockfile + ")",
			}}
		} else {
			// Direct dependencies only: a transitive dependency would be
			// invisible, so the negative verdict is weaker.
			result.Confidence = 0.60
			result.Evidence = []EvidencePointer{{
				Kind: EvidenceKindAnalyzerError, // re-used as informational
				Description: "no vulnerable package in package.json direct dependencies; " +
					"no lockfile found, so transitive dependencies are not visible (confidence reduced)",
			}}
		}
		return result, nil
	}

	for i, hit := range hits {
		if i >= npmMaxGraphEvidence {
			result.Evidence = append(result.Evidence, EvidencePointer{
				Kind:        EvidenceKindAnalyzerError,
				Description: fmt.Sprintf("dependency-graph evidence capped at %d entries (%d packages matched)", npmMaxGraphEvidence, len(hits)),
			})
			break
		}
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind:        EvidenceKindImportPath,
			ImportPath:  hit.name,
			FilePath:    hit.source.file,
			Description: "package present in dependency graph (" + hit.source.String() + ")",
		})
	}

	if a.SkipSourceScan {
		// Test hook: stop after stage 1, mirroring GoAnalyzer.SkipPackagesLoad.
		result.Status = StatusImportOnly
		result.Confidence = 0.60
		return result, nil
	}

	// Symbol selectors: server-side normalisation is assumed, but malformed
	// entries are skipped individually (never fatal) — unlike the Go
	// analyzer's parseSymbolSelectors, which rejects the whole set.
	selectors, malformed := parseNpmSymbolSelectors(input.VulnerableSymbols)

	// ---- stages 2+3: source scan (imports, then file-scoped symbols) ----
	scan, scanErr := a.scanNpmSource(ctx, projectPath, hits, selectors)
	if scanErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Graph hit already established; degrade like the Go analyzer's
		// failed symbol walk: import_only at reduced confidence, not unknown.
		result.Status = StatusImportOnly
		result.Confidence = 0.50 // lower than clean import_only — degraded path
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind:        EvidenceKindAnalyzerError,
			Description: fmt.Sprintf("source scan failed: %v", scanErr),
		})
		return result, nil
	}

	result.Evidence = append(result.Evidence, scan.importEvidence...)
	result.Evidence = append(result.Evidence, scan.noteEvidence...)

	if scan.truncated {
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind:        EvidenceKindAnalyzerError,
			Description: fmt.Sprintf("source scan stopped after %d files; results may be incomplete", npmMaxSourceFiles),
		})
	}
	if scan.symlinksSkipped > 0 {
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind: EvidenceKindAnalyzerError,
			Description: fmt.Sprintf("%d symlink(s) skipped during the source walk "+
				"(symlinks are never followed: the link's lstat size would bypass the %d-byte file cap while os.ReadFile reads the target)",
				scan.symlinksSkipped, npmMaxFileSizeBytes),
		})
	}

	// Selector bookkeeping notes are emitted regardless of verdict so a
	// reviewer can always see why symbol matching was partial or skipped.
	switch {
	case len(input.VulnerableSymbols) == 0:
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind:        EvidenceKindAnalyzerError,
			Description: "advisory did not publish vulnerable symbol names; symbol matching skipped",
		})
	case len(selectors) == 0:
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind:        EvidenceKindAnalyzerError,
			Description: fmt.Sprintf("no well-formed vulnerable symbol selectors (%d malformed skipped); symbol matching skipped", len(malformed)),
		})
	case len(malformed) > 0:
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind:        EvidenceKindAnalyzerError,
			Description: fmt.Sprintf("%d malformed symbol selector(s) skipped", len(malformed)),
		})
	}

	if len(scan.symbolEvidence) > 0 {
		result.Status = StatusReachable
		switch {
		case len(scan.symbolEvidence) >= 2:
			result.Confidence = 0.85
		default:
			result.Confidence = 0.70
		}
		result.Evidence = append(result.Evidence, scan.symbolEvidence...)
		return result, nil
	}

	result.Status = StatusImportOnly
	result.Confidence = 0.60
	if len(scan.importEvidence) == 0 {
		result.Evidence = append(result.Evidence, EvidencePointer{
			Kind: EvidenceKindAnalyzerError,
			Description: "no first-party source file imports the vulnerable package; " +
				"it appears to be a transitive (or unused) dependency",
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// stage 1: dependency graph (package.json + lockfiles)
// ---------------------------------------------------------------------------

// npmGraphSource records where a package name was seen, for evidence text.
type npmGraphSource struct {
	file    string // e.g. "package-lock.json", "package.json"
	section string // e.g. "dependencies", "" for lockfiles
}

func (s npmGraphSource) String() string {
	if s.section == "" {
		return s.file
	}
	return s.file + " " + s.section
}

// npmDependencyGraph is the stage-1 view of the project: the set of package
// names present in the manifest and lockfile(s), lowercased for
// case-insensitive matching (npm enforces lowercase for new packages, but
// legacy mixed-case names exist).
type npmDependencyGraph struct {
	packages map[string]npmGraphSource // lower(name) → first source seen
	lockfile string                    // basename of the first parsed lockfile, "" if none
}

// add records a package name unless already present. Lockfile entries are
// added after manifest entries and deliberately do NOT overwrite them, so
// evidence points at the most user-actionable location (the manifest).
func (g *npmDependencyGraph) add(name string, src npmGraphSource) {
	name = strings.TrimSpace(name)
	if name == "" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return
	}
	key := strings.ToLower(name)
	if _, ok := g.packages[key]; !ok {
		g.packages[key] = src
	}
}

// loadNpmDependencyGraph reads package.json plus any supported lockfile in
// the project root. Monorepo/workspace layouts are only partially covered:
// like the Go analyzer's single-go.mod premise, only the root manifest and
// root lockfile are consulted (workspace package lockfile entries still
// appear in root lockfiles for npm/pnpm, so transitive coverage is usually
// retained).
//
// Errors:
//   - package.json present but unparsable → error (user-actionable, like a
//     broken go.mod).
//   - package.json absent → fine if at least one lockfile parses.
//   - nothing parsable at all → error ("not an npm project").
func loadNpmDependencyGraph(projectPath string) (*npmDependencyGraph, error) {
	g := &npmDependencyGraph{packages: make(map[string]npmGraphSource)}

	manifestFound := false
	manifestPath := filepath.Join(projectPath, "package.json")
	if data, err := os.ReadFile(manifestPath); err == nil {
		if perr := parseNpmManifest(data, g); perr != nil {
			return nil, fmt.Errorf("parse package.json: %w", perr)
		}
		manifestFound = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read package.json: %w", err)
	}

	type lockSpec struct {
		name  string
		parse func([]byte, string, *npmDependencyGraph) error
	}
	lockfiles := []lockSpec{
		{"package-lock.json", parsePackageLockPackages},
		{"npm-shrinkwrap.json", parsePackageLockPackages}, // same format as package-lock.json
		{"pnpm-lock.yaml", parsePnpmLockPackages},
		{"yarn.lock", parseYarnLockPackages},
	}
	for _, lf := range lockfiles {
		data, err := os.ReadFile(filepath.Join(projectPath, lf.name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", lf.name, err)
		}
		if perr := lf.parse(data, lf.name, g); perr != nil {
			// A present-but-broken lockfile is suspicious; if the manifest
			// (or an earlier lockfile) already parsed we continue on that
			// basis, otherwise surface the error.
			if manifestFound || g.lockfile != "" {
				continue
			}
			return nil, fmt.Errorf("parse %s: %w", lf.name, perr)
		}
		if g.lockfile == "" {
			g.lockfile = lf.name
		}
	}

	if !manifestFound && g.lockfile == "" {
		return nil, errors.New("no package.json or supported lockfile (package-lock.json / npm-shrinkwrap.json / pnpm-lock.yaml / yarn.lock) found — not an npm project?")
	}
	return g, nil
}

// parseNpmManifest collects direct dependency names from package.json.
// peerDependencies are intentionally excluded: they express a host-side
// requirement, not a resolved installation (false-negative direction).
func parseNpmManifest(data []byte, g *npmDependencyGraph) error {
	var manifest struct {
		Dependencies         map[string]json.RawMessage `json:"dependencies"`
		DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
		OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	sections := []struct {
		name string
		deps map[string]json.RawMessage
	}{
		{"dependencies", manifest.Dependencies},
		{"devDependencies", manifest.DevDependencies},
		{"optionalDependencies", manifest.OptionalDependencies},
	}
	for _, s := range sections {
		for name := range s.deps {
			g.add(name, npmGraphSource{file: "package.json", section: s.name})
		}
	}
	return nil
}

// parsePackageLockPackages collects package names from package-lock.json
// (or npm-shrinkwrap.json — sourceFile records which). Both shapes are
// handled:
//
//   - v2/v3 "packages": keys are install paths ("node_modules/x",
//     "node_modules/a/node_modules/b", "node_modules/@scope/name"); the
//     package name is the part after the LAST "node_modules/". Workspace
//     link keys without a node_modules segment are skipped (first-party).
//   - v1 (and v2 back-compat) "dependencies": names are keys, nested
//     recursively.
func parsePackageLockPackages(data []byte, sourceFile string, g *npmDependencyGraph) error {
	src := npmGraphSource{file: sourceFile}
	var lock struct {
		Packages     map[string]json.RawMessage `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}
	const marker = "node_modules/"
	for key := range lock.Packages {
		idx := strings.LastIndex(key, marker)
		if idx < 0 {
			continue // root ("") or workspace link — first-party
		}
		g.add(key[idx+len(marker):], src)
	}
	var walkV1 func(deps map[string]json.RawMessage, depth int)
	walkV1 = func(deps map[string]json.RawMessage, depth int) {
		if depth > 100 { // defensive; JSON cannot cycle but can nest absurdly
			return
		}
		for name, raw := range deps {
			g.add(name, src)
			var nested struct {
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if err := json.Unmarshal(raw, &nested); err == nil && len(nested.Dependencies) > 0 {
				walkV1(nested.Dependencies, depth+1)
			}
		}
	}
	walkV1(lock.Dependencies, 0)
	return nil
}

// parsePnpmLockPackages collects package names from pnpm-lock.yaml
// (lockfile versions 5.x, 6.x and 9.x). Names come from three places:
// top-level dependency maps (v5), per-importer dependency maps (v6+ /
// workspaces), and the keys of "packages"/"snapshots" maps, which encode
// name+version as "/name/1.0.0" (v5), "/name@1.0.0" (v6) or "name@1.0.0"
// (v9), with an optional "(peer)" suffix.
func parsePnpmLockPackages(data []byte, sourceFile string, g *npmDependencyGraph) error {
	src := npmGraphSource{file: sourceFile}
	type depMaps struct {
		Dependencies         map[string]yaml.Node `yaml:"dependencies"`
		DevDependencies      map[string]yaml.Node `yaml:"devDependencies"`
		OptionalDependencies map[string]yaml.Node `yaml:"optionalDependencies"`
	}
	var doc struct {
		Dependencies         map[string]yaml.Node `yaml:"dependencies"`
		DevDependencies      map[string]yaml.Node `yaml:"devDependencies"`
		OptionalDependencies map[string]yaml.Node `yaml:"optionalDependencies"`
		Importers            map[string]depMaps   `yaml:"importers"`
		Packages             map[string]yaml.Node `yaml:"packages"`
		Snapshots            map[string]yaml.Node `yaml:"snapshots"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	addMaps := func(m depMaps) {
		for name := range m.Dependencies {
			g.add(name, src)
		}
		for name := range m.DevDependencies {
			g.add(name, src)
		}
		for name := range m.OptionalDependencies {
			g.add(name, src)
		}
	}
	addMaps(depMaps{
		Dependencies:         doc.Dependencies,
		DevDependencies:      doc.DevDependencies,
		OptionalDependencies: doc.OptionalDependencies,
	})
	for _, imp := range doc.Importers {
		addMaps(imp)
	}
	for key := range doc.Packages {
		g.add(pnpmPackageNameFromKey(key), src)
	}
	for key := range doc.Snapshots {
		g.add(pnpmPackageNameFromKey(key), src)
	}
	return nil
}

// pnpmPackageNameFromKey extracts the package name from a pnpm-lock.yaml
// packages/snapshots key. Returns "" when the key cannot be classified.
//
//	"/lodash/4.17.21"        (v5)  → "lodash"
//	"/@scope/name/1.0.0"     (v5)  → "@scope/name"
//	"/lodash@4.17.21"        (v6)  → "lodash"
//	"lodash@4.17.21"         (v9)  → "lodash"
//	"@scope/name@1.0.0(peer@1.0.0)"→ "@scope/name"
func pnpmPackageNameFromKey(key string) string {
	key = strings.TrimSpace(key)
	if i := strings.IndexByte(key, '('); i >= 0 { // peer-dependency suffix
		key = key[:i]
	}
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return ""
	}
	// npm package names cannot contain "@" except the scope prefix at
	// index 0, so any later "@" separates name from version (v6/v9 form).
	if i := strings.LastIndexByte(key, '@'); i > 0 {
		return key[:i]
	}
	// v5 form: name and version separated by "/". For scoped packages the
	// name itself contains one "/", so split on the LAST one.
	if i := strings.LastIndexByte(key, '/'); i > 0 {
		return key[:i]
	}
	return key
}

// parseYarnLockPackages collects package names from yarn.lock via line
// scanning. Handles classic v1 ("name@range, name@range2:") and berry
// (`"name@npm:range":`) descriptor headers: a header is any non-indented,
// non-comment line ending in ":"; each comma-separated descriptor yields a
// name by cutting at the last "@" (scope prefix "@" at index 0 excluded).
func parseYarnLockPackages(data []byte, sourceFile string, g *npmDependencyGraph) error {
	src := npmGraphSource{file: sourceFile}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		line = strings.TrimRight(line, " \r")
		if !strings.HasSuffix(line, ":") {
			continue
		}
		for _, desc := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
			desc = strings.Trim(strings.TrimSpace(desc), `"'`)
			if desc == "" || strings.ContainsAny(desc, " \t") {
				continue
			}
			if i := strings.LastIndexByte(desc, '@'); i > 0 {
				desc = desc[:i]
			}
			g.add(desc, src)
		}
	}
	return nil
}

// npmPackageHit is a stage-1 match: the vulnerable package name (as
// supplied by the advisory) plus where the graph saw it.
type npmPackageHit struct {
	name   string // as supplied in VulnerableModules
	lower  string // lowercase key used for matching
	source npmGraphSource
}

// matchNpmPackages returns the subset of wanted package names present in
// the dependency graph. Matching is exact but case-insensitive (legacy npm
// packages may carry uppercase letters); prefix matching is NOT performed,
// per the ReachabilityInput contract.
func matchNpmPackages(g *npmDependencyGraph, wanted []string) []npmPackageHit {
	var hits []npmPackageHit
	seen := make(map[string]struct{})
	for _, w := range wanted {
		name := strings.TrimSpace(w)
		if name == "" {
			continue
		}
		lower := strings.ToLower(name)
		if _, dup := seen[lower]; dup {
			continue
		}
		if src, ok := g.packages[lower]; ok {
			seen[lower] = struct{}{}
			hits = append(hits, npmPackageHit{name: name, lower: lower, source: src})
		}
	}
	return hits
}

// ---------------------------------------------------------------------------
// symbol selectors (npm form)
// ---------------------------------------------------------------------------

// npmSymbolSelector is the parsed form of an npm symbol selector as
// delivered by the server: 1..3 dot-separated JavaScript identifiers.
//
//	"defaultsDeep"        — bare export name (the most common npm form)
//	"_.defaultsDeep"      — receiver.method
//	"auth.api.removeUser" — call chain (matched on its 1..2 trailing parts)
type npmSymbolSelector struct {
	parts []string
	full  string
}

func (s npmSymbolSelector) leaf() string { return s.parts[len(s.parts)-1] }

// npmIdentRe is the JavaScript identifier shape accepted in selector parts
// and import-clause bindings ("$" is legal in JS, unlike Go): first rune a
// Unicode letter, "_" or "$"; the rest may add Unicode digits. This is
// deliberately in LOCKSTEP with the server-side selector filter
// isJSIdentifier (apps/api/internal/handler/reachability.go) and the CLI
// filter isJSIdentifierShaped (sbomhub-cli cmd/sbomhub/commands/
// reachability.go): a selector those filters let through must never be
// silently dropped here as "malformed" (that demoted e.g. "café.parse"
// projects to import_only with no symbol matching at all).
var npmIdentRe = regexp.MustCompile(`^[\p{L}_$][\p{L}\p{Nd}_$]*$`)

// parseNpmSymbolSelectors parses the server-normalised selectors. The
// server is trusted to have sanitised them already, so no re-sanitisation
// happens here — but malformed entries are skipped INDIVIDUALLY (returned
// in malformed for evidence text) rather than failing the whole set, unlike
// the Go analyzer's parseSymbolSelectors.
func parseNpmSymbolSelectors(in []string) (valid []npmSymbolSelector, malformed []string) {
	seen := make(map[string]struct{})
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		parts := strings.Split(s, ".")
		ok := len(parts) >= 1 && len(parts) <= 3
		for _, p := range parts {
			if !npmIdentRe.MatchString(p) {
				ok = false
				break
			}
		}
		if !ok {
			malformed = append(malformed, s)
			continue
		}
		valid = append(valid, npmSymbolSelector{parts: parts, full: s})
	}
	return valid, malformed
}

// ---------------------------------------------------------------------------
// stages 2+3: source scan
// ---------------------------------------------------------------------------

// npmSourceExts are the file extensions scanned. (.mts/.cts and non-JS
// assets are out of scope for M44.)
var npmSourceExts = map[string]struct{}{
	".js": {}, ".mjs": {}, ".cjs": {}, ".jsx": {}, ".ts": {}, ".tsx": {},
}

// npmSkipDirs are directory basenames excluded from the walk, in addition
// to every hidden directory (".git", ".next", …). node_modules is
// third-party code; dist/build/coverage/out are generated output whose
// bundled copies of dependencies would produce false positives.
var npmSkipDirs = map[string]struct{}{
	"node_modules": {}, "dist": {}, "build": {}, "coverage": {}, "out": {},
}

// Import-statement regexes, applied to comment-stripped content. Character
// classes match newlines in Go regexp, so multi-line named-import blocks
// are covered; the [^'";]* clause guard stops matches from crossing string
// literals or statement boundaries.
var (
	// import/export ... from 'spec' (named, default, namespace, re-export)
	reNpmImportFrom = regexp.MustCompile(`\b(import|export)\b([^'";]*?)\bfrom\s*['"]([^'"]+)['"]`)
	// import 'spec' (side-effect import)
	reNpmImportBare = regexp.MustCompile(`\bimport\s*['"]([^'"]+)['"]`)
	// import('spec') (dynamic import; no binding tracking)
	reNpmImportDynamic = regexp.MustCompile(`\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	// require('spec') anywhere
	reNpmRequire = regexp.MustCompile(`\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	// const|let|var <ident> = require('spec') — the identifier class matches
	// npmIdentRe (Unicode letters/digits allowed, in lockstep with the
	// server-side isJSIdentifier rule).
	reNpmRequireBind = regexp.MustCompile(`\b(?:const|let|var)\s+([\p{L}_$][\p{L}\p{Nd}_$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	// const|let|var { a, b: c } = require('spec')  (single-level destructuring)
	reNpmRequireDestructure = regexp.MustCompile(`\b(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

// npmScanResult aggregates the source-scan outcome.
type npmScanResult struct {
	importEvidence []EvidencePointer
	symbolEvidence []EvidencePointer
	// noteEvidence carries informational analyzer_error entries produced by
	// the scan itself (e.g. "binding imported but no use found"); they never
	// influence the verdict.
	noteEvidence    []EvidencePointer
	truncated       bool // npmMaxSourceFiles budget exhausted
	symlinksSkipped int  // symlinks (file or dir) skipped by the walk
}

// scanNpmSource walks the project tree once, performing the import-level
// scan (stage 2) and, for files that import a vulnerable package, the
// file-scoped symbol match (stage 3).
func (a *NpmAnalyzer) scanNpmSource(ctx context.Context, root string, hits []npmPackageHit, selectors []npmSymbolSelector) (*npmScanResult, error) {
	pkgByLower := make(map[string]npmPackageHit, len(hits))
	for _, h := range hits {
		pkgByLower[h.lower] = h
	}

	res := &npmScanResult{}
	filesScanned := 0
	seenImport := make(map[string]struct{}) // file + pkg dedupe
	seenSymbol := make(map[string]struct{}) // file + selector + pos dedupe
	memberRegexCache := make(map[string]*regexp.Regexp)

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			if d == nil {
				return err // root itself unreadable
			}
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil // unreadable file: skip, keep walking
		}
		if d.IsDir() {
			name := d.Name()
			if path != root {
				if _, skip := npmSkipDirs[name]; skip || strings.HasPrefix(name, ".") {
					return fs.SkipDir
				}
			}
			return nil
		}
		if t := d.Type(); !t.IsRegular() {
			// Never follow symlinks (file OR directory links): d.Info()
			// reports the LINK's own lstat size, not the target's, so a
			// tiny link to a huge file or an unbounded device node
			// (/dev/zero) would pass the npmMaxFileSizeBytes gate below
			// and os.ReadFile would read the TARGET — an unbounded-read
			// DoS and a way to smuggle out-of-tree content into the
			// verdict. Skipping is false-negative direction; symlinks are
			// counted for an informational evidence note. Other irregular
			// files (FIFOs, sockets, device nodes) are skipped silently —
			// reading them could block forever.
			if t&fs.ModeSymlink != 0 {
				res.symlinksSkipped++
			}
			return nil
		}
		if _, ok := npmSourceExts[strings.ToLower(filepath.Ext(d.Name()))]; !ok {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > npmMaxFileSizeBytes {
			return nil
		}
		if filesScanned >= npmMaxSourceFiles {
			res.truncated = true
			return fs.SkipAll
		}
		filesScanned++

		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // unreadable file: skip
		}
		scanNpmFile(relPath(root, path), string(data), pkgByLower, selectors,
			res, seenImport, seenSymbol, memberRegexCache)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return res, nil
}

// npmFileBindings tracks, within one file, how a vulnerable package is
// bound to local names.
type npmFileBindings struct {
	// receivers are module-object bindings: default imports, `* as ns`
	// namespace imports and `const x = require(...)` assignments. A member
	// call `<receiver>.<symbol>(` counts as a symbol reference.
	receivers []string
	// named maps ORIGINAL export names (import {orig as alias}) to the
	// binding's local name and declaration offset. A named binding counts
	// as a symbol reference only when its LOCAL name is used (called or
	// referenced) outside binding declarations — the import statement alone
	// proves nothing and claiming reachable for it would be a false
	// positive, violating the analyzer's false-negative-only error budget.
	named map[string]npmNamedBinding
}

// npmNamedBinding records one named binding (ESM named import or require
// destructure) of a vulnerable package within a file.
type npmNamedBinding struct {
	local  string // local identifier the binding is usable as (alias-aware)
	offset int    // byte offset of the binding declaration (for the unused-binding note)
}

// scanNpmFile performs the per-file import scan and file-scoped symbol
// match, appending evidence to res. content is the raw file text; all
// regexes run on lexed copies with identical byte offsets (see stripJSCode)
// so line/column evidence maps back to the original.
func scanNpmFile(relFile, content string, pkgByLower map[string]npmPackageHit,
	selectors []npmSymbolSelector, res *npmScanResult,
	seenImport, seenSymbol map[string]struct{},
	memberRegexCache map[string]*regexp.Regexp,
) {
	stripped, codeOnly := stripJSCode(content)
	lines := newNpmLineIndex(stripped)

	// inCode reports whether the byte at offset off survived the
	// string/template blanking of stripJSCode, i.e. a regex match anchored
	// there sits in real code. Import/require matches (which run on
	// stripped, because they must read the quoted specifier) are validated
	// at two offsets: the match start (a keyword letter — blanked to ' '
	// inside a string, so the comparison fails there) and the specifier's
	// closing quote (a delimiter that only survives blanking when the
	// specifier is a real string literal in code, not text inside an
	// enclosing string or template literal the match straddled into).
	inCode := func(off int) bool { return codeOnly[off] == stripped[off] }

	bindings := make(map[string]*npmFileBindings) // pkg lower → bindings
	bindingsFor := func(lower string) *npmFileBindings {
		b := bindings[lower]
		if b == nil {
			b = &npmFileBindings{named: make(map[string]npmNamedBinding)}
			bindings[lower] = b
		}
		return b
	}

	// declSpans collects the byte spans of every binding-declaration
	// statement seen in this file (import ... from, const x = require(...),
	// destructuring requires) — for ANY package, vulnerable or not. An
	// identifier occurrence inside one of these spans is a declaration,
	// not a use; see npmFindIdentifierUse.
	var declSpans [][2]int

	recordImport := func(pkg npmPackageHit, specifier string, offset int, form string) {
		key := relFile + "\x00" + pkg.lower
		if _, dup := seenImport[key]; dup {
			return
		}
		seenImport[key] = struct{}{}
		if len(res.importEvidence)+len(res.symbolEvidence) >= npmMaxSourceEvidence {
			return // hit is still recorded via seenImport; evidence capped
		}
		line, col := lines.locate(offset)
		res.importEvidence = append(res.importEvidence, EvidencePointer{
			Kind:        EvidenceKindImportPath,
			FilePath:    relFile,
			Line:        line,
			Column:      col,
			ImportPath:  pkg.name,
			Description: fmt.Sprintf("source imports vulnerable package %s (%s %q)", pkg.name, form, specifier),
		})
	}

	// -- import ... from / export ... from --
	for _, m := range reNpmImportFrom.FindAllStringSubmatchIndex(stripped, -1) {
		if !inCode(m[0]) || !inCode(m[7]) {
			continue // statement text inside a string/template literal
		}
		declSpans = append(declSpans, [2]int{m[0], m[1]})
		keyword := stripped[m[2]:m[3]]
		clause := stripped[m[4]:m[5]]
		spec := stripped[m[6]:m[7]]
		pkg, ok := lookupNpmSpecifier(spec, pkgByLower)
		if !ok {
			continue
		}
		trimmedClause := strings.TrimSpace(clause)
		if strings.HasPrefix(trimmedClause, "type ") || strings.HasPrefix(trimmedClause, "type{") {
			continue // TS type-only import/export: erased at runtime
		}
		recordImport(pkg, spec, m[0], keyword+" from")
		if keyword == "import" {
			receivers, named := parseNpmImportClause(clause)
			b := bindingsFor(pkg.lower)
			b.receivers = append(b.receivers, receivers...)
			for _, n := range named {
				if _, dup := b.named[n.orig]; !dup {
					b.named[n.orig] = npmNamedBinding{local: n.local, offset: m[0]}
				}
			}
		}
	}

	// -- import 'spec' (side-effect) --
	for _, m := range reNpmImportBare.FindAllStringSubmatchIndex(stripped, -1) {
		if !inCode(m[0]) || !inCode(m[3]) {
			continue
		}
		spec := stripped[m[2]:m[3]]
		if pkg, ok := lookupNpmSpecifier(spec, pkgByLower); ok {
			recordImport(pkg, spec, m[0], "import")
		}
	}

	// -- import('spec') (dynamic) --
	for _, m := range reNpmImportDynamic.FindAllStringSubmatchIndex(stripped, -1) {
		if !inCode(m[0]) || !inCode(m[3]) {
			continue
		}
		spec := stripped[m[2]:m[3]]
		if pkg, ok := lookupNpmSpecifier(spec, pkgByLower); ok {
			recordImport(pkg, spec, m[0], "dynamic import")
		}
	}

	// -- require('spec') — all call sites, import-level evidence --
	for _, m := range reNpmRequire.FindAllStringSubmatchIndex(stripped, -1) {
		if !inCode(m[0]) || !inCode(m[3]) {
			continue
		}
		spec := stripped[m[2]:m[3]]
		if pkg, ok := lookupNpmSpecifier(spec, pkgByLower); ok {
			recordImport(pkg, spec, m[0], "require")
		}
	}

	// -- const x = require('spec') — receiver binding --
	for _, m := range reNpmRequireBind.FindAllStringSubmatchIndex(stripped, -1) {
		if !inCode(m[0]) || !inCode(m[5]) {
			continue
		}
		declSpans = append(declSpans, [2]int{m[0], m[1]})
		ident := stripped[m[2]:m[3]]
		spec := stripped[m[4]:m[5]]
		if pkg, ok := lookupNpmSpecifier(spec, pkgByLower); ok {
			b := bindingsFor(pkg.lower)
			b.receivers = append(b.receivers, ident)
		}
	}

	// -- const {a, b: c} = require('spec') — named bindings --
	for _, m := range reNpmRequireDestructure.FindAllStringSubmatchIndex(stripped, -1) {
		if !inCode(m[0]) || !inCode(m[5]) {
			continue
		}
		declSpans = append(declSpans, [2]int{m[0], m[1]})
		items := stripped[m[2]:m[3]]
		spec := stripped[m[4]:m[5]]
		pkg, ok := lookupNpmSpecifier(spec, pkgByLower)
		if !ok {
			continue
		}
		b := bindingsFor(pkg.lower)
		for _, item := range strings.Split(items, ",") {
			orig, local := item, item
			if i := strings.IndexByte(item, ':'); i >= 0 {
				orig, local = item[:i], item[i+1:]
			}
			orig = strings.TrimSpace(orig)
			local = strings.TrimSpace(local)
			if !npmIdentRe.MatchString(orig) || !npmIdentRe.MatchString(local) {
				continue // nested destructuring, "...rest", etc — skip
			}
			if _, dup := b.named[orig]; !dup {
				b.named[orig] = npmNamedBinding{local: local, offset: m[0]}
			}
		}
	}

	// ---- stage 3: file-scoped symbol match ----
	if len(selectors) == 0 || len(bindings) == 0 {
		return
	}

	recordSymbol := func(sel npmSymbolSelector, pkg npmPackageHit, offset int, how string) {
		line, col := lines.locate(offset)
		key := fmt.Sprintf("%s\x00%s\x00%d:%d", relFile, sel.full, line, col)
		if _, dup := seenSymbol[key]; dup {
			return
		}
		seenSymbol[key] = struct{}{}
		if len(res.importEvidence)+len(res.symbolEvidence) >= npmMaxSourceEvidence {
			// Verdict must still see the hit even when evidence is capped.
			if len(res.symbolEvidence) >= 2 {
				return
			}
		}
		res.symbolEvidence = append(res.symbolEvidence, EvidencePointer{
			Kind:        EvidenceKindSymbolRef,
			FilePath:    relFile,
			Line:        line,
			Column:      col,
			Symbol:      sel.full,
			Description: fmt.Sprintf("source reference to vulnerable symbol %s (%s of package %s)", sel.full, how, pkg.name),
		})
	}

	// Unused named-binding notes are deduped per package+leaf within the
	// file (two selectors sharing a leaf would otherwise double-report).
	notedUnused := make(map[string]struct{})
	recordUnusedBinding := func(sel npmSymbolSelector, pkg npmPackageHit, offset int) {
		key := pkg.lower + "\x00" + sel.leaf()
		if _, dup := notedUnused[key]; dup {
			return
		}
		notedUnused[key] = struct{}{}
		if len(res.importEvidence)+len(res.symbolEvidence)+len(res.noteEvidence) >= npmMaxSourceEvidence {
			return // informational only; never affects the verdict
		}
		line, col := lines.locate(offset)
		res.noteEvidence = append(res.noteEvidence, EvidencePointer{
			Kind:     EvidenceKindAnalyzerError, // re-used as informational
			FilePath: relFile,
			Line:     line,
			Column:   col,
			Description: fmt.Sprintf("vulnerable symbol %s of package %s: "+
				"binding imported but no use found outside import/require declarations; "+
				"not counted as a symbol reference", sel.leaf(), pkg.name),
		})
	}

	// Deterministic evidence order: sort the per-package binding sets
	// (map iteration order would otherwise randomise multi-package files).
	lowers := make([]string, 0, len(bindings))
	for lower := range bindings {
		lowers = append(lowers, lower)
	}
	sort.Strings(lowers)

	for _, lower := range lowers {
		b := bindings[lower]
		pkg := pkgByLower[lower]
		for _, sel := range selectors {
			leaf := sel.leaf()

			// (i) named import / require-destructure binding of the symbol.
			// The binding alone is NOT a hit — `import {merge}` with no
			// call or reference must stay import_only. The LOCAL name must
			// be used outside binding declarations: called (merge(...)) or
			// referenced (arr.map(merge)) — a bare reference hands the
			// function around, so it may still execute.
			if nb, ok := b.named[leaf]; ok {
				if useOff, found := npmFindIdentifierUse(codeOnly, nb.local, declSpans); found {
					recordSymbol(sel, pkg, useOff, "use of named import binding")
				} else {
					recordUnusedBinding(sel, pkg, nb.offset)
				}
			}

			// (ii) <receiver>.<leaf>( member call — plus, for 3-part
			// selectors, the 2-part trailing chain <receiver>.<mid>.<leaf>(.
			// Every identifier part is QuoteMeta'd: "$" is a legal JS
			// identifier character but a regex ANCHOR, so an unquoted
			// "$watch" tail could never match. The receiver's left boundary
			// is checked on the preceding rune instead of `\b`: "$" is not
			// a \w character, so `\b\$` DEMANDED a word char before the
			// receiver — it never matched `$.ajax(` at statement start yet
			// happily matched the different identifier `x$.ajax(`.
			var tails []string
			tails = append(tails, regexp.QuoteMeta(leaf))
			if len(sel.parts) == 3 {
				tails = append(tails, regexp.QuoteMeta(sel.parts[1])+`\s*\.\s*`+regexp.QuoteMeta(sel.parts[2]))
			}
			for _, recv := range b.receivers {
				for _, tail := range tails {
					pattern := regexp.QuoteMeta(recv) + `\s*\.\s*` + tail + `\s*\(`
					re := memberRegexCache[pattern]
					if re == nil {
						re = regexp.MustCompile(pattern)
						memberRegexCache[pattern] = re
					}
					for _, loc := range re.FindAllStringIndex(codeOnly, -1) {
						// The receiver must start at an identifier
						// boundary: not the tail of a longer identifier
						// (x$.ajax) and not itself a member access
						// (chain.recv.leaf()).
						if !npmIdentBoundaryBefore(codeOnly, loc[0]) {
							continue
						}
						recordSymbol(sel, pkg, loc[0], "member call via binding")
					}
				}
			}
		}
	}
}

// isNpmIdentRune reports whether r can appear in a JavaScript identifier as
// accepted by npmIdentRe (Unicode letters/digits plus "_" and "$").
func isNpmIdentRune(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// npmIdentBoundaryBefore reports whether off sits at an identifier start
// boundary: the rune immediately before off must not be an identifier rune
// (which would make the match a suffix of a longer identifier) and must not
// be "." (which would make the match a member-access leaf).
func npmIdentBoundaryBefore(s string, off int) bool {
	if off == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:off])
	return !isNpmIdentRune(r) && r != '.'
}

// npmFindIdentifierUse returns the byte offset of the first free-standing
// use of the identifier local in codeOnly (string/template bodies already
// blanked). A use is an occurrence with identifier boundaries on both sides
// that is not a member-access leaf (preceded by "."), not an object-literal
// key (followed by ":", which also skips `cond ? local : x` — an accepted
// false-negative), and not inside any declaration span (import/require
// statements: the occurrence there IS the declaration, not a use). Both
// calls (local(...)) and bare references (arr.map(local)) qualify: a
// reference hands the vulnerable function around, so it may be executed.
func npmFindIdentifierUse(codeOnly, local string, declSpans [][2]int) (int, bool) {
	for from := 0; from < len(codeOnly); {
		i := strings.Index(codeOnly[from:], local)
		if i < 0 {
			return 0, false
		}
		off := from + i
		from = off + 1
		if !npmIdentBoundaryBefore(codeOnly, off) {
			continue
		}
		end := off + len(local)
		if end < len(codeOnly) {
			if r, _ := utf8.DecodeRuneInString(codeOnly[end:]); isNpmIdentRune(r) {
				continue
			}
		}
		j := end
		for j < len(codeOnly) && (codeOnly[j] == ' ' || codeOnly[j] == '\t' ||
			codeOnly[j] == '\n' || codeOnly[j] == '\r') {
			j++
		}
		if j < len(codeOnly) && codeOnly[j] == ':' {
			continue // object-literal key, not a reference
		}
		inDecl := false
		for _, sp := range declSpans {
			if off >= sp[0] && off < sp[1] {
				inDecl = true
				break
			}
		}
		if inDecl {
			continue
		}
		return off, true
	}
	return 0, false
}

// lookupNpmSpecifier resolves a module specifier to a matched vulnerable
// package, attributing subpath imports ("pkg/sub", "@scope/name/sub") to
// their package. Relative paths, absolute paths, package-internal "#"
// imports and protocol-prefixed specifiers ("node:fs") never match.
func lookupNpmSpecifier(spec string, pkgByLower map[string]npmPackageHit) (npmPackageHit, bool) {
	name := npmPackageFromSpecifier(spec)
	if name == "" {
		return npmPackageHit{}, false
	}
	hit, ok := pkgByLower[strings.ToLower(name)]
	return hit, ok
}

// npmPackageFromSpecifier extracts the package name from an import/require
// specifier, or "" when the specifier does not reference an npm package.
func npmPackageFromSpecifier(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" ||
		strings.HasPrefix(spec, ".") ||
		strings.HasPrefix(spec, "/") ||
		strings.HasPrefix(spec, "#") ||
		strings.Contains(spec, ":") { // node:, data:, file:, https:, …
		return ""
	}
	segs := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(segs) < 2 || segs[1] == "" {
			return ""
		}
		return segs[0] + "/" + segs[1]
	}
	return segs[0]
}

// npmNamedImport is one named binding from an ESM import clause: the
// ORIGINAL export name (selector matching keys on it) plus the LOCAL
// identifier it is bound to ("import {orig as local}"), which is what
// use-site detection must search the file for.
type npmNamedImport struct {
	orig  string
	local string
}

// parseNpmImportClause splits an ESM import clause (the text between
// `import` and `from`) into receiver bindings (default and namespace
// imports — usable as `<binding>.<symbol>(`), and named bindings (original
// export name plus local alias).
//
//	" _ "                        → receivers [_]
//	" * as ns "                  → receivers [ns]
//	" _, { merge as m, get } "   → receivers [_], named [merge→m, get→get]
//	" { default as lodash } "    → receivers [lodash]
//	" { type Foo, bar } "        → named [bar→bar]   (TS inline type specifier)
func parseNpmImportClause(clause string) (receivers []string, named []npmNamedImport) {
	braceOpen := strings.IndexByte(clause, '{')
	braceClose := strings.LastIndexByte(clause, '}')

	outside := clause
	inside := ""
	if braceOpen >= 0 && braceClose > braceOpen {
		outside = clause[:braceOpen] + " " + clause[braceClose+1:]
		inside = clause[braceOpen+1 : braceClose]
	}

	for _, part := range strings.Split(outside, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(part, "*"); ok {
			rest = strings.TrimSpace(rest)
			if ns, ok := strings.CutPrefix(rest, "as "); ok {
				ns = strings.TrimSpace(ns)
				if npmIdentRe.MatchString(ns) {
					receivers = append(receivers, ns)
				}
			}
			continue
		}
		if npmIdentRe.MatchString(part) && part != "type" {
			receivers = append(receivers, part) // default import binding
		}
	}

	for _, item := range strings.Split(inside, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "type ") {
			continue // TS inline type specifier: erased at runtime
		}
		orig, alias := item, item
		if i := strings.Index(item, " as "); i >= 0 {
			orig = strings.TrimSpace(item[:i])
			alias = strings.TrimSpace(item[i+len(" as "):])
		}
		if orig == "default" {
			// `import { default as x }` binds the module object itself.
			if npmIdentRe.MatchString(alias) {
				receivers = append(receivers, alias)
			}
			continue
		}
		if npmIdentRe.MatchString(orig) && npmIdentRe.MatchString(alias) {
			named = append(named, npmNamedImport{orig: orig, local: alias})
		}
	}
	return receivers, named
}

// ---------------------------------------------------------------------------
// comment/string stripping + line index
// ---------------------------------------------------------------------------

// stripJSComments returns src with // line comments and /* */ block
// comments replaced by spaces (newlines preserved). Thin wrapper around
// stripJSCode, kept for callers that only need the comment-stripped view.
func stripJSComments(src string) string {
	stripped, _ := stripJSCode(src)
	return stripped
}

// stripJSCode lexes src once and returns two equal-length views whose byte
// offsets (and therefore line/column positions) map 1:1 onto the original:
//
//   - stripped: // line comments and /* */ block comments replaced by
//     spaces (newlines preserved); string and template literal bodies are
//     kept intact so import/require specifiers remain readable.
//   - codeOnly: additionally, single-/double-quoted string bodies and
//     template-literal text (escape sequences included) are replaced by
//     spaces, quote/backtick delimiters kept. Template-literal ${...}
//     interpolations are code and are preserved; nesting (templates inside
//     interpolations inside templates …) is handled via a depth stack.
//
// Import/require regexes run on stripped (they must read the quoted
// specifier) and validate their match offsets against codeOnly, so a
// statement that merely appears inside a string or template literal
// (docstrings, log messages) can no longer fake an import or a symbol hit
// — that would violate the analyzer's false-negative-only error direction.
// Symbol matching runs on codeOnly outright.
//
// Known heuristic limits (false-negative direction, documented for
// maintainers): regex literals are not modelled, so `/\/*` inside a regex
// can eat code until the next `*/`, and a quote inside a regex opens a
// phantom string in codeOnly until the next quote; a // or /* sequence
// inside a ${...} interpolation is treated as a comment, so a pathological
// `${x // }`  can blank the rest of the template's line. All are acceptable
// for a conservative scanner whose output feeds an LLM + human approval
// pipeline.
func stripJSCode(src string) (stripped, codeOnly string) {
	out := []byte(src)  // comments blanked
	code := []byte(src) // comments + string/template bodies blanked
	const (
		stCode = iota
		stLineComment
		stBlockComment
		stSingle
		stDouble
		stBacktick
	)
	state := stCode
	// interpDepth holds one unbalanced-'{' counter per template literal
	// whose ${...} interpolation is currently open; the innermost counter
	// decides when a '}' closes that interpolation (returning to template
	// text) rather than an object literal inside it.
	var interpDepth []int
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case stCode:
			switch c {
			case '/':
				if i+1 < len(src) {
					switch src[i+1] {
					case '/':
						state = stLineComment
						out[i], out[i+1] = ' ', ' '
						code[i], code[i+1] = ' ', ' '
						i++
					case '*':
						state = stBlockComment
						out[i], out[i+1] = ' ', ' '
						code[i], code[i+1] = ' ', ' '
						i++
					}
				}
			case '\'':
				state = stSingle
			case '"':
				state = stDouble
			case '`':
				state = stBacktick
			case '{':
				if n := len(interpDepth); n > 0 {
					interpDepth[n-1]++
				}
			case '}':
				if n := len(interpDepth); n > 0 {
					if interpDepth[n-1] == 0 {
						interpDepth = interpDepth[:n-1]
						state = stBacktick
					} else {
						interpDepth[n-1]--
					}
				}
			}
		case stLineComment:
			if c == '\n' {
				state = stCode
			} else {
				out[i], code[i] = ' ', ' '
			}
		case stBlockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				out[i], out[i+1] = ' ', ' '
				code[i], code[i+1] = ' ', ' '
				i++
				state = stCode
			} else if c != '\n' {
				out[i], code[i] = ' ', ' '
			}
		case stSingle, stDouble:
			quote := byte('\'')
			if state == stDouble {
				quote = '"'
			}
			switch {
			case c == '\\':
				code[i] = ' '
				if i+1 < len(src) {
					if src[i+1] != '\n' {
						code[i+1] = ' '
					}
					i++ // skip escaped char
				}
			case c == quote:
				state = stCode
			case c == '\n':
				state = stCode // unterminated string literal: resync
			default:
				code[i] = ' '
			}
		case stBacktick:
			switch {
			case c == '\\':
				code[i] = ' '
				if i+1 < len(src) {
					if src[i+1] != '\n' {
						code[i+1] = ' '
					}
					i++ // skip escaped char
				}
			case c == '`':
				state = stCode
			case c == '$' && i+1 < len(src) && src[i+1] == '{':
				// ${ opens an interpolation: its body is code. The "${"
				// and matching "}" delimiters stay visible in both views.
				interpDepth = append(interpDepth, 0)
				state = stCode
				i++ // consume '{' so it is not counted as a brace
			case c != '\n':
				code[i] = ' '
			}
		}
	}
	return string(out), string(code)
}

// npmLineIndex maps byte offsets to 1-based line/column pairs.
type npmLineIndex []int // byte offset of each line start

func newNpmLineIndex(s string) npmLineIndex {
	ix := npmLineIndex{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			ix = append(ix, i+1)
		}
	}
	return ix
}

func (ix npmLineIndex) locate(offset int) (line, col int) {
	i := sort.Search(len(ix), func(n int) bool { return ix[n] > offset }) - 1
	if i < 0 {
		i = 0
	}
	return i + 1, offset - ix[i] + 1
}
