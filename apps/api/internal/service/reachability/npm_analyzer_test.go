package reachability

// Tests for the npm reachability analyzer (M44 Wave 1, F469).
//
// All fixtures under testdata/npm_* use fake package names (acme-lodash,
// @acme/scoped-lib, …) that do not exist in the public registry, and the
// analyzer never touches the network or spawns a toolchain — the whole
// suite is offline-safe. Cases that need directories the repo cannot carry
// (node_modules/, dist/ are gitignored) build a temp project instead.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// npmEvidenceOfKind filters a result's evidence by kind.
func npmEvidenceOfKind(res *ReachabilityResult, kind EvidenceKind) []EvidencePointer {
	var out []EvidencePointer
	for _, e := range res.Evidence {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// npmHasDescription reports whether any evidence description contains substr.
func npmHasDescription(res *ReachabilityResult, substr string) bool {
	for _, e := range res.Evidence {
		if strings.Contains(e.Description, substr) {
			return true
		}
	}
	return false
}

func TestNpmAnalyze_NotPresent_WithLockfile(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			AdvisoryID:        "GHSA-npm-0001",
			Ecosystem:         "npm",
			VulnerableModules: []string{"totally-absent-pkg"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, StatusNotPresent, res.Status)
	assert.InDelta(t, 0.90, res.Confidence, 0.001)
	assert.Equal(t, "npm", res.Ecosystem)
	assert.Equal(t, npmAnalyzerName, res.AnalyzerName)
	assert.True(t, npmHasDescription(res, "package-lock.json"))
}

func TestNpmAnalyze_NotPresent_NoLockfile_ReducedConfidence(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_no_lockfile_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"totally-absent-pkg"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusNotPresent, res.Status)
	assert.InDelta(t, 0.60, res.Confidence, 0.001)
	assert.True(t, npmHasDescription(res, "no lockfile found"),
		"expected the reduced-confidence explanation, got %+v", res.Evidence)
}

func TestNpmAnalyze_Reachable_RequireBinding_BareSelector(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusReachable, res.Status)
	assert.InDelta(t, 0.70, res.Confidence, 0.001)

	imports := npmEvidenceOfKind(res, EvidenceKindImportPath)
	require.NotEmpty(t, imports)
	// Graph evidence first (package.json), then the source import.
	assert.Equal(t, "acme-lodash", imports[0].ImportPath)
	var sourceImport *EvidencePointer
	for i := range imports {
		if imports[i].FilePath == "src/cjs_consumer.js" {
			sourceImport = &imports[i]
		}
	}
	require.NotNil(t, sourceImport, "expected import evidence in src/cjs_consumer.js, got %+v", imports)
	assert.Equal(t, 4, sourceImport.Line)

	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	require.Len(t, symbols, 1)
	assert.Equal(t, "defaultsDeep", symbols[0].Symbol)
	assert.Equal(t, "src/cjs_consumer.js", symbols[0].FilePath)
	assert.Equal(t, 9, symbols[0].Line)
	assert.Equal(t, 10, symbols[0].Column)
}

func TestNpmAnalyze_Reachable_ReceiverDotMethodSelector(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"_.defaultsDeep"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusReachable, res.Status)
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	require.Len(t, symbols, 1)
	assert.Equal(t, "_.defaultsDeep", symbols[0].Symbol)
	assert.Equal(t, "src/cjs_consumer.js", symbols[0].FilePath)
}

func TestNpmAnalyze_Reachable_ESMNamedImport_ScopedPackage(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"@acme/scoped-lib"},
			VulnerableSymbols: []string{"deepMerge"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusReachable, res.Status)
	assert.InDelta(t, 0.70, res.Confidence, 0.001)
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	require.Len(t, symbols, 1)
	assert.Equal(t, "deepMerge", symbols[0].Symbol)
	assert.Equal(t, "src/esm_consumer.ts", symbols[0].FilePath)
	// Since M44 Phase D, a named import binding alone is NOT a symbol hit
	// (an unused import must stay import_only); the evidence points at the
	// USE site — the deepMerge(a, b) call on line 6 — not the import
	// statement on line 2.
	assert.Equal(t, 6, symbols[0].Line)
	assert.Contains(t, symbols[0].Description, "named import binding")
}

func TestNpmAnalyze_Reachable_TwoHits_HigherConfidence(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash", "@acme/scoped-lib"},
			VulnerableSymbols: []string{"defaultsDeep", "deepMerge"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusReachable, res.Status)
	assert.InDelta(t, 0.85, res.Confidence, 0.001)
	assert.Len(t, npmEvidenceOfKind(res, EvidenceKindSymbolRef), 2)
}

func TestNpmAnalyze_Reachable_NoLockfile_DefaultImport(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_no_lockfile_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	require.NoError(t, err)
	// A positive hit is a hit: lockfile absence does not weaken direct
	// source evidence.
	assert.Equal(t, StatusReachable, res.Status)
	assert.InDelta(t, 0.70, res.Confidence, 0.001)
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	require.Len(t, symbols, 1)
	assert.Equal(t, "src/app.js", symbols[0].FilePath)
}

func TestNpmAnalyze_ImportOnly_SymbolSuppliedButNotHit(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"nonexistentFn"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
	assert.InDelta(t, 0.60, res.Confidence, 0.001)
	assert.Empty(t, npmEvidenceOfKind(res, EvidenceKindSymbolRef))
	// The source import is still evidence.
	imports := npmEvidenceOfKind(res, EvidenceKindImportPath)
	var found bool
	for _, e := range imports {
		if e.FilePath == "src/cjs_consumer.js" {
			found = true
		}
	}
	assert.True(t, found, "expected source import evidence, got %+v", imports)
}

func TestNpmAnalyze_ImportOnly_NoSymbolsSupplied(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
	assert.InDelta(t, 0.60, res.Confidence, 0.001)
	assert.True(t, npmHasDescription(res, "did not publish vulnerable symbol names"))
}

func TestNpmAnalyze_ImportOnly_TransitiveOnly(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-deep-transitive"},
			VulnerableSymbols: []string{"anything"},
		})
	require.NoError(t, err)
	// Present in the lockfile (nested under acme-transitive-parent) but
	// never imported by first-party source.
	assert.Equal(t, StatusImportOnly, res.Status)
	assert.InDelta(t, 0.60, res.Confidence, 0.001)
	assert.True(t, npmHasDescription(res, "transitive"),
		"expected the transitive-dependency note, got %+v", res.Evidence)
	graph := npmEvidenceOfKind(res, EvidenceKindImportPath)
	require.NotEmpty(t, graph)
	assert.Contains(t, graph[0].Description, "package-lock.json")
}

func TestNpmAnalyze_ImportOnly_DevDependency_CommentedRequireIgnored(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-dev-tool"},
			VulnerableSymbols: []string{"lint"},
		})
	require.NoError(t, err)
	// devDependency counts as present (stage 1), and the commented-out
	// require in src/cjs_consumer.js must NOT count as a source import.
	assert.Equal(t, StatusImportOnly, res.Status)
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		assert.Empty(t, e.Line, "commented-out require must not yield source evidence: %+v", e)
	}
	assert.True(t, npmHasDescription(res, "devDependencies"))
}

func TestNpmAnalyze_ImportOnly_DynamicImport(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-transitive-parent"},
			VulnerableSymbols: []string{"parentFn"},
		})
	require.NoError(t, err)
	// Dynamic import() yields import-level evidence but no binding, so the
	// verdict stays import_only even with symbols supplied.
	assert.Equal(t, StatusImportOnly, res.Status)
	imports := npmEvidenceOfKind(res, EvidenceKindImportPath)
	var found bool
	for _, e := range imports {
		if e.FilePath == "src/dynamic_consumer.mjs" {
			found = true
			assert.Contains(t, e.Description, "dynamic import")
		}
	}
	assert.True(t, found, "expected dynamic-import evidence, got %+v", imports)
}

func TestNpmAnalyze_SkipSourceScan(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{SkipSourceScan: true}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
	assert.InDelta(t, 0.60, res.Confidence, 0.001)
	assert.Empty(t, npmEvidenceOfKind(res, EvidenceKindSymbolRef))
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		assert.Zero(t, e.Line, "stage-1-only run must not carry source positions: %+v", e)
	}
}

func TestNpmAnalyze_CaseInsensitivePackageMatch(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"ACME-Lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	require.NoError(t, err)
	// Legacy npm packages may carry uppercase; matching is case-insensitive
	// end to end (graph and import specifiers).
	assert.Equal(t, StatusReachable, res.Status)
}

func TestNpmAnalyze_MalformedSelectorsSkippedIndividually(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"@acme/scoped-lib"},
			VulnerableSymbols: []string{"deepMerge", "not-an-ident!", "a.b.c.d", "1bad", ""},
		})
	require.NoError(t, err, "malformed selectors must never be fatal")
	assert.Equal(t, StatusReachable, res.Status, "the well-formed selector must still match")
	assert.True(t, npmHasDescription(res, "malformed symbol selector"))
}

func TestNpmAnalyze_AllSelectorsMalformed(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"not-an-ident!", "a.b.c.d"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
	assert.True(t, npmHasDescription(res, "no well-formed vulnerable symbol selectors"))
}

func TestNpmAnalyze_UnknownOnEmptyProjectPath(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "   ",
		ReachabilityInput{Ecosystem: "npm", VulnerableModules: []string{"x"}})
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, res.Status)
	assert.Equal(t, 0.0, res.Confidence)
	require.Len(t, res.Evidence, 1)
	assert.Equal(t, EvidenceKindAnalyzerError, res.Evidence[0].Kind)
}

func TestNpmAnalyze_UnknownOnUnsupportedEcosystem(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{Ecosystem: "go", VulnerableModules: []string{"x"}})
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, res.Status)
	assert.Contains(t, res.Evidence[0].Description, `unsupported ecosystem "go"`)
}

func TestNpmAnalyze_UnknownOnEmptyVulnerableModules(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/npm_project",
		ReachabilityInput{Ecosystem: "npm"})
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, res.Status)
}

func TestNpmAnalyze_UnknownOnNonNpmProject(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), t.TempDir(),
		ReachabilityInput{Ecosystem: "npm", VulnerableModules: []string{"x"}})
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, res.Status)
	assert.Contains(t, res.Evidence[0].Description, "dependency graph load failed")
}

func TestNpmAnalyze_NilContext(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}
	//nolint:staticcheck // deliberately testing nil-context handling
	res, err := a.Analyze(nil, "testdata/npm_project",
		ReachabilityInput{Ecosystem: "npm", VulnerableModules: []string{"x"}})
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestNpmAnalyze_CancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &NpmAnalyzer{}
	res, err := a.Analyze(ctx, "testdata/npm_project",
		ReachabilityInput{Ecosystem: "npm", VulnerableModules: []string{"acme-lodash"}})
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, res)
}

// TestNpmAnalyze_ExcludedDirsAndOversizeFiles builds a temp project because
// node_modules/ and dist/ are gitignored in this repo and cannot be carried
// as fixtures. Vulnerable-looking code inside node_modules/, dist/, hidden
// dirs, and oversized files must not influence the verdict.
func TestNpmAnalyze_ExcludedDirsAndOversizeFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	mustWrite("package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
	mustWrite("package-lock.json", `{
		"lockfileVersion": 3,
		"packages": {"node_modules/acme-lodash": {"version": "4.17.21"}}
	}`)
	vulnCode := "const _ = require('acme-lodash');\n_.defaultsDeep({}, {});\n"
	mustWrite("node_modules/acme-lodash/index.js", vulnCode)
	mustWrite("dist/bundle.js", vulnCode)
	mustWrite("build/out.js", vulnCode)
	mustWrite(".next/server/page.js", vulnCode)
	// Oversized first-party file: skipped by the size cap.
	mustWrite("src/huge.js", vulnCode+strings.Repeat("// padding padding padding\n", 50000))

	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status,
		"vulnerable code only in excluded/oversized locations must not be reachable")
	for _, e := range res.Evidence {
		assert.NotContains(t, e.FilePath, "node_modules")
		assert.NotContains(t, e.FilePath, "dist")
		assert.NotContains(t, e.FilePath, ".next")
		assert.NotContains(t, e.FilePath, "huge.js")
	}
	assert.True(t, npmHasDescription(res, "no first-party source file imports"))
}

func TestNpmAnalyze_PnpmLockfileProject(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}

	// Transitive dependency: only visible through pnpm-lock.yaml snapshots.
	res, err := a.Analyze(context.Background(), "testdata/npm_pnpm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-deep-transitive"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
	assert.True(t, npmHasDescription(res, "pnpm-lock.yaml"))

	// Absent package: full-confidence not_present thanks to the lockfile.
	res, err = a.Analyze(context.Background(), "testdata/npm_pnpm_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"totally-absent-pkg"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusNotPresent, res.Status)
	assert.InDelta(t, 0.90, res.Confidence, 0.001)
}

func TestNpmAnalyze_YarnLockfileProject(t *testing.T) {
	t.Parallel()
	a := &NpmAnalyzer{}

	res, err := a.Analyze(context.Background(), "testdata/npm_yarn_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-deep-transitive"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
	assert.True(t, npmHasDescription(res, "yarn.lock"))

	res, err = a.Analyze(context.Background(), "testdata/npm_yarn_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"@acme/scoped-lib"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
}

// ---------------------------------------------------------------------------
// unit tests for the parsing helpers
// ---------------------------------------------------------------------------

func TestParsePackageLockPackages_V1Shape(t *testing.T) {
	t.Parallel()
	g := &npmDependencyGraph{packages: map[string]npmGraphSource{}}
	data := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"acme-a": {"version": "1.0.0", "dependencies": {
				"acme-nested": {"version": "2.0.0"}
			}},
			"@scope/b": {"version": "3.0.0"}
		}
	}`)
	require.NoError(t, parsePackageLockPackages(data, "package-lock.json", g))
	for _, want := range []string{"acme-a", "acme-nested", "@scope/b"} {
		_, ok := g.packages[want]
		assert.True(t, ok, "missing %s in %v", want, g.packages)
	}
}

func TestPnpmPackageNameFromKey(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"/lodash/4.17.21":               "lodash",
		"/@scope/name/1.0.0":            "@scope/name",
		"/lodash@4.17.21":               "lodash",
		"lodash@4.17.21":                "lodash",
		"@scope/name@1.0.0":             "@scope/name",
		"@scope/name@1.0.0(peer@2.0.0)": "@scope/name",
		"/foo@1.0.0(react@18.0.0)":      "foo",
		"":                              "",
		"/":                             "",
		"plainname":                     "plainname",
	}
	for in, want := range cases {
		assert.Equal(t, want, pnpmPackageNameFromKey(in), "key %q", in)
	}
}

func TestParseYarnLockPackages_BerryDescriptors(t *testing.T) {
	t.Parallel()
	g := &npmDependencyGraph{packages: map[string]npmGraphSource{}}
	data := []byte(`# yarn berry style
__metadata:
  version: 6

"lodash@npm:^4.17.15, lodash@npm:^4.17.19":
  version: 4.17.21

"@babel/code-frame@npm:^7.0.0":
  version: 7.12.13
`)
	require.NoError(t, parseYarnLockPackages(data, "yarn.lock", g))
	_, ok := g.packages["lodash"]
	assert.True(t, ok, "lodash missing: %v", g.packages)
	_, ok = g.packages["@babel/code-frame"]
	assert.True(t, ok, "@babel/code-frame missing: %v", g.packages)
	_, ok = g.packages["__metadata"]
	assert.False(t, ok, "__metadata must be filtered out")
}

func TestNpmPackageFromSpecifier(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"lodash":                "lodash",
		"lodash/fp":             "lodash",
		"@scope/name":           "@scope/name",
		"@scope/name/sub/path":  "@scope/name",
		"./relative":            "",
		"../up":                 "",
		"/abs/path":             "",
		"#internal":             "",
		"node:fs":               "",
		"https://cdn.example/x": "",
		"@":                     "",
		"@scope":                "",
		"":                      "",
	}
	for in, want := range cases {
		assert.Equal(t, want, npmPackageFromSpecifier(in), "specifier %q", in)
	}
}

func TestParseNpmImportClause(t *testing.T) {
	t.Parallel()
	// Named bindings carry BOTH the original export name (selector matching
	// keys on it) and the local alias (M44 Phase D: use-site detection must
	// search the file for the LOCAL identifier — for `merge as m` an unused
	// `merge` string proves nothing, only uses of `m` do).
	cases := []struct {
		clause    string
		receivers []string
		named     []npmNamedImport
	}{
		{" _ ", []string{"_"}, nil},
		{" * as ns ", []string{"ns"}, nil},
		{" _, { merge as m, get } ", []string{"_"},
			[]npmNamedImport{{orig: "merge", local: "m"}, {orig: "get", local: "get"}}},
		{" { default as lodash } ", []string{"lodash"}, nil},
		{" { type Foo, bar } ", nil, []npmNamedImport{{orig: "bar", local: "bar"}}},
		{" { a, b, c } ", nil,
			[]npmNamedImport{{orig: "a", local: "a"}, {orig: "b", local: "b"}, {orig: "c", local: "c"}}},
		{" d, * as ns ", []string{"d", "ns"}, nil},
	}
	for _, tc := range cases {
		receivers, named := parseNpmImportClause(tc.clause)
		assert.Equal(t, tc.receivers, receivers, "receivers for %q", tc.clause)
		assert.Equal(t, tc.named, named, "named for %q", tc.clause)
	}
}

func TestParseNpmSymbolSelectors(t *testing.T) {
	t.Parallel()
	valid, malformed := parseNpmSymbolSelectors([]string{
		"defaultsDeep", "_.merge", "auth.api.removeUser", "$.extend",
		"a.b.c.d", "not-an-ident!", "", "  ", "defaultsDeep", // dup skipped
	})
	require.Len(t, valid, 4)
	assert.Equal(t, "defaultsDeep", valid[0].full)
	assert.Equal(t, []string{"_", "merge"}, valid[1].parts)
	assert.Equal(t, "removeUser", valid[2].leaf())
	assert.Equal(t, "$.extend", valid[3].full)
	assert.Equal(t, []string{"a.b.c.d", "not-an-ident!"}, malformed)
}

func TestStripJSComments(t *testing.T) {
	t.Parallel()
	src := "const a = require('x'); // require('gone')\n" +
		"/* require('also-gone') */\n" +
		"const url = 'http://not-a-comment';\n" +
		"const s = \"//still-a-string\";\n"
	out := stripJSComments(src)
	assert.Equal(t, len(src), len(out), "offsets must be preserved")
	assert.Contains(t, out, "require('x')")
	assert.NotContains(t, out, "gone")
	assert.Contains(t, out, "http://not-a-comment")
	assert.Contains(t, out, "//still-a-string")
}

func TestNpmLineIndex(t *testing.T) {
	t.Parallel()
	ix := newNpmLineIndex("ab\ncd\n\nef")
	line, col := ix.locate(0)
	assert.Equal(t, []int{1, 1}, []int{line, col})
	line, col = ix.locate(4) // "d"
	assert.Equal(t, []int{2, 2}, []int{line, col})
	line, col = ix.locate(7) // "e"
	assert.Equal(t, []int{4, 1}, []int{line, col})
}

// ---------------------------------------------------------------------------
// M44 Phase D round 1 regression tests (R2a: findings 1-5)
// ---------------------------------------------------------------------------

// npmWriteFile writes one file under root, creating parent directories.
func npmWriteFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

// TestNpmAnalyze_SymlinksNotFollowed guards the size-cap bypass (finding 1):
// d.Info() on a symlink reports the LINK's own lstat size, so before the fix
// a tiny symlink pointing at a huge file (or an unbounded device node like
// /dev/zero) passed the npmMaxFileSizeBytes gate and os.ReadFile read the
// TARGET — an unbounded-read DoS plus a false-positive vector (the target's
// content influenced the verdict). Symlinks (file and directory alike) must
// be skipped; only symlinks with a SOURCE-FILE extension — the ones that
// would have been scan candidates as regular files — are counted in the
// informational note (round-2 finding 4: counting directory links and
// non-source links too overstated the note).
func TestNpmAnalyze_SymlinksNotFollowed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()

	npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
	npmWriteFile(t, root, "package-lock.json", `{
		"lockfileVersion": 3,
		"packages": {"node_modules/acme-lodash": {"version": "4.17.21"}}
	}`)

	// Big REGULAR target outside the project: vulnerable-looking code on
	// top, padded past npmMaxFileSizeBytes so a direct in-tree copy would be
	// size-capped — only the symlink's small lstat size lets it through.
	vuln := "const _ = require('acme-lodash');\n_.defaultsDeep({}, {});\n"
	big := vuln + strings.Repeat("// pad\n", npmMaxFileSizeBytes/7+1024)
	npmWriteFile(t, outside, "big_target.js", big)

	if err := os.Symlink(filepath.Join(outside, "big_target.js"),
		filepath.Join(root, "big_link.js")); err != nil {
		t.Skipf("cannot create symlinks on this platform: %v", err)
	}
	wantSymlinks := 1

	// Directory symlink: WalkDir surfaces it as a non-dir entry; it must
	// not be followed (and never was), but its basename has no source
	// extension, so it was never a scan candidate and must NOT be counted
	// (round-2 finding 4: counting it overstated the note).
	npmWriteFile(t, outside, "linked_dir/inner.js", vuln)
	require.NoError(t, os.Symlink(filepath.Join(outside, "linked_dir"),
		filepath.Join(root, "linked_dir")))

	// Non-source file symlink (README/asset links, .bin shims and the like):
	// skipped, but not a candidate — must NOT be counted either.
	npmWriteFile(t, outside, "notes.txt", "plain text\n")
	require.NoError(t, os.Symlink(filepath.Join(outside, "notes.txt"),
		filepath.Join(root, "notes_link.txt")))

	// Unbounded device node, when the platform has one: before the fix,
	// os.ReadFile on this link never terminated (R1 reproduced the DoS).
	// Its .js name makes it a would-be candidate, so it IS counted.
	if _, err := os.Stat("/dev/zero"); err == nil {
		require.NoError(t, os.Symlink("/dev/zero", filepath.Join(root, "zero_link.js")))
		wantSymlinks++
	}

	a := &NpmAnalyzer{}
	res, err := a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status,
		"symlinked content must not influence the verdict")
	for _, e := range res.Evidence {
		assert.NotContains(t, e.FilePath, "big_link")
		assert.NotContains(t, e.FilePath, "zero_link")
		assert.NotContains(t, e.FilePath, "linked_dir")
		assert.NotContains(t, e.FilePath, "notes_link")
	}
	assert.True(t, npmHasDescription(res,
		fmt.Sprintf("%d symlink(s) with source-file extensions skipped", wantSymlinks)),
		"expected a %d-symlink note, got %+v", wantSymlinks, res.Evidence)
}

// TestNpmAnalyze_StringLiteralContentIgnored guards finding 2: require()/
// import statements and member-call text inside '…'/"…" string literals and
// template-literal text must produce neither import evidence/bindings nor
// symbol hits (docstrings and log messages were a false-reachable vector —
// the analyzer's error budget is false-negative-only). Code inside
// template-literal ${...} interpolations is real code and must keep
// matching.
func TestNpmAnalyze_StringLiteralContentIgnored(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	npmWriteFile(t, root, "package.json",
		`{"dependencies": {"acme-lodash": "^1.0.0", "acme-str-only": "^1.0.0", "acme-tpl-pkg": "^1.0.0"}}`)
	npmWriteFile(t, root, "src/strings.js",
		"const _ = require('acme-lodash');\n"+
			"\n"+
			"const doc = \"call require('acme-str-only') then _.merge(a, b)\";\n"+
			"const doc2 = 'single: require(\"acme-str-only\") and _.merge(';\n"+
			"const tpl = `template: require('acme-str-only') and _.merge( text`;\n"+
			"\n"+
			"module.exports = { doc, doc2, tpl, _ };\n")
	npmWriteFile(t, root, "src/tpl_code.js",
		"const _ = require('acme-lodash');\n"+
			"export const msg = `sum: ${_.defaultsDeep({}, {})} via ${require('acme-tpl-pkg').x}`;\n")

	a := &NpmAnalyzer{}

	// (a) A package referenced ONLY inside string/template text: stage 2
	// must not see a source import at all.
	res, err := a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-str-only"},
			VulnerableSymbols: []string{"merge"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		assert.Zero(t, e.Line, "string-literal require must not yield source import evidence: %+v", e)
	}
	assert.True(t, npmHasDescription(res, "no first-party source file imports"),
		"expected the transitive/unused note, got %+v", res.Evidence)

	// (b) A really-imported package whose symbol appears only inside
	// string/template text: must stay import_only, not reachable.
	res, err = a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"merge", "_.merge"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status,
		"symbol text inside string literals must not be a symbol hit")
	assert.Empty(t, npmEvidenceOfKind(res, EvidenceKindSymbolRef))

	// (c) Code inside a template-literal ${...} interpolation IS code:
	// the member call must be found.
	res, err = a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-lodash"},
			VulnerableSymbols: []string{"defaultsDeep"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusReachable, res.Status,
		"member call inside ${...} interpolation must stay detectable")
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	require.Len(t, symbols, 1)
	assert.Equal(t, "src/tpl_code.js", symbols[0].FilePath)

	// (d) require() inside a ${...} interpolation is a real import.
	res, err = a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-tpl-pkg"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusImportOnly, res.Status)
	var tplImport bool
	for _, e := range npmEvidenceOfKind(res, EvidenceKindImportPath) {
		if e.FilePath == "src/tpl_code.js" {
			tplImport = true
		}
	}
	assert.True(t, tplImport, "require inside ${...} must yield import evidence, got %+v", res.Evidence)
}

// TestNpmAnalyze_DollarIdentifierSelectors guards finding 3: "$" is a legal
// JS identifier character but a regex anchor, so before the fix the
// member-call pattern was doubly broken — `$watch` became "end-of-line
// anchor + watch" (never matches) and the leading `\b` DEMANDED a word char
// before a `$` receiver, so `$.ajax(` at statement start never matched while
// `x$.ajax(` (a different identifier) falsely did.
func TestNpmAnalyze_DollarIdentifierSelectors(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	npmWriteFile(t, root, "package.json",
		`{"dependencies": {"acme-jquery": "^1.0.0", "acme-vue": "^1.0.0"}}`)
	npmWriteFile(t, root, "src/jq.js",
		"const $ = require('acme-jquery');\n"+
			"const x$ = { ajax() {} };\n"+
			"$.ajax({ url: '/api' });\n"+
			"x$.ajax({ url: '/decoy' });\n")
	npmWriteFile(t, root, "src/vue.js",
		"const svc = require('acme-vue');\n"+
			"svc.$watch('prop', () => {});\n")

	a := &NpmAnalyzer{}

	// `$` as the receiver: $.ajax( at statement start must match; the
	// x$.ajax( decoy (different identifier) must NOT.
	res, err := a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-jquery"},
			VulnerableSymbols: []string{"$.ajax"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusReachable, res.Status)
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	require.Len(t, symbols, 1, "exactly the $.ajax( call, not the x$.ajax( decoy: %+v", symbols)
	assert.Equal(t, 3, symbols[0].Line)
	assert.Equal(t, 1, symbols[0].Column)

	// `$` inside the method name: svc.$watch( must match.
	res, err = a.Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-vue"},
			VulnerableSymbols: []string{"svc.$watch"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusReachable, res.Status)
	symbols = npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	require.Len(t, symbols, 1)
	assert.Equal(t, "src/vue.js", symbols[0].FilePath)
	assert.Equal(t, 2, symbols[0].Line)
}

// TestNpmAnalyze_NamedImportRequiresUse guards finding 4: a named import /
// require-destructure binding of a vulnerable symbol is only a symbol
// reference when the LOCAL identifier is actually used outside binding
// declarations — either called (merge(...)) or referenced (arr.map(merge);
// a bare reference hands the function around, so it may execute). An import
// that is never used must stay import_only (false-positive direction
// otherwise) with an explanatory evidence note.
func TestNpmAnalyze_NamedImportRequiresUse(t *testing.T) {
	t.Parallel()
	analyze := func(t *testing.T, source string) *ReachabilityResult {
		t.Helper()
		root := t.TempDir()
		npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
		npmWriteFile(t, root, "src/app.js", source)
		res, err := (&NpmAnalyzer{}).Analyze(context.Background(), root,
			ReachabilityInput{
				Ecosystem:         "npm",
				VulnerableModules: []string{"acme-lodash"},
				VulnerableSymbols: []string{"merge"},
			})
		require.NoError(t, err)
		return res
	}

	t.Run("unused named import is import_only with note", func(t *testing.T) {
		res := analyze(t, "import { merge } from 'acme-lodash';\nexport const answer = 42;\n")
		assert.Equal(t, StatusImportOnly, res.Status)
		assert.Empty(t, npmEvidenceOfKind(res, EvidenceKindSymbolRef))
		assert.True(t, npmHasDescription(res, "binding imported but no use found"),
			"expected the unused-binding note, got %+v", res.Evidence)
	})

	t.Run("call is reachable", func(t *testing.T) {
		res := analyze(t, "import { merge } from 'acme-lodash';\nmerge({}, {});\n")
		assert.Equal(t, StatusReachable, res.Status)
		symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
		require.Len(t, symbols, 1)
		assert.Equal(t, 2, symbols[0].Line)
		assert.Contains(t, symbols[0].Description, "named import binding")
	})

	t.Run("bare reference (callback passing) is reachable", func(t *testing.T) {
		res := analyze(t, "import { merge } from 'acme-lodash';\n"+
			"export const out = [1].map(merge);\n")
		assert.Equal(t, StatusReachable, res.Status)
	})

	t.Run("aliased import matched via alias use", func(t *testing.T) {
		res := analyze(t, "import { merge as m } from 'acme-lodash';\nm({}, {});\n")
		assert.Equal(t, StatusReachable, res.Status)
	})

	t.Run("aliased import not matched by same-named local fn", func(t *testing.T) {
		// The vulnerable binding's LOCAL name is m; a different local
		// function that happens to be called merge must not count.
		res := analyze(t, "import { merge as m } from 'acme-lodash';\n"+
			"const merge = () => {};\nmerge();\n")
		assert.Equal(t, StatusImportOnly, res.Status)
	})

	t.Run("unused require destructure is import_only", func(t *testing.T) {
		res := analyze(t, "const { merge } = require('acme-lodash');\nexport const answer = 42;\n")
		assert.Equal(t, StatusImportOnly, res.Status)
		assert.True(t, npmHasDescription(res, "binding imported but no use found"))
	})

	t.Run("object-literal key is not a use", func(t *testing.T) {
		res := analyze(t, "import { merge } from 'acme-lodash';\n"+
			"export const o = { merge: 1 };\n")
		assert.Equal(t, StatusImportOnly, res.Status)
	})
}

// TestNpmAnalyze_UnicodeIdentifierSelector guards finding 5: the server-side
// filter (isJSIdentifier) and the CLI filter (isJSIdentifierShaped) accept
// Unicode letters in selector parts, so the analyzer must too — before the
// fix the ASCII-only npmIdentRe silently dropped such selectors as
// "malformed" and the verdict degraded to import_only.
func TestNpmAnalyze_UnicodeIdentifierSelector(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-uni": "^1.0.0"}}`)
	npmWriteFile(t, root, "src/uni.js",
		"const café = require('acme-uni');\ncafé.parse('data');\n")

	res, err := (&NpmAnalyzer{}).Analyze(context.Background(), root,
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"acme-uni"},
			VulnerableSymbols: []string{"café.parse"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusReachable, res.Status)
	assert.False(t, npmHasDescription(res, "malformed"),
		"a Unicode-letter selector must not be skipped as malformed: %+v", res.Evidence)
	symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
	require.Len(t, symbols, 1)
	assert.Equal(t, "café.parse", symbols[0].Symbol)
	assert.Equal(t, 2, symbols[0].Line)
}

func TestParseNpmSymbolSelectors_UnicodeIdentifiers(t *testing.T) {
	t.Parallel()
	valid, malformed := parseNpmSymbolSelectors([]string{
		"café.parse", "変数.メソッド", "1café",
	})
	require.Len(t, valid, 2, "Unicode-letter selectors must parse: %+v (malformed %v)", valid, malformed)
	assert.Equal(t, "café.parse", valid[0].full)
	assert.Equal(t, "メソッド", valid[1].leaf())
	assert.Equal(t, []string{"1café"}, malformed, "leading digit still malformed")
}

func TestStripJSCode_StringAndTemplateBlanking(t *testing.T) {
	t.Parallel()
	src := "const a = require('x');\n" +
		"const s = \"require('y') and _.merge(\";\n" +
		"const t = `text ${_.merge(a, b)} more ${`inner ${deep} rest`} end`;\n"
	stripped, codeOnly := stripJSCode(src)
	require.Equal(t, len(src), len(stripped), "offsets must be preserved")
	require.Equal(t, len(src), len(codeOnly), "offsets must be preserved")
	// stripped keeps string content (import specifiers must stay readable).
	assert.Contains(t, stripped, "require('y')")
	// codeOnly blanks string bodies and template text…
	assert.NotContains(t, codeOnly, "require('y')")
	assert.NotContains(t, codeOnly, "text")
	assert.NotContains(t, codeOnly, "more")
	assert.NotContains(t, codeOnly, "inner")
	assert.NotContains(t, codeOnly, "end")
	// …but keeps real code, including inside ${} interpolations (nested).
	assert.Contains(t, codeOnly, "require(")
	assert.Contains(t, codeOnly, "_.merge(a, b)")
	assert.Contains(t, codeOnly, "deep")
	// Newlines survive so the line index still works.
	assert.Equal(t, strings.Count(src, "\n"), strings.Count(codeOnly, "\n"))
}

// ---------------------------------------------------------------------------
// M44 Phase D round 2 regression tests (R3a: npm analyzer findings), kept in
// lockstep with the CLI suite.
// ---------------------------------------------------------------------------

// TestNpmAnalyze_MethodDefinitionKeyNotAUse guards round-2 finding 1: an
// object-literal / class-body method DEFINITION key that happens to carry the
// vulnerable symbol's name (`const o = { merge() {…} }`) is not a use of the
// imported binding — before the fix the `merge(` text was read as a call and
// the verdict went false-reachable. The decisive shape is that the ')'
// matching the identifier's '(' is directly followed by '{' (a block never
// follows a call expression without a statement break), so real calls —
// including `foo(merge(1))` and `if (merge(x)) {`, whose extra ')' sits
// between the call's ')' and the '{' — keep matching.
func TestNpmAnalyze_MethodDefinitionKeyNotAUse(t *testing.T) {
	t.Parallel()
	analyze := func(t *testing.T, source string) *ReachabilityResult {
		t.Helper()
		root := t.TempDir()
		npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
		npmWriteFile(t, root, "src/app.js", source)
		res, err := (&NpmAnalyzer{}).Analyze(context.Background(), root,
			ReachabilityInput{
				Ecosystem:         "npm",
				VulnerableModules: []string{"acme-lodash"},
				VulnerableSymbols: []string{"merge"},
			})
		require.NoError(t, err)
		return res
	}
	wantImportOnly := func(t *testing.T, res *ReachabilityResult) {
		t.Helper()
		assert.Equal(t, StatusImportOnly, res.Status)
		assert.Empty(t, npmEvidenceOfKind(res, EvidenceKindSymbolRef))
		assert.True(t, npmHasDescription(res, "binding imported but no use found"),
			"expected the unused-binding note, got %+v", res.Evidence)
	}

	t.Run("object method shorthand key is not a use", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"const o = { merge(a, b) { return a; } };\n"+
				"export default o;\n"))
	})

	t.Run("async and getter shorthand keys are not uses", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"const o = { async merge(a) { return a; } };\n"+
				"const p = { get merge() { return 1; } };\n"+
				"export default [o, p];\n"))
	})

	t.Run("class method key is not a use", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"class C { merge(x) { return x; } }\n"+
				"export default C;\n"))
	})

	t.Run("Allman-style body brace on the next line is still a definition", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"const o = { merge (a, b)\n"+
				"{ return a; } };\n"+
				"export default o;\n"))
	})

	t.Run("sloppy-mode function declaration is not a use", func(t *testing.T) {
		// var + function-declaration redeclaration is valid sloppy-mode JS;
		// the declaration's `merge(` must not read as a call of the binding.
		wantImportOnly(t, analyze(t,
			"var { merge } = require('acme-lodash');\n"+
				"function merge(a) { return a; }\n"))
	})

	t.Run("call in argument position is a use", func(t *testing.T) {
		res := analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"export const r = JSON.stringify(merge({}, {}));\n")
		assert.Equal(t, StatusReachable, res.Status)
	})

	t.Run("call in an if condition is a use", func(t *testing.T) {
		res := analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"if (merge({})) { console.log('hit'); }\n")
		assert.Equal(t, StatusReachable, res.Status)
	})

	t.Run("shorthand property value is still a use", func(t *testing.T) {
		// `{ merge }` REFERENCES the binding (hands the function around) —
		// the definition-key exclusion must not over-reach into it.
		res := analyze(t,
			"import { merge } from 'acme-lodash';\n"+
				"export const o = { merge };\n")
		assert.Equal(t, StatusReachable, res.Status)
	})
}

// TestNpmAnalyze_RegexLiteralStringParity guards round-2 finding 2 (R1b
// reproduced it live): stripJSCode did not model regex literals, so a quote
// or backtick INSIDE a regex (`/'/`, "/\\`/") opened a phantom string in
// codeOnly; the parity flip turned later real string text into phantom code
// and `_.merge(` inside a docstring became a false-reachable symbol hit.
// Regex literals are now lexed via a prev-token heuristic and blanked, while
// division expressions stay untouched.
func TestNpmAnalyze_RegexLiteralStringParity(t *testing.T) {
	t.Parallel()
	analyze := func(t *testing.T, source string, symbols []string) *ReachabilityResult {
		t.Helper()
		root := t.TempDir()
		npmWriteFile(t, root, "package.json", `{"dependencies": {"acme-lodash": "^4.17.0"}}`)
		npmWriteFile(t, root, "src/app.js", source)
		res, err := (&NpmAnalyzer{}).Analyze(context.Background(), root,
			ReachabilityInput{
				Ecosystem:         "npm",
				VulnerableModules: []string{"acme-lodash"},
				VulnerableSymbols: symbols,
			})
		require.NoError(t, err)
		return res
	}
	wantImportOnly := func(t *testing.T, res *ReachabilityResult) {
		t.Helper()
		assert.Equal(t, StatusImportOnly, res.Status)
		assert.Empty(t, npmEvidenceOfKind(res, EvidenceKindSymbolRef))
	}

	t.Run("quote in regex must not turn a same-line string into code", func(t *testing.T) {
		// Same line matters: the string lexer resyncs at newlines, so the
		// R1b parity flip is confined to (and reproduced on) one line.
		wantImportOnly(t, analyze(t,
			"const _ = require('acme-lodash');\n"+
				"const esc = /'/; const doc = 'docs: _.merge(a, b) example';\n"+
				"module.exports = { _, esc, doc };\n",
			[]string{"merge", "_.merge"}))
	})

	t.Run("backtick in regex must not open a phantom template", func(t *testing.T) {
		// R1b: the parity flip from /\`/ swallowed the REAL template opener,
		// so the template's multi-line text body became phantom code.
		wantImportOnly(t, analyze(t,
			"const _ = require('acme-lodash');\n"+
				"const re = /\\`/;\n"+
				"const tpl = `multi\n"+
				"line _.merge(a, b) text\n"+
				"end`;\n"+
				"module.exports = { _, re, tpl };\n",
			[]string{"merge", "_.merge"}))
	})

	t.Run("regex as a call argument", func(t *testing.T) {
		wantImportOnly(t, analyze(t,
			"const _ = require('acme-lodash');\n"+
				"const out = 'x'.replace(/'/g, '-'); const doc = 'see _.merge(a, b)';\n"+
				"module.exports = { _, out, doc };\n",
			[]string{"merge", "_.merge"}))
	})

	t.Run("division is not misread as a regex", func(t *testing.T) {
		res := analyze(t,
			"const _ = require('acme-lodash');\n"+
				"const ratio = 10 / 2 / 5;\n"+
				"_.defaultsDeep({}, {});\n",
			[]string{"defaultsDeep"})
		require.Equal(t, StatusReachable, res.Status,
			"division must not blank following code")
		symbols := npmEvidenceOfKind(res, EvidenceKindSymbolRef)
		require.Len(t, symbols, 1)
		assert.Equal(t, 3, symbols[0].Line)
	})
}

func TestStripJSCode_RegexLiterals(t *testing.T) {
	t.Parallel()
	src := "const esc = /'/; const doc = 'STRTEXT _.merge(a, b)';\n" +
		"const re = /RXBODY[/]\\//gi;\n" +
		"const ratio = a / b / c;\n" +
		"return /'/.test(s) ? 1 : 0;\n"
	stripped, codeOnly := stripJSCode(src)
	require.Equal(t, len(src), len(stripped), "offsets must be preserved")
	require.Equal(t, len(src), len(codeOnly), "offsets must be preserved")
	// The quote inside /'/ must not flip string parity: the next string
	// stays a string (blanked in codeOnly) and its declaration stays code.
	assert.NotContains(t, codeOnly, "STRTEXT")
	assert.NotContains(t, codeOnly, "_.merge(")
	assert.NotContains(t, codeOnly, "RXBODY")
	assert.NotContains(t, codeOnly, "gi")
	assert.Contains(t, codeOnly, "const doc =")
	assert.Contains(t, codeOnly, "a / b / c")
	assert.Contains(t, codeOnly, ".test(s) ? 1 : 0")
	// stripped only blanks comments: string text stays readable there.
	assert.Contains(t, stripped, "STRTEXT")
	assert.Equal(t, strings.Count(src, "\n"), strings.Count(codeOnly, "\n"))
}
