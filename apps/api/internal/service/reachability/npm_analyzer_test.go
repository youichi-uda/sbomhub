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
	assert.Equal(t, 2, symbols[0].Line)
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
	cases := []struct {
		clause    string
		receivers []string
		named     []string
	}{
		{" _ ", []string{"_"}, nil},
		{" * as ns ", []string{"ns"}, nil},
		{" _, { merge as m, get } ", []string{"_"}, []string{"merge", "get"}},
		{" { default as lodash } ", []string{"lodash"}, nil},
		{" { type Foo, bar } ", nil, []string{"bar"}},
		{" { a, b, c } ", nil, []string{"a", "b", "c"}},
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
