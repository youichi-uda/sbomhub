package reachability

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture projects under testdata reference example.test/vulnpkg, a
// fake module that does not exist in the public module proxy. We therefore
// run Analyze with SkipPackagesLoad=true (covering the stage-1 module
// graph logic) and exercise the AST symbol walk separately via
// inspectFileForSelectors against the same fixture files. This keeps the
// test suite offline-safe and reproducible in CI.

func TestAnalyze_NotPresent(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{SkipPackagesLoad: true}
	res, err := a.Analyze(context.Background(),
		"testdata/not_present_project",
		ReachabilityInput{
			AdvisoryID:        "GHSA-test-0001",
			Ecosystem:         "go",
			VulnerableModules: []string{"example.test/vulnpkg"},
			VulnerableSymbols: []string{"vulnpkg.Unmarshal"},
		})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, StatusNotPresent, res.Status)
	assert.InDelta(t, 0.90, res.Confidence, 0.001)
	assert.Equal(t, "go", res.Ecosystem)
	assert.Equal(t, analyzerName, res.AnalyzerName)
}

func TestAnalyze_ImportOnly_ViaSkipPackagesLoad(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{SkipPackagesLoad: true}
	res, err := a.Analyze(context.Background(),
		"testdata/import_only_project",
		ReachabilityInput{
			AdvisoryID:        "GHSA-test-0002",
			Ecosystem:         "go",
			VulnerableModules: []string{"example.test/vulnpkg"},
			VulnerableSymbols: []string{"vulnpkg.Unmarshal"},
		})
	require.NoError(t, err)
	require.NotNil(t, res)
	// With SkipPackagesLoad we cannot reach the symbol stage, so this
	// asserts the import-only fallback path. The "actual" import-only
	// verification (vs reachable) happens in TestInspectFile_ImportOnly.
	assert.Equal(t, StatusImportOnly, res.Status)
	assert.InDelta(t, 0.60, res.Confidence, 0.001)
	require.NotEmpty(t, res.Evidence)
	// First evidence entry should be the import-path hit.
	assert.Equal(t, EvidenceKindImportPath, res.Evidence[0].Kind)
	assert.Equal(t, "example.test/vulnpkg", res.Evidence[0].ImportPath)
}

func TestAnalyze_UnknownOnEmptyProjectPath(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(), "  ",
		ReachabilityInput{
			Ecosystem:         "go",
			VulnerableModules: []string{"example.test/vulnpkg"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, res.Status)
	assert.Equal(t, 0.0, res.Confidence)
	require.Len(t, res.Evidence, 1)
	assert.Equal(t, EvidenceKindAnalyzerError, res.Evidence[0].Kind)
}

func TestAnalyze_UnknownOnUnsupportedEcosystem(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(), "testdata/not_present_project",
		ReachabilityInput{
			Ecosystem:         "npm",
			VulnerableModules: []string{"lodash"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, res.Status)
	require.Len(t, res.Evidence, 1)
	assert.Contains(t, res.Evidence[0].Description, "npm")
	assert.Contains(t, res.Evidence[0].Description, "M2")
}

func TestAnalyze_UnknownOnMissingGoMod(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(),
		"testdata/__no_such_dir__",
		ReachabilityInput{
			Ecosystem:         "go",
			VulnerableModules: []string{"example.test/vulnpkg"},
		})
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, res.Status)
}

func TestAnalyze_UnknownOnEmptyVulnerableModules(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	res, err := a.Analyze(context.Background(),
		"testdata/vulnerable_project",
		ReachabilityInput{Ecosystem: "go"})
	require.NoError(t, err)
	assert.Equal(t, StatusUnknown, res.Status)
}

func TestAnalyze_NilContext(t *testing.T) {
	t.Parallel()
	a := &GoAnalyzer{}
	//nolint:staticcheck // intentionally passing nil to verify defensive check
	_, err := a.Analyze(nil, "testdata/not_present_project",
		ReachabilityInput{Ecosystem: "go", VulnerableModules: []string{"x"}})
	require.Error(t, err)
}

func TestLoadModuleGraph_ReadsRequireBlock(t *testing.T) {
	t.Parallel()
	graph, err := loadModuleGraph("testdata/vulnerable_project")
	require.NoError(t, err)
	assert.Contains(t, graph, "example.test/vulnpkg")
}

func TestLoadModuleGraph_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := loadModuleGraph("testdata/__no_such_dir__")
	require.Error(t, err)
}

func TestMatchModules(t *testing.T) {
	t.Parallel()
	graph := map[string]struct{}{
		"github.com/foo/bar":   {},
		"example.test/vulnpkg": {},
	}
	hits := matchModules(graph, []string{"example.test/vulnpkg", "missing/mod"})
	assert.Equal(t, []string{"example.test/vulnpkg"}, hits)
}

func TestParseSymbolSelectors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       []string
		wantPkg  []string
		wantLeaf []string
		wantErr  bool
	}{
		{
			name:     "two-part",
			in:       []string{"yaml.Unmarshal"},
			wantPkg:  []string{"yaml"},
			wantLeaf: []string{"Unmarshal"},
		},
		{
			name:     "three-part method",
			in:       []string{"sql.DB.Exec"},
			wantPkg:  []string{"sql"},
			wantLeaf: []string{"Exec"},
		},
		{
			name:    "bare function rejected",
			in:      []string{"Unmarshal"},
			wantErr: true,
		},
		{
			name:     "trimming + skip empty",
			in:       []string{"  ", "yaml.Unmarshal"},
			wantPkg:  []string{"yaml"},
			wantLeaf: []string{"Unmarshal"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSymbolSelectors(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, len(tc.wantPkg))
			for i, g := range got {
				assert.Equal(t, tc.wantPkg[i], g.pkg)
				assert.Equal(t, tc.wantLeaf[i], g.leaf)
			}
		})
	}
}

func TestMatchSelector(t *testing.T) {
	t.Parallel()
	want := symbolSelector{pkg: "yaml", leaf: "Unmarshal", full: "yaml.Unmarshal"}
	assert.True(t, matchSelector("yaml", "Unmarshal", want))
	assert.False(t, matchSelector("yaml", "Marshal", want))
	assert.False(t, matchSelector("json", "Unmarshal", want))
}

// --- AST inspection ----------------------------------------------------

func TestInspectFile_Reachable(t *testing.T) {
	t.Parallel()
	file, fset := parseFixture(t, "testdata/vulnerable_project/main.go")
	wanted, err := parseSymbolSelectors([]string{"vulnpkg.Unmarshal"})
	require.NoError(t, err)
	seen := map[string]struct{}{}
	hits := inspectFileForSelectors(fset, file, "main.go", wanted, seen)
	require.Len(t, hits, 1, "expected exactly one symbol-ref evidence for vulnpkg.Unmarshal")
	assert.Equal(t, EvidenceKindSymbolRef, hits[0].Kind)
	assert.Equal(t, "vulnpkg.Unmarshal", hits[0].Symbol)
	assert.Equal(t, "main.go", hits[0].FilePath)
	assert.Greater(t, hits[0].Line, 0)
	assert.Greater(t, hits[0].Column, 0)
}

func TestInspectFile_ImportOnly(t *testing.T) {
	t.Parallel()
	file, fset := parseFixture(t, "testdata/import_only_project/main.go")
	wanted, err := parseSymbolSelectors([]string{"vulnpkg.Unmarshal"})
	require.NoError(t, err)
	seen := map[string]struct{}{}
	hits := inspectFileForSelectors(fset, file, "main.go", wanted, seen)
	assert.Empty(t, hits, "import-only fixture must not match vulnpkg.Unmarshal")
}

func TestInspectFile_DedupesAcrossCalls(t *testing.T) {
	t.Parallel()
	file, fset := parseFixture(t, "testdata/vulnerable_project/main.go")
	wanted, err := parseSymbolSelectors([]string{"vulnpkg.Unmarshal"})
	require.NoError(t, err)
	seen := map[string]struct{}{}
	first := inspectFileForSelectors(fset, file, "main.go", wanted, seen)
	second := inspectFileForSelectors(fset, file, "main.go", wanted, seen)
	assert.Len(t, first, 1)
	assert.Empty(t, second, "second pass with shared seen map must be deduped")
}

func parseFixture(t *testing.T, path string) (file *ast.File, fset *token.FileSet) {
	t.Helper()
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	fs := token.NewFileSet()
	parsed, err := parser.ParseFile(fs, abs, nil, parser.ParseComments)
	require.NoError(t, err)
	return parsed, fs
}
