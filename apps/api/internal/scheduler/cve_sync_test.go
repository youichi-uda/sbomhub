package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// GetBySource satisfies the M43 Phase D R4-widened advisoryExcerptUpserter
// contract for the base M32 fake (Go allows methods in any file of the
// declaring package): it always reports "no existing row" (nil, nil), which
// keeps every pre-R4 test's tombstone behaviour byte-identical — a tombstone
// against no existing row writes a plain empty row. Tests that need
// existing-row semantics use fakeAdvisoryExcerptStore below, whose own
// GetBySource shadows this one.
func (f *fakeAdvisoryExcerptUpserter) GetBySource(context.Context, uuid.UUID, string, string) (*repository.AdvisoryExcerpt, error) {
	return nil, nil
}

// fakeAdvisoryExcerptStore extends the M32 fake with a configurable
// GetBySource read so the M43 Phase D R4 tombstone clobber guard can be
// unit-tested hermetically: `existing` seeds the rows the store already
// holds (keyed tenant|cve|source via excerptStoreKey), getKeys records which
// keys the writer consulted (and in what order), and getErr fails every read
// (the chunk-abort path). Upsert recording is inherited from the embedded
// fake.
type fakeAdvisoryExcerptStore struct {
	fakeAdvisoryExcerptUpserter
	existing map[string]*repository.AdvisoryExcerpt
	getKeys  []string
	getErr   error
}

func excerptStoreKey(tenantID uuid.UUID, cveID, source string) string {
	return tenantID.String() + "|" + cveID + "|" + source
}

func (f *fakeAdvisoryExcerptStore) GetBySource(_ context.Context, tenantID uuid.UUID, cveID, source string) (*repository.AdvisoryExcerpt, error) {
	key := excerptStoreKey(tenantID, cveID, source)
	f.getKeys = append(f.getKeys, key)
	if f.getErr != nil {
		return nil, f.getErr
	}
	if e, ok := f.existing[key]; ok {
		cp := *e // value copy: callers must not mutate the seeded row
		return &cp, nil
	}
	return nil, nil
}

// TestNewCVESyncJob_DefaultBaseURL asserts an empty baseURL falls back to the
// cveSyncAPIURL const (M40 Wave B).
func TestNewCVESyncJob_DefaultBaseURL(t *testing.T) {
	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "", false)
	if j.baseURL != cveSyncAPIURL {
		t.Errorf("expected default baseURL %q, got %q", cveSyncAPIURL, j.baseURL)
	}
	if j.offline {
		t.Error("expected offline false by default")
	}

	j2 := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "https://mirror.example/cves", true)
	if j2.baseURL != "https://mirror.example/cves" {
		t.Errorf("expected overridden baseURL, got %q", j2.baseURL)
	}
	if !j2.offline {
		t.Error("expected offline true")
	}
}

// TestCVESyncJob_Offline_RunSkips asserts offline mode short-circuits Run at the
// top before any DB or network access (M40 Wave B). A nil *sql.DB proves no DB
// path is reached.
func TestCVESyncJob_Offline_RunSkips(t *testing.T) {
	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "", true)
	if err := j.Run(context.Background()); err != nil {
		t.Fatalf("offline Run should return nil, got %v", err)
	}
}

// TestCVESyncJob_FetchModifiedCVEs_HTTPMock drives fetchModifiedCVEs against an
// injected httptest base URL and asserts the NVD modified-feed JSON parses
// (M40 Wave B). fetchModifiedCVEs touches only the HTTP client + baseURL, so no
// DB is required.
func TestCVESyncJob_FetchModifiedCVEs_HTTPMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("startIndex") == "" {
			t.Error("expected startIndex query param")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"startIndex": 0,
			"resultsPerPage": 2000,
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2023-1234",
						"published": "2023-01-15T10:15:00Z",
						"lastModified": "2023-06-20T15:45:00Z",
						"descriptions": [
							{"lang": "en", "value": "Test vuln in libfoo"}
						],
						"metrics": {
							"cvssMetricV31": [
								{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
							]
						},
						"configurations": [
							{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:foo:libfoo:1.0.0:*:*:*:*:*:*:*", "vulnerable": true}]}]}
						]
					}
				}
			]
		}`))
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, server.URL, false)
	cves, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("fetchModifiedCVEs returned error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("expected 1 CVE, got %d", len(cves))
	}
	if cves[0].ID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", cves[0].ID)
	}
	if cves[0].Description != "Test vuln in libfoo" {
		t.Errorf("unexpected description: %q", cves[0].Description)
	}
	if cves[0].Severity != "HIGH" || cves[0].CVSSScore != 7.5 {
		t.Errorf("expected HIGH/7.5, got %s/%f", cves[0].Severity, cves[0].CVSSScore)
	}
	// Keywords should include the CPE product for downstream matching.
	found := false
	for _, kw := range cves[0].Keywords {
		if kw == "libfoo" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'libfoo' keyword extracted from CPE, got %v", cves[0].Keywords)
	}
}

// ============================================================================
// M43 Wave 3 (F467, issue #169): OSV / Go vulndb structured vulnerable
// symbols → advisory_excerpts.vuln_funcs (source 'osv').
//
// Hermetic throughout: the OSV API is an httptest server injected via
// WithOSVBaseURL, the candidate enumeration + write-pass SQL wire is sqlmock,
// and the excerpt Upsert is intercepted by fakeAdvisoryExcerptUpserter
// (advisory_excerpt_test.go). Real-PG properties (RLS WITH CHECK under the
// GUC, ON CONFLICT idempotency, migration 056's CHECK swap) are repository /
// integration territory — see the M32 caveat header in
// advisory_excerpt_test.go, which applies identically here.
// ============================================================================

// zeroOSVFetchDelay removes the politeness pause for the duration of a test
// (defer-restore pattern, same as cveMatchBatchChunkSize overrides).
func zeroOSVFetchDelay(t *testing.T) {
	t.Helper()
	prevDelay := osvVulnFuncsFetchDelay
	osvVulnFuncsFetchDelay = 0
	t.Cleanup(func() { osvVulnFuncsFetchDelay = prevDelay })
}

// captureSlog redirects the PROCESS-GLOBAL default slog logger into a buffer
// for the duration of one test (restored via t.Cleanup) so log-line
// contracts — e.g. the M43 Phase D R3 mass-404 suppression Warn — can be
// asserted. Tests using it must not run in parallel (none in this package
// do). The code under test logs synchronously from the test goroutine, so a
// plain buffer is safe.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// wave1NormalizeReplica restates the FROZEN Wave 1 wire-normalisation spec
// from handler.normalizeVulnFuncs (reachability.go): TrimSpace → strip one
// trailing "()" → dot-split → keep only 2..3 parts → every part
// Go-identifier-shaped → first-seen-order dedupe. Re-implemented here (not
// imported — the handler helper is unexported in another package) so the
// scheduler's stored selectors are pinned against the exact rules the
// serving edge applies: any element this replica would drop is dead weight
// the M43 Wave 3 producer must never persist.
func wave1NormalizeReplica(raw []string) []string {
	isIdent := func(s string) bool {
		if s == "" {
			return false
		}
		for i, r := range s {
			switch {
			case r == '_' || unicode.IsLetter(r):
			case i > 0 && unicode.IsDigit(r):
			default:
				return false
			}
		}
		return true
	}
	var out []string
	seen := make(map[string]struct{}, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, "()")
		if s == "" {
			continue
		}
		parts := strings.Split(s, ".")
		if len(parts) < 2 || len(parts) > 3 {
			continue
		}
		ok := true
		for _, p := range parts {
			if !isIdent(p) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// assertWireSafe asserts every produced selector survives the Wave 1 edge
// normalisation UNCHANGED (same elements, same order).
func assertWireSafe(t *testing.T, funcs []string) {
	t.Helper()
	norm := wave1NormalizeReplica(funcs)
	if len(norm) != len(funcs) {
		t.Fatalf("W1 normalisation dropped elements: stored %v, survives %v", funcs, norm)
	}
	for i := range funcs {
		if norm[i] != funcs[i] {
			t.Errorf("W1 normalisation changed element %d: stored %q, survives %q", i, funcs[i], norm[i])
		}
	}
}

// TestOSVGoPackageIdent pins the path → package-identifier heuristic the
// selector conversion depends on, including the conservative skips.
func TestOSVGoPackageIdent(t *testing.T) {
	cases := []struct {
		path string
		want string
		ok   bool
	}{
		{"html/template", "template", true},
		{"net/http", "http", true},
		{"unsafe", "unsafe", true},
		{"golang.org/x/net/http2", "http2", true},
		{"github.com/foo/bar", "bar", true},
		// Module major-version suffix (v2+) strips to the previous segment.
		{"github.com/labstack/echo/v4", "echo", true},
		{"github.com/go-chi/chi/v5", "chi", true},
		// v1 is NEVER a module suffix — k8s-style version packages keep it.
		{"k8s.io/api/core/v1", "v1", true},
		// gopkg.in convention (M43 Phase D R2 finding 3): a final segment of
		// the form "<ident>.v<N>" resolves to "<ident>" — gopkg.in/yaml.v2's
		// source package really is "yaml".
		{"gopkg.in/yaml.v2", "yaml", true},
		{"gopkg.in/yaml.v3", "yaml", true},
		{"gopkg.in/check.v1", "check", true},
		// Subpackages under a gopkg.in module keep the plain last segment.
		{"gopkg.in/mgo.v2/bson", "bson", true},
		// M43 Phase D R3 finding 4: the "<ident>.v<N>" resolution is a
		// gopkg.in-documented convention, NOT a general rule — the same shape
		// on any other host is a guess (github.com/foo/bar.v2 may declare
		// package bar, bar_v2, ...) and keeps the conservative skip.
		{"github.com/foo/bar.v2", "", false},
		{"example.com/x/foo.v3", "", false},
		{"bar.v2", "", false},
		// NOT the gopkg.in shape: digits must follow "v" exclusively, the
		// prefix must be identifier-shaped, and both halves must be present.
		{"gopkg.in/yaml.v2x", "", false},
		{"gopkg.in/yaml.vv2", "", false},
		{"gopkg.in/1yaml.v2", "", false},
		{"gopkg.in/yaml.", "", false},
		{"gopkg.in/.v2", "", false},
		{"gopkg.in/a.b.v2", "", false},
		// Not identifier-shaped: conservative skip.
		{"github.com/foo/go-bar", "", false},
		{"", "", false},
		{"   ", "", false},
		// vN as the ONLY segment cannot resolve to a previous segment and
		// v2 alone is not a plausible package ident either way.
		{"github.com/foo/bar/v2/baz", "baz", true},
	}
	for _, tc := range cases {
		got, ok := osvGoPackageIdent(tc.path)
		if ok != tc.ok || got != tc.want {
			t.Errorf("osvGoPackageIdent(%q) = (%q, %v), want (%q, %v)", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

// osvVulnFromJSON decodes a raw OSV JSON document through the same
// json.Unmarshal route the client uses, so EcosystemSpecific carries real
// decoded shapes (map[string]interface{} / []interface{}), not hand-built
// typed values.
func osvVulnFromJSON(t *testing.T, raw string) *client.OSVVulnerability {
	t.Helper()
	var v client.OSVVulnerability
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("fixture unmarshal: %v", err)
	}
	return &v
}

const osvGoFixtureJSON = `{
	"id": "GO-2025-1111",
	"summary": "HTML template injection in libfoo",
	"details": "Longer details text.",
	"aliases": ["CVE-2025-1111", "GHSA-xxxx-yyyy-zzzz"],
	"affected": [
		{
			"package": {"name": "stdlib", "ecosystem": "Go"},
			"ecosystem_specific": {
				"imports": [
					{"path": "html/template", "symbols": ["Parse", "Template.Execute"]}
				]
			}
		},
		{
			"package": {"name": "github.com/foo/bar", "ecosystem": "Go"},
			"ecosystem_specific": {
				"imports": [
					{"path": "github.com/foo/bar/baz", "goos": ["linux"], "symbols": ["Do", "Parse", "Do"]},
					{"path": "gopkg.in/yaml.v2", "symbols": ["Unmarshal"]},
					{"path": "github.com/foo/bar/baz", "symbols": ["weird/sym", "Has Space", "Do()"]}
				]
			}
		},
		{
			"package": {"name": "gopkg.in/yaml.v2", "ecosystem": "Go"},
			"ecosystem_specific": {
				"imports": [{"path": "gopkg.in/yaml.v2", "symbols": ["Unmarshal"]}]
			}
		},
		{
			"package": {"name": "libfoo", "ecosystem": "npm"},
			"ecosystem_specific": {
				"imports": [{"path": "ignored", "symbols": ["NotGo"]}]
			}
		}
	]
}`

// TestExtractOSVGoVulnFuncs_ConvertsAndUnions pins the core conversion:
// imports[].{path, symbols[]} → "pkgIdent.Symbol" selectors, unioned across
// affected entries / import entries with first-seen-order dedupe, with
// non-Go ecosystems, imports whose path escapes their module (the yaml.v2
// import under module github.com/foo/bar — M43 Phase D R2 finding 4) and
// non-wire-safe symbols dropped. The gopkg.in/yaml.v2 module's OWN entry
// resolves to package ident "yaml" (finding 3).
func TestExtractOSVGoVulnFuncs_ConvertsAndUnions(t *testing.T) {
	got := extractOSVGoVulnFuncs(osvVulnFromJSON(t, osvGoFixtureJSON))
	want := []string{"template.Parse", "template.Template.Execute", "baz.Do", "baz.Parse", "yaml.Unmarshal"}
	if len(got) != len(want) {
		t.Fatalf("extractOSVGoVulnFuncs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("extractOSVGoVulnFuncs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// The stored selectors MUST pass the Wave 1 serving-edge normalisation
	// unchanged — this is the load-bearing compatibility pin for the whole
	// feature (a producer/consumer drift here silently empties the wire).
	assertWireSafe(t, got)

	// "Do()" dedupes against "Do" after the "()" strip: assert no fifth
	// element appeared.
	for _, s := range got {
		if strings.Contains(s, "(") || strings.Contains(s, "/") || strings.Contains(s, " ") {
			t.Errorf("non-wire-safe selector leaked: %q", s)
		}
	}
}

// TestExtractOSVGoVulnFuncs_NoGoData asserts nil / non-Go / symbol-less
// records extract to nothing (→ no row upserted downstream).
func TestExtractOSVGoVulnFuncs_NoGoData(t *testing.T) {
	if got := extractOSVGoVulnFuncs(nil); got != nil {
		t.Errorf("nil record: got %v, want nil", got)
	}
	noSymbols := osvVulnFromJSON(t, `{
		"id": "GO-2025-2222",
		"affected": [
			{"package": {"name": "github.com/a/b", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/a/b"}]}},
			{"package": {"name": "leftpad", "ecosystem": "npm"},
			 "ecosystem_specific": {"imports": [{"path": "x", "symbols": ["Y"]}]}}
		]
	}`)
	if got := extractOSVGoVulnFuncs(noSymbols); len(got) != 0 {
		t.Errorf("symbol-less record: got %v, want empty", got)
	}
}

// TestExtractOSVGoVulnFuncs_GopkgInVersionedPackage pins the M43 Phase D R2
// finding 3 fix: gopkg.in-style versioned module paths ("<ident>.v<N>" final
// segment) resolve to "<ident>" instead of being dropped wholesale, so the
// whole gopkg.in/yaml.vN family produces selectors again.
func TestExtractOSVGoVulnFuncs_GopkgInVersionedPackage(t *testing.T) {
	got := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
		"id": "GO-2025-5555",
		"affected": [
			{"package": {"name": "gopkg.in/yaml.v2", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "gopkg.in/yaml.v2", "symbols": ["Unmarshal"]}]}},
			{"package": {"name": "gopkg.in/yaml.v3", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "gopkg.in/yaml.v3", "symbols": ["Decoder.Decode"]}]}}
		]
	}`))
	want := []string{"yaml.Unmarshal", "yaml.Decoder.Decode"}
	if len(got) != len(want) {
		t.Fatalf("extractOSVGoVulnFuncs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("extractOSVGoVulnFuncs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	assertWireSafe(t, got)
}

// TestExtractOSVGoVulnFuncs_ImportPathMustMatchModule pins the M43 Phase D R2
// finding 4 fix: imports[].path must equal the affected package (module) name
// or be a "/"-delimited subpath of it. A crafted record cannot attribute
// unrelated packages' selectors (e.g. path "fmt" under github.com/a/b) to a
// module; non-"/"-boundary prefixes (github.com/a/bx) are also rejected.
func TestExtractOSVGoVulnFuncs_ImportPathMustMatchModule(t *testing.T) {
	got := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
		"id": "GO-2025-6666",
		"affected": [
			{"package": {"name": "github.com/a/b", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [
				{"path": "fmt", "symbols": ["Println"]},
				{"path": "github.com/other/mod", "symbols": ["Evil"]},
				{"path": "github.com/a/bx", "symbols": ["Sneaky"]},
				{"path": "github.com/a/b", "symbols": ["Root"]},
				{"path": "github.com/a/b/pkg", "symbols": ["Do"]}
			 ]}}
		]
	}`))
	want := []string{"b.Root", "pkg.Do"}
	if len(got) != len(want) {
		t.Fatalf("extractOSVGoVulnFuncs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("extractOSVGoVulnFuncs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestExtractOSVGoVulnFuncs_StdlibPathsAllowed pins that the module-prefix
// requirement (finding 4) keeps working for Go vulndb's "stdlib" module,
// whose imports[].path values are bare stdlib package paths ("html/template")
// that are NOT prefixed by the module name — while rejecting BOTH
// domain-shaped module paths AND (M43 Phase D R3 finding 1) dot-less
// external module paths ("corp/internal/vuln") smuggled under a forged
// "stdlib" record: the first path segment must be a real Go standard-library
// top-level package.
func TestExtractOSVGoVulnFuncs_StdlibPathsAllowed(t *testing.T) {
	got := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
		"id": "GO-2025-7777",
		"affected": [
			{"package": {"name": "stdlib", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [
				{"path": "html/template", "symbols": ["Parse"]},
				{"path": "fmt", "symbols": ["Sprintf"]},
				{"path": "github.com/evil/mod", "symbols": ["Injected"]},
				{"path": "corp/internal/vuln", "symbols": ["Forged"]}
			 ]}}
		]
	}`))
	want := []string{"template.Parse", "fmt.Sprintf"}
	if len(got) != len(want) {
		t.Fatalf("extractOSVGoVulnFuncs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("extractOSVGoVulnFuncs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestOSVImportPathWithinModule pins the M43 Phase D R3 finding 1 fix
// directly on the helper: under Go vulndb's synthetic "stdlib" / "toolchain"
// modules an imports[].path is admitted ONLY when its first segment is a Go
// standard-library top-level package (goStdlibTopLevelPackages allowlist) —
// the R2 "no dot in the first segment" heuristic let a forged stdlib record
// smuggle "corp/internal/vuln"-style external module paths through, planting
// fake selectors ("vuln.X") that steer the CLI AST walk toward false
// reachable verdicts. Real modules keep the R2 module-prefix rule unchanged.
func TestOSVImportPathWithinModule(t *testing.T) {
	cases := []struct {
		module, path string
		want         bool
	}{
		// stdlib carve-out: real standard-library package paths pass.
		{"stdlib", "fmt", true},
		{"stdlib", "html/template", true},
		{"stdlib", "net/http", true},
		{"stdlib", "crypto/tls", true},
		{"toolchain", "fmt", true},
		// R3 finding 1: dot-less first segments that are NOT stdlib
		// top-level packages are rejected.
		{"stdlib", "corp/internal/vuln", false},
		{"stdlib", "internal/poison", false},
		{"stdlib", "vendor/golang.org/x/net/http2", false},
		{"toolchain", "corp/internal/vuln", false},
		// Conservative by design: cmd/* is not in `go doc std`, so
		// toolchain-only paths drop to import-level reachability.
		{"toolchain", "cmd/go", false},
		// Domain-shaped smuggles keep failing as under R2.
		{"stdlib", "github.com/evil/mod", false},
		// Empty / blank inputs.
		{"stdlib", "", false},
		{"", "fmt", false},
		{"stdlib", "   ", false},
		// Non-synthetic modules: R2 finding 4 module-prefix rule unchanged.
		{"github.com/a/b", "github.com/a/b", true},
		{"github.com/a/b", "github.com/a/b/pkg", true},
		{"github.com/a/b", "github.com/a/bx", false},
		{"github.com/a/b", "fmt", false},
	}
	for _, tc := range cases {
		if got := osvImportPathWithinModule(tc.module, tc.path); got != tc.want {
			t.Errorf("osvImportPathWithinModule(%q, %q) = %v, want %v", tc.module, tc.path, got, tc.want)
		}
	}
}

// TestExtractOSVGoVulnFuncs_SymbolCap pins the M43 Phase D R2 finding 2 cap:
// a hostile/degenerate record cannot balloon a vuln_funcs row — extraction
// truncates at 200 selectors per CVE (osvVulnFuncsMaxSymbolsPerCVE), keeping
// the first 200 in order.
func TestExtractOSVGoVulnFuncs_SymbolCap(t *testing.T) {
	symbols := make([]string, 0, 250)
	for i := 0; i < 250; i++ {
		symbols = append(symbols, fmt.Sprintf("Sym%03d", i))
	}
	b, err := json.Marshal(symbols)
	if err != nil {
		t.Fatalf("marshal symbols: %v", err)
	}
	got := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
		"id": "GO-2025-8888",
		"affected": [
			{"package": {"name": "github.com/a/b", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/a/b", "symbols": `+string(b)+`}]}}
		]
	}`))
	if len(got) != 200 {
		t.Fatalf("extracted %d selectors, want cap 200", len(got))
	}
	if got[0] != "b.Sym000" || got[199] != "b.Sym199" {
		t.Errorf("cap must keep the first 200 in order: got[0]=%q got[199]=%q", got[0], got[199])
	}
}

// TestOSVWireSafeSelector_ByteLengthCap pins the M43 Phase D R2 finding 2
// selector size bound: a selector longer than 256 bytes
// (osvVulnFuncsMaxSelectorBytes) is dropped; exactly 256 bytes is kept.
func TestOSVWireSafeSelector_ByteLengthCap(t *testing.T) {
	// "p." + 254 chars = 256 bytes → kept.
	atCap := strings.Repeat("A", 254)
	if sel, ok := osvWireSafeSelector("p", atCap); !ok || len(sel) != 256 {
		t.Errorf("selector at 256 bytes must be kept: ok=%v len=%d", ok, len(sel))
	}
	// "p." + 255 chars = 257 bytes → dropped.
	overCap := strings.Repeat("A", 255)
	if _, ok := osvWireSafeSelector("p", overCap); ok {
		t.Error("selector over 256 bytes must be dropped")
	}
}

// TestOSVExcerptText_RuneCap pins the M43 Phase D R2 finding 2 excerpt bound:
// raw_excerpt grounding text is capped at 2000 runes (osvExcerptMaxRunes),
// rune-safe (no mid-UTF-8-sequence cut), applied to the summary/details pick.
func TestOSVExcerptText_RuneCap(t *testing.T) {
	long := strings.Repeat("あ", 3000)
	got := osvExcerptText(&client.OSVVulnerability{Summary: long})
	if utf8.RuneCountInString(got) != 2000 {
		t.Fatalf("excerpt rune count = %d, want 2000", utf8.RuneCountInString(got))
	}
	if !utf8.ValidString(got) {
		t.Error("truncated excerpt is not valid UTF-8 (must cut on rune boundary)")
	}
	if got != strings.Repeat("あ", 2000) {
		t.Error("truncation must keep the first 2000 runes verbatim")
	}
	// At/under the cap: unchanged (details fallback path included).
	exact := strings.Repeat("x", 2000)
	if osvExcerptText(&client.OSVVulnerability{Details: exact}) != exact {
		t.Error("excerpt at exactly 2000 runes must be unchanged")
	}
}

// --- syncOSVVulnFuncs end-to-end harness -----------------------------------

// expectOSVCandidateRead mocks Pass A for one chunk: BEGIN, then per tenant
// SET LOCAL + candidate SELECT (rows provided by the caller), then COMMIT.
// The regex also pins the explicit components tenant predicate
// (c.tenant_id = $1 — M43 Phase D R2 finding 5, belt+braces alongside the
// RLS GUC): a query without it fails to match and the test errors.
func expectOSVCandidateQuery(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectQuery(`SELECT DISTINCT v\.cve_id, COALESCE\(c\.purl, ''\)[\s\S]*c\.tenant_id = \$1`).
		WillReturnRows(rows)
}

func osvCandidateRows(pairs ...[2]string) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"cve_id", "purl"})
	for _, p := range pairs {
		rows.AddRow(p[0], p[1])
	}
	return rows
}

// newOSVSyncMockDB builds the sqlmock DB used by the syncOSVVulnFuncs tests.
func newOSVSyncMockDB(t *testing.T) (*sqlmock.Sqlmock, *CVESyncJob, *fakeAdvisoryExcerptUpserter, func(string)) {
	t.Helper()
	zeroOSVFetchDelay(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	fake := &fakeAdvisoryExcerptUpserter{}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, fake, "", false)
	return &mock, j, fake, func(baseURL string) { j.WithOSVBaseURL(baseURL) }
}

// TestCVESyncJob_SyncOSVVulnFuncs_EndToEnd drives the full pass for one
// tenant: candidate enumeration (a Go purl row AND an npm purl row — the
// latter must be filtered ecosystem-side WITHOUT ever reaching the OSV API),
// one OSV fetch, selector conversion, and one source='osv' excerpt upsert
// under the tenant GUC.
func TestCVESyncJob_SyncOSVVulnFuncs_EndToEnd(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if !strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-1111") {
			t.Errorf("unexpected OSV request path %q (npm-purl CVE must never be fetched)", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvGoFixtureJSON))
	}))
	defer server.Close()
	setOSV(server.URL)

	// Pass A (read chunk).
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-1111", "pkg:golang/github.com/foo/bar@v1.2.3"},
		[2]string{"CVE-2025-9999", "pkg:npm/leftpad@1.0.0"}, // Go-side ecosystem filter drops this
	))
	mock.ExpectCommit()
	// Pass B (write chunk).
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("OSV requests = %d, want exactly 1 (one fetch per distinct Go CVE)", got)
	}
	if fake.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1", fake.callCount())
	}
	call := fake.calls[0]
	if call.Source != osvVulnFuncsSource {
		t.Errorf("Source = %q, want %q", call.Source, osvVulnFuncsSource)
	}
	if call.TenantID != tenantID || call.CVEID != "CVE-2025-1111" {
		t.Errorf("row keyed (%v, %q), want (%v, %q)", call.TenantID, call.CVEID, tenantID, "CVE-2025-1111")
	}
	if call.FetchedAt == nil {
		t.Error("FetchedAt nil, want stamped (freshness window depends on it)")
	}
	if call.RawExcerpt != "HTML template injection in libfoo" {
		t.Errorf("RawExcerpt = %q, want OSV summary", call.RawExcerpt)
	}
	var funcs []string
	if err := json.Unmarshal(call.VulnFuncs, &funcs); err != nil {
		t.Fatalf("VulnFuncs not a JSON string array: %v (%s)", err, call.VulnFuncs)
	}
	want := []string{"template.Parse", "template.Template.Execute", "baz.Do", "baz.Parse", "yaml.Unmarshal"}
	if len(funcs) != len(want) {
		t.Fatalf("VulnFuncs = %v, want %v", funcs, want)
	}
	for i := range want {
		if funcs[i] != want[i] {
			t.Errorf("VulnFuncs[%d] = %q, want %q", i, funcs[i], want[i])
		}
	}
	assertWireSafe(t, funcs)
}

// TestCVESyncJob_SyncOSVVulnFuncs_FanOutSingleFetch pins the "fetch once,
// fan out per tenant" contract: two tenants list the SAME CVE → exactly one
// OSV request, two per-tenant upserts (tenant order preserved).
func TestCVESyncJob_SyncOSVVulnFuncs_FanOutSingleFetch(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantA, tenantB := uuid.New(), uuid.New()

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvGoFixtureJSON))
	}))
	defer server.Close()
	setOSV(server.URL)

	goRow := [2]string{"CVE-2025-1111", "pkg:golang/github.com/foo/bar@v1.2.3"}
	mock.ExpectBegin()
	expectSetLocal(mock, tenantA)
	expectOSVCandidateQuery(mock, osvCandidateRows(goRow))
	expectSetLocal(mock, tenantB)
	expectOSVCandidateQuery(mock, osvCandidateRows(goRow))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantA)
	expectSetLocal(mock, tenantB)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantA, tenantB})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("OSV requests = %d, want exactly 1 (same CVE must not be re-fetched per tenant)", got)
	}
	if fake.callCount() != 2 {
		t.Fatalf("Upsert calls = %d, want 2 (one per tenant)", fake.callCount())
	}
	if fake.calls[0].TenantID != tenantA || fake.calls[1].TenantID != tenantB {
		t.Errorf("tenant fan-out order = [%v, %v], want [%v, %v]",
			fake.calls[0].TenantID, fake.calls[1].TenantID, tenantA, tenantB)
	}
	for i, c := range fake.calls {
		if c.CVEID != "CVE-2025-1111" || c.Source != osvVulnFuncsSource {
			t.Errorf("calls[%d] = (%q, %q), want (CVE-2025-1111, osv)", i, c.CVEID, c.Source)
		}
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_404WritesTombstoneAndContinues: a 404 (no
// OSV record) is a DEFINITIVE negative — it writes an empty-vuln_funcs 'osv'
// tombstone row (M43 Phase D R2 finding 1) whose fetched_at lands in the
// freshness window, so the CVE leaves the candidate set for
// osvVulnFuncsRefreshInterval instead of re-consuming fetch-cap budget every
// tick and starving later CVEs. Later CVEs in the same tick still resolve +
// write. (The actual candidate exclusion is the NOT EXISTS fetched_at clause
// — a real-PG property; this test pins the fields it keys on: source='osv'
// and a stamped FetchedAt.)
func TestCVESyncJob_SyncOSVVulnFuncs_404WritesTombstoneAndContinues(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-0404") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvGoFixtureJSON))
	}))
	defer server.Close()
	setOSV(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-0404", "pkg:golang/github.com/gone/gone@v0.1.0"},
		[2]string{"CVE-2025-1111", "pkg:golang/github.com/foo/bar@v1.2.3"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if fake.callCount() != 2 {
		t.Fatalf("Upsert calls = %d, want 2 (404 tombstone + resolved CVE)", fake.callCount())
	}
	tomb := fake.calls[0]
	if tomb.CVEID != "CVE-2025-0404" || tomb.Source != osvVulnFuncsSource {
		t.Errorf("tombstone keyed (%q, %q), want (CVE-2025-0404, osv)", tomb.CVEID, tomb.Source)
	}
	if len(tomb.VulnFuncs) != 0 {
		t.Errorf("tombstone VulnFuncs = %s, want empty (repo normalises nil to '[]')", tomb.VulnFuncs)
	}
	if tomb.RawExcerpt != "" {
		t.Errorf("404 tombstone RawExcerpt = %q, want empty", tomb.RawExcerpt)
	}
	if tomb.FetchedAt == nil {
		t.Error("tombstone FetchedAt nil, want stamped (the freshness-window negative cache keys on it)")
	}
	if fake.calls[1].CVEID != "CVE-2025-1111" {
		t.Errorf("second row CVE = %q, want CVE-2025-1111", fake.calls[1].CVEID)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_NoSymbolsWritesTombstone: an OSV record
// that exists but yields no extractable symbols is also a DEFINITIVE
// negative (M43 Phase D R2 finding 1) — it writes an empty-vuln_funcs
// tombstone (with the record's summary as grounding text) instead of leaving
// the CVE permanently stale at the front of the deterministic candidate
// order.
func TestCVESyncJob_SyncOSVVulnFuncs_NoSymbolsWritesTombstone(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Go record, imports present, but no symbols[] anywhere. The record
		// id is GO-prefixed so no alias follow-up fires either.
		_, _ = w.Write([]byte(`{
			"id": "GO-2025-2222",
			"summary": "whole-module vulnerability",
			"affected": [
				{"package": {"name": "github.com/a/b", "ecosystem": "Go"},
				 "ecosystem_specific": {"imports": [{"path": "github.com/a/b"}]}}
			]
		}`))
	}))
	defer server.Close()
	setOSV(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-2222", "pkg:golang/github.com/a/b@v1.0.0"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1 (no symbols → tombstone row)", fake.callCount())
	}
	tomb := fake.calls[0]
	if tomb.CVEID != "CVE-2025-2222" || tomb.Source != osvVulnFuncsSource {
		t.Errorf("tombstone keyed (%q, %q), want (CVE-2025-2222, osv)", tomb.CVEID, tomb.Source)
	}
	if len(tomb.VulnFuncs) != 0 {
		t.Errorf("tombstone VulnFuncs = %s, want empty", tomb.VulnFuncs)
	}
	if tomb.RawExcerpt != "whole-module vulnerability" {
		t.Errorf("tombstone RawExcerpt = %q, want the record summary", tomb.RawExcerpt)
	}
	if tomb.FetchedAt == nil {
		t.Error("tombstone FetchedAt nil, want stamped")
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_RecordNoSymbolsOverwritesPositiveRow pins
// the M43 Phase D R5 retraction path END-TO-END (fetch classification →
// write branch), narrowed + instrumented by R6: the tenant holds an existing
// POSITIVE source='osv' row, and this tick's main lookup retrieves a genuine
// GO- record BODY (ID field "GO-"-prefixed) that yields no extractable
// symbols — an authoritative empty, i.e. upstream withdrew/corrected the
// symbol list. Unlike a true 404 (which preserves the positive row —
// TombstonePreservesPositiveRow), the retraction OVERWRITES the row: empty
// vuln_funcs, the retraction record's summary as the new excerpt, and no
// preserve Info line. R6 additions: the write does ONE pre-write GetBySource
// read (it fuels the retraction observability) and, because the prior row was
// positive, emits exactly ONE osvRetractionOverwriteWarnMsg Warn carrying
// tenant_id + cve_id + go_id.
func TestCVESyncJob_SyncOSVVulnFuncs_RecordNoSymbolsOverwritesPositiveRow(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()
	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)

	store := &fakeAdvisoryExcerptStore{existing: map[string]*repository.AdvisoryExcerpt{
		excerptStoreKey(tenantID, "CVE-2025-2222", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-2222", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["b.Withdrawn"]`), RawExcerpt: "old excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The record EXISTS (GO-prefixed: no alias follow-up) but its symbol
		// list is gone — the upstream retraction shape.
		_, _ = w.Write([]byte(`{
			"id": "GO-2025-2222",
			"summary": "symbols withdrawn upstream",
			"affected": [
				{"package": {"name": "github.com/a/b", "ecosystem": "Go"},
				 "ecosystem_specific": {"imports": [{"path": "github.com/a/b"}]}}
			]
		}`))
	}))
	defer server.Close()
	j.WithOSVBaseURL(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-2222", "pkg:golang/github.com/a/b@v1.0.0"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if store.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1", store.callCount())
	}
	row := store.calls[0]
	if row.CVEID != "CVE-2025-2222" || row.Source != osvVulnFuncsSource {
		t.Errorf("row keyed (%q, %q), want (CVE-2025-2222, osv)", row.CVEID, row.Source)
	}
	if len(row.VulnFuncs) != 0 {
		t.Errorf("VulnFuncs = %s, want empty (the retraction must overwrite the positive row)", row.VulnFuncs)
	}
	if row.RawExcerpt != "symbols withdrawn upstream" {
		t.Errorf("RawExcerpt = %q, want the retraction record's summary", row.RawExcerpt)
	}
	// M43 Phase D R6: every EMPTY write does one pre-write read — for the
	// authoritative-empty shape it decides the retraction Warn below.
	wantKey := excerptStoreKey(tenantID, "CVE-2025-2222", osvVulnFuncsSource)
	if len(store.getKeys) != 1 || store.getKeys[0] != wantKey {
		t.Errorf("GetBySource calls = %v, want exactly [%s] (one pre-write read per empty write)", store.getKeys, wantKey)
	}
	got := logs.String()
	if strings.Contains(got, osvTombstonePreserveInfoMsg) {
		t.Error("preserve Info fired on a retraction write, want none (nothing was preserved)")
	}
	// M43 Phase D R6: overwriting a previously-positive row with an
	// authoritative empty is the one write that destroys stored symbols —
	// exactly ONE Warn, carrying the (tenant, cve, GO- id) triple.
	if n := strings.Count(got, osvRetractionOverwriteWarnMsg); n != 1 {
		t.Errorf("retraction overwrite Warn logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if !strings.Contains(got, "tenant_id="+tenantID.String()) ||
		!strings.Contains(got, "cve_id=CVE-2025-2222") ||
		!strings.Contains(got, "go_id=GO-2025-2222") {
		t.Errorf("retraction Warn must carry tenant_id + cve_id + go_id attrs, got: %s", got)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_AliasNotFoundPreservesPositiveRow pins the
// M43 Phase D R6 narrowing of the retraction authority (round 5 High
// finding), partial-mirror shape (a): the main lookup retrieves the GHSA/CVE
// home record, but the GO- alias follow-up 404s — e.g. a mirror that carries
// GHSA advisories but not Go vulndb. Under R5 this counted as an
// authoritative empty (recordFound stood up on ANY non-nil main record) and
// silently wiped the tenant's existing positive row every freshness window.
// R6 keys the clobber authority on the GO- record BODY itself: nothing
// GO--bodied was retrieved here, so the empty outcome is preserve-side —
// existing positive row kept wholesale, fetched_at refreshed only, one
// preserve Info, and no retraction Warn.
func TestCVESyncJob_SyncOSVVulnFuncs_AliasNotFoundPreservesPositiveRow(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()
	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)

	store := &fakeAdvisoryExcerptStore{existing: map[string]*repository.AdvisoryExcerpt{
		excerptStoreKey(tenantID, "CVE-2025-6001", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-6001", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["keep.Me"]`), RawExcerpt: "kept excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-6001"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"id": "GHSA-pppp-qqqq-rrrr",
				"summary": "ghsa home summary",
				"aliases": ["CVE-2025-6001", "GO-2025-6001"],
				"affected": [{"package": {"name": "github.com/p/q", "ecosystem": "Go"}}]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-6001"):
			w.WriteHeader(http.StatusNotFound) // the partial-mirror hole
		default:
			t.Errorf("unexpected OSV request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	j.WithOSVBaseURL(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-6001", "pkg:golang/github.com/p/q@v1.0.0"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("OSV requests = %d, want 2 (main + GO- alias follow-up)", got)
	}
	if store.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1", store.callCount())
	}
	row := store.calls[0]
	var funcs []string
	if err := json.Unmarshal(row.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "keep.Me" {
		t.Errorf("VulnFuncs = %s (err %v), want [\"keep.Me\"] (an alias 404 must NOT clobber the positive row)", row.VulnFuncs, err)
	}
	if row.RawExcerpt != "kept excerpt" {
		t.Errorf("RawExcerpt = %q, want the preserved %q", row.RawExcerpt, "kept excerpt")
	}
	if row.FetchedAt == nil || !row.FetchedAt.After(stale.Add(time.Hour)) {
		t.Errorf("FetchedAt = %v, want refreshed past the stale stamp %v (the negative cache keys on it)", row.FetchedAt, stale)
	}
	wantKey := excerptStoreKey(tenantID, "CVE-2025-6001", osvVulnFuncsSource)
	if len(store.getKeys) != 1 || store.getKeys[0] != wantKey {
		t.Errorf("GetBySource calls = %v, want exactly [%s]", store.getKeys, wantKey)
	}
	got := logs.String()
	if n := strings.Count(got, osvTombstonePreserveInfoMsg); n != 1 {
		t.Errorf("preserve Info logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if strings.Contains(got, osvRetractionOverwriteWarnMsg) {
		t.Errorf("retraction Warn fired on a preserve-side alias 404, want none (logs: %s)", got)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_NonAuthoritativeRecordPreservesPositiveRow
// pins the other two R6 preserve-side shapes of the round 5 High finding: (b)
// a skeletal `200 {}` body (ID field empty — e.g. a stub mirror answering
// every path with an empty JSON object) and (c) a non-Go home record with NO
// GO- alias at all. Under R5 both counted as authoritative empties and wiped
// existing positive rows; under R6 neither retrieved a GO- record body, so
// both are preserve-side: data kept, fetched_at refreshed, one preserve Info
// each, no retraction Warn.
func TestCVESyncJob_SyncOSVVulnFuncs_NonAuthoritativeRecordPreservesPositiveRow(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()
	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)

	store := &fakeAdvisoryExcerptStore{existing: map[string]*repository.AdvisoryExcerpt{
		excerptStoreKey(tenantID, "CVE-2025-6002", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-6002", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["skel.Keep"]`), RawExcerpt: "skeletal-kept", FetchedAt: &stale,
		},
		excerptStoreKey(tenantID, "CVE-2025-6003", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-6003", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["noalias.Keep"]`), RawExcerpt: "noalias-kept", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-6002"):
			_, _ = w.Write([]byte(`{}`)) // skeletal body: ID empty, nothing to follow up
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-6003"):
			_, _ = w.Write([]byte(`{
				"id": "GHSA-ssss-tttt-uuuu",
				"summary": "advisory without a Go vulndb alias",
				"aliases": ["CVE-2025-6003"],
				"affected": [{"package": {"name": "github.com/n/o", "ecosystem": "Go"}}]
			}`))
		default:
			t.Errorf("unexpected OSV request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	j.WithOSVBaseURL(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-6002", "pkg:golang/github.com/m/n@v1.0.0"},
		[2]string{"CVE-2025-6003", "pkg:golang/github.com/n/o@v1.0.0"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("OSV requests = %d, want 2 (neither shape has a GO- alias to follow up)", got)
	}
	if store.callCount() != 2 {
		t.Fatalf("Upsert calls = %d, want 2", store.callCount())
	}
	wantKept := map[string]string{"CVE-2025-6002": "skel.Keep", "CVE-2025-6003": "noalias.Keep"}
	for _, row := range store.calls {
		var funcs []string
		if err := json.Unmarshal(row.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != wantKept[row.CVEID] {
			t.Errorf("%s VulnFuncs = %s (err %v), want [%q] (non-authoritative empties must preserve)", row.CVEID, row.VulnFuncs, err, wantKept[row.CVEID])
		}
		if row.FetchedAt == nil || !row.FetchedAt.After(stale.Add(time.Hour)) {
			t.Errorf("%s FetchedAt = %v, want refreshed past the stale stamp", row.CVEID, row.FetchedAt)
		}
	}
	got := logs.String()
	if n := strings.Count(got, osvTombstonePreserveInfoMsg); n != 2 {
		t.Errorf("preserve Info logged %d times, want exactly 2 (logs: %s)", n, got)
	}
	if strings.Contains(got, osvRetractionOverwriteWarnMsg) {
		t.Errorf("retraction Warn fired on preserve-side shapes, want none (logs: %s)", got)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_AliasRetractionOverwritesPositiveRow pins
// the alias-path half of the R6 authority rule: the main lookup is a GHSA
// home without symbols, and the GO- alias follow-up retrieves a genuine GO-
// record BODY that carries no extractable symbols — an authoritative empty
// learned via the alias. The retraction overwrites the existing positive row
// (empty vuln_funcs; the main record's summary stays as grounding since the
// alias yielded no symbols) and emits exactly ONE retraction Warn whose go_id
// names the alias-retrieved GO- record.
func TestCVESyncJob_SyncOSVVulnFuncs_AliasRetractionOverwritesPositiveRow(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()
	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)

	store := &fakeAdvisoryExcerptStore{existing: map[string]*repository.AdvisoryExcerpt{
		excerptStoreKey(tenantID, "CVE-2025-6004", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-6004", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["gone.Sym"]`), RawExcerpt: "pre-retraction excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-6004"):
			_, _ = w.Write([]byte(`{
				"id": "GHSA-vvvv-wwww-xxxx",
				"summary": "ghsa retraction summary",
				"aliases": ["CVE-2025-6004", "GO-2025-6004"],
				"affected": [{"package": {"name": "github.com/r/s", "ecosystem": "Go"}}]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-6004"):
			// A real GO- record body whose symbol list is gone: the
			// authoritative retraction shape, retrieved via the alias.
			_, _ = w.Write([]byte(`{
				"id": "GO-2025-6004",
				"summary": "go vulndb withdrawn",
				"affected": [
					{"package": {"name": "github.com/r/s", "ecosystem": "Go"},
					 "ecosystem_specific": {"imports": [{"path": "github.com/r/s"}]}}
				]
			}`))
		default:
			t.Errorf("unexpected OSV request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	j.WithOSVBaseURL(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-6004", "pkg:golang/github.com/r/s@v1.0.0"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("OSV requests = %d, want 2 (main + GO- alias follow-up)", got)
	}
	if store.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1", store.callCount())
	}
	row := store.calls[0]
	if len(row.VulnFuncs) != 0 {
		t.Errorf("VulnFuncs = %s, want empty (an alias-retrieved GO- retraction must overwrite the positive row)", row.VulnFuncs)
	}
	if row.RawExcerpt != "ghsa retraction summary" {
		t.Errorf("RawExcerpt = %q, want the main record's summary (the alias yielded no symbols, so the excerpt pick is unchanged)", row.RawExcerpt)
	}
	got := logs.String()
	if strings.Contains(got, osvTombstonePreserveInfoMsg) {
		t.Error("preserve Info fired on a retraction write, want none")
	}
	if n := strings.Count(got, osvRetractionOverwriteWarnMsg); n != 1 {
		t.Errorf("retraction overwrite Warn logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if !strings.Contains(got, "tenant_id="+tenantID.String()) ||
		!strings.Contains(got, "cve_id=CVE-2025-6004") ||
		!strings.Contains(got, "go_id=GO-2025-6004") {
		t.Errorf("retraction Warn must carry tenant_id + cve_id + go_id (the ALIAS record's id), got: %s", got)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_TransientErrorNoTombstone pins the flip
// side of the finding 1 fix (and the finding 7 OSV-500 test hole): a
// non-404 HTTP failure is TRANSIENT — warn + skip, NO tombstone row and no
// write-pass tx at all, so the CVE is retried on the next tick instead of
// being negative-cached for a week off one flaky response.
func TestCVESyncJob_SyncOSVVulnFuncs_TransientErrorNoTombstone(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	setOSV(server.URL)

	// ONLY the read pass: ExpectationsWereMet fails if a write-pass BEGIN
	// happens.
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-0500", "pkg:golang/github.com/flaky/mod@v1.0.0"},
	))
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("Upsert calls = %d, want 0 (transient error must not tombstone)", fake.callCount())
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_AliasFollowUp: when the alias-resolved
// record is NOT the Go vulndb entry (no Go imports), exactly ONE follow-up
// fetch of the first GO- alias recovers the symbols. Bound: 2 requests.
func TestCVESyncJob_SyncOSVVulnFuncs_AliasFollowUp(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-3333"):
			// GHSA home record: aliases carry the Go vulndb id but no
			// Go ecosystem_specific.imports.
			_, _ = w.Write([]byte(`{
				"id": "GHSA-aaaa-bbbb-cccc",
				"summary": "ghsa summary",
				"aliases": ["CVE-2025-3333", "GO-2025-3333"],
				"affected": [{"package": {"name": "github.com/x/y", "ecosystem": "Go"}}]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-3333"):
			_, _ = w.Write([]byte(`{
				"id": "GO-2025-3333",
				"summary": "go vulndb summary",
				"affected": [
					{"package": {"name": "github.com/x/y", "ecosystem": "Go"},
					 "ecosystem_specific": {"imports": [{"path": "github.com/x/y", "symbols": ["Handle"]}]}}
				]
			}`))
		default:
			t.Errorf("unexpected OSV request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	setOSV(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-3333", "pkg:golang/github.com/x/y@v2.0.0"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("OSV requests = %d, want exactly 2 (main + one GO- alias follow-up)", got)
	}
	if fake.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1", fake.callCount())
	}
	var funcs []string
	if err := json.Unmarshal(fake.calls[0].VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "y.Handle" {
		t.Errorf("VulnFuncs = %s (err %v), want [\"y.Handle\"]", fake.calls[0].VulnFuncs, err)
	}
	if fake.calls[0].RawExcerpt != "go vulndb summary" {
		t.Errorf("RawExcerpt = %q, want the symbol-bearing record's summary", fake.calls[0].RawExcerpt)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_FetchCap: the per-tick request cap stops
// further lookups; capped CVEs get no row (they stay stale → retried next
// tick), already-resolved CVEs still write.
func TestCVESyncJob_SyncOSVVulnFuncs_FetchCap(t *testing.T) {
	prevCap := osvVulnFuncsFetchCap
	osvVulnFuncsFetchCap = 1
	t.Cleanup(func() { osvVulnFuncsFetchCap = prevCap })

	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvGoFixtureJSON))
	}))
	defer server.Close()
	setOSV(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-1111", "pkg:golang/github.com/foo/bar@v1.2.3"},
		[2]string{"CVE-2025-4444", "pkg:golang/github.com/foo/qux@v1.0.0"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("OSV requests = %d, want 1 (cap must stop the second lookup)", got)
	}
	if fake.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1 (only the pre-cap CVE writes)", fake.callCount())
	}
	if fake.calls[0].CVEID != "CVE-2025-1111" {
		t.Errorf("written CVE = %q, want CVE-2025-1111", fake.calls[0].CVEID)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_Offline_NoCalls: offline mode makes the
// whole pass a no-op with ZERO network and ZERO DB access (nil *sql.DB
// proves the DB path is never reached), and the OSV client's own offline
// short-circuit is a second fence for direct fetch calls.
func TestCVESyncJob_SyncOSVVulnFuncs_Offline_NoCalls(t *testing.T) {
	zeroOSVFetchDelay(t)
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	fake := &fakeAdvisoryExcerptUpserter{}
	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, fake, "", true).WithOSVBaseURL(server.URL)

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{uuid.New()})
	if hit {
		t.Error("offline syncOSVVulnFuncs must not make any HTTP request")
	}
	if fake.callCount() != 0 {
		t.Errorf("offline syncOSVVulnFuncs upserted %d rows, want 0", fake.callCount())
	}

	// Second fence: even a direct fetch loop is inert offline (client-level
	// WithOffline short-circuit, M40 pattern). With tombstones (M43 Phase D
	// R2 finding 1) this also pins that offline "no record" responses are
	// NOT misread as definitive 404 negatives.
	out, _ := j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2025-1111"})
	if hit {
		t.Error("offline OSV client must not make any HTTP request")
	}
	if len(out) != 0 {
		t.Errorf("offline fetch resolved %d CVEs, want 0", len(out))
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_AliasDeterminations pins the tombstone
// decision table on the alias follow-up path (M43 Phase D R2 finding 1; R6
// re-classified the alias-404 shape):
//   - alias 404            → definitive → PRESERVE-side tombstone outcome
//     (empty symbols, goID == "" — no GO- record body was retrieved, so the
//     write path must not let it clobber an existing positive row)
//   - alias transient 500  → NOT definitive → no outcome (retry next tick)
//   - alias skipped by cap → NOT definitive → no outcome (retry next tick)
func TestCVESyncJob_FetchOSVVulnFuncs_AliasDeterminations(t *testing.T) {
	zeroOSVFetchDelay(t)
	prevCap := osvVulnFuncsFetchCap
	osvVulnFuncsFetchCap = 5
	t.Cleanup(func() { osvVulnFuncsFetchCap = prevCap })

	ghsaNoSymbols := func(cve, goAlias string) string {
		return `{
			"id": "GHSA-` + cve + `",
			"summary": "ghsa summary",
			"aliases": ["` + cve + `", "` + goAlias + `"],
			"affected": [{"package": {"name": "github.com/x/y", "ecosystem": "Go"}}]
		}`
	}
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-1001"):
			_, _ = w.Write([]byte(ghsaNoSymbols("CVE-2025-1001", "GO-2025-1001")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-1001"):
			w.WriteHeader(http.StatusNotFound) // definitive
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-1002"):
			_, _ = w.Write([]byte(ghsaNoSymbols("CVE-2025-1002", "GO-2025-1002")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-1002"):
			w.WriteHeader(http.StatusInternalServerError) // transient
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-1003"):
			// Fetching this one is request #5 == cap → its alias follow-up
			// must be skipped, leaving the CVE undetermined.
			_, _ = w.Write([]byte(ghsaNoSymbols("CVE-2025-1003", "GO-2025-1003")))
		default:
			t.Errorf("unexpected OSV request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	out, _ := j.fetchOSVVulnFuncs(context.Background(),
		[]string{"CVE-2025-1001", "CVE-2025-1002", "CVE-2025-1003"})

	if got := atomic.LoadInt32(&requests); got != 5 {
		t.Errorf("OSV requests = %d, want 5 (2 + 2 + 1 capped)", got)
	}
	o, ok := out["CVE-2025-1001"]
	if !ok {
		t.Fatal("alias-404 CVE missing from outcomes, want a tombstone outcome")
	}
	if len(o.symbols) != 0 {
		t.Errorf("alias-404 outcome symbols = %v, want empty (tombstone)", o.symbols)
	}
	// M43 Phase D R6 classification (round 5 High finding, reversing R5): the
	// GO- alias 404'd, so no Go vulndb record BODY was retrieved this tick —
	// the mirror may simply not carry Go vulndb (partial mirror). The outcome
	// must be PRESERVE-side (goID == ""), never an authoritative empty: R5's
	// recordFound stood up off the GHSA home record alone and let this shape
	// silently wipe existing positive rows.
	if o.goID != "" {
		t.Errorf("alias-404 outcome goID = %q, want empty (no GO- record body retrieved — preserve-side, not authoritative)", o.goID)
	}
	if _, ok := out["CVE-2025-1002"]; ok {
		t.Error("alias-transient CVE must NOT be tombstoned (no outcome)")
	}
	if _, ok := out["CVE-2025-1003"]; ok {
		t.Error("alias-capped CVE must NOT be tombstoned (determination incomplete)")
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_CtxCancelledStopsLoop pins the per-CVE
// ctx-cancellation break in the fetch loop (M43 Phase D R2 finding 7 test
// hole): an already-cancelled ctx makes the loop exit before ANY lookup.
func TestCVESyncJob_FetchOSVVulnFuncs_CtxCancelledStopsLoop(t *testing.T) {
	zeroOSVFetchDelay(t)
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvGoFixtureJSON))
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, _ := j.fetchOSVVulnFuncs(ctx, []string{"CVE-2025-1111", "CVE-2025-4444"})

	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Errorf("OSV requests = %d, want 0 (cancelled ctx must stop the loop up front)", got)
	}
	if len(out) != 0 {
		t.Errorf("outcomes = %d entries, want 0", len(out))
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_PolitenessSleepCtxAware pins the M43
// Phase D R2 finding 6 fix: the politeness pause between OSV lookups must
// honour ctx cancellation instead of blocking the scheduler shutdown for the
// full delay. With a 5s delay and a ~500ms cancel, the pre-fix time.Sleep
// path takes >5s; the ctx-aware select returns promptly.
func TestCVESyncJob_FetchOSVVulnFuncs_PolitenessSleepCtxAware(t *testing.T) {
	prevDelay := osvVulnFuncsFetchDelay
	osvVulnFuncsFetchDelay = 5 * time.Second
	t.Cleanup(func() { osvVulnFuncsFetchDelay = prevDelay })

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvGoFixtureJSON))
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(500*time.Millisecond, cancel)
	defer timer.Stop()

	start := time.Now()
	out, _ := j.fetchOSVVulnFuncs(ctx, []string{"CVE-2025-1111", "CVE-2025-4444"})
	elapsed := time.Since(start)

	if elapsed >= 3*time.Second {
		t.Errorf("fetch loop took %v, want prompt return on ctx cancel (politeness sleep must be ctx-aware)", elapsed)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("OSV requests = %d, want 1 (first immediate, second aborted in the pause)", got)
	}
	if _, ok := out["CVE-2025-1111"]; !ok {
		t.Error("first CVE (fetched before cancel) missing from outcomes")
	}
	if _, ok := out["CVE-2025-4444"]; ok {
		t.Error("aborted CVE must have no outcome (no tombstone)")
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_Mass404WritesTombstonesAndWarns pins the
// M43 Phase D R4 redesign of the R3 mass-404 valve (Codex 42nd [High]): a
// tick whose EVERY lookup (>= osvVulnFuncsMass404WarnThreshold of them)
// returns "no record" still tombstones ALL of them. Suppressing the
// tombstones (the R3 behaviour) re-introduced the R1 starvation for a
// LEGITIMATE all-404 backlog: with the cap-sized head of the deterministic
// candidate order genuinely absent from OSV, no tombstone was ever written,
// so the same CVEs re-consumed the entire fetch cap tick after tick and
// every CVE sorted after them stayed stale forever. The anomaly signature
// (mirror misconfiguration / endpoint outage) is preserved as EXACTLY ONE
// observability Warn — no suppression; the mass-tombstone threat the valve
// used to cover is handled structurally by the write path, which never
// clobbers an existing non-empty vuln_funcs row (see
// TestCVESyncJob_WriteOSVVulnFuncs_TombstonePreservesPositiveRow).
func TestCVESyncJob_FetchOSVVulnFuncs_Mass404WritesTombstonesAndWarns(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // every path 404s: outage OR a genuine all-404 backlog
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ids := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2025-9%03d", i))
	}
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids)

	if !anomalous {
		t.Error("anomalousTick = false on a 100% definitive-404 tick over the Warn threshold, want true (the write pass keys the R5 fetched_at backdate on it)")
	}
	if len(out) != 25 {
		t.Fatalf("all-404 tick produced %d outcomes, want 25 (the negative cache must fill even on all-404 ticks — suppression = R1 starvation)", len(out))
	}
	for _, id := range ids {
		o, ok := out[id]
		if !ok {
			t.Fatalf("%s missing from outcomes, want a tombstone outcome", id)
		}
		if len(o.symbols) != 0 {
			t.Errorf("%s outcome symbols = %v, want empty (tombstone)", id, o.symbols)
		}
		// M43 Phase D R5/R6 classification guard: a 404 tombstone must stay
		// non-authoritative (goID == "") so the write path's clobber guard
		// (preserve existing positive rows) applies to it.
		if o.goID != "" {
			t.Errorf("%s outcome goID = %q, want empty (no record was retrieved — true 404)", id, o.goID)
		}
	}
	got := logs.String()
	if n := strings.Count(got, osvMass404WarnMsg); n != 1 {
		t.Errorf("mass-404 observability Warn logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if !strings.Contains(got, "level=WARN") ||
		!strings.Contains(got, "fetches=25") ||
		!strings.Contains(got, "not_found=25") {
		t.Errorf("observability Warn must carry level=WARN + fetches/not_found counts, got: %s", got)
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_PartialMass404StillTombstones is the
// mass-404 Warn's normal-operation guard (M43 Phase D R4; R6 predicate): with
// at least one RECORD BODY retrieved in the tick (24× 404 + 1 resolved record
// here) the mirror demonstrably serves records, so the tick is not anomalous —
// 404s tombstone exactly as before (M43 Phase D R2 finding 1 semantics) and
// the anomaly Warn does not fire.
func TestCVESyncJob_FetchOSVVulnFuncs_PartialMass404StillTombstones(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-1111") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(osvGoFixtureJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ids := make([]string, 0, 25)
	for i := 0; i < 24; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2025-9%03d", i))
	}
	ids = append(ids, "CVE-2025-1111")
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids)

	if anomalous {
		t.Error("anomalousTick = true on a tick that retrieved a record body, want false (normal ticks must keep the full freshness window)")
	}
	if len(out) != 25 {
		t.Fatalf("outcomes = %d, want 25 (24 tombstones + 1 positive)", len(out))
	}
	tombstones := 0
	for _, o := range out {
		if len(o.symbols) == 0 {
			tombstones++
		}
	}
	if tombstones != 24 {
		t.Errorf("tombstone outcomes = %d, want 24 (partial 404s keep tombstoning)", tombstones)
	}
	if o := out["CVE-2025-1111"]; len(o.symbols) == 0 {
		t.Error("resolved CVE lost its symbols")
	}
	if strings.Contains(logs.String(), osvMass404WarnMsg) {
		t.Error("mass-404 anomaly Warn fired on a tick that retrieved a record body, want none")
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_Mass404WithTransientStillAnomalous pins
// the M43 Phase D R6 anomaly predicate (round 5 Low finding 3): the R4/R5
// rule `notFound == fetches` demanded a 100% not-found RATE, so a single
// transient failure in an otherwise all-404 tick (25×404 + 1×timeout here;
// 499×404 + 1×timeout in the wild) defeated the anomaly determination — no
// Warn, and the tick's tombstones kept the FULL 7-day freshness window
// instead of the shortened anomaly retry. R6 keys on the two counts that
// matter: at least osvVulnFuncsMass404WarnThreshold definitive 404s AND zero
// record bodies retrieved — transient failures no longer dilute the
// denominator.
func TestCVESyncJob_FetchOSVVulnFuncs_Mass404WithTransientStillAnomalous(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8500") {
			w.WriteHeader(http.StatusInternalServerError) // one transient blip
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ids := make([]string, 0, 26)
	for i := 0; i < 25; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2025-9%03d", i))
	}
	// The transient sits mid-tick, not at an edge.
	ids = append(ids[:10], append([]string{"CVE-2025-8500"}, ids[10:]...)...)
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids)

	if !anomalous {
		t.Error("anomalousTick = false on 25×404 + 1×transient, want true (>= threshold 404s with ZERO records retrieved — a transient must not veto the anomaly)")
	}
	if len(out) != 25 {
		t.Fatalf("outcomes = %d, want 25 (the transient CVE gets no tombstone)", len(out))
	}
	if _, ok := out["CVE-2025-8500"]; ok {
		t.Error("transient CVE must have no outcome (retry next tick)")
	}
	got := logs.String()
	if n := strings.Count(got, osvMass404WarnMsg); n != 1 {
		t.Errorf("mass-404 Warn logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if !strings.Contains(got, "fetches=26") ||
		!strings.Contains(got, "not_found=25") ||
		!strings.Contains(got, "records_retrieved=0") {
		t.Errorf("anomaly Warn must carry fetches / not_found / records_retrieved counts, got: %s", got)
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_Mass404BelowThresholdNotAnomalous pins the
// R6 predicate's lower edge: 19×404 + 1×transient is 20 fetches, but only 19
// definitive 404s — BELOW osvVulnFuncsMass404WarnThreshold (20) — so the tick
// is NOT anomalous (no Warn, full freshness window), even though zero records
// were retrieved. The threshold counts 404s, not fetches: a small tick must
// not be branded a mirror anomaly off fewer not-founds than the bar.
func TestCVESyncJob_FetchOSVVulnFuncs_Mass404BelowThresholdNotAnomalous(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8500") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ids := make([]string, 0, 20)
	for i := 0; i < 19; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2025-9%03d", i))
	}
	ids = append(ids, "CVE-2025-8500")
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids)

	if anomalous {
		t.Error("anomalousTick = true with only 19 definitive 404s, want false (the threshold counts 404s, not fetches)")
	}
	if len(out) != 19 {
		t.Fatalf("outcomes = %d, want 19 tombstones", len(out))
	}
	if strings.Contains(logs.String(), osvMass404WarnMsg) {
		t.Error("mass-404 Warn fired below the 404-count threshold, want none")
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_AnomalousMass404BackdatesTombstones pins
// the M43 Phase D R5 blind-spot fix on the R4 mass-404 posture: an ANOMALOUS
// tick (>= osvVulnFuncsMass404WarnThreshold definitive 404s, zero record
// bodies retrieved — exactly the mass-404 Warn's trigger) still writes every
// tombstone (the R1 starvation fix is untouched), but their fetched_at is
// BACKDATED by (osvVulnFuncsRefreshInterval - osvVulnFuncsAnomalyRetryInterval)
// so a mirror misconfiguration repaired after the bad tick negative-caches
// the affected CVEs only until the first daily tick after the 48h margin
// (2–3 days) instead of the full 7-day freshness window. The Warn fires
// exactly once and its message names the shortened freshness — with the
// honest 2–3 day horizon (M43 Phase D R6, round 5 Low finding 2) — for
// operators.
func TestCVESyncJob_SyncOSVVulnFuncs_AnomalousMass404BackdatesTombstones(t *testing.T) {
	logs := captureSlog(t)
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // every path 404s: the anomaly signature
	}))
	defer server.Close()
	setOSV(server.URL)

	pairs := make([][2]string, 0, 25)
	for i := 0; i < 25; i++ {
		pairs = append(pairs, [2]string{
			fmt.Sprintf("CVE-2025-9%03d", i),
			fmt.Sprintf("pkg:golang/github.com/gone/mod%03d@v1.0.0", i),
		})
	}
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(pairs...))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	before := time.Now().UTC()
	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})
	after := time.Now().UTC()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if fake.callCount() != 25 {
		t.Fatalf("Upsert calls = %d, want 25 (anomalous ticks must still tombstone — suppression = R1 starvation)", fake.callCount())
	}
	backdate := osvVulnFuncsRefreshInterval - osvVulnFuncsAnomalyRetryInterval
	lo, hi := before.Add(-backdate), after.Add(-backdate)
	for _, call := range fake.calls {
		if len(call.VulnFuncs) != 0 {
			t.Errorf("%s VulnFuncs = %s, want empty tombstone", call.CVEID, call.VulnFuncs)
		}
		if call.FetchedAt == nil {
			t.Fatalf("%s FetchedAt nil, want a backdated stamp", call.CVEID)
		}
		if call.FetchedAt.Before(lo) || call.FetchedAt.After(hi) {
			t.Errorf("%s FetchedAt = %v, want backdated into [%v, %v] (now - (refreshInterval - anomalyRetryInterval)) so the CVE re-candidates at the first daily tick after the %v margin",
				call.CVEID, call.FetchedAt, lo, hi, osvVulnFuncsAnomalyRetryInterval)
		}
	}
	if n := strings.Count(logs.String(), osvMass404WarnMsg); n != 1 {
		t.Errorf("mass-404 Warn logged %d times, want exactly 1 (logs: %s)", n, logs.String())
	}
	if !strings.Contains(osvMass404WarnMsg, "shortened freshness") {
		t.Errorf("mass-404 Warn message must name the shortened freshness for operators, got %q", osvMass404WarnMsg)
	}
	// M43 Phase D R6 (round 5 Low finding 2): the message must state the
	// EFFECTIVE retry horizon honestly. The 48h backdate margin plus the
	// inclusive `fetched_at >= cutoff` freshness comparison (and write
	// latency) means a 24h tick cadence first re-fetches at the +72h tick —
	// "2–3 days", not the old "~2 days".
	if !strings.Contains(osvMass404WarnMsg, "2–3 days") || !strings.Contains(osvMass404WarnMsg, "48h") {
		t.Errorf("mass-404 Warn message must state the effective 2–3 day retry (first daily tick after the 48h margin), got %q", osvMass404WarnMsg)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_PartialMass404KeepsFullFreshness is the
// backdate's normal-operation guard (M43 Phase D R5): with ANY non-404
// response in the tick (24× 404 + 1 resolved record) the tick is NOT
// anomalous, so every row — tombstones included — keeps the ordinary
// fetched_at = now stamp and the full osvVulnFuncsRefreshInterval freshness
// window.
func TestCVESyncJob_SyncOSVVulnFuncs_PartialMass404KeepsFullFreshness(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-1111") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(osvGoFixtureJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	setOSV(server.URL)

	pairs := make([][2]string, 0, 25)
	for i := 0; i < 24; i++ {
		pairs = append(pairs, [2]string{
			fmt.Sprintf("CVE-2025-9%03d", i),
			fmt.Sprintf("pkg:golang/github.com/gone/mod%03d@v1.0.0", i),
		})
	}
	pairs = append(pairs, [2]string{"CVE-2025-1111", "pkg:golang/github.com/foo/bar@v1.2.3"})
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(pairs...))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	before := time.Now().UTC()
	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})
	after := time.Now().UTC()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if fake.callCount() != 25 {
		t.Fatalf("Upsert calls = %d, want 25 (24 tombstones + 1 positive)", fake.callCount())
	}
	for _, call := range fake.calls {
		if call.FetchedAt == nil {
			t.Fatalf("%s FetchedAt nil, want stamped", call.CVEID)
		}
		if call.FetchedAt.Before(before) || call.FetchedAt.After(after) {
			t.Errorf("%s FetchedAt = %v, want ordinary now stamp in [%v, %v] (non-anomalous ticks must NOT backdate)",
				call.CVEID, call.FetchedAt, before, after)
		}
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_OfflineClientOnlineJobDrift pins the M43
// Phase D R4 offline-drift guard (which replaces the R3 valve's drift role):
// the JOB is online (j.offline = false, so the existing guard does not trip)
// but the OSV CLIENT has been flipped offline — its GetVulnerability
// short-circuits to (nil, nil), byte-identical to a real 404, so letting the
// pass run would mass-tombstone the entire candidate set. R4 disambiguates
// STRUCTURALLY via the client.IsOffline accessor: syncOSVVulnFuncs skips the
// whole pass up front — no candidate enumeration (the nil *sql.DB proves
// zero DB access), no HTTP, no tombstones — with exactly one skip Warn.
// Candidates stay stale and retry once the drift is fixed. The existing
// j.offline guard (Offline_NoCalls test) is unchanged.
func TestCVESyncJob_SyncOSVVulnFuncs_OfflineClientOnlineJobDrift(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	fake := &fakeAdvisoryExcerptUpserter{}
	// nil *sql.DB: the drift skip must fire BEFORE Pass A's candidate
	// enumeration ever touches the pool.
	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, fake, "", false)
	j.WithOSVBaseURL(server.URL)
	j.osv.WithOffline(true) // the drift: offline client under an online job

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{uuid.New()})

	if hit {
		t.Error("offline-drifted client must not make any HTTP request")
	}
	if fake.callCount() != 0 {
		t.Fatalf("Upsert calls = %d, want 0 (offline-client drift must not tombstone)", fake.callCount())
	}
	if n := strings.Count(logs.String(), osvOfflineDriftSkipWarnMsg); n != 1 {
		t.Errorf("drift skip Warn logged %d times, want exactly 1 (logs: %s)", n, logs.String())
	}

	// Defence-in-depth: even a DIRECT fetch loop consults IsOffline — zero
	// lookups, zero outcomes — so nothing downstream can tombstone off the
	// client's (nil, nil) short-circuit regardless of the caller.
	out, _ := j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2025-1111"})
	if hit {
		t.Error("offline-drifted client must not make any HTTP request (direct fetch)")
	}
	if len(out) != 0 {
		t.Errorf("direct fetch resolved %d CVEs, want 0", len(out))
	}
}

// TestCVESyncJob_WriteOSVVulnFuncs_TombstonePreservesPositiveRow pins the
// M43 Phase D R4 structural replacement for the R3 suppression valve, plus
// the R5/R6 split of the definitive-negative shapes (keyed on the outcome's
// goID clobber-authority token since R6): before ANY empty write the pass
// reads the existing (tenant, cve, source='osv') row via GetBySource ON THE
// CHUNK TX. A PRESERVE-side empty (goID == "") landing on a row with
// non-empty vuln_funcs preserves the row's data wholesale, refreshes ONLY
// fetched_at, and emits ONE Info line (the divergence is operator-visible) —
// so a mirror misconfiguration mass-404-ing every path can never empty
// previously-positive rows, no matter how many ticks it survives. An
// AUTHORITATIVE empty (goID != "": a GO- record body with no symbols — an
// upstream withdrawal/correction) is NOT preserved: it overwrites the row
// wholesale, empty vuln_funcs plus the record's excerpt, and — R6 — when
// that overwrite destroys a positive row it emits exactly ONE retraction
// Warn (tenant_id, cve_id, go_id). Decision table:
//   - 404 vs existing positive row      → data preserved, fetched_at
//     refreshed, one Info line
//   - 404 vs existing tombstone         → stays an empty tombstone
//   - 404 vs no existing row            → new empty tombstone
//   - GO- record-no-symbols vs positive → overwritten empty (retraction
//     propagates) + one retraction Warn
//   - positive fetch                    → new data replaces the row
//     unconditionally (no pre-write read: fresh symbols are authoritative)
func TestCVESyncJob_WriteOSVVulnFuncs_TombstonePreservesPositiveRow(t *testing.T) {
	logs := captureSlog(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()
	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)

	store := &fakeAdvisoryExcerptStore{existing: map[string]*repository.AdvisoryExcerpt{
		excerptStoreKey(tenantID, "CVE-2025-0404", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-0404", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["a.B"]`), RawExcerpt: "kept excerpt", FetchedAt: &stale,
		},
		excerptStoreKey(tenantID, "CVE-2025-0405", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-0405", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`[]`), FetchedAt: &stale, // existing tombstone
		},
		excerptStoreKey(tenantID, "CVE-2025-0407", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-0407", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["old.Sym"]`), RawExcerpt: "old excerpt", FetchedAt: &stale,
		},
		excerptStoreKey(tenantID, "CVE-2025-0408", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-0408", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["gone.Sym"]`), RawExcerpt: "pre-retraction excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	// One write chunk: BEGIN, tenant GUC, five fake-intercepted read/upserts,
	// COMMIT. Any extra SQL fails ExpectationsWereMet.
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	outcomes := map[string]osvVulnFuncsOutcome{
		"CVE-2025-0404": {},                                                    // true 404 vs positive row
		"CVE-2025-0405": {},                                                    // true 404 vs existing tombstone
		"CVE-2025-0406": {},                                                    // true 404 vs no row
		"CVE-2025-0407": {symbols: []string{"x.New"}, excerpt: "fresh"},        // positive vs positive row
		"CVE-2025-0408": {excerpt: "withdrawn upstream", goID: "GO-2025-0408"}, // authoritative empty vs positive row
	}
	rows, tenants := j.writeOSVVulnFuncs(context.Background(),
		[]osvTenantCandidates{{tenantID: tenantID, cveIDs: []string{
			"CVE-2025-0404", "CVE-2025-0405", "CVE-2025-0406", "CVE-2025-0407", "CVE-2025-0408",
		}}},
		outcomes, false)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if rows != 5 || tenants != 1 {
		t.Fatalf("(rows, tenants) = (%d, %d), want (5, 1)", rows, tenants)
	}
	if store.callCount() != 5 {
		t.Fatalf("Upsert calls = %d, want 5", store.callCount())
	}
	byCVE := map[string]repository.AdvisoryExcerpt{}
	for _, c := range store.calls {
		byCVE[c.CVEID] = c
	}

	kept := byCVE["CVE-2025-0404"]
	var funcs []string
	if err := json.Unmarshal(kept.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "a.B" {
		t.Errorf("preserved VulnFuncs = %s (err %v), want [\"a.B\"] (a tombstone must not clobber a positive row)", kept.VulnFuncs, err)
	}
	if kept.RawExcerpt != "kept excerpt" {
		t.Errorf("preserved RawExcerpt = %q, want %q", kept.RawExcerpt, "kept excerpt")
	}
	if kept.FetchedAt == nil {
		t.Fatal("preserved row FetchedAt nil, want refreshed (the negative cache keys on it)")
	}
	if !kept.FetchedAt.After(stale.Add(time.Hour)) {
		t.Errorf("preserved row FetchedAt = %v, want refreshed past the stale stamp %v", kept.FetchedAt, stale)
	}

	if tomb := byCVE["CVE-2025-0405"]; len(tomb.VulnFuncs) != 0 || tomb.FetchedAt == nil {
		t.Errorf("existing-tombstone row = (%s, %v), want empty VulnFuncs + refreshed FetchedAt", tomb.VulnFuncs, tomb.FetchedAt)
	}
	if tomb := byCVE["CVE-2025-0406"]; len(tomb.VulnFuncs) != 0 || tomb.FetchedAt == nil {
		t.Errorf("no-existing-row tombstone = (%s, %v), want empty VulnFuncs + stamped FetchedAt", tomb.VulnFuncs, tomb.FetchedAt)
	}

	pos := byCVE["CVE-2025-0407"]
	if err := json.Unmarshal(pos.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "x.New" {
		t.Errorf("positive VulnFuncs = %s (err %v), want [\"x.New\"] (fresh symbols are authoritative)", pos.VulnFuncs, err)
	}
	if pos.RawExcerpt != "fresh" {
		t.Errorf("positive RawExcerpt = %q, want %q", pos.RawExcerpt, "fresh")
	}

	// M43 Phase D R5/R6: the authoritative empty (GO- record body retrieved,
	// no symbols) OVERWRITES the existing positive row — the retraction
	// propagates, with the retraction record's excerpt stored as the new
	// grounding.
	retr := byCVE["CVE-2025-0408"]
	if len(retr.VulnFuncs) != 0 {
		t.Errorf("retraction VulnFuncs = %s, want empty (a goID-backed empty outcome must overwrite the positive row)", retr.VulnFuncs)
	}
	if retr.RawExcerpt != "withdrawn upstream" {
		t.Errorf("retraction RawExcerpt = %q, want %q (the retraction record's own excerpt)", retr.RawExcerpt, "withdrawn upstream")
	}
	if retr.FetchedAt == nil {
		t.Error("retraction FetchedAt nil, want stamped")
	}

	// Every EMPTY write consults GetBySource exactly once (M43 Phase D R6:
	// the three true-404 tombstones for the clobber guard, the authoritative
	// empty for the retraction Warn); the positive write never reads — its
	// fetched data is authoritative — keeping the added per-row read cost
	// proportional to the tick's empty-outcome row count.
	wantKeys := []string{
		excerptStoreKey(tenantID, "CVE-2025-0404", osvVulnFuncsSource),
		excerptStoreKey(tenantID, "CVE-2025-0405", osvVulnFuncsSource),
		excerptStoreKey(tenantID, "CVE-2025-0406", osvVulnFuncsSource),
		excerptStoreKey(tenantID, "CVE-2025-0408", osvVulnFuncsSource),
	}
	if len(store.getKeys) != len(wantKeys) {
		t.Fatalf("GetBySource calls = %v, want %v (empty-outcome writes only)", store.getKeys, wantKeys)
	}
	for i := range wantKeys {
		if store.getKeys[i] != wantKeys[i] {
			t.Errorf("GetBySource call %d = %q, want %q", i, store.getKeys[i], wantKeys[i])
		}
	}

	// M43 Phase D R5 observability: the preserve path (404 vs positive row)
	// logs exactly ONE Info line carrying the (tenant, cve) divergence; the
	// other quadrants stay silent.
	got := logs.String()
	if n := strings.Count(got, osvTombstonePreserveInfoMsg); n != 1 {
		t.Errorf("preserve Info logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if !strings.Contains(got, "cve_id=CVE-2025-0404") || !strings.Contains(got, "tenant_id="+tenantID.String()) {
		t.Errorf("preserve Info must carry cve_id + tenant_id attrs, got: %s", got)
	}
	// M43 Phase D R6 observability: ONLY the authoritative-empty-vs-positive
	// quadrant (CVE-2025-0408) logs the retraction Warn — the true-404
	// preserves and the fresh/empty tombstones stay silent.
	if n := strings.Count(got, osvRetractionOverwriteWarnMsg); n != 1 {
		t.Errorf("retraction Warn logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if !strings.Contains(got, "cve_id=CVE-2025-0408") || !strings.Contains(got, "go_id=GO-2025-0408") {
		t.Errorf("retraction Warn must carry cve_id + go_id attrs, got: %s", got)
	}
}

// TestCVESyncJob_WriteOSVVulnFuncs_AnomalousTickBackdatesPreservedRow pins a
// deliberate (previously undocumented) interaction between the R5 anomaly
// backdate and the R4 clobber guard (M43 Phase D R6, round 5 Low finding 4):
// on an ANOMALOUS tick, a true-404 landing on an existing POSITIVE row still
// preserves the row's data — but the refreshed fetched_at takes the BACKDATED
// anomaly stamp, exactly like a plain tombstone. That is the desired shape:
// a 404-vs-positive divergence observed during a suspected mirror anomaly is
// re-verified on the shortened 2–3 day schedule instead of sitting
// unexamined for the full 7-day window.
func TestCVESyncJob_WriteOSVVulnFuncs_AnomalousTickBackdatesPreservedRow(t *testing.T) {
	logs := captureSlog(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()
	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)

	store := &fakeAdvisoryExcerptStore{existing: map[string]*repository.AdvisoryExcerpt{
		excerptStoreKey(tenantID, "CVE-2025-0404", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-0404", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["a.B"]`), RawExcerpt: "kept excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	before := time.Now().UTC()
	rows, tenants := j.writeOSVVulnFuncs(context.Background(),
		[]osvTenantCandidates{{tenantID: tenantID, cveIDs: []string{"CVE-2025-0404", "CVE-2025-0410"}}},
		map[string]osvVulnFuncsOutcome{
			"CVE-2025-0404": {}, // true 404 vs existing positive row
			"CVE-2025-0410": {}, // true 404 vs no row
		},
		true) // anomalousTick
	after := time.Now().UTC()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if rows != 2 || tenants != 1 {
		t.Fatalf("(rows, tenants) = (%d, %d), want (2, 1)", rows, tenants)
	}
	byCVE := map[string]repository.AdvisoryExcerpt{}
	for _, c := range store.calls {
		byCVE[c.CVEID] = c
	}
	backdate := osvVulnFuncsRefreshInterval - osvVulnFuncsAnomalyRetryInterval
	lo, hi := before.Add(-backdate), after.Add(-backdate)

	kept := byCVE["CVE-2025-0404"]
	var funcs []string
	if err := json.Unmarshal(kept.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "a.B" {
		t.Errorf("preserved VulnFuncs = %s (err %v), want [\"a.B\"] (the anomaly backdate must not weaken the clobber guard)", kept.VulnFuncs, err)
	}
	if kept.RawExcerpt != "kept excerpt" {
		t.Errorf("preserved RawExcerpt = %q, want %q", kept.RawExcerpt, "kept excerpt")
	}
	if kept.FetchedAt == nil {
		t.Fatal("preserved row FetchedAt nil, want the backdated anomaly stamp")
	}
	if kept.FetchedAt.Before(lo) || kept.FetchedAt.After(hi) {
		t.Errorf("preserved row FetchedAt = %v, want backdated into [%v, %v] — on an anomalous tick the PRESERVED row re-candidates on the shortened schedule too",
			kept.FetchedAt, lo, hi)
	}
	if tomb := byCVE["CVE-2025-0410"]; tomb.FetchedAt == nil || tomb.FetchedAt.Before(lo) || tomb.FetchedAt.After(hi) {
		t.Errorf("fresh tombstone FetchedAt = %v, want backdated into [%v, %v]", tomb.FetchedAt, lo, hi)
	}
	if n := strings.Count(logs.String(), osvTombstonePreserveInfoMsg); n != 1 {
		t.Errorf("preserve Info logged %d times, want exactly 1", n)
	}
}

// TestCVESyncJob_WriteOSVVulnFuncs_PreWriteReadErrorAbortsChunk pins the R4
// clobber guard's failure posture: the pre-write GetBySource runs INSIDE the
// chunk tx (with real PG an error there has already aborted the tx
// server-side), so a read failure aborts the chunk exactly like an Upsert
// failure — rollback, ZERO counted rows (the caller's totals must match
// durable rows), warn + continue at the caller. The rows self-heal next tick
// via the freshness window.
func TestCVESyncJob_WriteOSVVulnFuncs_PreWriteReadErrorAbortsChunk(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()

	store := &fakeAdvisoryExcerptStore{getErr: errors.New("simulated aborted-tx read failure")}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectRollback()

	rows, tenants := j.writeOSVVulnFuncs(context.Background(),
		[]osvTenantCandidates{{tenantID: tenantID, cveIDs: []string{"CVE-2025-0404"}}},
		map[string]osvVulnFuncsOutcome{"CVE-2025-0404": {}}, false)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if rows != 0 || tenants != 0 {
		t.Errorf("(rows, tenants) = (%d, %d), want (0, 0) on chunk abort", rows, tenants)
	}
	if store.callCount() != 0 {
		t.Errorf("Upsert calls = %d, want 0 (the read failed before any write)", store.callCount())
	}
}

// TestOSVImportPathWithinModule_SimdAllowed pins the M43 Phase D R4 Medium
// fix (Codex 42nd, web-verified against pkg.go.dev): go1.26.5 ships the new
// top-level standard-library package "simd" (simd/archsimd), so Go vulndb
// stdlib records citing it must pass the allowlist instead of being
// conservatively dropped to import-level reachability.
func TestOSVImportPathWithinModule_SimdAllowed(t *testing.T) {
	if !osvImportPathWithinModule("stdlib", "simd/archsimd") {
		t.Error(`osvImportPathWithinModule("stdlib", "simd/archsimd") = false, want true (go1.26.5 std package)`)
	}
	if !osvImportPathWithinModule("stdlib", "simd") {
		t.Error(`osvImportPathWithinModule("stdlib", "simd") = false, want true`)
	}
}

// TestGoStdlibTopLevelPackages_ToolchainDrift executes `go list std` with
// the test environment's toolchain and asserts the toolchain's top-level
// package segments (with "internal" / "vendor" / "cmd" excluded — not
// importable by user code / toolchain-only, per the allowlist docstring) are
// a SUBSET of goStdlibTopLevelPackages: a Go release adding a new top-level
// std package fails this test and forces the allowlist to follow (M43 Phase
// D R4 — "simd" was exactly such a miss). The reverse direction is
// deliberately permitted: the allowlist may run AHEAD of older toolchains
// (e.g. "simd" before go1.26.5) without failing on them.
//
// Known blind spot (M43 Phase D R5, round 4 Low finding): GOEXPERIMENT-gated
// packages ("simd" on toolchains that gate it) do NOT appear in a plain
// `go list std`, so this drift check can neither discover them nor defend
// their allowlist entries. This test deliberately does not depend on any
// GOEXPERIMENT value in the environment — gated packages are covered by
// explicit per-package pins instead (TestOSVImportPathWithinModule_SimdAllowed
// is the pattern); add such a pin whenever a gated package is added to
// goStdlibTopLevelPackages.
func TestGoStdlibTopLevelPackages_ToolchainDrift(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not on PATH; toolchain drift check skipped")
	}
	out, err := exec.Command(goBin, "list", "std").Output()
	if err != nil {
		t.Skipf("`go list std` failed (%v); toolchain drift check skipped", err)
	}
	t.Log("drift check covers ungated std packages only: GOEXPERIMENT-gated packages (e.g. simd) are invisible to a plain `go list std` and are pinned explicitly (see TestOSVImportPathWithinModule_SimdAllowed)")

	seen := make(map[string]struct{})
	var missing []string
	for _, line := range strings.Split(string(out), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" {
			continue
		}
		first := pkg
		if i := strings.IndexByte(pkg, '/'); i >= 0 {
			first = pkg[:i]
		}
		if first == "internal" || first == "vendor" || first == "cmd" {
			continue
		}
		if _, dup := seen[first]; dup {
			continue
		}
		seen[first] = struct{}{}
		if _, ok := goStdlibTopLevelPackages[first]; !ok {
			missing = append(missing, first)
		}
	}
	if len(seen) == 0 {
		t.Fatal("`go list std` produced no top-level segments; unexpected empty output")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("toolchain std packages missing from goStdlibTopLevelPackages (add them to cve_sync.go): %v", missing)
	}
}

// TestOSVTombstoneRow_ListVulnFuncsByCVEs_Harmless re-pins (from the
// producer's side) that the M43 Phase D R2 finding 1 tombstone rows are
// wire-inert: the W1 reader (repository.ListVulnFuncsByCVEs) unions nothing
// out of an empty '[]' vuln_funcs row — a CVE with ONLY a tombstone is
// simply absent from the map (handler: "no symbols known"), and a tombstone
// alongside a real row contributes zero extra elements.
func TestOSVTombstoneRow_ListVulnFuncsByCVEs_Harmless(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT cve_id, vuln_funcs\s+FROM advisory_excerpts`).
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "vuln_funcs"}).
			AddRow("CVE-2025-1", []byte(`[]`)).            // osv tombstone
			AddRow("CVE-2025-1", []byte(`["tpl.Parse"]`)). // real nvd row
			AddRow("CVE-2025-2", []byte(`[]`)))            // tombstone only

	repo := repository.NewAdvisoryExcerptsRepository(db)
	got, err := repo.ListVulnFuncsByCVEs(context.Background(), tenantID, []string{"CVE-2025-1", "CVE-2025-2"})
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if funcs := got["CVE-2025-1"]; len(funcs) != 1 || funcs[0] != "tpl.Parse" {
		t.Errorf("CVE-2025-1 funcs = %v, want exactly [tpl.Parse] (tombstone adds nothing)", funcs)
	}
	if _, ok := got["CVE-2025-2"]; ok {
		t.Error("CVE-2025-2 (tombstone only) must be absent from the map, not an empty entry")
	}
}

// TestCVESyncJob_Run_NVDFailureStillRunsOSVPass pins the M43 Phase D R2
// finding 6 availability fix: the OSV vuln_funcs backfill (Phase 3) is
// independent of the NVD feed, so an NVD outage must not starve it — Run()
// executes the OSV pass and THEN surfaces the NVD error (last-sync time
// stays un-advanced so the NVD window is retried in full next tick).
func TestCVESyncJob_Run_NVDFailureStillRunsOSVPass(t *testing.T) {
	zeroOSVFetchDelay(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()

	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer nvd.Close()
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvGoFixtureJSON))
	}))
	defer osv.Close()

	// getLastSyncTime's system_settings read is deliberately unexpected: the
	// sqlmock error routes Run through its "use 24h ago" fallback.
	// After the NVD 503: tenants enumeration, then the OSV read + write pass.
	mock.ExpectQuery(`SELECT id FROM tenants ORDER BY created_at`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(tenantID.String()))
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-1111", "pkg:golang/github.com/foo/bar@v1.2.3"},
	))
	mock.ExpectCommit()
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	fake := &fakeAdvisoryExcerptUpserter{}
	j := NewCVESyncJob(db, repository.NewTenantRepository(db), "", 24*time.Hour, fake, nvd.URL, false)
	j.WithOSVBaseURL(osv.URL)

	err = j.Run(context.Background())
	if err == nil {
		t.Error("Run must still surface the NVD fetch error")
	}
	if merr := mock.ExpectationsWereMet(); merr != nil {
		t.Errorf("unmet sqlmock expectations (OSV pass must run despite NVD failure): %v", merr)
	}
	if fake.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1 (OSV pass must complete before Run returns)", fake.callCount())
	}
	if fake.calls[0].CVEID != "CVE-2025-1111" || fake.calls[0].Source != osvVulnFuncsSource {
		t.Errorf("row = (%q, %q), want (CVE-2025-1111, osv)", fake.calls[0].CVEID, fake.calls[0].Source)
	}
}
