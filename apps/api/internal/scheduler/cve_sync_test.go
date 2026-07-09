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

// TestOSVCandidateQuery_CoversGoAndNpm pins the M44 Wave 2 (F470) candidate
// prefilter: the OSV pass enumerates BOTH Go- and npm-ecosystem purls (the
// ILIKEs are row-transfer prefilters only; repository.EcosystemFromPurl
// remains the authoritative Go-side derivation), and keeps the explicit
// tenant predicate (M43 Phase D R2 finding 5).
func TestOSVCandidateQuery_CoversGoAndNpm(t *testing.T) {
	for _, want := range []string{
		`c.purl ILIKE 'pkg:golang%'`,
		`c.purl ILIKE 'pkg:npm%'`,
		`c.tenant_id = $1`,
	} {
		if !strings.Contains(osvCVECandidateQuery, want) {
			t.Errorf("candidate query missing %q:\n%s", want, osvCVECandidateQuery)
		}
	}
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
	got, _ := extractOSVGoVulnFuncs(osvVulnFromJSON(t, osvGoFixtureJSON))
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

// TestExtractOSVGoVulnFuncs_ScopedByModule pins the M43 Phase D round 8
// (R8f) module attribution: alongside the flat union, extraction returns
// the same selectors grouped by the OSV affected module they were declared
// under (module = affected[].package.name, "stdlib" verbatim), with
// same-module imports unioned into ONE entry (the fixture's two
// github.com/foo/bar/baz imports) and modules kept in first-seen order.
// The serving edge keys on this attribution to stop one module's symbols
// from reaching a sibling module's target rows.
func TestExtractOSVGoVulnFuncs_ScopedByModule(t *testing.T) {
	flat, scoped := extractOSVGoVulnFuncs(osvVulnFromJSON(t, osvGoFixtureJSON))
	want := []osvScopedVulnFuncs{
		{Module: "stdlib", VulnFuncs: []string{"template.Parse", "template.Template.Execute"}},
		{Module: "github.com/foo/bar", VulnFuncs: []string{"baz.Do", "baz.Parse"}},
		{Module: "gopkg.in/yaml.v2", VulnFuncs: []string{"yaml.Unmarshal"}},
	}
	if len(scoped) != len(want) {
		t.Fatalf("scoped = %+v, want %+v", scoped, want)
	}
	for i := range want {
		if scoped[i].Module != want[i].Module {
			t.Fatalf("scoped[%d].Module = %q, want %q", i, scoped[i].Module, want[i].Module)
		}
		if len(scoped[i].VulnFuncs) != len(want[i].VulnFuncs) {
			t.Fatalf("scoped[%d] (%s) funcs = %v, want %v", i, scoped[i].Module, scoped[i].VulnFuncs, want[i].VulnFuncs)
		}
		for j := range want[i].VulnFuncs {
			if scoped[i].VulnFuncs[j] != want[i].VulnFuncs[j] {
				t.Errorf("scoped[%d].VulnFuncs[%d] = %q, want %q", i, j, scoped[i].VulnFuncs[j], want[i].VulnFuncs[j])
			}
		}
		assertWireSafe(t, scoped[i].VulnFuncs)
	}
	// In this fixture no selector recurs across modules, so the flat union
	// and the scoped attribution carry exactly the same selectors.
	total := 0
	for _, sc := range scoped {
		total += len(sc.VulnFuncs)
	}
	if total != len(flat) {
		t.Errorf("scoped total = %d selectors, flat = %d — want equal for a record without cross-module duplicates", total, len(flat))
	}
}

// TestExtractOSVGoVulnFuncs_ScopedCrossModuleDuplicate pins the R8f
// cross-module duplicate rule: a selector declared under TWO modules (a
// fork/major-version family — github.com/x/mod and github.com/x/mod/v3
// both resolve to package ident "mod") is a flat-union dup (flat keeps the
// first occurrence only, unchanged pre-R8f behaviour) but IS attributed to
// EACH module in scoped, so neither module's target rows lose it.
func TestExtractOSVGoVulnFuncs_ScopedCrossModuleDuplicate(t *testing.T) {
	flat, scoped := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
		"id": "GO-2025-9990",
		"affected": [
			{"package": {"name": "github.com/x/mod", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/x/mod", "symbols": ["Parse"]}]}},
			{"package": {"name": "github.com/x/mod/v3", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/x/mod/v3", "symbols": ["Parse", "Extra"]}]}}
		]
	}`))
	wantFlat := []string{"mod.Parse", "mod.Extra"}
	if len(flat) != len(wantFlat) || flat[0] != wantFlat[0] || flat[1] != wantFlat[1] {
		t.Fatalf("flat = %v, want %v (global first-seen dedupe unchanged)", flat, wantFlat)
	}
	if len(scoped) != 2 {
		t.Fatalf("scoped = %+v, want 2 module entries", scoped)
	}
	if scoped[0].Module != "github.com/x/mod" || len(scoped[0].VulnFuncs) != 1 || scoped[0].VulnFuncs[0] != "mod.Parse" {
		t.Errorf("scoped[0] = %+v, want {github.com/x/mod [mod.Parse]}", scoped[0])
	}
	if scoped[1].Module != "github.com/x/mod/v3" || len(scoped[1].VulnFuncs) != 2 ||
		scoped[1].VulnFuncs[0] != "mod.Parse" || scoped[1].VulnFuncs[1] != "mod.Extra" {
		t.Errorf("scoped[1] = %+v, want {github.com/x/mod/v3 [mod.Parse mod.Extra]} (the duplicate must reach the second module too)", scoped[1])
	}
}

// TestExtractOSVGoVulnFuncs_NoGoData asserts nil / non-Go / symbol-less
// records extract to nothing (→ no row upserted downstream).
func TestExtractOSVGoVulnFuncs_NoGoData(t *testing.T) {
	if got, scoped := extractOSVGoVulnFuncs(nil); got != nil || scoped != nil {
		t.Errorf("nil record: got (%v, %v), want (nil, nil)", got, scoped)
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
	if got, scoped := extractOSVGoVulnFuncs(noSymbols); len(got) != 0 || len(scoped) != 0 {
		t.Errorf("symbol-less record: got (%v, %v), want both empty", got, scoped)
	}
}

// TestExtractOSVGoVulnFuncs_GopkgInVersionedPackage pins the M43 Phase D R2
// finding 3 fix: gopkg.in-style versioned module paths ("<ident>.v<N>" final
// segment) resolve to "<ident>" instead of being dropped wholesale, so the
// whole gopkg.in/yaml.vN family produces selectors again.
func TestExtractOSVGoVulnFuncs_GopkgInVersionedPackage(t *testing.T) {
	got, _ := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
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
	got, _ := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
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
	got, _ := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
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
	got, _ := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
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

// TestExtractOSVGoVulnFuncs_ScopedCapDropWarns pins the M43 Phase D R9
// fix (round 9 Low finding): when cross-module duplicate attributions push
// the scoped total past osvVulnFuncsMaxSymbolsPerCVE, the drop must not be
// silent. The dropped selector still ships in the flat union, but the
// second module's scoped entry never receives it — target rows routed
// through the scoped column silently lose the selector — so a Warn with
// the osv_id and dropped count fires (parity with the flat cap Warn).
func TestExtractOSVGoVulnFuncs_ScopedCapDropWarns(t *testing.T) {
	logs := captureSlog(t)
	symbols := make([]string, 0, osvVulnFuncsMaxSymbolsPerCVE)
	for i := 0; i < osvVulnFuncsMaxSymbolsPerCVE; i++ {
		symbols = append(symbols, fmt.Sprintf("Sym%03d", i))
	}
	b, err := json.Marshal(symbols)
	if err != nil {
		t.Fatalf("marshal symbols: %v", err)
	}
	// Module 1 fills BOTH the flat union and the scoped total to exactly
	// the cap; module 2 (same fork family, same package ident "mod")
	// re-declares two of the same selectors — flat-union dups, so only
	// the scoped-cap branch sees them, and both are dropped there.
	flat, scoped := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
		"id": "GO-2025-9991",
		"affected": [
			{"package": {"name": "github.com/x/mod", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/x/mod", "symbols": `+string(b)+`}]}},
			{"package": {"name": "github.com/x/mod/v3", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/x/mod/v3", "symbols": ["Sym000", "Sym001"]}]}}
		]
	}`))
	if len(flat) != osvVulnFuncsMaxSymbolsPerCVE {
		t.Fatalf("flat = %d selectors, want %d (module 1 fills the cap)", len(flat), osvVulnFuncsMaxSymbolsPerCVE)
	}
	if len(scoped) != 1 || scoped[0].Module != "github.com/x/mod" || len(scoped[0].VulnFuncs) != osvVulnFuncsMaxSymbolsPerCVE {
		t.Fatalf("scoped = %+v, want only github.com/x/mod with %d funcs (v3 attributions dropped at cap)", scoped, osvVulnFuncsMaxSymbolsPerCVE)
	}
	out := logs.String()
	if !strings.Contains(out, "scoped symbol cap") || !strings.Contains(out, "GO-2025-9991") {
		t.Errorf("scoped-cap drop must Warn with the osv_id (parity with the flat cap Warn), got logs:\n%s", out)
	}
	if !strings.Contains(out, "dropped=2") {
		t.Errorf("scoped-cap Warn must carry the dropped count (want dropped=2), got logs:\n%s", out)
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
// RLS GUC) and BOTH ecosystem prefilters (pkg:golang + pkg:npm — M44 Wave 2
// / F470): a query missing any of them fails to match and the test errors.
func expectOSVCandidateQuery(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectQuery(`SELECT DISTINCT v\.cve_id, COALESCE\(c\.purl, ''\)[\s\S]*c\.tenant_id = \$1[\s\S]*pkg:golang%[\s\S]*pkg:npm%`).
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
// tenant: candidate enumeration (a Go purl row AND a pypi purl row — the
// latter is outside the pass's Go/npm ecosystems and must be filtered
// ecosystem-side WITHOUT ever reaching the OSV API; npm rows are IN scope
// since M44 Wave 2 / F470 and have their own end-to-end test below), one OSV
// fetch, selector conversion, and one source='osv' excerpt upsert under the
// tenant GUC.
func TestCVESyncJob_SyncOSVVulnFuncs_EndToEnd(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if !strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-1111") {
			t.Errorf("unexpected OSV request path %q (pypi-purl CVE must never be fetched)", r.URL.Path)
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
		[2]string{"CVE-2025-9999", "pkg:pypi/leftpad@1.0.0"}, // Go-side ecosystem filter drops this (not Go/npm)
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

	// M43 Phase D round 8 (R8f): the same write also stores the
	// module-scoped attribution (migration 057) so the serving edge can
	// stop cross-module symbol leakage — the on-disk shape is
	// [{"module": ..., "vuln_funcs": [...]}, ...] in first-seen module order.
	var scopedRows []osvScopedVulnFuncs
	if err := json.Unmarshal(call.VulnFuncsScoped, &scopedRows); err != nil {
		t.Fatalf("VulnFuncsScoped not the scoped JSON shape: %v (%s)", err, call.VulnFuncsScoped)
	}
	wantScoped := []osvScopedVulnFuncs{
		{Module: "stdlib", VulnFuncs: []string{"template.Parse", "template.Template.Execute"}},
		{Module: "github.com/foo/bar", VulnFuncs: []string{"baz.Do", "baz.Parse"}},
		{Module: "gopkg.in/yaml.v2", VulnFuncs: []string{"yaml.Unmarshal"}},
	}
	if len(scopedRows) != len(wantScoped) {
		t.Fatalf("VulnFuncsScoped = %+v, want %+v", scopedRows, wantScoped)
	}
	for i := range wantScoped {
		if scopedRows[i].Module != wantScoped[i].Module {
			t.Fatalf("VulnFuncsScoped[%d].Module = %q, want %q", i, scopedRows[i].Module, wantScoped[i].Module)
		}
		if len(scopedRows[i].VulnFuncs) != len(wantScoped[i].VulnFuncs) {
			t.Fatalf("VulnFuncsScoped[%d] funcs = %v, want %v", i, scopedRows[i].VulnFuncs, wantScoped[i].VulnFuncs)
		}
		for j := range wantScoped[i].VulnFuncs {
			if scopedRows[i].VulnFuncs[j] != wantScoped[i].VulnFuncs[j] {
				t.Errorf("VulnFuncsScoped[%d].VulnFuncs[%d] = %q, want %q", i, j, scopedRows[i].VulnFuncs[j], wantScoped[i].VulnFuncs[j])
			}
		}
	}
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
		// id is GO-prefixed so no alias follow-up fires either, and it lists
		// the requested CVE among its aliases — the LINKED shape every real
		// Go vulndb record has (M43 Phase D R7 linkage rule: an unlinked
		// body would be rejected wholesale instead of tombstoning
		// authoritatively).
		_, _ = w.Write([]byte(`{
			"id": "GO-2025-2222",
			"summary": "whole-module vulnerability",
			"aliases": ["CVE-2025-2222"],
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
		// The record EXISTS (GO-prefixed: no alias follow-up), is LINKED to
		// the requested CVE via its aliases (M43 Phase D R7 — retraction
		// authority additionally requires linkage), but its symbol list is
		// gone — the upstream retraction shape.
		_, _ = w.Write([]byte(`{
			"id": "GO-2025-2222",
			"summary": "symbols withdrawn upstream",
			"aliases": ["CVE-2025-2222"],
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
// each, no retraction Warn. (Since M43 Phase D R7 the skeletal `{}` shape is
// additionally rejected by the linkage rule with an unlinked-record Warn —
// its preserve-side classification here is unchanged.)
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
	out, _ := j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2025-1111"}, nil)
	if hit {
		t.Error("offline OSV client must not make any HTTP request")
	}
	if len(out) != 0 {
		t.Errorf("offline fetch resolved %d CVEs, want 0", len(out))
	}

	// M44 F470: the offline fences are ecosystem-agnostic — an npm-needing
	// CVE (which would otherwise spend a GHSA- follow-up) makes zero
	// requests and reaches zero outcomes too.
	out, _ = j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2019-10744"},
		map[string]osvCVEEcosystems{"CVE-2019-10744": {needNpm: true}})
	if hit {
		t.Error("offline OSV client must not make any HTTP request for npm CVEs either (M44 F470)")
	}
	if len(out) != 0 {
		t.Errorf("offline npm fetch resolved %d CVEs, want 0", len(out))
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
		[]string{"CVE-2025-1001", "CVE-2025-1002", "CVE-2025-1003"}, nil)

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
	out, _ := j.fetchOSVVulnFuncs(ctx, []string{"CVE-2025-1111", "CVE-2025-4444"}, nil)

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
	out, _ := j.fetchOSVVulnFuncs(ctx, []string{"CVE-2025-1111", "CVE-2025-4444"}, nil)
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
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids, nil)

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
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids, nil)

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
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids, nil)

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
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids, nil)

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
	out, _ := j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2025-1111"}, nil)
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
			VulnFuncs:       json.RawMessage(`["a.B"]`),
			VulnFuncsScoped: json.RawMessage(`[{"module":"github.com/kept/mod","vuln_funcs":["a.B"]}]`),
			RawExcerpt:      "kept excerpt", FetchedAt: &stale,
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
			VulnFuncs:       json.RawMessage(`["gone.Sym"]`),
			VulnFuncsScoped: json.RawMessage(`[{"module":"github.com/gone/mod","vuln_funcs":["gone.Sym"]}]`),
			RawExcerpt:      "pre-retraction excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	// One write chunk: BEGIN, tenant GUC, five fake-intercepted read/upserts,
	// COMMIT. Any extra SQL fails ExpectationsWereMet.
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	outcomes := map[string]osvVulnFuncsOutcome{
		"CVE-2025-0404": {}, // true 404 vs positive row
		"CVE-2025-0405": {}, // true 404 vs existing tombstone
		"CVE-2025-0406": {}, // true 404 vs no row
		"CVE-2025-0407": { // GO-VOUCHED positive vs positive row (M44 F470:
			// goSymbols marks the structured-Go extraction that authorises
			// the unconditional replace; an npm-prose-only positive would
			// take the merge path instead — see the npm authority test)
			symbols:   []string{"x.New"},
			scoped:    []osvScopedVulnFuncs{{Module: "github.com/fresh/mod", VulnFuncs: []string{"x.New"}}},
			excerpt:   "fresh",
			goSymbols: true,
		},
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
	// M43 Phase D R8f: the preserve path copies vuln_funcs_scoped wholesale
	// too — losing the module attribution while keeping the flat union would
	// silently degrade the row back to CVE-wide (cross-module) serving.
	if string(kept.VulnFuncsScoped) != `[{"module":"github.com/kept/mod","vuln_funcs":["a.B"]}]` {
		t.Errorf("preserved VulnFuncsScoped = %s, want the seeded scoped attribution kept verbatim", kept.VulnFuncsScoped)
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

	if tomb := byCVE["CVE-2025-0405"]; len(tomb.VulnFuncs) != 0 || len(tomb.VulnFuncsScoped) != 0 || tomb.FetchedAt == nil {
		t.Errorf("existing-tombstone row = (%s, %s, %v), want empty VulnFuncs + empty VulnFuncsScoped + refreshed FetchedAt", tomb.VulnFuncs, tomb.VulnFuncsScoped, tomb.FetchedAt)
	}
	if tomb := byCVE["CVE-2025-0406"]; len(tomb.VulnFuncs) != 0 || len(tomb.VulnFuncsScoped) != 0 || tomb.FetchedAt == nil {
		t.Errorf("no-existing-row tombstone = (%s, %s, %v), want empty VulnFuncs + empty VulnFuncsScoped + stamped FetchedAt", tomb.VulnFuncs, tomb.VulnFuncsScoped, tomb.FetchedAt)
	}

	pos := byCVE["CVE-2025-0407"]
	if err := json.Unmarshal(pos.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "x.New" {
		t.Errorf("positive VulnFuncs = %s (err %v), want [\"x.New\"] (fresh symbols are authoritative)", pos.VulnFuncs, err)
	}
	if string(pos.VulnFuncsScoped) != `[{"module":"github.com/fresh/mod","vuln_funcs":["x.New"]}]` {
		t.Errorf("positive VulnFuncsScoped = %s, want the fresh outcome's scoped attribution (R8f)", pos.VulnFuncsScoped)
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
	if len(retr.VulnFuncsScoped) != 0 {
		t.Errorf("retraction VulnFuncsScoped = %s, want empty (the retraction wipes the module attribution with the flat union — R8f)", retr.VulnFuncsScoped)
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

// ============================================================================
// M43 Phase D R7 (round 6 findings): record linkage verification (High),
// commit-gated preserve/retraction logs (Low), alias non-GO body branch pins
// (Low), and mass-skeletal mirror observability (Low).
// ============================================================================

// TestCVESyncJob_FetchOSVVulnFuncs_UnlinkedMainRecordRejected pins the M43
// Phase D R7 linkage rule on the MAIN lookup (round 6 High finding): before
// R7 the GO- prefix check trusted the BODY to identify itself, but nothing
// tied the body to the CVE the lookup asked about, so a crafted / mis-routed
// mirror answering every /vulns/{cve} path with ONE canned GO- record could
// (a) gain clobber authority over unrelated CVEs' positive rows (canned body
// without symbols → authoritative empty → positive wipe every freshness
// window) or (b) inject one advisory's selectors into every tenant row
// (canned body WITH symbols → positive outcome). R7 accepts a retrieved body
// only when it vouches for the request — body.ID == the requested id, or the
// CVE named among body.aliases. Anything else is rejected WHOLESALE: symbols
// unused, excerpt unused, aliases not followed, no clobber authority — the
// outcome is a PRESERVE-side empty tombstone (existing positive rows survive
// via the R4 clobber guard) and exactly one osvUnlinkedRecordWarnMsg Warn
// (cve_id, got_id, requested_id — the fetch stage has no tenant) fires per
// rejected lookup.
func TestCVESyncJob_FetchOSVVulnFuncs_UnlinkedMainRecordRejected(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	// The canned unrelated Go vulndb record a hostile/broken mirror serves
	// for every path: aliases name a FOREIGN CVE, never the requested one.
	unlinkedNoSymbols := `{
		"id": "GO-2020-0001",
		"summary": "canned unrelated record",
		"aliases": ["CVE-2020-9999"],
		"affected": [
			{"package": {"name": "github.com/u/v", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/u/v"}]}}
		]
	}`
	unlinkedWithSymbols := `{
		"id": "GO-2020-0001",
		"summary": "canned unrelated record with symbols",
		"aliases": ["CVE-2020-9999"],
		"affected": [
			{"package": {"name": "github.com/u/v", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/u/v", "symbols": ["Inject"]}]}}
		]
	}`
	linkedWithSymbols := `{
		"id": "GO-2025-7003",
		"summary": "linked go record",
		"aliases": ["CVE-2025-7003"],
		"affected": [
			{"package": {"name": "github.com/u/v", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [{"path": "github.com/u/v", "symbols": ["Real"]}]}}
		]
	}`
	// Linkage's OTHER acceptance arm: the body's own ID IS the requested CVE
	// id (a CVE-home record) — accepted even with no aliases at all.
	cveHomeRecord := `{
		"id": "CVE-2025-7004",
		"summary": "cve home record",
		"affected": [{"package": {"name": "github.com/u/v", "ecosystem": "Go"}}]
	}`

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-7001"):
			_, _ = w.Write([]byte(unlinkedNoSymbols))
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-7002"):
			_, _ = w.Write([]byte(unlinkedWithSymbols))
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-7003"):
			_, _ = w.Write([]byte(linkedWithSymbols))
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-7004"):
			_, _ = w.Write([]byte(cveHomeRecord))
		default:
			t.Errorf("unexpected OSV request path %q (an unlinked record's aliases must never be followed)", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	out, anomalous := j.fetchOSVVulnFuncs(context.Background(),
		[]string{"CVE-2025-7001", "CVE-2025-7002", "CVE-2025-7003", "CVE-2025-7004"}, nil)

	if anomalous {
		t.Error("anomalousTick = true on a tick that retrieved record bodies, want false (unlinked rejection is not the mass-404 anomaly)")
	}
	if got := atomic.LoadInt32(&requests); got != 4 {
		t.Errorf("OSV requests = %d, want 4 (one per CVE, no alias follow-ups)", got)
	}

	for _, id := range []string{"CVE-2025-7001", "CVE-2025-7002"} {
		o, ok := out[id]
		if !ok {
			t.Fatalf("%s missing from outcomes, want a preserve-side tombstone (linkage rejection is still definitive — the freshness window must advance)", id)
		}
		if len(o.symbols) != 0 {
			t.Errorf("%s symbols = %v, want none (an unlinked record's symbols must never be injected)", id, o.symbols)
		}
		if o.goID != "" {
			t.Errorf("%s goID = %q, want empty (an unlinked record must not gain clobber authority over positive rows)", id, o.goID)
		}
		if o.excerpt != "" {
			t.Errorf("%s excerpt = %q, want empty (wholesale rejection: the unrelated record's text must not become grounding)", id, o.excerpt)
		}
	}

	pos, ok := out["CVE-2025-7003"]
	if !ok || len(pos.symbols) != 1 || pos.symbols[0] != "v.Real" {
		t.Errorf("linked record outcome = %+v (ok=%v), want symbols [\"v.Real\"] (linkage via aliases keeps the normal positive path)", pos, ok)
	}
	if pos.goID != "GO-2025-7003" {
		t.Errorf("linked record goID = %q, want GO-2025-7003", pos.goID)
	}

	home, ok := out["CVE-2025-7004"]
	if !ok || len(home.symbols) != 0 || home.goID != "" {
		t.Errorf("cve-home outcome = %+v (ok=%v), want an accepted preserve-side empty (body.ID == requested id is the other linkage arm)", home, ok)
	}
	if home.excerpt != "cve home record" {
		t.Errorf("cve-home excerpt = %q, want %q (accepted records keep their excerpt)", home.excerpt, "cve home record")
	}

	got := logs.String()
	if n := strings.Count(got, osvUnlinkedRecordWarnMsg); n != 2 {
		t.Errorf("unlinked-record Warn logged %d times, want exactly 2 (one per rejected lookup; logs: %s)", n, got)
	}
	if !strings.Contains(got, "got_id=GO-2020-0001") ||
		!strings.Contains(got, "requested_id=CVE-2025-7001") ||
		!strings.Contains(got, "cve_id=CVE-2025-7002") {
		t.Errorf("unlinked Warn must carry cve_id + got_id + requested_id attrs, got: %s", got)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_UnlinkedRecordPreservesPositiveRow drives
// the R7 linkage rejection END-TO-END through the write path (round 6 High
// finding, injection arm): the tenant holds a positive row, and the mirror
// serves a canned UNLINKED GO- record WITH symbols for the CVE's path. The
// unrelated selectors must not replace the stored ones (no positive write),
// the rejection tombstones preserve-side — row data kept wholesale,
// fetched_at refreshed, one preserve Info — with one unlinked Warn and no
// retraction Warn.
func TestCVESyncJob_SyncOSVVulnFuncs_UnlinkedRecordPreservesPositiveRow(t *testing.T) {
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
		excerptStoreKey(tenantID, "CVE-2025-7005", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-7005", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["keep.Me"]`), RawExcerpt: "kept excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Canned GO- record, symbols present, but aliases never name the
		// requested CVE: the injection shape.
		_, _ = w.Write([]byte(`{
			"id": "GO-2020-0001",
			"summary": "canned unrelated record with symbols",
			"aliases": ["CVE-2020-9999"],
			"affected": [
				{"package": {"name": "github.com/u/v", "ecosystem": "Go"},
				 "ecosystem_specific": {"imports": [{"path": "github.com/u/v", "symbols": ["Inject"]}]}}
			]
		}`))
	}))
	defer server.Close()
	j.WithOSVBaseURL(server.URL)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-7005", "pkg:golang/github.com/p/q@v1.0.0"},
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
	var funcs []string
	if err := json.Unmarshal(row.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "keep.Me" {
		t.Errorf("VulnFuncs = %s (err %v), want [\"keep.Me\"] (an unlinked record's symbols must not replace the stored row)", row.VulnFuncs, err)
	}
	if row.RawExcerpt != "kept excerpt" {
		t.Errorf("RawExcerpt = %q, want the preserved %q", row.RawExcerpt, "kept excerpt")
	}
	if row.FetchedAt == nil || !row.FetchedAt.After(stale.Add(time.Hour)) {
		t.Errorf("FetchedAt = %v, want refreshed past the stale stamp (the rejection is still a definitive determination)", row.FetchedAt)
	}
	wantKey := excerptStoreKey(tenantID, "CVE-2025-7005", osvVulnFuncsSource)
	if len(store.getKeys) != 1 || store.getKeys[0] != wantKey {
		t.Errorf("GetBySource calls = %v, want exactly [%s]", store.getKeys, wantKey)
	}
	got := logs.String()
	if n := strings.Count(got, osvUnlinkedRecordWarnMsg); n != 1 {
		t.Errorf("unlinked Warn logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if n := strings.Count(got, osvTombstonePreserveInfoMsg); n != 1 {
		t.Errorf("preserve Info logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if strings.Contains(got, osvRetractionOverwriteWarnMsg) {
		t.Error("retraction Warn fired for an unlinked record, want none (no clobber authority)")
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_AliasFollowUpLinkage pins the R7 linkage
// rule on the ALIAS follow-up plus the previously un-pinned non-GO alias
// body branch (round 6 findings 1 and 3). Follow-up acceptance: the body's
// own ID IS the requested GO- alias (aliases may be absent — Go vulndb
// records often do not list their own aliases), or its aliases name the CVE
// under determination. Table:
//   - GO- body, ID == requested alias, NO aliases, symbols → accepted →
//     positive (finding 1d)
//   - GO- body, DIFFERENT id, foreign aliases, symbols     → rejected →
//     preserve-side + unlinked Warn (requested_id = the GO- alias)
//   - non-GO GHSA body LINKED via aliases naming the CVE   → accepted, but
//     no GO- identity → preserve-side, no Warn (finding 3)
//   - skeletal `{}` body                                   → unlinked →
//     rejected → preserve-side + unlinked Warn (finding 3)
func TestCVESyncJob_FetchOSVVulnFuncs_AliasFollowUpLinkage(t *testing.T) {
	zeroOSVFetchDelay(t)
	prevCap := osvVulnFuncsFetchCap
	osvVulnFuncsFetchCap = 20
	t.Cleanup(func() { osvVulnFuncsFetchCap = prevCap })
	logs := captureSlog(t)

	ghsaHome := func(cve, goAlias string) string {
		return `{
			"id": "GHSA-home-` + cve + `",
			"summary": "ghsa home ` + cve + `",
			"aliases": ["` + cve + `", "` + goAlias + `"],
			"affected": [{"package": {"name": "github.com/w/x", "ecosystem": "Go"}}]
		}`
	}
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8001"):
			_, _ = w.Write([]byte(ghsaHome("CVE-2025-8001", "GO-2025-8001")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-8001"):
			// Self-identifying GO- body, aliases ABSENT: must be accepted via
			// its own ID matching the requested alias (finding 1d).
			_, _ = w.Write([]byte(`{
				"id": "GO-2025-8001",
				"summary": "go vulndb body",
				"affected": [
					{"package": {"name": "github.com/w/x", "ecosystem": "Go"},
					 "ecosystem_specific": {"imports": [{"path": "github.com/w/x", "symbols": ["Sym"]}]}}
				]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8003"):
			_, _ = w.Write([]byte(ghsaHome("CVE-2025-8003", "GO-2025-8003")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-8003"):
			// Canned unrelated GO- record under the alias path: neither the
			// requested id nor an alias of the CVE — must be rejected.
			_, _ = w.Write([]byte(`{
				"id": "GO-2020-0001",
				"summary": "canned unrelated record",
				"aliases": ["CVE-2020-9999"],
				"affected": [
					{"package": {"name": "github.com/u/v", "ecosystem": "Go"},
					 "ecosystem_specific": {"imports": [{"path": "github.com/u/v", "symbols": ["Inject"]}]}}
				]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8004"):
			_, _ = w.Write([]byte(ghsaHome("CVE-2025-8004", "GO-2025-8004")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-8004"):
			// Non-GO body under the GO- path but LINKED (aliases name the
			// CVE): accepted, yet carries no GO- identity → preserve-side.
			_, _ = w.Write([]byte(`{
				"id": "GHSA-zzzz-yyyy-xxxx",
				"summary": "ghsa served under the GO- path",
				"aliases": ["CVE-2025-8004"]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8005"):
			_, _ = w.Write([]byte(ghsaHome("CVE-2025-8005", "GO-2025-8005")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-8005"):
			_, _ = w.Write([]byte(`{}`)) // skeletal: unlinked junk
		default:
			t.Errorf("unexpected OSV request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	out, _ := j.fetchOSVVulnFuncs(context.Background(),
		[]string{"CVE-2025-8001", "CVE-2025-8003", "CVE-2025-8004", "CVE-2025-8005"}, nil)

	if got := atomic.LoadInt32(&requests); got != 8 {
		t.Errorf("OSV requests = %d, want 8 (main + one alias follow-up each)", got)
	}

	pos, ok := out["CVE-2025-8001"]
	if !ok || len(pos.symbols) != 1 || pos.symbols[0] != "x.Sym" {
		t.Errorf("self-identifying alias body outcome = %+v (ok=%v), want symbols [\"x.Sym\"] (av.ID == requested GO- id must be accepted even with no aliases)", pos, ok)
	}
	if pos.goID != "GO-2025-8001" {
		t.Errorf("self-identifying alias body goID = %q, want GO-2025-8001", pos.goID)
	}

	for _, id := range []string{"CVE-2025-8003", "CVE-2025-8004", "CVE-2025-8005"} {
		o, ok := out[id]
		if !ok {
			t.Fatalf("%s missing from outcomes, want a preserve-side tombstone", id)
		}
		if len(o.symbols) != 0 {
			t.Errorf("%s symbols = %v, want none", id, o.symbols)
		}
		if o.goID != "" {
			t.Errorf("%s goID = %q, want empty (preserve-side)", id, o.goID)
		}
	}
	// Rejecting the follow-up body must not discard the accepted MAIN
	// record's excerpt.
	if o := out["CVE-2025-8003"]; o.excerpt != "ghsa home CVE-2025-8003" {
		t.Errorf("CVE-2025-8003 excerpt = %q, want the accepted main record's summary", o.excerpt)
	}

	got := logs.String()
	if n := strings.Count(got, osvUnlinkedRecordWarnMsg); n != 2 {
		t.Errorf("unlinked Warn logged %d times, want exactly 2 (the canned GO- body and the skeletal body; the linked GHSA body is accepted silently; logs: %s)", n, got)
	}
	if !strings.Contains(got, "requested_id=GO-2025-8003") ||
		!strings.Contains(got, "got_id=GO-2020-0001") ||
		!strings.Contains(got, "requested_id=GO-2025-8005") {
		t.Errorf("unlinked Warn must carry the requested GO- alias in requested_id, got: %s", got)
	}
}

// TestCVESyncJob_WriteOSVVulnFuncs_CommitFailureSuppressesWriteLogs pins the
// M43 Phase D R7 commit-gating of the write pass's observability lines
// (round 6 finding 2): the preserve Info and retraction Warn describe WRITES,
// but pre-R7 they were emitted mid-tx — a chunk whose COMMIT then failed had
// already logged a preservation / retraction that never became durable
// (operator-facing lies, and a rolled-back retraction Warn is a false wipe
// alarm). R7 buffers the chunk's events and emits them only after
// tx.Commit() succeeds: a failed commit emits NEITHER line (the chunk-abort
// Warn still fires) and contributes zero rows.
func TestCVESyncJob_WriteOSVVulnFuncs_CommitFailureSuppressesWriteLogs(t *testing.T) {
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
		excerptStoreKey(tenantID, "CVE-2025-0408", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-0408", Source: osvVulnFuncsSource,
			VulnFuncs: json.RawMessage(`["gone.Sym"]`), RawExcerpt: "pre-retraction excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit().WillReturnError(errors.New("simulated commit failure"))

	rows, tenants := j.writeOSVVulnFuncs(context.Background(),
		[]osvTenantCandidates{{tenantID: tenantID, cveIDs: []string{"CVE-2025-0404", "CVE-2025-0408"}}},
		map[string]osvVulnFuncsOutcome{
			"CVE-2025-0404": {},                     // would-be preserve Info
			"CVE-2025-0408": {goID: "GO-2025-0408"}, // would-be retraction Warn
		}, false)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if rows != 0 || tenants != 0 {
		t.Errorf("(rows, tenants) = (%d, %d), want (0, 0) on commit failure", rows, tenants)
	}
	got := logs.String()
	if strings.Contains(got, osvTombstonePreserveInfoMsg) {
		t.Errorf("preserve Info fired despite a failed COMMIT — the preservation never became durable (logs: %s)", got)
	}
	if strings.Contains(got, osvRetractionOverwriteWarnMsg) {
		t.Errorf("retraction Warn fired despite a failed COMMIT — a rolled-back wipe is a false alarm (logs: %s)", got)
	}
	if !strings.Contains(got, "OSV vuln_funcs write chunk aborted") {
		t.Errorf("chunk-abort Warn missing after commit failure, got: %s", got)
	}
}

// TestEmitOSVVulnFuncsWriteLogs unit-pins the extracted emitter the R7
// commit-gating hangs on (round 6 finding 2): buffered events reproduce the
// exact pre-R7 lines — preserve at Info with (tenant_id, cve_id), retraction
// at Warn with (tenant_id, cve_id, go_id) — in buffered order, and an empty
// batch emits nothing.
func TestEmitOSVVulnFuncsWriteLogs(t *testing.T) {
	logs := captureSlog(t)
	tenantID := uuid.New()

	emitOSVVulnFuncsWriteLogs(nil) // aborted / event-less chunks emit nothing
	if got := logs.String(); got != "" {
		t.Errorf("empty batch emitted output: %s", got)
	}

	emitOSVVulnFuncsWriteLogs([]osvVulnFuncsWriteLogEvent{
		{tenantID: tenantID, cveID: "CVE-2025-0404"},
		{retraction: true, tenantID: tenantID, cveID: "CVE-2025-0408", goID: "GO-2025-0408"},
	})
	got := logs.String()
	if n := strings.Count(got, osvTombstonePreserveInfoMsg); n != 1 {
		t.Errorf("preserve Info logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if n := strings.Count(got, osvRetractionOverwriteWarnMsg); n != 1 {
		t.Errorf("retraction Warn logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		switch {
		case strings.Contains(line, osvTombstonePreserveInfoMsg):
			if !strings.Contains(line, "level=INFO") ||
				!strings.Contains(line, "tenant_id="+tenantID.String()) ||
				!strings.Contains(line, "cve_id=CVE-2025-0404") {
				t.Errorf("preserve line must be INFO with tenant_id + cve_id, got: %s", line)
			}
		case strings.Contains(line, osvRetractionOverwriteWarnMsg):
			if !strings.Contains(line, "level=WARN") ||
				!strings.Contains(line, "tenant_id="+tenantID.String()) ||
				!strings.Contains(line, "cve_id=CVE-2025-0408") ||
				!strings.Contains(line, "go_id=GO-2025-0408") {
				t.Errorf("retraction line must be WARN with tenant_id + cve_id + go_id, got: %s", line)
			}
		}
	}
	if pi, ri := strings.Index(got, osvTombstonePreserveInfoMsg), strings.Index(got, osvRetractionOverwriteWarnMsg); pi > ri {
		t.Errorf("events emitted out of buffered order (preserve at %d, retraction at %d)", pi, ri)
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_MassSkeletalWarns pins the M43 Phase D R7
// observability fill-in for the mass-404 predicate's blind spot (round 6
// finding 4): a mirror answering EVERY path 200 `{}` (or any canned junk)
// never increments notFound, so the mass-404 Warn stays silent — yet the tick
// determines nothing (no GO- identity, no symbols; every outcome a
// preserve-side tombstone), which is exactly the stub-mirror signature. R7
// emits ONE osvMassSkeletalWarnMsg Warn when a tick fetches and retrieves at
// least the mass threshold of record bodies with ZERO GO- identities and
// ZERO symbols. Warn-ONLY, deliberately no anomalous backdate: the same
// counters describe a legitimate backlog of Go-ecosystem CVEs whose
// advisories are GHSA/CVE-home-only (a Go-ecosystem candidate with no GO-
// record in OSV is a normal, permanent state), so tombstones keep NORMAL
// freshness — pinned here via anomalousTick == false, which is the only
// signal the write pass backdates on.
func TestCVESyncJob_FetchOSVVulnFuncs_MassSkeletalWarns(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`)) // every path: skeletal 200
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ids := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2025-7%03d", i))
	}
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids, nil)

	if anomalous {
		t.Error("anomalousTick = true on a mass-skeletal tick, want false (Warn-only: a legitimate GHSA-home-only backlog is indistinguishable, so no backdate)")
	}
	if len(out) != 25 {
		t.Fatalf("outcomes = %d, want 25 preserve-side tombstones", len(out))
	}
	for id, o := range out {
		if len(o.symbols) != 0 || o.goID != "" {
			t.Errorf("%s outcome = %+v, want a preserve-side empty", id, o)
		}
	}
	got := logs.String()
	if n := strings.Count(got, osvMassSkeletalWarnMsg); n != 1 {
		t.Errorf("mass-skeletal Warn logged %d times, want exactly 1 (logs: %s)", n, got)
	}
	if !strings.Contains(got, "fetches=25") || !strings.Contains(got, "records_retrieved=25") {
		t.Errorf("mass-skeletal Warn must carry fetches + records_retrieved counts, got: %s", got)
	}
	if strings.Contains(got, osvMass404WarnMsg) {
		t.Error("mass-404 Warn fired on a zero-404 tick, want none (the two anomaly signatures are disjoint)")
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_MassLinkedRecordsNoSkeletalWarn is the
// mass-skeletal Warn's normal-operation guard (M43 Phase D R7 finding 4): a
// tick of the same size whose every lookup retrieves a LINKED GO- record
// WITH symbols determines plenty — no skeletal Warn, no mass-404 Warn, all
// positive outcomes.
func TestCVESyncJob_FetchOSVVulnFuncs_MassLinkedRecordsNoSkeletalWarn(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		w.Header().Set("Content-Type", "application/json")
		// A per-path linked Go vulndb record: id GO-<n>, aliases naming the
		// requested CVE, symbols present.
		fmt.Fprintf(w, `{
			"id": %q,
			"summary": "linked record",
			"aliases": [%q],
			"affected": [
				{"package": {"name": "github.com/l/m", "ecosystem": "Go"},
				 "ecosystem_specific": {"imports": [{"path": "github.com/l/m", "symbols": ["Do"]}]}}
			]
		}`, "GO-"+strings.TrimPrefix(id, "CVE-"), id)
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ids := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2025-7%03d", i))
	}
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids, nil)

	if anomalous {
		t.Error("anomalousTick = true on an all-positive tick, want false")
	}
	if len(out) != 25 {
		t.Fatalf("outcomes = %d, want 25 positives", len(out))
	}
	for id, o := range out {
		if len(o.symbols) != 1 || o.symbols[0] != "m.Do" {
			t.Errorf("%s symbols = %v, want [\"m.Do\"]", id, o.symbols)
		}
	}
	got := logs.String()
	if strings.Contains(got, osvMassSkeletalWarnMsg) {
		t.Error("mass-skeletal Warn fired on an all-positive tick, want none")
	}
	if strings.Contains(got, osvMass404WarnMsg) {
		t.Error("mass-404 Warn fired on an all-positive tick, want none")
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

	mock.ExpectQuery(`SELECT cve_id, vuln_funcs, vuln_funcs_scoped\s+FROM advisory_excerpts`).
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "vuln_funcs", "vuln_funcs_scoped"}).
			AddRow("CVE-2025-1", []byte(`[]`), []byte(`[]`)).            // osv tombstone (both columns empty)
			AddRow("CVE-2025-1", []byte(`["tpl.Parse"]`), []byte(`[]`)). // real nvd row
			AddRow("CVE-2025-2", []byte(`[]`), []byte(`[]`)))            // tombstone only

	repo := repository.NewAdvisoryExcerptsRepository(db)
	got, err := repo.ListVulnFuncsByCVEs(context.Background(), tenantID, []string{"CVE-2025-1", "CVE-2025-2"})
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if funcs := got["CVE-2025-1"].Unscoped; len(funcs) != 1 || funcs[0] != "tpl.Parse" {
		t.Errorf("CVE-2025-1 funcs = %v, want exactly [tpl.Parse] (tombstone adds nothing)", funcs)
	}
	if scoped := got["CVE-2025-1"].Scoped; len(scoped) != 0 {
		t.Errorf("CVE-2025-1 scoped = %+v, want none (tombstone scoped '[]' adds nothing)", scoped)
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

// ============================================================================
// M44 Wave 2 (F470): OSV pass extended to npm — GHSA- alias follow-up + npm
// prose extraction → the same source='osv' rows, npm package names in the
// vuln_funcs_scoped module slot, and NO clobber authority for prose.
// Hermetic like the M43 suite above: httptest OSV, sqlmock wire, fake
// excerpt store.
// ============================================================================

// osvNpmCVEHomeFixtureJSON is the shape OSV really returns for a CVE-id
// lookup of an npm vulnerability (2026-07-10 recon): a CVE-namespace record
// with plain prose (no backticks), no affected packages, and the GHSA home
// only reachable through aliases.
const osvNpmCVEHomeFixtureJSON = `{
	"id": "CVE-2019-10744",
	"summary": "lodash CVE-namespace prose without backticks",
	"details": "Versions of lodash lower than 4.17.12 are vulnerable to Prototype Pollution.",
	"aliases": ["GHSA-jf85-cpcp-j695"]
}`

// osvNpmGHSAFixtureJSON mirrors the real GHSA-jf85-cpcp-j695 (lodash
// CVE-2019-10744) OSV record: markdown details with backticked tokens, npm
// affected entries for the fork family, and a non-npm (RubyGems) entry that
// must not receive a scoped attribution.
const osvNpmGHSAFixtureJSON = `{
	"id": "GHSA-jf85-cpcp-j695",
	"summary": "Prototype Pollution in lodash",
	"details": "Versions of ` + "`lodash`" + ` before 4.17.12 are vulnerable to Prototype Pollution. The function ` + "`defaultsDeep`" + ` allows a malicious user to modify the prototype of ` + "`Object`" + ` via a crafted payload.\n\n## Recommendation\n\nUpgrade to version 4.17.12 or later.",
	"aliases": ["CVE-2019-10744"],
	"affected": [
		{"package": {"name": "lodash", "ecosystem": "npm"}},
		{"package": {"name": "lodash-es", "ecosystem": "npm"}},
		{"package": {"name": "lodash-rails", "ecosystem": "RubyGems"}}
	]
}`

// npmWireNormalizeReplica restates the FROZEN M44 Wave 3 npm
// wire-normalisation spec from handler.normalizeVulnFuncsNpm
// (reachability.go): TrimSpace → strip one trailing "()" → dot-split → 1..3
// non-empty JS-identifier-shaped parts ('$'/'_' legal) → ≤256 bytes →
// first-seen-order dedupe. Re-implemented here (the handler helpers are
// unexported in another package) so the scheduler's stored npm tokens are
// pinned against the exact rules the serving edge applies — the same
// load-bearing producer/consumer pin wave1NormalizeReplica provides for Go
// selectors (a drift here silently empties the npm wire).
func npmWireNormalizeReplica(raw []string) []string {
	isJSIdent := func(s string) bool {
		if s == "" {
			return false
		}
		for i, r := range s {
			switch {
			case r == '_' || r == '$' || unicode.IsLetter(r):
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
		if s == "" || len(s) > 256 {
			continue
		}
		parts := strings.Split(s, ".")
		if len(parts) < 1 || len(parts) > 3 {
			continue
		}
		ok := true
		for _, p := range parts {
			if !isJSIdent(p) {
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

// assertNpmWireSafe asserts every produced npm token survives the M44 Wave 3
// serving-edge normalisation UNCHANGED (same elements, same order).
func assertNpmWireSafe(t *testing.T, funcs []string) {
	t.Helper()
	norm := npmWireNormalizeReplica(funcs)
	if len(norm) != len(funcs) {
		t.Fatalf("npm wire normalisation dropped elements: stored %v, survives %v", funcs, norm)
	}
	for i := range funcs {
		if norm[i] != funcs[i] {
			t.Errorf("npm wire normalisation changed element %d: stored %q, survives %q", i, funcs[i], norm[i])
		}
	}
}

// TestExtractOSVNpmVulnFuncs pins the npm extraction contract (M44 F470):
// prose tokens filtered through the npm gates, attributed to EVERY affected
// npm package (first-seen order, non-npm ecosystems excluded, "@scope/name"
// verbatim), and DROPPED WHOLESALE — flat included — when the record lists
// no npm affected entry (scope unknown must never pollute the CVE-wide
// union; M43 anti-pattern 72).
func TestExtractOSVNpmVulnFuncs(t *testing.T) {
	flat, scoped := extractOSVNpmVulnFuncs(osvVulnFromJSON(t, osvNpmGHSAFixtureJSON))
	if len(flat) != 1 || flat[0] != "defaultsDeep" {
		t.Fatalf("flat = %v, want [\"defaultsDeep\"] (function-adjacent token only; the backticked package name and `Object` must not leak)", flat)
	}
	assertNpmWireSafe(t, flat)
	wantScoped := []osvScopedVulnFuncs{
		{Module: "lodash", VulnFuncs: []string{"defaultsDeep"}},
		{Module: "lodash-es", VulnFuncs: []string{"defaultsDeep"}},
	}
	if len(scoped) != len(wantScoped) {
		t.Fatalf("scoped = %+v, want %+v (every npm package attributed, RubyGems excluded)", scoped, wantScoped)
	}
	for i := range wantScoped {
		if scoped[i].Module != wantScoped[i].Module ||
			len(scoped[i].VulnFuncs) != 1 || scoped[i].VulnFuncs[0] != "defaultsDeep" {
			t.Errorf("scoped[%d] = %+v, want %+v", i, scoped[i], wantScoped[i])
		}
	}

	// Scope unknown: prose token present but NO npm affected entry → both
	// shapes empty, nothing stored.
	noNpmAffected := osvVulnFromJSON(t, `{
		"id": "CVE-2025-4242",
		"details": "The function `+"`defaultsDeep`"+` is vulnerable to prototype pollution.",
		"affected": [{"package": {"name": "lodash-rails", "ecosystem": "RubyGems"}}]
	}`)
	if f, s := extractOSVNpmVulnFuncs(noNpmAffected); len(f) != 0 || len(s) != 0 {
		t.Errorf("scope-unknown record: got (%v, %v), want both empty (drop, never CVE-wide)", f, s)
	}

	// Scoped npm package names pass through verbatim, @scope/name included.
	scopedPkg := osvVulnFromJSON(t, `{
		"id": "GHSA-aaaa-bbbb-cccc",
		"details": "The function `+"`run`"+` is vulnerable to command injection.",
		"aliases": ["CVE-2025-4243"],
		"affected": [{"package": {"name": "@scope/pkg", "ecosystem": "npm"}}]
	}`)
	f, s := extractOSVNpmVulnFuncs(scopedPkg)
	if len(f) != 1 || f[0] != "run" || len(s) != 1 || s[0].Module != "@scope/pkg" {
		t.Errorf("scoped-package record: got (%v, %+v), want ([run], [{@scope/pkg [run]}])", f, s)
	}

	if f, s := extractOSVNpmVulnFuncs(nil); f != nil || s != nil {
		t.Errorf("nil record: got (%v, %v), want (nil, nil)", f, s)
	}
}

// TestExtractOSVNpmVulnFuncs_ScopedCap pins the npm scoped attribution
// bound: the per-package fan-out (every npm package receives the token
// list) is capped at osvVulnFuncsMaxSymbolsPerCVE TOTAL attributions, with
// one Warn carrying the dropped count — parity with the R9 Go scoped-cap
// Warn.
func TestExtractOSVNpmVulnFuncs_ScopedCap(t *testing.T) {
	logs := captureSlog(t)
	var b strings.Builder
	for i := 0; i < 90; i++ {
		fmt.Fprintf(&b, "The function `fn%03d` is vulnerable. ", i)
	}
	vuln := &client.OSVVulnerability{
		ID:      "GHSA-cap-cap-cap1",
		Details: b.String(),
		Affected: []client.OSVAffected{
			{Package: client.OSVPackage{Name: "p1", Ecosystem: "npm"}},
			{Package: client.OSVPackage{Name: "p2", Ecosystem: "npm"}},
			{Package: client.OSVPackage{Name: "p3", Ecosystem: "npm"}},
		},
	}
	flat, scoped := extractOSVNpmVulnFuncs(vuln)
	if len(flat) != 90 {
		t.Fatalf("flat = %d tokens, want 90", len(flat))
	}
	if len(scoped) != 3 {
		t.Fatalf("scoped = %d entries, want 3 (p3 keeps a truncated entry)", len(scoped))
	}
	if len(scoped[0].VulnFuncs) != 90 || len(scoped[1].VulnFuncs) != 90 || len(scoped[2].VulnFuncs) != 20 {
		t.Errorf("scoped sizes = (%d, %d, %d), want (90, 90, 20) — total capped at %d",
			len(scoped[0].VulnFuncs), len(scoped[1].VulnFuncs), len(scoped[2].VulnFuncs), osvVulnFuncsMaxSymbolsPerCVE)
	}
	got := logs.String()
	if !strings.Contains(got, "scoped symbol cap") || !strings.Contains(got, "GHSA-cap-cap-cap1") || !strings.Contains(got, "dropped=70") {
		t.Errorf("scoped-cap drop must Warn with osv_id and dropped count, got logs:\n%s", got)
	}
}

// TestNpmWireSafeSymbol pins the npm store-time shape gate (M44 F470): 1..3
// JS-identifier dot-parts ('$' allowed, bare names LEGAL — the npm-dominant
// form, unlike Go's 2..3-part selectors), one trailing call-parens group
// stripped, byte cap enforced. Deliberately shape-only: semantic noise
// (`headers.location`) is the prose extractor's job to gate, and what
// reaches this function must only be checked for wire legality.
func TestNpmWireSafeSymbol(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"defaultsDeep", "defaultsDeep", true},
		{"a.b.c", "a.b.c", true},
		{"$.extend", "$.extend", true},
		{"_.merge", "_.merge", true},
		{"escape()", "escape", true},
		{"pad(1, 2)", "pad", true},
		{" spaced ", "spaced", true},
		{"headers.location", "headers.location", true}, // shape-legal; precision is the extractor's gate
		{"a.b.c.d", "", false},
		{"", "", false},
		{"1abc", "", false},
		{"with space", "", false},
		{"a-b", "", false},
		{"a/b", "", false},
		{"a..b", "", false},
		{strings.Repeat("A", 257), "", false},
		{strings.Repeat("A", 256), strings.Repeat("A", 256), true},
	}
	for _, c := range cases {
		got, ok := npmWireSafeSymbol(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("npmWireSafeSymbol(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_NpmEndToEnd drives the full pass for one
// npm CVE: candidate enumeration keeps the npm purl (M44 F470 — the M43
// Go-only filter dropped it), the main lookup returns the CVE-namespace
// record (plain prose, no tokens), ONE GHSA- alias follow-up retrieves the
// markdown home, and the upsert stores the extracted token flat + scoped to
// the affected npm packages with the GHSA summary as grounding.
func TestCVESyncJob_SyncOSVVulnFuncs_NpmEndToEnd(t *testing.T) {
	mockp, j, fake, setOSV := newOSVSyncMockDB(t)
	mock := *mockp
	tenantID := uuid.New()

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2019-10744"):
			_, _ = w.Write([]byte(osvNpmCVEHomeFixtureJSON))
		case strings.HasSuffix(r.URL.Path, "/vulns/GHSA-jf85-cpcp-j695"):
			_, _ = w.Write([]byte(osvNpmGHSAFixtureJSON))
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
		[2]string{"CVE-2019-10744", "pkg:npm/lodash@4.17.11"},
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
		t.Errorf("OSV requests = %d, want exactly 2 (main + one GHSA- alias follow-up)", got)
	}
	if fake.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1", fake.callCount())
	}
	call := fake.calls[0]
	if call.TenantID != tenantID || call.CVEID != "CVE-2019-10744" || call.Source != osvVulnFuncsSource {
		t.Errorf("row keyed (%v, %q, %q), want (%v, CVE-2019-10744, osv)", call.TenantID, call.CVEID, call.Source, tenantID)
	}
	var funcs []string
	if err := json.Unmarshal(call.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "defaultsDeep" {
		t.Errorf("VulnFuncs = %s (err %v), want [\"defaultsDeep\"]", call.VulnFuncs, err)
	}
	assertNpmWireSafe(t, funcs)
	var scopedRows []osvScopedVulnFuncs
	if err := json.Unmarshal(call.VulnFuncsScoped, &scopedRows); err != nil {
		t.Fatalf("VulnFuncsScoped not the scoped JSON shape: %v (%s)", err, call.VulnFuncsScoped)
	}
	wantScoped := []osvScopedVulnFuncs{
		{Module: "lodash", VulnFuncs: []string{"defaultsDeep"}},
		{Module: "lodash-es", VulnFuncs: []string{"defaultsDeep"}},
	}
	if len(scopedRows) != len(wantScoped) {
		t.Fatalf("VulnFuncsScoped = %+v, want %+v", scopedRows, wantScoped)
	}
	for i := range wantScoped {
		if scopedRows[i].Module != wantScoped[i].Module ||
			len(scopedRows[i].VulnFuncs) != 1 || scopedRows[i].VulnFuncs[0] != "defaultsDeep" {
			t.Errorf("VulnFuncsScoped[%d] = %+v, want %+v", i, scopedRows[i], wantScoped[i])
		}
	}
	if call.RawExcerpt != "Prototype Pollution in lodash" {
		t.Errorf("RawExcerpt = %q, want the token-bearing GHSA record's summary", call.RawExcerpt)
	}
	if call.FetchedAt == nil {
		t.Error("FetchedAt nil, want stamped")
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_BothEcosystemsThreeRequestBound pins the
// M44 F470 per-CVE fetch bound: a CVE listed by BOTH ecosystems spends
// exactly main + GO- follow-up + GHSA- follow-up = 3 requests, and the one
// outcome carries both sides — Go selectors + npm tokens in the flat union,
// both scoped attributions, the GO- clobber authority, and the Go-side
// excerpt (structured source outranks prose).
func TestCVESyncJob_FetchOSVVulnFuncs_BothEcosystemsThreeRequestBound(t *testing.T) {
	zeroOSVFetchDelay(t)
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8101"):
			_, _ = w.Write([]byte(`{
				"id": "CVE-2025-8101",
				"summary": "cve home prose",
				"aliases": ["GO-2025-8101", "GHSA-8101-aaaa-bbbb"]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-8101"):
			_, _ = w.Write([]byte(`{
				"id": "GO-2025-8101",
				"summary": "go vulndb summary",
				"aliases": ["CVE-2025-8101"],
				"affected": [
					{"package": {"name": "github.com/x/y", "ecosystem": "Go"},
					 "ecosystem_specific": {"imports": [{"path": "github.com/x/y", "symbols": ["Handle"]}]}}
				]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/GHSA-8101-aaaa-bbbb"):
			_, _ = w.Write([]byte(`{
				"id": "GHSA-8101-aaaa-bbbb",
				"summary": "ghsa summary",
				"details": "The function ` + "`pad`" + ` is vulnerable to a prototype pollution attack.",
				"aliases": ["CVE-2025-8101"],
				"affected": [{"package": {"name": "leftpad", "ecosystem": "npm"}}]
			}`))
		default:
			t.Errorf("unexpected OSV request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	out, _ := j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2025-8101"},
		map[string]osvCVEEcosystems{"CVE-2025-8101": {needGo: true, needNpm: true}})

	if got := atomic.LoadInt32(&requests); got != 3 {
		t.Errorf("OSV requests = %d, want exactly 3 (main + GO- + GHSA-; the per-CVE bound)", got)
	}
	o, ok := out["CVE-2025-8101"]
	if !ok {
		t.Fatal("both-ecosystem CVE missing from outcomes")
	}
	wantFlat := []string{"y.Handle", "pad"}
	if len(o.symbols) != len(wantFlat) || o.symbols[0] != wantFlat[0] || o.symbols[1] != wantFlat[1] {
		t.Errorf("symbols = %v, want %v (Go selectors first, then npm tokens)", o.symbols, wantFlat)
	}
	if len(o.scoped) != 2 ||
		o.scoped[0].Module != "github.com/x/y" || len(o.scoped[0].VulnFuncs) != 1 || o.scoped[0].VulnFuncs[0] != "y.Handle" ||
		o.scoped[1].Module != "leftpad" || len(o.scoped[1].VulnFuncs) != 1 || o.scoped[1].VulnFuncs[0] != "pad" {
		t.Errorf("scoped = %+v, want [{github.com/x/y [y.Handle]} {leftpad [pad]}]", o.scoped)
	}
	if o.goID != "GO-2025-8101" || !o.goSymbols || !o.goVouched() {
		t.Errorf("(goID, goSymbols) = (%q, %v), want (GO-2025-8101, true) — the Go side must keep its authority", o.goID, o.goSymbols)
	}
	if o.excerpt != "go vulndb summary" {
		t.Errorf("excerpt = %q, want the Go-symbol-bearing record's summary (outranks the GHSA excerpt)", o.excerpt)
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_GHSAFollowUpCapBlocked pins the
// undetermined shape on the npm follow-up (M44 F470, mirroring the M43 GO-
// cap rule): when the fetch cap blocks the GHSA- follow-up of a
// both-ecosystem CVE, NO outcome is written — even though the Go side
// already resolved positively — because a fresh row missing the npm side
// would negative-cache the npm tokens for a full freshness window.
func TestCVESyncJob_FetchOSVVulnFuncs_GHSAFollowUpCapBlocked(t *testing.T) {
	zeroOSVFetchDelay(t)
	prevCap := osvVulnFuncsFetchCap
	osvVulnFuncsFetchCap = 2
	t.Cleanup(func() { osvVulnFuncsFetchCap = prevCap })

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8102"):
			_, _ = w.Write([]byte(`{
				"id": "CVE-2025-8102",
				"summary": "cve home prose",
				"aliases": ["GO-2025-8102", "GHSA-8102-aaaa-bbbb"]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/GO-2025-8102"):
			_, _ = w.Write([]byte(`{
				"id": "GO-2025-8102",
				"summary": "go vulndb summary",
				"aliases": ["CVE-2025-8102"],
				"affected": [
					{"package": {"name": "github.com/x/y", "ecosystem": "Go"},
					 "ecosystem_specific": {"imports": [{"path": "github.com/x/y", "symbols": ["Handle"]}]}}
				]
			}`))
		default:
			t.Errorf("the capped GHSA- follow-up must never be fetched, got %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	out, _ := j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2025-8102"},
		map[string]osvCVEEcosystems{"CVE-2025-8102": {needGo: true, needNpm: true}})

	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("OSV requests = %d, want 2 (main + GO-; cap blocks the GHSA-)", got)
	}
	if len(out) != 0 {
		t.Errorf("outcomes = %v, want none (determination incomplete — the CVE retries next tick)", out)
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_GHSAAliasDeterminations pins the npm
// follow-up decision table (M44 F470, the GHSA mirror of the M43 GO- alias
// determinations):
//   - linked GHSA body, no extractable tokens → PRESERVE-side tombstone
//     (prose silence is not a withdrawal — no authority token exists)
//   - GHSA alias 404 → definitive → PRESERVE-side tombstone
//   - UNLINKED GHSA body (foreign id, aliases without the CVE) → rejected
//     wholesale with the R7 Warn; tokens/excerpt unused; PRESERVE-side
//     tombstone with the MAIN record's excerpt kept
//   - GHSA alias transient 500 → NOT definitive → no outcome
func TestCVESyncJob_FetchOSVVulnFuncs_GHSAAliasDeterminations(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	cveHome := func(cve, ghsaAlias string) string {
		return `{
			"id": "` + cve + `",
			"summary": "main prose for ` + cve + `",
			"aliases": ["` + ghsaAlias + `"]
		}`
	}
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8201"):
			_, _ = w.Write([]byte(cveHome("CVE-2025-8201", "GHSA-8201-aaaa-bbbb")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GHSA-8201-aaaa-bbbb"):
			// Linked (id == requested) but token-less: a routine npm
			// determination.
			_, _ = w.Write([]byte(`{
				"id": "GHSA-8201-aaaa-bbbb",
				"summary": "ghsa home without backticks",
				"aliases": ["CVE-2025-8201"],
				"affected": [{"package": {"name": "leftpad", "ecosystem": "npm"}}]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8202"):
			_, _ = w.Write([]byte(cveHome("CVE-2025-8202", "GHSA-8202-aaaa-bbbb")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GHSA-8202-aaaa-bbbb"):
			w.WriteHeader(http.StatusNotFound) // definitive alias 404
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8203"):
			_, _ = w.Write([]byte(cveHome("CVE-2025-8203", "GHSA-8203-aaaa-bbbb")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GHSA-8203-aaaa-bbbb"):
			// UNLINKED: foreign id, aliases name a different CVE — canned
			// junk that must be rejected wholesale (tokens unused).
			_, _ = w.Write([]byte(`{
				"id": "GHSA-9999-zzzz-yyyy",
				"summary": "junk",
				"details": "The function ` + "`evil`" + ` is vulnerable to everything.",
				"aliases": ["CVE-2020-0001"],
				"affected": [{"package": {"name": "evilpkg", "ecosystem": "npm"}}]
			}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/CVE-2025-8204"):
			_, _ = w.Write([]byte(cveHome("CVE-2025-8204", "GHSA-8204-aaaa-bbbb")))
		case strings.HasSuffix(r.URL.Path, "/vulns/GHSA-8204-aaaa-bbbb"):
			w.WriteHeader(http.StatusInternalServerError) // transient
		default:
			t.Errorf("unexpected OSV request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ids := []string{"CVE-2025-8201", "CVE-2025-8202", "CVE-2025-8203", "CVE-2025-8204"}
	ecos := make(map[string]osvCVEEcosystems, len(ids))
	for _, id := range ids {
		ecos[id] = osvCVEEcosystems{needNpm: true}
	}
	out, _ := j.fetchOSVVulnFuncs(context.Background(), ids, ecos)

	if got := atomic.LoadInt32(&requests); got != 8 {
		t.Errorf("OSV requests = %d, want 8 (4 mains + 4 GHSA- follow-ups)", got)
	}
	for _, id := range []string{"CVE-2025-8201", "CVE-2025-8202", "CVE-2025-8203"} {
		o, ok := out[id]
		if !ok {
			t.Errorf("%s missing from outcomes, want a preserve-side tombstone", id)
			continue
		}
		if len(o.symbols) != 0 || o.goID != "" || o.goVouched() {
			t.Errorf("%s outcome = %+v, want a preserve-side empty (no npm authority exists)", id, o)
		}
	}
	if o := out["CVE-2025-8203"]; o.excerpt != "main prose for CVE-2025-8203" {
		t.Errorf("unlinked-GHSA outcome excerpt = %q, want the accepted MAIN record's excerpt kept", o.excerpt)
	}
	if _, ok := out["CVE-2025-8204"]; ok {
		t.Error("transient GHSA- follow-up must NOT produce an outcome (retry next tick)")
	}
	got := logs.String()
	if !strings.Contains(got, osvUnlinkedRecordWarnMsg) ||
		!strings.Contains(got, "got_id=GHSA-9999-zzzz-yyyy") ||
		!strings.Contains(got, "requested_id=GHSA-8203-aaaa-bbbb") {
		t.Errorf("unlinked GHSA body must Warn with got_id/requested_id, got logs:\n%s", got)
	}
	if strings.Contains(got, "evil") && strings.Contains(got, "symbols") {
		t.Errorf("rejected body's tokens must never be extracted, got logs:\n%s", got)
	}
}

// TestCVESyncJob_WriteOSVVulnFuncs_NpmProseAuthority pins the M44 F470
// authority rule at the write edge: npm prose extraction NEVER destroys
// stored data.
//   - npm-only POSITIVE vs existing POSITIVE row → MERGE: flat union
//     (existing first), outcome's npm entries unioned into the stored
//     scoped attribution per module, AffectedPaths etc. preserved, the
//     outcome's excerpt adopted;
//   - npm-only POSITIVE vs absent row → written as-is;
//   - npm-only POSITIVE vs existing row with the SAME npm module → tokens
//     union per module (add-only: prose has no retraction authority);
//   - npm EMPTY vs existing POSITIVE row → preserved wholesale + ONE
//     preserve Info (the M43 R4/R5 guard, unchanged);
//   - npm-only POSITIVE vs FOREIGN-shaped stored bytes → preserved
//     wholesale (never clobber what you do not understand);
//
// and no retraction Warn fires anywhere — prose cannot retract.
func TestCVESyncJob_WriteOSVVulnFuncs_NpmProseAuthority(t *testing.T) {
	logs := captureSlog(t)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	tenantID := uuid.New()
	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)

	store := &fakeAdvisoryExcerptStore{existing: map[string]*repository.AdvisoryExcerpt{
		excerptStoreKey(tenantID, "CVE-2025-9001", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-9001", Source: osvVulnFuncsSource,
			VulnFuncs:       json.RawMessage(`["a.B"]`),
			VulnFuncsScoped: json.RawMessage(`[{"module":"github.com/kept/mod","vuln_funcs":["a.B"]}]`),
			AffectedPaths:   json.RawMessage(`["src/x.go"]`),
			RawExcerpt:      "kept go excerpt", FetchedAt: &stale,
		},
		excerptStoreKey(tenantID, "CVE-2025-9003", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-9003", Source: osvVulnFuncsSource,
			VulnFuncs:       json.RawMessage(`["defaultsDeep"]`),
			VulnFuncsScoped: json.RawMessage(`[{"module":"lodash","vuln_funcs":["defaultsDeep"]}]`),
			RawExcerpt:      "old ghsa excerpt", FetchedAt: &stale,
		},
		excerptStoreKey(tenantID, "CVE-2025-9004", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-9004", Source: osvVulnFuncsSource,
			VulnFuncs:       json.RawMessage(`["keep.Me"]`),
			VulnFuncsScoped: json.RawMessage(`[{"module":"github.com/keep/mod","vuln_funcs":["keep.Me"]}]`),
			RawExcerpt:      "kept excerpt 9004", FetchedAt: &stale,
		},
		excerptStoreKey(tenantID, "CVE-2025-9005", osvVulnFuncsSource): {
			TenantID: tenantID, CVEID: "CVE-2025-9005", Source: osvVulnFuncsSource,
			VulnFuncs:       json.RawMessage(`{"not":"an array"}`),
			VulnFuncsScoped: json.RawMessage(`{"foreign":"shape"}`),
			RawExcerpt:      "foreign excerpt", FetchedAt: &stale,
		},
	}}
	j := NewCVESyncJob(db, nil, "", 24*time.Hour, store, "", false)

	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	mock.ExpectCommit()

	npmPositive := osvVulnFuncsOutcome{
		symbols: []string{"defaultsDeep"},
		scoped:  []osvScopedVulnFuncs{{Module: "lodash", VulnFuncs: []string{"defaultsDeep"}}},
		excerpt: "ghsa excerpt",
		// goID == "" and goSymbols == false: npm-prose-only, no authority.
	}
	outcomes := map[string]osvVulnFuncsOutcome{
		"CVE-2025-9001": npmPositive, // merge into Go-positive row
		"CVE-2025-9002": npmPositive, // no existing row → as-is
		"CVE-2025-9003": { // same-module union, empty outcome excerpt
			symbols: []string{"defaultsDeep", "merge"},
			scoped:  []osvScopedVulnFuncs{{Module: "lodash", VulnFuncs: []string{"defaultsDeep", "merge"}}},
		},
		"CVE-2025-9004": {excerpt: "ghsa prose without tokens"}, // npm empty vs positive → preserve + Info
		"CVE-2025-9005": npmPositive,                            // foreign-shaped row → preserve wholesale
	}
	rows, tenants := j.writeOSVVulnFuncs(context.Background(),
		[]osvTenantCandidates{{tenantID: tenantID, cveIDs: []string{
			"CVE-2025-9001", "CVE-2025-9002", "CVE-2025-9003", "CVE-2025-9004", "CVE-2025-9005",
		}}},
		outcomes, false)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if rows != 5 || tenants != 1 {
		t.Fatalf("(rows, tenants) = (%d, %d), want (5, 1)", rows, tenants)
	}
	byCVE := map[string]repository.AdvisoryExcerpt{}
	for _, c := range store.calls {
		byCVE[c.CVEID] = c
	}

	merged := byCVE["CVE-2025-9001"]
	var funcs []string
	if err := json.Unmarshal(merged.VulnFuncs, &funcs); err != nil ||
		len(funcs) != 2 || funcs[0] != "a.B" || funcs[1] != "defaultsDeep" {
		t.Errorf("merged VulnFuncs = %s (err %v), want [\"a.B\",\"defaultsDeep\"] (existing first — Go data survives)", merged.VulnFuncs, err)
	}
	var scoped []osvScopedVulnFuncs
	if err := json.Unmarshal(merged.VulnFuncsScoped, &scoped); err != nil || len(scoped) != 2 ||
		scoped[0].Module != "github.com/kept/mod" || len(scoped[0].VulnFuncs) != 1 || scoped[0].VulnFuncs[0] != "a.B" ||
		scoped[1].Module != "lodash" || len(scoped[1].VulnFuncs) != 1 || scoped[1].VulnFuncs[0] != "defaultsDeep" {
		t.Errorf("merged VulnFuncsScoped = %s (err %v), want kept Go entry + appended lodash entry", merged.VulnFuncsScoped, err)
	}
	if string(merged.AffectedPaths) != `["src/x.go"]` {
		t.Errorf("merged AffectedPaths = %s, want preserved", merged.AffectedPaths)
	}
	if merged.RawExcerpt != "ghsa excerpt" {
		t.Errorf("merged RawExcerpt = %q, want the outcome's fresh excerpt", merged.RawExcerpt)
	}
	if merged.FetchedAt == nil || !merged.FetchedAt.After(stale.Add(time.Hour)) {
		t.Errorf("merged FetchedAt = %v, want refreshed", merged.FetchedAt)
	}

	fresh := byCVE["CVE-2025-9002"]
	if err := json.Unmarshal(fresh.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "defaultsDeep" {
		t.Errorf("fresh VulnFuncs = %s (err %v), want [\"defaultsDeep\"] (no row to merge with)", fresh.VulnFuncs, err)
	}
	if fresh.RawExcerpt != "ghsa excerpt" {
		t.Errorf("fresh RawExcerpt = %q, want %q", fresh.RawExcerpt, "ghsa excerpt")
	}

	union := byCVE["CVE-2025-9003"]
	if err := json.Unmarshal(union.VulnFuncs, &funcs); err != nil ||
		len(funcs) != 2 || funcs[0] != "defaultsDeep" || funcs[1] != "merge" {
		t.Errorf("union VulnFuncs = %s (err %v), want [\"defaultsDeep\",\"merge\"]", union.VulnFuncs, err)
	}
	if err := json.Unmarshal(union.VulnFuncsScoped, &scoped); err != nil || len(scoped) != 1 ||
		scoped[0].Module != "lodash" || len(scoped[0].VulnFuncs) != 2 ||
		scoped[0].VulnFuncs[0] != "defaultsDeep" || scoped[0].VulnFuncs[1] != "merge" {
		t.Errorf("union VulnFuncsScoped = %s (err %v), want ONE lodash entry with both tokens", union.VulnFuncsScoped, err)
	}
	if union.RawExcerpt != "old ghsa excerpt" {
		t.Errorf("union RawExcerpt = %q, want preserved (outcome excerpt empty)", union.RawExcerpt)
	}

	preserved := byCVE["CVE-2025-9004"]
	if err := json.Unmarshal(preserved.VulnFuncs, &funcs); err != nil || len(funcs) != 1 || funcs[0] != "keep.Me" {
		t.Errorf("preserved VulnFuncs = %s (err %v), want [\"keep.Me\"] (npm emptiness must never clobber)", preserved.VulnFuncs, err)
	}
	if preserved.RawExcerpt != "kept excerpt 9004" {
		t.Errorf("preserved RawExcerpt = %q, want kept", preserved.RawExcerpt)
	}

	foreign := byCVE["CVE-2025-9005"]
	if string(foreign.VulnFuncs) != `{"not":"an array"}` || string(foreign.VulnFuncsScoped) != `{"foreign":"shape"}` {
		t.Errorf("foreign-shape row = (%s, %s), want preserved verbatim", foreign.VulnFuncs, foreign.VulnFuncsScoped)
	}
	if foreign.RawExcerpt != "foreign excerpt" {
		t.Errorf("foreign RawExcerpt = %q, want preserved", foreign.RawExcerpt)
	}

	// Every npm-only positive AND every empty consulted the store once —
	// the merge guard's read cost is bounded by the row-write count, same
	// argument as the R4 guard.
	if len(store.getKeys) != 5 {
		t.Errorf("GetBySource calls = %d (%v), want 5", len(store.getKeys), store.getKeys)
	}
	got := logs.String()
	if n := strings.Count(got, osvTombstonePreserveInfoMsg); n != 1 {
		t.Errorf("preserve Info logged %d times, want exactly 1 (the 9004 empty-vs-positive quadrant)", n)
	}
	if strings.Contains(got, osvRetractionOverwriteWarnMsg) {
		t.Errorf("retraction Warn fired on an npm tick, want none (prose has no retraction authority): %s", got)
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_MassLinkedGHSANoSkeletalWarn pins the M44
// F470 mass-skeletal predicate extension: a threshold-sized npm backlog
// whose every lookup retrieves a LINKED GHSA home with no extractable
// tokens is a legitimate determination pattern (~54% of real npm advisories
// carry no usable prose tokens), NOT a skeletal mirror — no Warn. The
// linkage requirement keeps the suppression honest: a stub serving one
// canned GHSA body for every path stays unlinked (M43 R7) and still Warns
// (pinned by TestCVESyncJob_FetchOSVVulnFuncs_MassSkeletalWarns above,
// whose `{}` bodies remain unlinked).
func TestCVESyncJob_FetchOSVVulnFuncs_MassLinkedGHSANoSkeletalWarn(t *testing.T) {
	zeroOSVFetchDelay(t)
	logs := captureSlog(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		w.Header().Set("Content-Type", "application/json")
		// A per-path LINKED GHSA home: aliases name the requested CVE, npm
		// affected present, prose without backticks → zero tokens.
		fmt.Fprintf(w, `{
			"id": %q,
			"summary": "plain ghsa prose",
			"aliases": [%q],
			"affected": [{"package": {"name": "leftpad", "ecosystem": "npm"}}]
		}`, "GHSA-"+strings.TrimPrefix(id, "CVE-"), id)
	}))
	defer server.Close()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, &fakeAdvisoryExcerptUpserter{}, "", false)
	j.WithOSVBaseURL(server.URL)

	ids := make([]string, 0, 25)
	ecos := make(map[string]osvCVEEcosystems, 25)
	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("CVE-2025-8%03d", i)
		ids = append(ids, id)
		ecos[id] = osvCVEEcosystems{needNpm: true}
	}
	out, anomalous := j.fetchOSVVulnFuncs(context.Background(), ids, ecos)

	if anomalous {
		t.Error("anomalousTick = true on a linked-GHSA npm backlog, want false")
	}
	if len(out) != 25 {
		t.Fatalf("outcomes = %d, want 25 preserve-side tombstones", len(out))
	}
	for id, o := range out {
		if len(o.symbols) != 0 || o.goID != "" {
			t.Errorf("%s outcome = %+v, want a preserve-side empty", id, o)
		}
	}
	got := logs.String()
	if strings.Contains(got, osvMassSkeletalWarnMsg) {
		t.Error("mass-skeletal Warn fired on a linked-GHSA npm backlog, want none (M44 F470 ghsaLinkedSeen suppression)")
	}
	if strings.Contains(got, osvMass404WarnMsg) {
		t.Error("mass-404 Warn fired on a zero-404 tick, want none")
	}
}
