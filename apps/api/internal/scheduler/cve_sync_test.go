package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	prev := osvVulnFuncsFetchDelay
	osvVulnFuncsFetchDelay = 0
	t.Cleanup(func() { osvVulnFuncsFetchDelay = prev })
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
// that are NOT prefixed by the module name — while still rejecting
// domain-shaped module paths smuggled under a "stdlib" record.
func TestExtractOSVGoVulnFuncs_StdlibPathsAllowed(t *testing.T) {
	got := extractOSVGoVulnFuncs(osvVulnFromJSON(t, `{
		"id": "GO-2025-7777",
		"affected": [
			{"package": {"name": "stdlib", "ecosystem": "Go"},
			 "ecosystem_specific": {"imports": [
				{"path": "html/template", "symbols": ["Parse"]},
				{"path": "github.com/evil/mod", "symbols": ["Injected"]}
			 ]}}
		]
	}`))
	want := []string{"template.Parse"}
	if len(got) != len(want) {
		t.Fatalf("extractOSVGoVulnFuncs = %v, want %v", got, want)
	}
	if got[0] != want[0] {
		t.Errorf("extractOSVGoVulnFuncs[0] = %q, want %q", got[0], want[0])
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
	out := j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2025-1111"})
	if hit {
		t.Error("offline OSV client must not make any HTTP request")
	}
	if len(out) != 0 {
		t.Errorf("offline fetch resolved %d CVEs, want 0", len(out))
	}
}

// TestCVESyncJob_FetchOSVVulnFuncs_AliasDeterminations pins the tombstone
// decision table on the alias follow-up path (M43 Phase D R2 finding 1):
//   - alias 404            → definitive → tombstone outcome (empty symbols)
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

	out := j.fetchOSVVulnFuncs(context.Background(),
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
	out := j.fetchOSVVulnFuncs(ctx, []string{"CVE-2025-1111", "CVE-2025-4444"})

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
	out := j.fetchOSVVulnFuncs(ctx, []string{"CVE-2025-1111", "CVE-2025-4444"})
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
