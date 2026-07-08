package scheduler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/client"
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
		// Not identifier-shaped: conservative skip.
		{"gopkg.in/yaml.v2", "", false},
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
// non-Go ecosystems, non-identifier package paths (gopkg.in/yaml.v2) and
// non-wire-safe symbols dropped.
func TestExtractOSVGoVulnFuncs_ConvertsAndUnions(t *testing.T) {
	got := extractOSVGoVulnFuncs(osvVulnFromJSON(t, osvGoFixtureJSON))
	want := []string{"template.Parse", "template.Template.Execute", "baz.Do", "baz.Parse"}
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

// --- syncOSVVulnFuncs end-to-end harness -----------------------------------

// expectOSVCandidateRead mocks Pass A for one chunk: BEGIN, then per tenant
// SET LOCAL + candidate SELECT (rows provided by the caller), then COMMIT.
func expectOSVCandidateQuery(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectQuery(`SELECT DISTINCT v\.cve_id, COALESCE\(c\.purl, ''\)`).
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
	want := []string{"template.Parse", "template.Template.Execute", "baz.Do", "baz.Parse"}
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

// TestCVESyncJob_SyncOSVVulnFuncs_404SkipsAndContinues: a 404 (no OSV record)
// skips that CVE without failing the pass; later CVEs still resolve + write.
func TestCVESyncJob_SyncOSVVulnFuncs_404SkipsAndContinues(t *testing.T) {
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
	if fake.callCount() != 1 {
		t.Fatalf("Upsert calls = %d, want 1 (404 CVE skipped, next CVE still written)", fake.callCount())
	}
	if fake.calls[0].CVEID != "CVE-2025-1111" {
		t.Errorf("written CVE = %q, want CVE-2025-1111", fake.calls[0].CVEID)
	}
}

// TestCVESyncJob_SyncOSVVulnFuncs_NoSymbolsNoUpsert: an OSV record with no
// extractable symbols yields NO row (requirement: never write empty
// vuln_funcs rows) and NO write-pass transaction at all.
func TestCVESyncJob_SyncOSVVulnFuncs_NoSymbolsNoUpsert(t *testing.T) {
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

	// ONLY the read pass: ExpectationsWereMet fails if a write-pass BEGIN
	// happens.
	mock.ExpectBegin()
	expectSetLocal(mock, tenantID)
	expectOSVCandidateQuery(mock, osvCandidateRows(
		[2]string{"CVE-2025-2222", "pkg:golang/github.com/a/b@v1.0.0"},
	))
	mock.ExpectCommit()

	j.syncOSVVulnFuncs(context.Background(), []uuid.UUID{tenantID})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("Upsert calls = %d, want 0 (no symbols → no row)", fake.callCount())
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
	// WithOffline short-circuit, M40 pattern).
	out := j.fetchOSVVulnFuncs(context.Background(), []string{"CVE-2025-1111"})
	if hit {
		t.Error("offline OSV client must not make any HTTP request")
	}
	if len(out) != 0 {
		t.Errorf("offline fetch resolved %d CVEs, want 0", len(out))
	}
}
