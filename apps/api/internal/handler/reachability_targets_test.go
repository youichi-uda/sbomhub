package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// fakeReachabilityTargetsReader stands in for the project-scoped
// (cve_id, component_id, purl) read surface. It records the ecosystem filter
// argument so a test can assert the handler forwards ?ecosystem to the repo,
// and returns a canned row set (or error) without a live PostgreSQL.
type fakeReachabilityTargetsReader struct {
	rows         []repository.ReachabilityTarget
	err          error
	gotEcosystem string
	gotCalls     int
}

func (f *fakeReachabilityTargetsReader) ListReachabilityTargets(_ context.Context, _, _ uuid.UUID, ecosystem string) ([]repository.ReachabilityTarget, error) {
	f.gotCalls++
	f.gotEcosystem = ecosystem
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

// fakeReachabilityVulnFuncsReader stands in for the advisory-excerpt batch
// read (M43 Wave 1 / F465). It records the cveIDs argument so a test can
// assert the handler batches the DISTINCT worklist CVEs into a single call,
// and returns a canned raw (pre-normalisation) symbol map — normalisation is
// the handler's job, so the fake deliberately returns un-normalised strings.
type fakeReachabilityVulnFuncsReader struct {
	byCVE     map[string][]string
	err       error
	gotCVEIDs []string
	gotCalls  int
}

func (f *fakeReachabilityVulnFuncsReader) ListVulnFuncsByCVEs(_ context.Context, _ uuid.UUID, cveIDs []string) (map[string][]string, error) {
	f.gotCalls++
	f.gotCVEIDs = cveIDs
	if f.err != nil {
		return nil, f.err
	}
	if f.byCVE == nil {
		return map[string][]string{}, nil
	}
	return f.byCVE, nil
}

// doReachabilityTargets drives ReachabilityHandler.GetTargets with a bound
// tenant context, mirroring the TenantTx-wrapped read route in main.go.
func doReachabilityTargets(h *ReachabilityHandler, tenantID, projectID uuid.UUID, rawQuery string) (*httptest.ResponseRecorder, error) {
	e := echo.New()
	url := "/api/v1/projects/" + projectID.String() + "/reachability/targets"
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyRole, model.RoleMember)
	err := h.GetTargets(c)
	return rec, err
}

// targetsResponseShape mirrors the frozen JSON contract exactly (field names
// are load-bearing — the CLI consumes them), so decoding into it pins the
// wire shape rather than an internal Go struct. vuln_funcs (M43 Wave 1 /
// F465) is OMITTED — not an empty array — when the CVE has no well-formed
// advisory-declared symbols.
type targetsResponseShape struct {
	Targets []struct {
		CVEID            string   `json:"cve_id"`
		ComponentID      string   `json:"component_id"`
		Purl             string   `json:"purl"`
		ComponentName    string   `json:"component_name"`
		ComponentVersion string   `json:"component_version"`
		Ecosystem        string   `json:"ecosystem"`
		VulnFuncs        []string `json:"vuln_funcs"`
	} `json:"targets"`
}

// TestReachabilityHandler_GetTargets_HappyPath: two targets (a golang and an
// npm component) return 200 with the exact JSON shape, ecosystem is derived
// from purl ("go" for pkg:golang, "npm" for pkg:npm), and vuln_funcs (M43
// Wave 1 / F465) is attached per CVE from ONE batched advisory-excerpt read
// — normalised at this edge — while a CVE with no symbols omits the field
// entirely.
func TestReachabilityHandler_GetTargets_HappyPath(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	goComp := uuid.New()
	npmComp := uuid.New()

	tr := &fakeReachabilityTargetsReader{rows: []repository.ReachabilityTarget{
		{
			CVEID:            "CVE-2024-0001",
			ComponentID:      goComp,
			Purl:             "pkg:golang/example.com/foo@v1.2.3",
			ComponentName:    "foo",
			ComponentVersion: "v1.2.3",
		},
		{
			CVEID:            "CVE-2024-0002",
			ComponentID:      npmComp,
			Purl:             "pkg:npm/lodash@4.17.21",
			ComponentName:    "lodash",
			ComponentVersion: "4.17.21",
		},
	}}
	// Raw (pre-normalisation) union as the repo would return it: the handler
	// must trim, strip "()", drop the bare name, and dedupe before shipping.
	vf := &fakeReachabilityVulnFuncsReader{byCVE: map[string][]string{
		"CVE-2024-0001": {" xml.Unmarshal ", "Foo", "Bar.baz()", "xml.Unmarshal"},
		// CVE-2024-0002 intentionally absent: no advisory symbols known.
	}}
	h := &ReachabilityHandler{projects: &fakeReachabilityProjectReader{}, targets: tr, vulnFuncs: vf}

	rec, err := doReachabilityTargets(h, tenantID, projectID, "")
	if err != nil {
		t.Fatalf("GetTargets returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Field names are the contract: assert their literal presence on the wire.
	body := rec.Body.String()
	for _, key := range []string{`"cve_id"`, `"component_id"`, `"purl"`, `"component_name"`, `"component_version"`, `"ecosystem"`, `"vuln_funcs"`} {
		if !strings.Contains(body, key) {
			t.Errorf("response missing JSON key %s; body=%s", key, body)
		}
	}

	var resp targetsResponseShape
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Targets) != 2 {
		t.Fatalf("targets len = %d, want 2", len(resp.Targets))
	}

	t0 := resp.Targets[0]
	if t0.CVEID != "CVE-2024-0001" || t0.ComponentID != goComp.String() {
		t.Errorf("targets[0] cve/component = %q/%q", t0.CVEID, t0.ComponentID)
	}
	if t0.Purl != "pkg:golang/example.com/foo@v1.2.3" {
		t.Errorf("targets[0].purl = %q", t0.Purl)
	}
	if t0.ComponentName != "foo" || t0.ComponentVersion != "v1.2.3" {
		t.Errorf("targets[0] name/version = %q/%q", t0.ComponentName, t0.ComponentVersion)
	}
	if t0.Ecosystem != "go" {
		t.Errorf("targets[0].ecosystem = %q, want go (derived from pkg:golang)", t0.Ecosystem)
	}
	if resp.Targets[1].Ecosystem != "npm" {
		t.Errorf("targets[1].ecosystem = %q, want npm (derived from pkg:npm)", resp.Targets[1].Ecosystem)
	}

	// vuln_funcs: normalised server-side (trim / "()" strip / bare-name drop /
	// stable dedupe) — the CLI must never see a selector its parser rejects.
	want0 := []string{"xml.Unmarshal", "Bar.baz"}
	if len(t0.VulnFuncs) != len(want0) {
		t.Fatalf("targets[0].vuln_funcs = %v, want %v", t0.VulnFuncs, want0)
	}
	for i := range want0 {
		if t0.VulnFuncs[i] != want0[i] {
			t.Errorf("targets[0].vuln_funcs[%d] = %q, want %q", i, t0.VulnFuncs[i], want0[i])
		}
	}
	// No symbols for CVE-2024-0002 → the key must be ABSENT (omitempty), not [].
	if resp.Targets[1].VulnFuncs != nil {
		t.Errorf("targets[1].vuln_funcs = %v, want field omitted", resp.Targets[1].VulnFuncs)
	}
	if strings.Contains(body, `"vuln_funcs":[]`) || strings.Contains(body, `"vuln_funcs":null`) {
		t.Errorf("no-symbol row must omit vuln_funcs entirely; body=%s", body)
	}

	// One batched read over the distinct worklist CVEs (not one per target).
	if vf.gotCalls != 1 {
		t.Errorf("vuln_funcs reader called %d times, want exactly 1 batch call", vf.gotCalls)
	}
	if len(vf.gotCVEIDs) != 2 || vf.gotCVEIDs[0] != "CVE-2024-0001" || vf.gotCVEIDs[1] != "CVE-2024-0002" {
		t.Errorf("vuln_funcs reader received cveIDs = %v, want [CVE-2024-0001 CVE-2024-0002]", vf.gotCVEIDs)
	}
}

// TestReachabilityHandler_GetTargets_VulnFuncsSharedAcrossRows: two targets
// (distinct components) on the SAME CVE both carry the CVE's normalised
// vuln_funcs, and the batch read deduplicates the CVE id (one entry, one call).
func TestReachabilityHandler_GetTargets_VulnFuncsSharedAcrossRows(t *testing.T) {
	compA := uuid.New()
	compB := uuid.New()
	tr := &fakeReachabilityTargetsReader{rows: []repository.ReachabilityTarget{
		{CVEID: "CVE-2024-0009", ComponentID: compA, Purl: "pkg:golang/a@v1", ComponentName: "a", ComponentVersion: "v1"},
		{CVEID: "CVE-2024-0009", ComponentID: compB, Purl: "pkg:golang/b@v2", ComponentName: "b", ComponentVersion: "v2"},
	}}
	vf := &fakeReachabilityVulnFuncsReader{byCVE: map[string][]string{
		"CVE-2024-0009": {"Pkg.Type.Method"},
	}}
	h := &ReachabilityHandler{projects: &fakeReachabilityProjectReader{}, targets: tr, vulnFuncs: vf}

	rec, err := doReachabilityTargets(h, uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("GetTargets returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(vf.gotCVEIDs) != 1 || vf.gotCVEIDs[0] != "CVE-2024-0009" {
		t.Errorf("vuln_funcs reader received cveIDs = %v, want the deduped [CVE-2024-0009]", vf.gotCVEIDs)
	}
	var resp targetsResponseShape
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Targets) != 2 {
		t.Fatalf("targets len = %d, want 2", len(resp.Targets))
	}
	for i, tgt := range resp.Targets {
		if len(tgt.VulnFuncs) != 1 || tgt.VulnFuncs[0] != "Pkg.Type.Method" {
			t.Errorf("targets[%d].vuln_funcs = %v, want [Pkg.Type.Method]", i, tgt.VulnFuncs)
		}
	}
}

// TestReachabilityHandler_GetTargets_VulnFuncsLookupError: a failing
// advisory-excerpt batch read is a 500 (the worklist must not silently ship
// stripped of symbols — the CLI would quietly degrade to import-only).
func TestReachabilityHandler_GetTargets_VulnFuncsLookupError(t *testing.T) {
	tr := &fakeReachabilityTargetsReader{rows: []repository.ReachabilityTarget{
		{CVEID: "CVE-2024-0001", ComponentID: uuid.New(), Purl: "pkg:golang/x@v1", ComponentName: "x", ComponentVersion: "v1"},
	}}
	vf := &fakeReachabilityVulnFuncsReader{err: sql.ErrConnDone}
	h := &ReachabilityHandler{projects: &fakeReachabilityProjectReader{}, targets: tr, vulnFuncs: vf}

	rec, err := doReachabilityTargets(h, uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("GetTargets returned error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestNormalizeVulnFuncs pins the frozen normalisation spec (M43 Wave 1 /
// F465): trim → strip one trailing "()" → keep only dot-separated selectors
// with 2 or 3 identifier-shaped parts → stable-order dedupe. This edge is
// the single source of truth — the CLI's parseSymbolSelectors hard-fails the
// whole symbol walk on ONE malformed selector, so nothing malformed may ship.
func TestNormalizeVulnFuncs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil input", nil, nil},
		{"empty input", []string{}, nil},
		{"pkg.func kept", []string{"xml.Unmarshal"}, []string{"xml.Unmarshal"}},
		{"pkg.type.method kept", []string{"Pkg.Type.Method"}, []string{"Pkg.Type.Method"}},
		{"bare name dropped", []string{"Foo"}, nil},
		{"trailing parens stripped", []string{"Bar.baz()"}, []string{"Bar.baz"}},
		{"whitespace trimmed", []string{"  xml.Unmarshal\t"}, []string{"xml.Unmarshal"}},
		{"trim then paren strip", []string{" Bar.baz() "}, []string{"Bar.baz"}},
		{"four parts dropped", []string{"a.b.c.d"}, nil},
		{"empty part dropped", []string{"pkg."}, nil},
		{"leading dot dropped", []string{".Foo"}, nil},
		{"dedupe keeps first-seen order", []string{"b.a", "a.b", "b.a"}, []string{"b.a", "a.b"}},
		{"dedupe across paren variants", []string{"Bar.baz", "Bar.baz()"}, []string{"Bar.baz"}},
		{"slash path dropped", []string{"html/template.Parse"}, nil},
		{"embedded space dropped", []string{"Bar.b az"}, nil},
		{"java dollar dropped", []string{"com$Foo.bar"}, nil},
		{"generics noise dropped", []string{"Foo<T>.Bar"}, nil},
		{"colon dropped", []string{"Foo::Bar.baz"}, nil},
		{"hyphen dropped", []string{"my-pkg.Foo"}, nil},
		{"digit-leading part dropped", []string{"1pkg.Foo"}, nil},
		{"underscore and digits kept", []string{"pkg_v2.Do_1"}, []string{"pkg_v2.Do_1"}},
		{"mixed keeps only well-formed", []string{"Foo", "xml.Unmarshal", "a.b.c.d", "Bar.baz()"}, []string{"xml.Unmarshal", "Bar.baz"}},
		{"empty string dropped", []string{"", "   ", "()"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeVulnFuncs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeVulnFuncs(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("normalizeVulnFuncs(%v)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
			if len(tc.want) == 0 && got != nil {
				t.Errorf("normalizeVulnFuncs(%v) = %v, want nil (omitempty depends on it)", tc.in, got)
			}
		})
	}
}

// TestReachabilityHandler_GetTargets_EmptyList: no targets returns 200 with a
// non-null empty array (`{"targets":[]}`), not `null`.
func TestReachabilityHandler_GetTargets_EmptyList(t *testing.T) {
	tr := &fakeReachabilityTargetsReader{rows: nil}
	h := &ReachabilityHandler{projects: &fakeReachabilityProjectReader{}, targets: tr, vulnFuncs: &fakeReachabilityVulnFuncsReader{}}

	rec, err := doReachabilityTargets(h, uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("GetTargets returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); !strings.Contains(got, `"targets":[]`) {
		t.Errorf("empty response = %s, want a non-null empty array", got)
	}
}

// TestReachabilityHandler_GetTargets_EcosystemFilterForwarded: ?ecosystem=go is
// forwarded to the reader verbatim (the repo does the actual filtering), and
// the returned rows map through with the derived ecosystem.
func TestReachabilityHandler_GetTargets_EcosystemFilterForwarded(t *testing.T) {
	goComp := uuid.New()
	tr := &fakeReachabilityTargetsReader{rows: []repository.ReachabilityTarget{
		{CVEID: "CVE-2024-0001", ComponentID: goComp, Purl: "pkg:golang/x@v1", ComponentName: "x", ComponentVersion: "v1"},
	}}
	h := &ReachabilityHandler{projects: &fakeReachabilityProjectReader{}, targets: tr, vulnFuncs: &fakeReachabilityVulnFuncsReader{}}

	rec, err := doReachabilityTargets(h, uuid.New(), uuid.New(), "ecosystem=go")
	if err != nil {
		t.Fatalf("GetTargets returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if tr.gotEcosystem != "go" {
		t.Errorf("reader received ecosystem = %q, want go (forwarded from query)", tr.gotEcosystem)
	}
	var resp targetsResponseShape
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Targets) != 1 || resp.Targets[0].Ecosystem != "go" {
		t.Errorf("targets = %+v, want a single go row", resp.Targets)
	}
}

// TestReachabilityHandler_GetTargets_ProjectNotFound: a project the tenant does
// not own is a 404, and the targets reader is never called (the soft-reference
// guard runs first).
func TestReachabilityHandler_GetTargets_ProjectNotFound(t *testing.T) {
	tr := &fakeReachabilityTargetsReader{}
	vf := &fakeReachabilityVulnFuncsReader{}
	proj := &fakeReachabilityProjectReader{err: sql.ErrNoRows}
	h := &ReachabilityHandler{projects: proj, targets: tr, vulnFuncs: vf}

	rec, err := doReachabilityTargets(h, uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("GetTargets returned error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if tr.gotCalls != 0 {
		t.Errorf("targets reader called %d times, want 0 on project-not-found", tr.gotCalls)
	}
	if vf.gotCalls != 0 {
		t.Errorf("vuln_funcs reader called %d times, want 0 on project-not-found", vf.gotCalls)
	}
}
