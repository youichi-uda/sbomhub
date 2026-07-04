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
// wire shape rather than an internal Go struct.
type targetsResponseShape struct {
	Targets []struct {
		CVEID            string `json:"cve_id"`
		ComponentID      string `json:"component_id"`
		Purl             string `json:"purl"`
		ComponentName    string `json:"component_name"`
		ComponentVersion string `json:"component_version"`
		Ecosystem        string `json:"ecosystem"`
	} `json:"targets"`
}

// TestReachabilityHandler_GetTargets_HappyPath: two targets (a golang and an
// npm component) return 200 with the exact JSON shape, and ecosystem is
// derived from purl ("go" for pkg:golang, "npm" for pkg:npm).
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
	h := &ReachabilityHandler{projects: &fakeReachabilityProjectReader{}, targets: tr}

	rec, err := doReachabilityTargets(h, tenantID, projectID, "")
	if err != nil {
		t.Fatalf("GetTargets returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Field names are the contract: assert their literal presence on the wire.
	body := rec.Body.String()
	for _, key := range []string{`"cve_id"`, `"component_id"`, `"purl"`, `"component_name"`, `"component_version"`, `"ecosystem"`} {
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
}

// TestReachabilityHandler_GetTargets_EmptyList: no targets returns 200 with a
// non-null empty array (`{"targets":[]}`), not `null`.
func TestReachabilityHandler_GetTargets_EmptyList(t *testing.T) {
	tr := &fakeReachabilityTargetsReader{rows: nil}
	h := &ReachabilityHandler{projects: &fakeReachabilityProjectReader{}, targets: tr}

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
	h := &ReachabilityHandler{projects: &fakeReachabilityProjectReader{}, targets: tr}

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
	proj := &fakeReachabilityProjectReader{err: sql.ErrNoRows}
	h := &ReachabilityHandler{projects: proj, targets: tr}

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
}
