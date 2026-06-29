// Package handler — wire-level tests for the M10-6 (#74) project diff
// handler. The diff service itself is exhaustively tested in
// internal/service/diff/diff_test.go; the tests here pin the HTTP
// contract: status codes, query-string parsing, and the tenant_id
// requirement.
package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service/diff"
)

// ---------- fakes for the four repos consumed by diff.NewService ----------

type stubProjectRepo struct {
	owner uuid.UUID
}

func (s *stubProjectRepo) GetByTenant(_ context.Context, tenantID, projectID uuid.UUID) (*model.Project, error) {
	if tenantID == s.owner {
		return &model.Project{ID: projectID}, nil
	}
	return nil, sql.ErrNoRows
}

type stubSbomRepo struct {
	byID      map[uuid.UUID]model.Sbom
	byProject map[uuid.UUID][]model.Sbom
}

func (s *stubSbomRepo) ListByProject(_ context.Context, projectID uuid.UUID) ([]model.Sbom, error) {
	return s.byProject[projectID], nil
}
func (s *stubSbomRepo) GetByID(_ context.Context, id uuid.UUID) (*model.Sbom, error) {
	if v, ok := s.byID[id]; ok {
		cp := v
		return &cp, nil
	}
	return nil, sql.ErrNoRows
}

type stubComponentRepo struct {
	comps map[uuid.UUID][]model.Component
	vulns map[uuid.UUID][]model.ComponentVulnerability
}

func (s *stubComponentRepo) ListBySbom(_ context.Context, id uuid.UUID) ([]model.Component, error) {
	return s.comps[id], nil
}
func (s *stubComponentRepo) ListComponentVulnerabilitiesBySbom(_ context.Context, id uuid.UUID) ([]model.ComponentVulnerability, error) {
	return s.vulns[id], nil
}

type stubLicenseRepo struct{}

func (s *stubLicenseRepo) ListByProject(_ context.Context, _ uuid.UUID) ([]model.LicensePolicy, error) {
	return nil, nil
}

// ---------- fixture wiring ----------

func newDiffTestHandler(t *testing.T, tenantID, projectID uuid.UUID, sboms []model.Sbom, comps map[uuid.UUID][]model.Component, vulns map[uuid.UUID][]model.ComponentVulnerability) *DiffHandler {
	t.Helper()
	byID := make(map[uuid.UUID]model.Sbom, len(sboms))
	for _, s := range sboms {
		byID[s.ID] = s
	}
	svc := diff.NewService(
		&stubProjectRepo{owner: tenantID},
		&stubSbomRepo{byID: byID, byProject: map[uuid.UUID][]model.Sbom{projectID: sboms}},
		&stubComponentRepo{comps: comps, vulns: vulns},
		&stubLicenseRepo{},
	)
	return NewDiffHandler(svc)
}

// ---------- tests ----------

func TestDiffHandler_RequiresTenantContext(t *testing.T) {
	h := newDiffTestHandler(t, uuid.New(), uuid.New(), nil, nil, nil)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(uuid.New().String())

	_ = h.ProjectDiff(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing tenant ctx: got status %d, want 401", rec.Code)
	}
}

func TestDiffHandler_InvalidProjectID(t *testing.T) {
	tenantID := uuid.New()
	h := newDiffTestHandler(t, tenantID, uuid.New(), nil, nil, nil)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("not-a-uuid")
	c.Set(middleware.ContextKeyTenantID, tenantID)

	_ = h.ProjectDiff(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid project id: got status %d, want 400", rec.Code)
	}
}

func TestDiffHandler_InvalidFromOrTo(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	h := newDiffTestHandler(t, tenantID, projectID, nil, nil, nil)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?from=not-a-uuid", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)

	_ = h.ProjectDiff(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid from: got status %d, want 400", rec.Code)
	}
}

func TestDiffHandler_NoSboms_Returns404(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	h := newDiffTestHandler(t, tenantID, projectID, nil, nil, nil)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)

	_ = h.ProjectDiff(c)
	if rec.Code != http.StatusNotFound {
		t.Errorf("no-sboms: got status %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDiffHandler_CrossTenant_Returns404(t *testing.T) {
	tenantID := uuid.New()
	otherTenant := uuid.New()
	projectID := uuid.New()
	h := newDiffTestHandler(t, tenantID, projectID, nil, nil, nil)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, otherTenant)

	_ = h.ProjectDiff(c)
	if rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant: got status %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// F166: when only `from` is set AND it's already the newest SBOM, the
// handler must return 400 (ErrNoNewerSbom) — NOT 500 — so the UI can
// render an "already most recent" empty state.
func TestDiffHandler_FromIsNewest_Returns400(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	fromID := uuid.New()
	toID := uuid.New()
	now := time.Now()
	fromSbom := model.Sbom{ID: fromID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", CreatedAt: now.Add(-time.Hour)}
	toSbom := model.Sbom{ID: toID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", CreatedAt: now}

	h := newDiffTestHandler(t, tenantID, projectID,
		[]model.Sbom{toSbom, fromSbom}, // newest first
		map[uuid.UUID][]model.Component{},
		map[uuid.UUID][]model.ComponentVulnerability{},
	)

	e := echo.New()
	// Pass `from` = the NEWEST sbom (toID). Default resolution should
	// fail to find a successor and surface ErrNoNewerSbom.
	req := httptest.NewRequest(http.MethodGet, "/?from="+toID.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)

	_ = h.ProjectDiff(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("from-is-newest: got status %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDiffHandler_HappyPath_TwoSboms_DefaultsToNewest(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	fromID := uuid.New()
	toID := uuid.New()
	now := time.Now()
	fromSbom := model.Sbom{ID: fromID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", CreatedAt: now.Add(-time.Hour)}
	toSbom := model.Sbom{ID: toID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", CreatedAt: now}

	comps := map[uuid.UUID][]model.Component{
		fromID: {{Name: "axios", Version: "1.4.0", Type: "library", Purl: "pkg:npm/axios@1.4.0"}},
		toID:   {{Name: "axios", Version: "1.4.1", Type: "library", Purl: "pkg:npm/axios@1.4.1"}},
	}
	vulns := map[uuid.UUID][]model.ComponentVulnerability{}

	h := newDiffTestHandler(t, tenantID, projectID,
		[]model.Sbom{toSbom, fromSbom}, // newest-first per repo contract
		comps, vulns,
	)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+projectID.String()+"/diff", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)

	if err := h.ProjectDiff(c); err != nil {
		t.Fatalf("ProjectDiff returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp diff.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if resp.From == nil || resp.From.SbomID != fromID {
		t.Errorf("From: got %+v, want sbom_id=%s", resp.From, fromID)
	}
	if resp.To == nil || resp.To.SbomID != toID {
		t.Errorf("To: got %+v, want sbom_id=%s", resp.To, toID)
	}
	if len(resp.Components.VersionChanged) != 1 || resp.Components.VersionChanged[0].Name != "axios" {
		t.Errorf("VersionChanged: %+v", resp.Components.VersionChanged)
	}
}

func TestDiffHandler_HappyPath_SingleSbom_Baseline(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	soleID := uuid.New()
	sbom := model.Sbom{ID: soleID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", CreatedAt: time.Now()}

	comps := map[uuid.UUID][]model.Component{
		soleID: {
			{Name: "axios", Version: "1.4.0", Type: "library", Purl: "pkg:npm/axios@1.4.0"},
			{Name: "lodash", Version: "4.17.21", Type: "library", Purl: "pkg:npm/lodash@4.17.21"},
		},
	}
	h := newDiffTestHandler(t, tenantID, projectID, []model.Sbom{sbom}, comps, nil)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+projectID.String()+"/diff", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)

	if err := h.ProjectDiff(c); err != nil {
		t.Fatalf("ProjectDiff error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp diff.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.From != nil {
		t.Errorf("baseline: From should be nil; got %+v", resp.From)
	}
	if resp.To == nil || resp.To.SbomID != soleID {
		t.Errorf("baseline To: got %+v, want %s", resp.To, soleID)
	}
	if len(resp.Components.Added) != 2 {
		t.Errorf("baseline Added: got %d, want 2; %+v", len(resp.Components.Added), resp.Components.Added)
	}
	if len(resp.Components.Removed) != 0 {
		t.Errorf("baseline Removed must be empty; got %+v", resp.Components.Removed)
	}
}
