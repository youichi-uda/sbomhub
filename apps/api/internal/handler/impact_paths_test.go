package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
)

// stubCVEPathsService drives CVEPathsHandler down its error / success paths
// without a database. It satisfies the handler's cvePathsService interface.
type stubCVEPathsService struct {
	paths *model.CVEPathsResponse
	err   error
}

func (s stubCVEPathsService) GetCVEPaths(_ context.Context, _ uuid.UUID, _ string) (*model.CVEPathsResponse, error) {
	return s.paths, s.err
}

func newPathsCtx(t *testing.T, cveID string, withTenant bool) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/"+cveID+"/paths", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("cve_id")
	c.SetParamValues(cveID)
	if withTenant {
		c.Set(middleware.ContextKeyTenantID, uuid.New())
	}
	return c, rec
}

// TestGetCVEPaths_ErrorDoesNotLeakInternal pins F396: a service error carrying
// internal detail (SQL driver text, scan error, connection string) must yield
// 500 with a stable generic message — never the underlying error string.
func TestGetCVEPaths_ErrorDoesNotLeakInternal(t *testing.T) {
	leaky := errors.New(`aggregate cve affected components for CVE-2021-1: sql: Scan error on column index 5, name "type": converting NULL to string is unsupported; host=10.0.0.5 user="sbomhub_app" password=hunter2`)
	h := NewCVEPathsHandler(stubCVEPathsService{err: leaky})

	c, rec := newPathsCtx(t, "CVE-2021-0001", true)
	if err := h.GetCVEPaths(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{
		"Scan error", "converting NULL", "10.0.0.5", "sbomhub_app", "password", "hunter2",
		"aggregate cve affected", "sql:",
	} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks internal detail %q: %s", leak, body)
		}
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if resp["error"] != "failed to get vulnerability paths" {
		t.Errorf("error message = %q, want stable generic \"failed to get vulnerability paths\"", resp["error"])
	}
}

// TestGetCVEPaths_UnknownCVEIs404 keeps the nil-result -> 404 contract intact
// (an unknown CVE is distinct from a 500), so the F396 hardening does not
// swallow the not-found path.
func TestGetCVEPaths_UnknownCVEIs404(t *testing.T) {
	h := NewCVEPathsHandler(stubCVEPathsService{paths: nil, err: nil})
	c, rec := newPathsCtx(t, "CVE-9999-0001", true)
	if err := h.GetCVEPaths(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for unknown CVE", rec.Code)
	}
}

// TestGetCVEPaths_ZeroAffectedIs200 pins the blast-radius-0 boundary: a known
// CVE reaching no project is a non-nil empty result → 200 (NOT 404), so
// genuine-empty stays distinct from a broken endpoint. affected_projects must
// serialise as [] (F164), never null.
func TestGetCVEPaths_ZeroAffectedIs200(t *testing.T) {
	empty := &model.CVEPathsResponse{
		CVEID: "CVE-2024-0001", Severity: "HIGH", CVSSScore: 7.5,
		AffectedProjectCount: 0, TotalProjectCount: 5,
		AffectedProjects: []model.AffectedProjectPaths{},
	}
	h := NewCVEPathsHandler(stubCVEPathsService{paths: empty})
	c, rec := newPathsCtx(t, "CVE-2024-0001", true)
	if err := h.GetCVEPaths(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for known-but-empty CVE", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"affected_projects":[]`) {
		t.Errorf("affected_projects must serialise as [] not null: %s", rec.Body.String())
	}
}

// TestGetCVEPaths_MissingTenantIs401 documents the auth guard: no tenant in
// context -> 401, never reaching the service.
func TestGetCVEPaths_MissingTenantIs401(t *testing.T) {
	h := NewCVEPathsHandler(stubCVEPathsService{})
	c, rec := newPathsCtx(t, "CVE-2021-0001", false)
	if err := h.GetCVEPaths(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without tenant context", rec.Code)
	}
}

// TestGetCVEPaths_MissingCVEIs400 pins cve_id path-param validation: an empty
// cve_id is a 400 before the service is touched.
func TestGetCVEPaths_MissingCVEIs400(t *testing.T) {
	h := NewCVEPathsHandler(stubCVEPathsService{})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities//paths", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("cve_id")
	c.SetParamValues("")
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	if err := h.GetCVEPaths(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for empty cve_id", rec.Code)
	}
}

// TestGetCVEPaths_HappyPathShape pins the 200 envelope: the paths payload
// round-trips with the affected project + component chain intact.
func TestGetCVEPaths_HappyPathShape(t *testing.T) {
	resp := &model.CVEPathsResponse{
		CVEID: "CVE-2024-0002", Severity: "HIGH", CVSSScore: 7.5, InKEV: true,
		AffectedProjectCount: 1, TotalProjectCount: 3,
		AffectedProjects: []model.AffectedProjectPaths{{
			ProjectID: uuid.New(), ProjectName: "iot-gateway", SbomID: uuid.New(),
			Format: "cyclonedx", Degraded: false, ComponentCount: 1,
			AffectedComponents: []model.AffectedComponentPaths{{
				Name: "qs", Version: "6.2.0", Purl: "pkg:npm/qs@6.2.0",
				InGraph: true, IsDirect: false, Truncated: false, PathCount: 1,
				Paths: [][]model.PathNode{{
					{ID: "pkg:npm/app", Name: "app", Version: "1.0.0", Type: "application"},
					{ID: "pkg:npm/express", Name: "express", Version: "4.18.0", Type: "library"},
					{ID: "pkg:npm/qs", Name: "qs", Version: "6.2.0", Type: "library"},
				}},
			}},
		}},
	}
	h := NewCVEPathsHandler(stubCVEPathsService{paths: resp})
	c, rec := newPathsCtx(t, "CVE-2024-0002", true)
	if err := h.GetCVEPaths(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got model.CVEPathsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if got.AffectedProjectCount != 1 || len(got.AffectedProjects) != 1 {
		t.Fatalf("affected_project_count = %d (len %d), want 1", got.AffectedProjectCount, len(got.AffectedProjects))
	}
	comp := got.AffectedProjects[0].AffectedComponents[0]
	if comp.PathCount != 1 || len(comp.Paths) != 1 || len(comp.Paths[0]) != 3 {
		t.Fatalf("path chain not preserved: %+v", comp)
	}
	if comp.Paths[0][0].ID != "pkg:npm/app" || comp.Paths[0][2].ID != "pkg:npm/qs" {
		t.Errorf("path not root→…→target: %+v", comp.Paths[0])
	}
}
