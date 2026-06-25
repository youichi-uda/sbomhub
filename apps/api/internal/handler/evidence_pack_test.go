package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/evidence_pack"
)

// ----------------------------------------------------------------------------
// Fakes — mirror the M1 pattern used by vex_drafts_test.go.
// ----------------------------------------------------------------------------

type fakeVEXDraftReader struct {
	rows []repository.VEXDraft
}

func (f *fakeVEXDraftReader) ListByProject(_ context.Context, _, _ uuid.UUID, _ repository.VEXDraftListFilter) ([]repository.VEXDraft, error) {
	return f.rows, nil
}

type fakeCRAReportReader struct {
	rows []repository.CRAReport
}

func (f *fakeCRAReportReader) ListByProject(_ context.Context, _, _ uuid.UUID, _ repository.CRAReportListFilter) ([]repository.CRAReport, error) {
	return f.rows, nil
}

type fakeProjectReaderHandler struct {
	project *model.Project
	err     error
}

func (f *fakeProjectReaderHandler) GetByTenant(_ context.Context, _, _ uuid.UUID) (*model.Project, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.project, nil
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func newEvidencePackTestHandler(t *testing.T, vex *fakeVEXDraftReader, cra *fakeCRAReportReader, proj *fakeProjectReaderHandler) *EvidencePackHandler {
	t.Helper()
	builder := evidence_pack.NewBuilder(vex, cra, proj)
	// auditRepo is nil — production wiring supplies one, but the
	// handler tolerates nil for tests so we can exercise the wire-
	// level behaviour without hitting Postgres.
	return NewEvidencePackHandler(builder, nil)
}

// installTenantContext sets the middleware context keys that
// NewTenantContext consults. Mirrors the pattern in
// vex_drafts_test.go.
func installTenantContext(c echo.Context, tenantID, userID uuid.UUID, role string) {
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, userID)
	c.Set(middleware.ContextKeyRole, role)
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

func TestEvidencePackHandler_Build_HappyPath(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	vex := &fakeVEXDraftReader{rows: []repository.VEXDraft{}}
	cra := &fakeCRAReportReader{rows: []repository.CRAReport{}}
	proj := &fakeProjectReaderHandler{project: &model.Project{
		ID:   projectID,
		Name: "demo",
	}}
	h := newEvidencePackTestHandler(t, vex, cra, proj)

	e := echo.New()
	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/"+projectID.String()+"/evidence-pack/build", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	installTenantContext(c, tenantID, uuid.New(), model.RoleAdmin)

	if err := h.Build(c); err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("Content-Type = %q, want text/markdown*", ct)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment;") || !strings.Contains(cd, ".md") {
		t.Errorf("Content-Disposition = %q, want attachment;*.md", cd)
	}
	if rec.Header().Get("X-Evidence-Pack-VEX-Count") != "0" {
		t.Errorf("X-Evidence-Pack-VEX-Count = %q, want 0", rec.Header().Get("X-Evidence-Pack-VEX-Count"))
	}
	if !strings.Contains(rec.Body.String(), "SBOMHub AI Compliance Evidence Pack") {
		t.Errorf("body missing header; body=%q", rec.Body.String())
	}
}

func TestEvidencePackHandler_Build_Unauthorized(t *testing.T) {
	h := newEvidencePackTestHandler(t,
		&fakeVEXDraftReader{}, &fakeCRAReportReader{}, &fakeProjectReaderHandler{project: &model.Project{Name: "p"}})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(uuid.New().String())
	// No tenant context installed.

	_ = h.Build(c)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestEvidencePackHandler_Build_ForbiddenForReader(t *testing.T) {
	h := newEvidencePackTestHandler(t,
		&fakeVEXDraftReader{}, &fakeCRAReportReader{}, &fakeProjectReaderHandler{project: &model.Project{Name: "p"}})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(uuid.New().String())
	installTenantContext(c, uuid.New(), uuid.New(), model.RoleViewer)

	_ = h.Build(c)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not json: %v (body=%q)", err, rec.Body.String())
	}
	// F10 generic body discipline: do not leak the reason.
	if body["error"] != "write permission required" {
		t.Errorf("error body = %q, want generic", body["error"])
	}
}

func TestEvidencePackHandler_Build_InvalidProjectID(t *testing.T) {
	h := newEvidencePackTestHandler(t,
		&fakeVEXDraftReader{}, &fakeCRAReportReader{}, &fakeProjectReaderHandler{project: &model.Project{Name: "p"}})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("not-a-uuid")
	installTenantContext(c, uuid.New(), uuid.New(), model.RoleAdmin)

	_ = h.Build(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestEvidencePackHandler_Build_UnsupportedFormat(t *testing.T) {
	projectID := uuid.New()
	h := newEvidencePackTestHandler(t,
		&fakeVEXDraftReader{}, &fakeCRAReportReader{}, &fakeProjectReaderHandler{project: &model.Project{ID: projectID, Name: "p"}})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{"format":"pdf"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	installTenantContext(c, uuid.New(), uuid.New(), model.RoleAdmin)

	_ = h.Build(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unsupported format") {
		t.Errorf("body missing unsupported-format hint: %q", rec.Body.String())
	}
}

func TestEvidencePackHandler_Build_ProjectNotFound_Generic404(t *testing.T) {
	// Builder propagates sql.ErrNoRows when the project reader returns
	// it; the handler folds that into a generic 404 body (#F10).
	projectID := uuid.New()
	h := newEvidencePackTestHandler(t,
		&fakeVEXDraftReader{}, &fakeCRAReportReader{}, &fakeProjectReaderHandler{err: errProjectMissingForTest()})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	installTenantContext(c, uuid.New(), uuid.New(), model.RoleAdmin)

	_ = h.Build(c)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "project not found" {
		t.Errorf("error body = %q, want generic project-not-found", body["error"])
	}
}

// errProjectMissingForTest returns a wrapped sql.ErrNoRows so the
// builder propagates it and the handler can fold to 404.
func errProjectMissingForTest() error {
	return fmt.Errorf("evidence_pack.Build: resolve project: %w", sql.ErrNoRows)
}
