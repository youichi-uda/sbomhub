package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/evidence_pack"
)

// fakeHandlerVEXExporter injects deterministic CycloneDX VEX bytes into
// the zip builder for the handler-level zip tests.
type fakeHandlerVEXExporter struct {
	data []byte
}

func (f *fakeHandlerVEXExporter) ExportCycloneDXVEX(_ context.Context, _ uuid.UUID) ([]byte, error) {
	return f.data, nil
}

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
	// METI reader/catalog are nil in the handler test wiring — the
	// handler's IncludeMETIAssessment default is true but the wire-
	// level tests below pass `{"include_meti_assessment": false}` (or
	// the legacy `include_meti_placeholder`) so the builder never
	// reaches the nil meti/catalog branch. The dedicated builder test
	// (evidence_pack/builder_test.go) exercises the live METI section.
	builder := evidence_pack.NewBuilder(vex, cra, proj, nil, nil)
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
	// M3-6 (#42): opt out of the METI section here because this
	// handler-level test wires the builder with a nil METI reader
	// (see newEvidencePackTestHandler). The dedicated builder test
	// exercises the live METI section.
	body := bytes.NewBufferString(`{"include_meti_assessment": false}`)
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

// TestEvidencePackHandler_Build_Zip pins the F405 / M31 (#140) zip
// render path: application/zip content type, the zip-specific
// Content-Disposition + X-Evidence-Pack-Format header, the preserved
// VEX/CRA count headers, and a well-formed zip body carrying the core
// entries.
func TestEvidencePackHandler_Build_Zip(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	vex := &fakeVEXDraftReader{rows: []repository.VEXDraft{}}
	cra := &fakeCRAReportReader{rows: []repository.CRAReport{}}
	proj := &fakeProjectReaderHandler{project: &model.Project{ID: projectID, Name: "demo"}}
	builder := evidence_pack.NewBuilder(vex, cra, proj, nil, nil).
		WithVEXExporter(&fakeHandlerVEXExporter{data: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)})
	h := NewEvidencePackHandler(builder, nil)

	e := echo.New()
	// Opt out of METI (builder wired with nil meti reader/catalog).
	body := bytes.NewBufferString(`{"format":"zip","include_meti_assessment":false}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectID.String()+"/evidence-pack/build", body)
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
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", ct)
	}
	if f := rec.Header().Get("X-Evidence-Pack-Format"); f != "zip" {
		t.Errorf("X-Evidence-Pack-Format = %q, want zip", f)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment;") || !strings.Contains(cd, ".zip") {
		t.Errorf("Content-Disposition = %q, want attachment;*.zip", cd)
	}
	if rec.Header().Get("X-Evidence-Pack-VEX-Count") != "0" {
		t.Errorf("X-Evidence-Pack-VEX-Count = %q, want 0", rec.Header().Get("X-Evidence-Pack-VEX-Count"))
	}
	if rec.Header().Get("X-Evidence-Pack-CRA-Count") != "0" {
		t.Errorf("X-Evidence-Pack-CRA-Count = %q, want 0", rec.Header().Get("X-Evidence-Pack-CRA-Count"))
	}

	// Body must be a well-formed zip carrying report.md, vex.cdx.json,
	// and manifest.json.
	raw := rec.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("response body is not a zip: %v", err)
	}
	present := map[string]bool{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
		present[f.Name] = true
	}
	for _, want := range []string{"report.md", "vex.cdx.json", "manifest.json"} {
		if !present[want] {
			t.Errorf("zip missing entry %q (have %v)", want, present)
		}
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

// ----------------------------------------------------------------------------
// F236 (M15-4 fix, anti-pattern 53 dual-path audit resolution) pins.
// ----------------------------------------------------------------------------

// captureStringArgMatcher is a sqlmock argument matcher that records the
// matched driver.Value as a string into target — used by the F236 pin
// below to assert the exact audit_logs.action column value the handler
// wrote, without paying a Postgres round-trip.
type captureStringArgMatcher struct {
	target *string
}

func (m captureStringArgMatcher) Match(v driver.Value) bool {
	switch s := v.(type) {
	case string:
		*m.target = s
		return true
	case []byte:
		*m.target = string(s)
		return true
	}
	return false
}

// TestEvidencePackHandler_Build_HappyPath_EmitsSingleAuditRow_F236 pins
// the M15-4 dual-path audit resolution from the HANDLER side. It drives
// EvidencePackHandler.Build against a sqlmock-backed AuditRepository on
// the happy path and asserts:
//
//  1. Exactly ONE INSERT into audit_logs is issued by the handler
//     during the request (pre-F236 the handler + middleware BOTH wrote
//     a row for the same request, producing two rows; F236 skips the
//     middleware for the /evidence-pack family so only the handler
//     writes). This test does NOT wire the middleware — the middleware-
//     side skip is pinned separately by
//     TestDetermineActionAndResource_EvidencePackSkipped_F236 in
//     middleware/audit_test.go. The single-row pin here catches the
//     inverse regression: a future refactor that also removed the
//     handler audit_pair would leave zero rows behind (silent
//     forensic-log gap for evidence pack builds).
//
//  2. The action column is "evidence_pack.built" (dotted). Pre-F236 the
//     handler emitted "evidence_pack_built" (underscore) via a local
//     handler constant AuditActionEvidencePackBuilt while the
//     middleware emitted "evidence_pack.built" via
//     model.ActionEvidencePackBuilt — two rows, two different action
//     strings, forensic GROUP BY queries had to alias both. F236
//     removes the local underscore constant and points the handler at
//     model.ActionEvidencePackBuilt so the dotted form is the ONLY
//     string emitted for evidence pack builds going forward.
//
// This is the anti-pattern 53 (middleware-vs-handler audit dual-path)
// closure meta-test on the handler side; the middleware-side closure
// lives in TestDetermineActionAndResource_EvidencePackSkipped_F236.
// Together they pin the invariant "evidence pack build produces
// exactly one audit row, action=evidence_pack.built" end-to-end.
func TestEvidencePackHandler_Build_HappyPath_EmitsSingleAuditRow_F236(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	var capturedAction string
	// The handler ultimately calls AuditRepository.Log which wraps
	// Create with `INSERT INTO audit_logs (...) VALUES ($1..$10)` (see
	// repository/audit.go). Column order: id, tenant_id, user_id,
	// action, resource_type, resource_id, details, ip_address,
	// user_agent, created_at. We capture arg #4 (action) with the
	// string matcher and accept anything for the other columns —
	// details map contents are exercised by other suites.
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // tenant_id
			sqlmock.AnyArg(), // user_id
			captureStringArgMatcher{target: &capturedAction}, // action
			sqlmock.AnyArg(), // resource_type
			sqlmock.AnyArg(), // resource_id
			sqlmock.AnyArg(), // details (JSON)
			sqlmock.AnyArg(), // ip_address
			sqlmock.AnyArg(), // user_agent
			sqlmock.AnyArg(), // created_at
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	auditRepo := repository.NewAuditRepository(db)

	tenantID := uuid.New()
	projectID := uuid.New()

	vex := &fakeVEXDraftReader{rows: []repository.VEXDraft{}}
	cra := &fakeCRAReportReader{rows: []repository.CRAReport{}}
	proj := &fakeProjectReaderHandler{project: &model.Project{
		ID:   projectID,
		Name: "demo",
	}}
	builder := evidence_pack.NewBuilder(vex, cra, proj, nil, nil)
	h := NewEvidencePackHandler(builder, auditRepo)

	e := echo.New()
	// Opt out of the METI section — the builder wiring here uses a nil
	// METI reader (mirrors newEvidencePackTestHandler above).
	body := bytes.NewBufferString(`{"include_meti_assessment": false}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectID.String()+"/evidence-pack/build", body)
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

	// Assertion 1: exactly one audit INSERT was issued. sqlmock's
	// ExpectationsWereMet returns an error if the ExpectExec above was
	// NOT consumed (handler forgot to write) OR if a SECOND
	// unmatched INSERT was issued (double-audit regression — the whole
	// point of F236 is that the middleware no longer double-writes for
	// this endpoint, but the handler still MUST write exactly one row).
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("F236 regression: unmet or exceeded sqlmock expectations: %v — "+
			"the handler must write exactly ONE audit_logs INSERT for a "+
			"successful evidence_pack build (pre-F236 the middleware + "+
			"handler each wrote one row, producing two)", err)
	}

	// Assertion 2: the action column is the dotted form. Pre-F236 the
	// handler emitted "evidence_pack_built" (underscore, via a local
	// constant AuditActionEvidencePackBuilt now removed). F236 unifies
	// on model.ActionEvidencePackBuilt = "evidence_pack.built".
	if capturedAction != model.ActionEvidencePackBuilt {
		t.Errorf("F236 regression: audit_logs.action = %q, want %q "+
			"(unified dotted form; the underscore local constant "+
			"AuditActionEvidencePackBuilt was removed in M15-4)",
			capturedAction, model.ActionEvidencePackBuilt)
	}
	if capturedAction != "evidence_pack.built" {
		t.Errorf("F236 regression: audit_logs.action = %q, want literal "+
			"\"evidence_pack.built\" — the dotted form must survive any "+
			"future rename of model.ActionEvidencePackBuilt (operator "+
			"forensic queries and the docs/operations migration note both "+
			"reference the literal string)", capturedAction)
	}
}
