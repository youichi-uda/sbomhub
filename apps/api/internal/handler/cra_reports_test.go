package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/cra"
)

// ----------------------------------------------------------------------------
// Handler-level fakes for cra.Runner / repository.CRAReportsRepository /
// repository.AuditRepository. The handler is wired against narrow
// interfaces (see cra_reports.go) so the runner does not need to fan out
// to a real LLM provider for these regression tests.
// ----------------------------------------------------------------------------

type fakeCRARunner struct {
	mu       sync.Mutex
	captured []cra.RunInput
	result   *cra.RunResult
	err      error
}

func (f *fakeCRARunner) Run(_ context.Context, in cra.RunInput) (*cra.RunResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captured = append(f.captured, in)
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		// Stamp the runner's view of (project, vuln, cve, type, lang)
		// back onto the report so the response shape mirrors production
		// behaviour even with a fake.
		if f.result.Report == nil {
			f.result.Report = &repository.CRAReport{}
		}
		f.result.Report.TenantID = in.TenantID
		f.result.Report.ProjectID = in.ProjectID
		f.result.Report.VulnerabilityID = in.VulnerabilityID
		f.result.Report.CVEID = in.CVEID
		f.result.Report.ReportType = string(in.ReportType)
		f.result.Report.Lang = string(in.Lang)
	}
	return f.result, nil
}

type fakeCRAReportStore struct {
	mu sync.Mutex

	byID            map[uuid.UUID]repository.CRAReport
	byProject       map[uuid.UUID][]repository.CRAReport
	getErr          error
	listErr         error
	countErr        error
	updateErr       error
	updateCalls     int
	lastListFilter  repository.CRAReportListFilter
	listCalled      bool
	lastCountFilter repository.CRAReportListFilter
	countCalled     bool
}

func (f *fakeCRAReportStore) Get(_ context.Context, tenantID, id uuid.UUID) (*repository.CRAReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	r, ok := f.byID[id]
	if !ok {
		return nil, nil
	}
	if r.TenantID != tenantID {
		return nil, nil
	}
	dup := r
	return &dup, nil
}

func (f *fakeCRAReportStore) ListByProject(_ context.Context, tenantID, projectID uuid.UUID, filter repository.CRAReportListFilter) ([]repository.CRAReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalled = true
	f.lastListFilter = filter
	if f.listErr != nil {
		return nil, f.listErr
	}
	rows := f.byProject[projectID]
	out := make([]repository.CRAReport, 0)
	for _, r := range rows {
		if r.TenantID != tenantID {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeCRAReportStore) CountByProject(_ context.Context, tenantID, projectID uuid.UUID, filter repository.CRAReportListFilter) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.countCalled = true
	f.lastCountFilter = filter
	if f.countErr != nil {
		return 0, f.countErr
	}
	rows := f.byProject[projectID]
	n := 0
	for _, r := range rows {
		if r.TenantID == tenantID {
			n++
		}
	}
	return n, nil
}

func (f *fakeCRAReportStore) UpdateDecision(_ context.Context, tenantID, id uuid.UUID, upd repository.CRAReportDecisionUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateCalls++
	if f.updateErr != nil {
		return f.updateErr
	}
	r, ok := f.byID[id]
	if !ok || r.TenantID != tenantID {
		return errors.New("not found")
	}
	r.Decision = upd.Decision
	r.DecisionBy = &upd.DecisionBy
	now := time.Now().UTC()
	r.DecisionAt = &now
	r.DecisionNote = upd.DecisionNote
	if upd.EditedDraftText != nil {
		r.DraftText = *upd.EditedDraftText
	}
	r.UpdatedAt = now
	f.byID[id] = r
	return nil
}

type fakeCRAAudit struct {
	mu      sync.Mutex
	entries []model.CreateAuditLogInput
	err     error
}

func (f *fakeCRAAudit) Log(_ context.Context, input *model.CreateAuditLogInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, *input)
	return f.err
}

// fakeCRASubmissions implements craSubmissionEarliestReader (M34-B /
// F424). `earliest` is the controllable report-id → earliest
// submitted_at map; ids absent from it are treated as "not submitted"
// exactly like the real repository (they are simply omitted from the
// returned map). `err` forces the non-fatal degradation path.
type fakeCRASubmissions struct {
	mu       sync.Mutex
	earliest map[uuid.UUID]time.Time
	err      error
	called   bool
	lastIDs  []uuid.UUID
}

func (f *fakeCRASubmissions) EarliestSubmittedAtByReports(_ context.Context, _ uuid.UUID, reportIDs []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = true
	f.lastIDs = append([]uuid.UUID(nil), reportIDs...)
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[uuid.UUID]time.Time, len(reportIDs))
	for _, id := range reportIDs {
		if t, ok := f.earliest[id]; ok {
			out[id] = t
		}
	}
	return out, nil
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

type craHarness struct {
	runner      *fakeCRARunner
	store       *fakeCRAReportStore
	audit       *fakeCRAAudit
	submissions *fakeCRASubmissions
	handler     *CRAReportsHandler
	tenantID    uuid.UUID
	projectID   uuid.UUID
	userID      uuid.UUID
}

func newCRAHarness() *craHarness {
	tenantID := uuid.New()
	projectID := uuid.New()
	userID := uuid.New()
	runner := &fakeCRARunner{
		result: &cra.RunResult{
			Report: &repository.CRAReport{
				ID:       uuid.New(),
				Decision: "pending",
				State:    "draft",
				Evidence: json.RawMessage(`[{"kind":"vex_draft"}]`),
			},
		},
	}
	store := &fakeCRAReportStore{
		byID:      make(map[uuid.UUID]repository.CRAReport),
		byProject: make(map[uuid.UUID][]repository.CRAReport),
	}
	audit := &fakeCRAAudit{}
	submissions := &fakeCRASubmissions{earliest: make(map[uuid.UUID]time.Time)}
	h := NewCRAReportsHandler(runner, store, audit, submissions)
	return &craHarness{
		runner:      runner,
		store:       store,
		audit:       audit,
		submissions: submissions,
		handler:     h,
		tenantID:    tenantID,
		projectID:   projectID,
		userID:      userID,
	}
}

func (h *craHarness) seedReport(reportID, projectID uuid.UUID) repository.CRAReport {
	r := repository.CRAReport{
		ID:              reportID,
		TenantID:        h.tenantID,
		ProjectID:       projectID,
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2026-3100",
		ReportType:      "early_warning",
		Lang:            "ja",
		State:           "draft",
		DraftText:       "draft body",
		Decision:        "pending",
		Evidence:        json.RawMessage(`[{"kind":"vex_draft"}]`),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	h.store.byID[reportID] = r
	h.store.byProject[projectID] = append(h.store.byProject[projectID], r)
	return r
}

// seedReportWith seeds a report with a caller-controlled report_type and
// awareness instant so the F424 deadline-enrichment tests can drive each
// DeadlineStatus branch (M34-B). awareness == nil exercises the
// not_applicable path.
func (h *craHarness) seedReportWith(reportID, projectID uuid.UUID, reportType string, awareness *time.Time) repository.CRAReport {
	r := repository.CRAReport{
		ID:              reportID,
		TenantID:        h.tenantID,
		ProjectID:       projectID,
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2026-3100",
		ReportType:      reportType,
		Lang:            "ja",
		State:           "draft",
		DraftText:       "draft body",
		Decision:        "pending",
		Evidence:        json.RawMessage(`[{"kind":"vex_draft"}]`),
		AwarenessTime:   awareness,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	h.store.byID[reportID] = r
	h.store.byProject[projectID] = append(h.store.byProject[projectID], r)
	return r
}

func (h *craHarness) ctxWithRole(c echo.Context, role string) {
	c.Set(middleware.ContextKeyTenantID, h.tenantID)
	c.Set(middleware.ContextKeyUserID, h.userID)
	c.Set(middleware.ContextKeyRole, role)
}

func runReportRequestBody(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"vulnerability_id": uuid.NewString(),
		"cve_id":           "CVE-2026-3100",
		"report_type":      "early_warning",
		"lang":             "ja",
		"product_name":     "AcmeRouter",
		"reporter_name":    "Taro Yamada",
		"contact_email":    "psirt@example.com",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(body)
}

// ----------------------------------------------------------------------------
// Happy paths
// ----------------------------------------------------------------------------

func TestCRAReportsHandler_RunReport_HappyPath(t *testing.T) {
	h := newCRAHarness()

	body := runReportRequestBody(t)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("RunReport status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if got := len(h.runner.captured); got != 1 {
		t.Fatalf("expected 1 runner.Run call, got %d", got)
	}
	in := h.runner.captured[0]
	if in.TenantID != h.tenantID || in.ProjectID != h.projectID {
		t.Errorf("RunInput tenant/project mismatch: got %v/%v", in.TenantID, in.ProjectID)
	}
	if in.ReportType != cra.ReportTypeEarlyWarning {
		t.Errorf("RunInput.ReportType = %q, want %q", in.ReportType, cra.ReportTypeEarlyWarning)
	}
	if in.Lang != cra.LangJA {
		t.Errorf("RunInput.Lang = %q, want %q", in.Lang, cra.LangJA)
	}
}

func TestCRAReportsHandler_ListReports_HappyPath_EmitsXTotalCount_F28(t *testing.T) {
	h := newCRAHarness()
	// Seed 3 reports for the project.
	for i := 0; i < 3; i++ {
		h.seedReport(uuid.New(), h.projectID)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListReports(c); err != nil {
		t.Fatalf("ListReports returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("ListReports status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	got := rec.Header().Get("X-Total-Count")
	if got != "3" {
		t.Errorf("X-Total-Count = %q, want %q", got, "3")
	}
	if !h.store.countCalled {
		t.Errorf("CountByProject should be invoked for X-Total-Count")
	}
}

func TestCRAReportsHandler_GetReport_HappyPath(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	h.seedReport(rid, h.projectID)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.GetReport(c); err != nil {
		t.Fatalf("GetReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("GetReport status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCRAReportsHandler_Decide_HappyPath_EmitsDecidedAudit(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	h.seedReport(rid, h.projectID)

	body, _ := json.Marshal(map[string]string{"decision": "approved"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/decision",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Decide status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.updateCalls != 1 {
		t.Errorf("UpdateDecision call count = %d, want 1", h.store.updateCalls)
	}
	if got := len(h.audit.entries); got != 1 {
		t.Fatalf("expected 1 cra_report_decided audit entry, got %d", got)
	}
	if h.audit.entries[0].Action != model.AuditActionCRAReportDecided {
		t.Errorf("audit action = %q, want %q", h.audit.entries[0].Action, model.AuditActionCRAReportDecided)
	}
}

func TestCRAReportsHandler_Reanalyse_HappyPath_RerunsRunner(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	src := h.seedReport(rid, h.projectID)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/reanalyse",
		strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Reanalyse(c); err != nil {
		t.Fatalf("Reanalyse returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("Reanalyse status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if got := len(h.runner.captured); got != 1 {
		t.Fatalf("expected 1 runner.Run call, got %d", got)
	}
	in := h.runner.captured[0]
	if in.CVEID != src.CVEID {
		t.Errorf("Reanalyse CVEID = %q, want %q (default from source)", in.CVEID, src.CVEID)
	}
	if in.ReportType != cra.ReportType(src.ReportType) {
		t.Errorf("Reanalyse ReportType = %q, want %q", in.ReportType, src.ReportType)
	}
}

// TestCRAReportsHandler_Reanalyse_InheritsSourceAwareness_F427 pins the
// F427 fix (Codex 20th unique catch): reanalysing a report with an empty
// body must inherit the source report's awareness_time into the new run so
// the Art.14 deadline clock survives. Pre-fix the new row got NULL
// awareness and its deadline collapsed to not_applicable.
func TestCRAReportsHandler_Reanalyse_InheritsSourceAwareness_F427(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	awareness := time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)
	h.seedReportWith(rid, h.projectID, string(cra.ReportTypeEarlyWarning), &awareness)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/reanalyse",
		strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Reanalyse(c); err != nil {
		t.Fatalf("Reanalyse returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("Reanalyse status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if len(h.runner.captured) != 1 {
		t.Fatalf("expected 1 runner.Run call, got %d", len(h.runner.captured))
	}
	want := awareness.Format(time.RFC3339)
	if got := h.runner.captured[0].AwarenessTime; got != want {
		t.Errorf("F427: Reanalyse must inherit source awareness_time = %q, got %q", want, got)
	}
}

// TestCRAReportsHandler_Reanalyse_MalformedAwareness_Returns400_F427 pins
// that a mistyped awareness_time OVERRIDE on Reanalyse is a clean 400
// (Reanalyse bypasses buildRunInput), not a 500 surfaced from the runner
// parse, and that it rejects before the runner runs.
func TestCRAReportsHandler_Reanalyse_MalformedAwareness_Returns400_F427(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	h.seedReport(rid, h.projectID)

	body, _ := json.Marshal(map[string]string{"awareness_time": "not-a-timestamp"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/reanalyse",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Reanalyse(c); err != nil {
		t.Fatalf("Reanalyse returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F427: malformed reanalyse awareness_time status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if len(h.runner.captured) != 0 {
		t.Errorf("F427: malformed awareness must reject before the runner, got %d Run calls", len(h.runner.captured))
	}
}

// ----------------------------------------------------------------------------
// F8/F9 — cross-project access must 404 (every report-id endpoint)
// ----------------------------------------------------------------------------

func TestCRAReportsHandler_GetReport_CrossProject_Returns404(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	otherProject := uuid.New()
	h.seedReport(rid, otherProject) // report in a DIFFERENT project

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.GetReport(c); err != nil {
		t.Fatalf("GetReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-project GET status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	// Body MUST NOT leak the foreign project id or any internal hint.
	if strings.Contains(rec.Body.String(), otherProject.String()) {
		t.Errorf("404 body must not leak foreign project_id: %s", rec.Body.String())
	}
}

func TestCRAReportsHandler_Decide_CrossProject_Returns404_NoUpdate(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	otherProject := uuid.New()
	h.seedReport(rid, otherProject)

	body, _ := json.Marshal(map[string]string{"decision": "approved"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/decision",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-project decide status = %d, want 404", rec.Code)
	}
	if h.store.updateCalls != 0 {
		t.Errorf("cross-project decide must NOT call UpdateDecision, got %d", h.store.updateCalls)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("cross-project decide must NOT emit audit row, got %d", len(h.audit.entries))
	}
}

func TestCRAReportsHandler_Reanalyse_CrossProject_Returns404_NoRun(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	otherProject := uuid.New()
	h.seedReport(rid, otherProject)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/reanalyse",
		strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Reanalyse(c); err != nil {
		t.Fatalf("Reanalyse returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-project reanalyse status = %d, want 404", rec.Code)
	}
	if len(h.runner.captured) != 0 {
		t.Errorf("cross-project reanalyse must NOT call runner.Run, got %d calls", len(h.runner.captured))
	}
}

// ----------------------------------------------------------------------------
// F15 — read-only API key cannot drive write endpoints
// ----------------------------------------------------------------------------

func TestCRAReportsHandler_RunReport_ReadOnly_Returns403(t *testing.T) {
	h := newCRAHarness()
	body := runReportRequestBody(t)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F15: read-only RunReport status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if len(h.runner.captured) != 0 {
		t.Errorf("F15: runner.Run must not be called for read-only role")
	}
}

func TestCRAReportsHandler_Decide_ReadOnly_Returns403(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	h.seedReport(rid, h.projectID)
	body, _ := json.Marshal(map[string]string{"decision": "approved"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/decision",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F15: read-only Decide status = %d, want 403", rec.Code)
	}
	if h.store.updateCalls != 0 {
		t.Errorf("F15: UpdateDecision must not run for read-only role")
	}
}

func TestCRAReportsHandler_Reanalyse_ReadOnly_Returns403(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	h.seedReport(rid, h.projectID)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/reanalyse",
		strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.Reanalyse(c); err != nil {
		t.Fatalf("Reanalyse returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F15: read-only Reanalyse status = %d, want 403", rec.Code)
	}
	if len(h.runner.captured) != 0 {
		t.Errorf("F15: runner.Run must not be called for read-only role")
	}
}

// ----------------------------------------------------------------------------
// F24 / F27 — pagination clamp + offset cap
// ----------------------------------------------------------------------------

func TestCRAReportsHandler_ListReports_LimitOverflow_Returns400_F24(t *testing.T) {
	h := newCRAHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports?limit=2147483647", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListReports(c); err != nil {
		t.Fatalf("ListReports returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F24: limit overflow status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "limit exceeds maximum") {
		t.Errorf("F24: body should mention 'limit exceeds maximum', got %s", rec.Body.String())
	}
	if h.store.listCalled {
		t.Errorf("F24: ListByProject must NOT run when limit is rejected")
	}
}

func TestCRAReportsHandler_ListReports_OffsetOverflow_Returns400_F27(t *testing.T) {
	h := newCRAHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports?offset=2147483647", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListReports(c); err != nil {
		t.Fatalf("ListReports returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F27: offset overflow status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "offset exceeds maximum") {
		t.Errorf("F27: body should mention 'offset exceeds maximum', got %s", rec.Body.String())
	}
	if h.store.listCalled {
		t.Errorf("F27: ListByProject must NOT run when offset is rejected")
	}
}

func TestCRAReportsHandler_ListReports_LimitAtBoundary_Passes(t *testing.T) {
	h := newCRAHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports?limit="+strconv.Itoa(MaxCRAReportsListLimit), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListReports(c); err != nil {
		t.Fatalf("ListReports returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("F24: limit=%d (boundary) status = %d, want 200", MaxCRAReportsListLimit, rec.Code)
	}
	if h.store.lastListFilter.Limit != MaxCRAReportsListLimit {
		t.Errorf("F24: filter.Limit at boundary = %d, want %d",
			h.store.lastListFilter.Limit, MaxCRAReportsListLimit)
	}
}

// ----------------------------------------------------------------------------
// F12 — CVE id mismatch maps to generic 400
// ----------------------------------------------------------------------------

func TestCRAReportsHandler_RunReport_ErrCVEIDMismatch_Maps400(t *testing.T) {
	h := newCRAHarness()
	h.runner.err = cra.ErrCVEIDMismatch

	body := runReportRequestBody(t)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F12: ErrCVEIDMismatch status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	// Body must NOT leak the sentinel message verbatim.
	if strings.Contains(rec.Body.String(), "cve_id does not match vulnerability_id") {
		t.Errorf("F12: 400 body must be generic; got %s", rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// Cross-project source vex_draft sentinel → 404 (M2-3 carry-over)
// ----------------------------------------------------------------------------

func TestCRAReportsHandler_RunReport_ErrSourceVEXDraftCrossProject_Maps404(t *testing.T) {
	h := newCRAHarness()
	h.runner.err = cra.ErrSourceVEXDraftCrossProject

	body := runReportRequestBody(t)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ErrSourceVEXDraftCrossProject status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	// Body must be generic — same shape as ErrSourceVEXDraftNotFound.
	if strings.Contains(rec.Body.String(), "does not belong to the target project") {
		t.Errorf("F10 carry-over: 404 body must be generic; got %s", rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// ErrNoApprovedVEXDraft → 409 (M2-3 recommendation)
// ----------------------------------------------------------------------------

func TestCRAReportsHandler_RunReport_ErrNoApprovedVEXDraft_Maps409(t *testing.T) {
	h := newCRAHarness()
	h.runner.err = cra.ErrNoApprovedVEXDraft

	body := runReportRequestBody(t)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("ErrNoApprovedVEXDraft status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no approved vex_draft") {
		t.Errorf("409 body should include actionable hint, got %s", rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// M2 Codex review #F30 — source vex_draft cve mismatch maps to 409
// ----------------------------------------------------------------------------

// TestCRAReportsHandler_RunReport_VEXDraftCVEMismatch_Returns409_F30
// pins the handler's mapping of the new sentinel
// cra.ErrSourceVEXDraftCVEMismatch to a 409 Conflict with an
// actionable hint in the body. The previous warn-only behaviour
// silently rendered a CRA report whose attached VEX draft covered a
// different CVE than the report's target — the F30 fix turns this
// into a hard reject at the runner layer (see runner_test.go), and
// this handler test ensures the sentinel propagates to the right
// status code so the UI / CLI can surface "attach a VEX draft for
// the correct CVE" rather than a generic 500.
func TestCRAReportsHandler_RunReport_VEXDraftCVEMismatch_Returns409_F30(t *testing.T) {
	h := newCRAHarness()
	h.runner.err = cra.ErrSourceVEXDraftCVEMismatch

	body := runReportRequestBody(t)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("F30: ErrSourceVEXDraftCVEMismatch status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "vex_draft cve_id does not match") {
		t.Errorf("F30: 409 body should surface actionable hint, got %s", rec.Body.String())
	}
	// Defensive: response body MUST NOT echo the sentinel verbatim
	// (which would leak the foreign draft's CVE id once the runner
	// wraps the error with provider-side details).
	if strings.Contains(rec.Body.String(), "cra: source vex_draft") {
		t.Errorf("F30: 409 body must be generic, not leak sentinel verbatim: %s", rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// M2 Codex review #F31 — re-decide on an already-decided report → 409
// ----------------------------------------------------------------------------

// TestCRAReportsHandler_Decide_AlreadyDecided_Returns409_F31 pins the
// state-machine guard at the handler layer: when loadReportScoped
// returns a report whose decision is NOT 'pending' (already approved
// / edited / rejected), the handler must reject with 409 BEFORE
// calling UpdateDecision and BEFORE emitting an audit row. Without
// this guard, a follow-up decision='edited' on an already-approved
// report would silently rewrite the approved draft_text (the AI
// evidence trail).
func TestCRAReportsHandler_Decide_AlreadyDecided_Returns409_F31(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	seeded := h.seedReport(rid, h.projectID)
	// Flip the seeded report into the 'approved' terminal state so the
	// state-machine guard in Decide trips.
	seeded.Decision = "approved"
	h.store.byID[rid] = seeded

	body, _ := json.Marshal(map[string]string{"decision": "edited"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/decision",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("F31: already-decided Decide status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already been decided") {
		t.Errorf("F31: 409 body should mention 'already been decided', got %s", rec.Body.String())
	}
	if h.store.updateCalls != 0 {
		t.Errorf("F31: UpdateDecision MUST NOT run when report is already decided, got %d", h.store.updateCalls)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F31: audit row MUST NOT be emitted when re-decision is rejected, got %d", len(h.audit.entries))
	}
}

// TestCRAReportsHandler_Decide_AlreadyDecided_TOCTOU_Returns409_F31
// pins the secondary path for F31: the report was 'pending' at
// loadReportScoped step but became non-pending between then and the
// UpdateDecision call (a concurrent request decided it). The
// repository's `decision = 'pending'` guard then returns sql.ErrNoRows,
// and the handler must translate this into a consistent 409 rather
// than the bare 500 that the pre-F31 code would have produced.
func TestCRAReportsHandler_Decide_AlreadyDecided_TOCTOU_Returns409_F31(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	h.seedReport(rid, h.projectID) // loaded report sees Decision = "pending"
	// Simulate the race: by the time UpdateDecision runs in the
	// repository layer, a concurrent decision has already landed, so
	// the WHERE-with-pending matches zero rows and the repo returns
	// wrapped sql.ErrNoRows.
	h.store.updateErr = fmt.Errorf("update cra_reports decision: %w", sql.ErrNoRows)

	body, _ := json.Marshal(map[string]string{"decision": "approved"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/decision",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("F31 (TOCTOU): status = %d, want 409 on repo ErrNoRows; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already been decided") {
		t.Errorf("F31 (TOCTOU): 409 body should mention 'already been decided', got %s", rec.Body.String())
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F31 (TOCTOU): audit row MUST NOT land when UPDATE rejected, got %d", len(h.audit.entries))
	}
}

// ----------------------------------------------------------------------------
// M2 Codex review #F32 — Decide audit failure must hard-fail (500) so
// the ambient TenantTx middleware rolls back the UpdateDecision row
// ----------------------------------------------------------------------------

// TestCRAReportsHandler_Decide_AuditFailure_RollsBack_F32 pins the
// audit-or-nothing contract for CRA decisions. The pre-F32 code did
// `slog.Warn` on audit failure and returned 200 with the fresh report
// — that meant an approved / edited / rejected CRA report could
// commit without its mandatory CRA Article 14 audit trail. The fix
// returns 500 so TenantTx (cmd/server/main.go wraps this route in
// TenantTx) rolls back the UpdateDecision UPDATE. The handler-level
// test cannot observe the actual DB rollback (the fake CRAReportStore
// has no tx semantics), so we pin the necessary precondition for
// rollback: the 500 status code. The TenantTx rollback behaviour is
// pinned separately in middleware/tx_test.go.
func TestCRAReportsHandler_Decide_AuditFailure_RollsBack_F32(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	h.seedReport(rid, h.projectID)
	// Force domain audit failure.
	h.audit.err = errors.New("audit storm — F32 regression scenario")

	body, _ := json.Marshal(map[string]string{"decision": "approved"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/decision",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("F32: audit failure status = %d, want 500 (so TenantTx rolls back); body=%s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "audit trail") {
		t.Errorf("F32: 500 body should mention audit trail; got %s", rec.Body.String())
	}
	// UpdateDecision was called (the fake committed it in-memory) BUT
	// the 500 status above is exactly what TenantTx needs to roll back
	// the real DB write — in production the cra_reports row never
	// commits. Audit row MUST also be attempted exactly once.
	if h.store.updateCalls != 1 {
		t.Errorf("F32: UpdateDecision call count = %d, want 1 (audit runs AFTER)", h.store.updateCalls)
	}
	if got := len(h.audit.entries); got != 1 {
		t.Errorf("F32: audit.Log should be attempted once (it then fails), got %d entries", got)
	}
}

// ----------------------------------------------------------------------------
// No auth context → 401 (defensive)
// ----------------------------------------------------------------------------

func TestCRAReportsHandler_NoAuth_Returns401(t *testing.T) {
	h := newCRAHarness()
	body := runReportRequestBody(t)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	// Intentionally do not set any auth context.

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth RunReport status = %d, want 401", rec.Code)
	}
}

// ----------------------------------------------------------------------------
// F208 / M14-1 — audit_resource_id context-key contract
// ----------------------------------------------------------------------------

// TestCRAReportsHandler_RunReport_SetsAuditResourceID_F208 pins that
// after a successful RunReport, the handler publishes the newly-minted
// cra_report UUID via middleware.SetAuditResourceID so the audit
// middleware records audit_logs.resource_id = report.ID instead of the
// parent project UUID. Without this Set the priority-list path would
// pick up :id (project) and forensic joins to cra_reports would
// silently drop (the original F190 limitation closed by F208).
func TestCRAReportsHandler_RunReport_SetsAuditResourceID_F208(t *testing.T) {
	h := newCRAHarness()
	wantReportID := uuid.New()
	h.runner.result = &cra.RunResult{
		Report: &repository.CRAReport{
			ID:       wantReportID,
			Decision: "pending",
			State:    "draft",
			Evidence: json.RawMessage(`[{"kind":"vex_draft"}]`),
		},
	}

	body := runReportRequestBody(t)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("RunReport status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	got, ok := c.Get(middleware.ContextKeyAuditResourceID).(uuid.UUID)
	if !ok {
		t.Fatalf("F208: context key %q must hold uuid.UUID after RunReport, got %T",
			middleware.ContextKeyAuditResourceID, c.Get(middleware.ContextKeyAuditResourceID))
	}
	if got != wantReportID {
		t.Errorf("F208: audit_resource_id = %s, want %s (new cra_report UUID, NOT parent project)",
			got, wantReportID)
	}
	if got == h.projectID {
		t.Fatalf("F208 regression: audit_resource_id = parent project UUID — F190 limitation back")
	}
}

// TestCRAReportsHandler_Reanalyse_SetsAuditResourceID_F208 pins that
// Reanalyse — which mints a FRESH cra_reports row preserving history —
// records the NEW row's UUID on the audit_resource_id context key,
// NOT the source :report_id from the URL. A walk of audit_logs ⨝
// cra_reports must line up "this AI re-judgement produced THIS new
// report row" rather than misattributing it to the source.
func TestCRAReportsHandler_Reanalyse_SetsAuditResourceID_F208(t *testing.T) {
	h := newCRAHarness()
	srcID := uuid.New()
	h.seedReport(srcID, h.projectID)

	newReportID := uuid.New()
	h.runner.result = &cra.RunResult{
		Report: &repository.CRAReport{
			ID:       newReportID,
			Decision: "pending",
			State:    "draft",
			Evidence: json.RawMessage(`[{"kind":"vex_draft"}]`),
		},
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+srcID.String()+"/reanalyse",
		strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), srcID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Reanalyse(c); err != nil {
		t.Fatalf("Reanalyse returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("Reanalyse status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	got, ok := c.Get(middleware.ContextKeyAuditResourceID).(uuid.UUID)
	if !ok {
		t.Fatalf("F208: context key %q must hold uuid.UUID after Reanalyse, got %T",
			middleware.ContextKeyAuditResourceID, c.Get(middleware.ContextKeyAuditResourceID))
	}
	if got != newReportID {
		t.Errorf("F208: audit_resource_id = %s, want %s (NEW cra_report UUID, NOT source)",
			got, newReportID)
	}
	if got == srcID {
		t.Fatalf("F208 regression: Reanalyse audit_resource_id = source :report_id "+
			"(history-preservation contract violated; new row %s would be unjoinable)", newReportID)
	}
}

// ----------------------------------------------------------------------------
// M34-B / F424 — read endpoints enrich with the derived Art.14 deadline
// ----------------------------------------------------------------------------

// deadlineEnvelope decodes the enriched ListReports body (the embedded
// *repository.CRAReport fields are promoted, so report_type /
// awareness_time sit alongside the derived deadline fields).
type deadlineEnvelope struct {
	Reports []deadlineReportView `json:"reports"`
}

type deadlineReportView struct {
	ID             uuid.UUID  `json:"id"`
	ReportType     string     `json:"report_type"`
	AwarenessTime  *time.Time `json:"awareness_time"`
	DeadlineStatus string     `json:"deadline_status"`
	DeadlineAt     *time.Time `json:"deadline_at"`
	SubmittedAt    *time.Time `json:"submitted_at"`
}

// TestCRAReportsHandler_ListReports_EnrichesDeadlineStatus_F424 seeds one
// report per DeadlineStatus and asserts the read endpoint computes each
// correctly from awareness_time + the batched earliest submission,
// including deadline_at / submitted_at presence. The submissions reader
// is invoked exactly once (batch, no N+1) with every page report id.
func TestCRAReportsHandler_ListReports_EnrichesDeadlineStatus_F424(t *testing.T) {
	h := newCRAHarness()
	now := time.Now().UTC()

	// early_warning window = 24h; detailed_notification window = 72h.
	awarenessRecent := now.Add(-2 * time.Hour) // deadline in the future
	awarenessOld := now.Add(-48 * time.Hour)   // deadline already passed (24h)
	submittedRecent := now.Add(-1 * time.Hour) // before the 24h deadline of awarenessRecent
	submittedLate := now.Add(-1 * time.Hour)   // after the 24h deadline of awarenessOld

	onTimeID := uuid.New()
	lateID := uuid.New()
	pendingID := uuid.New()
	overdueID := uuid.New()
	naNilID := uuid.New()
	naFinalID := uuid.New()

	// on_time: submitted before deadline.
	h.seedReportWith(onTimeID, h.projectID, string(cra.ReportTypeEarlyWarning), &awarenessRecent)
	h.submissions.earliest[onTimeID] = submittedRecent
	// late: submitted after deadline.
	h.seedReportWith(lateID, h.projectID, string(cra.ReportTypeEarlyWarning), &awarenessOld)
	h.submissions.earliest[lateID] = submittedLate
	// pending: not submitted, deadline in future.
	h.seedReportWith(pendingID, h.projectID, string(cra.ReportTypeEarlyWarning), &awarenessRecent)
	// overdue: not submitted, deadline passed.
	h.seedReportWith(overdueID, h.projectID, string(cra.ReportTypeEarlyWarning), &awarenessOld)
	// not_applicable: awareness nil.
	h.seedReportWith(naNilID, h.projectID, string(cra.ReportTypeEarlyWarning), nil)
	// not_applicable: final_report has no fixed clock even with awareness.
	h.seedReportWith(naFinalID, h.projectID, string(cra.ReportTypeFinalReport), &awarenessRecent)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListReports(c); err != nil {
		t.Fatalf("ListReports returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("ListReports status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !h.submissions.called {
		t.Fatalf("F424: EarliestSubmittedAtByReports must be invoked for enrichment")
	}
	if len(h.submissions.lastIDs) != 6 {
		t.Errorf("F424: batch lookup should carry all 6 page report ids (no N+1), got %d", len(h.submissions.lastIDs))
	}

	var env deadlineEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("F424: decode enriched body: %v; body=%s", err, rec.Body.String())
	}
	byID := make(map[uuid.UUID]deadlineReportView, len(env.Reports))
	for _, r := range env.Reports {
		byID[r.ID] = r
	}
	if len(byID) != 6 {
		t.Fatalf("F424: expected 6 enriched reports, got %d", len(byID))
	}

	// on_time.
	if v := byID[onTimeID]; v.DeadlineStatus != string(cra.DeadlineOnTime) {
		t.Errorf("F424: on_time report status = %q, want %q", v.DeadlineStatus, cra.DeadlineOnTime)
	} else {
		if v.DeadlineAt == nil || !v.DeadlineAt.Equal(awarenessRecent.Add(24*time.Hour)) {
			t.Errorf("F424: on_time deadline_at = %v, want %v", v.DeadlineAt, awarenessRecent.Add(24*time.Hour))
		}
		if v.SubmittedAt == nil || !v.SubmittedAt.Equal(submittedRecent) {
			t.Errorf("F424: on_time submitted_at = %v, want %v", v.SubmittedAt, submittedRecent)
		}
	}
	// late.
	if v := byID[lateID]; v.DeadlineStatus != string(cra.DeadlineLate) {
		t.Errorf("F424: late report status = %q, want %q", v.DeadlineStatus, cra.DeadlineLate)
	} else if v.SubmittedAt == nil {
		t.Errorf("F424: late report must carry submitted_at")
	}
	// pending.
	if v := byID[pendingID]; v.DeadlineStatus != string(cra.DeadlinePending) {
		t.Errorf("F424: pending report status = %q, want %q", v.DeadlineStatus, cra.DeadlinePending)
	} else {
		if v.DeadlineAt == nil {
			t.Errorf("F424: pending report must carry deadline_at")
		}
		if v.SubmittedAt != nil {
			t.Errorf("F424: pending report must have null submitted_at, got %v", v.SubmittedAt)
		}
	}
	// overdue.
	if v := byID[overdueID]; v.DeadlineStatus != string(cra.DeadlineOverdue) {
		t.Errorf("F424: overdue report status = %q, want %q", v.DeadlineStatus, cra.DeadlineOverdue)
	} else if v.SubmittedAt != nil {
		t.Errorf("F424: overdue report must have null submitted_at, got %v", v.SubmittedAt)
	}
	// not_applicable (awareness nil): no deadline_at.
	if v := byID[naNilID]; v.DeadlineStatus != string(cra.DeadlineNotApplicable) {
		t.Errorf("F424: awareness-nil report status = %q, want %q", v.DeadlineStatus, cra.DeadlineNotApplicable)
	} else if v.DeadlineAt != nil {
		t.Errorf("F424: not_applicable report must have null deadline_at, got %v", v.DeadlineAt)
	}
	// not_applicable (final_report): no window even with awareness.
	if v := byID[naFinalID]; v.DeadlineStatus != string(cra.DeadlineNotApplicable) {
		t.Errorf("F424: final_report status = %q, want %q", v.DeadlineStatus, cra.DeadlineNotApplicable)
	} else {
		if v.DeadlineAt != nil {
			t.Errorf("F424: final_report must have null deadline_at, got %v", v.DeadlineAt)
		}
		// awareness_time is still surfaced (embedded base struct) even
		// when the deadline is not_applicable.
		if v.AwarenessTime == nil || !v.AwarenessTime.Equal(awarenessRecent) {
			t.Errorf("F424: final_report awareness_time = %v, want %v (base struct surfaced)", v.AwarenessTime, awarenessRecent)
		}
	}
}

// TestCRAReportsHandler_GetReport_EnrichesDeadline_F424 pins the single-
// report read path: GetReport returns the derived deadline fields for
// one report using the same MIN(submitted_at) source of truth.
func TestCRAReportsHandler_GetReport_EnrichesDeadline_F424(t *testing.T) {
	h := newCRAHarness()
	now := time.Now().UTC()
	awareness := now.Add(-2 * time.Hour)
	submitted := now.Add(-1 * time.Hour)

	rid := uuid.New()
	h.seedReportWith(rid, h.projectID, string(cra.ReportTypeEarlyWarning), &awareness)
	h.submissions.earliest[rid] = submitted

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.GetReport(c); err != nil {
		t.Fatalf("GetReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("GetReport status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !h.submissions.called {
		t.Fatalf("F424: GetReport must invoke EarliestSubmittedAtByReports for enrichment")
	}

	var v deadlineReportView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("F424: decode enriched GetReport body: %v; body=%s", err, rec.Body.String())
	}
	if v.ID != rid {
		t.Errorf("F424: GetReport id = %s, want %s", v.ID, rid)
	}
	if v.DeadlineStatus != string(cra.DeadlineOnTime) {
		t.Errorf("F424: GetReport deadline_status = %q, want %q", v.DeadlineStatus, cra.DeadlineOnTime)
	}
	if v.DeadlineAt == nil || !v.DeadlineAt.Equal(awareness.Add(24*time.Hour)) {
		t.Errorf("F424: GetReport deadline_at = %v, want %v", v.DeadlineAt, awareness.Add(24*time.Hour))
	}
	if v.SubmittedAt == nil || !v.SubmittedAt.Equal(submitted) {
		t.Errorf("F424: GetReport submitted_at = %v, want %v", v.SubmittedAt, submitted)
	}
}

// TestCRAReportsHandler_ListReports_SubmissionsLookupFails_DoesNotFail_F424
// pins the F427 (M34 Phase D) contract: a submissions-lookup error does
// NOT 500 the read (availability preserved), AND it must NOT emit a false
// forward-looking verdict for a report that may have been filed on time.
// Instead the deadline verdict is SUPPRESSED — deadline_status is empty so
// the UI renders no badge — rather than a misleading "overdue".
func TestCRAReportsHandler_ListReports_SubmissionsLookupFails_DoesNotFail_F424(t *testing.T) {
	h := newCRAHarness()
	now := time.Now().UTC()
	awarenessOld := now.Add(-48 * time.Hour)

	rid := uuid.New()
	h.seedReportWith(rid, h.projectID, string(cra.ReportTypeEarlyWarning), &awarenessOld)
	h.submissions.err = errors.New("submissions storm — F424 degradation scenario")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListReports(c); err != nil {
		t.Fatalf("ListReports returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("F424: submissions failure must NOT break the list; status = %d, want 200", rec.Code)
	}
	var env deadlineEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("F424: decode degraded body: %v", err)
	}
	if len(env.Reports) != 1 {
		t.Fatalf("F424: degraded list should still return the report, got %d", len(env.Reports))
	}
	if env.Reports[0].DeadlineStatus != "" {
		t.Errorf("F427: on submissions-lookup failure the verdict must be SUPPRESSED "+
			"(empty deadline_status), got %q — a false verdict would mislead a filed report as overdue",
			env.Reports[0].DeadlineStatus)
	}
	if env.Reports[0].SubmittedAt != nil {
		t.Errorf("F427: suppressed report must have null submitted_at, got %v", env.Reports[0].SubmittedAt)
	}
}

// TestCRAReportsHandler_RunReport_MalformedAwareness_Returns400_F424 pins
// the run-path validation: a non-empty awareness_time that is not
// RFC3339 is a clean 400 BEFORE the runner is invoked (rather than a 500
// surfaced from the runner's later parse).
func TestCRAReportsHandler_RunReport_MalformedAwareness_Returns400_F424(t *testing.T) {
	h := newCRAHarness()
	body, err := json.Marshal(map[string]string{
		"vulnerability_id": uuid.NewString(),
		"cve_id":           "CVE-2026-3100",
		"report_type":      string(cra.ReportTypeEarlyWarning),
		"lang":             string(cra.LangJA),
		"awareness_time":   "not-a-timestamp",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F424: malformed awareness_time status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "awareness_time") {
		t.Errorf("F424: 400 body should name awareness_time, got %s", rec.Body.String())
	}
	if len(h.runner.captured) != 0 {
		t.Errorf("F424: runner.Run must NOT be called when awareness_time is malformed, got %d", len(h.runner.captured))
	}
}

// TestCRAReportsHandler_RunReport_ValidAwareness_Passes_F424 is the
// positive counterpart: a well-formed RFC3339 awareness_time passes the
// new validation and reaches the runner.
func TestCRAReportsHandler_RunReport_ValidAwareness_Passes_F424(t *testing.T) {
	h := newCRAHarness()
	body, err := json.Marshal(map[string]string{
		"vulnerability_id": uuid.NewString(),
		"cve_id":           "CVE-2026-3100",
		"report_type":      string(cra.ReportTypeEarlyWarning),
		"lang":             string(cra.LangJA),
		"awareness_time":   time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/run",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RunReport(c); err != nil {
		t.Fatalf("RunReport returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("F424: valid awareness_time status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if len(h.runner.captured) != 1 {
		t.Fatalf("F424: runner.Run should run once for valid awareness_time, got %d", len(h.runner.captured))
	}
}
