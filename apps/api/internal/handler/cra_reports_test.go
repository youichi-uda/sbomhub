package handler

import (
	"context"
	"encoding/json"
	"errors"
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

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

type craHarness struct {
	runner    *fakeCRARunner
	store     *fakeCRAReportStore
	audit     *fakeCRAAudit
	handler   *CRAReportsHandler
	tenantID  uuid.UUID
	projectID uuid.UUID
	userID    uuid.UUID
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
	h := NewCRAReportsHandler(runner, store, audit)
	return &craHarness{
		runner:    runner,
		store:     store,
		audit:     audit,
		handler:   h,
		tenantID:  tenantID,
		projectID: projectID,
		userID:    userID,
	}
}

func (h *craHarness) seedReport(reportID, projectID uuid.UUID) repository.CRAReport {
	r := repository.CRAReport{
		ID:               reportID,
		TenantID:         h.tenantID,
		ProjectID:        projectID,
		VulnerabilityID:  uuid.New(),
		CVEID:            "CVE-2026-3100",
		ReportType:       "early_warning",
		Lang:             "ja",
		State:            "draft",
		DraftText:        "draft body",
		Decision:         "pending",
		Evidence:         json.RawMessage(`[{"kind":"vex_draft"}]`),
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
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
	if h.audit.entries[0].Action != AuditActionCRAReportDecided {
		t.Errorf("audit action = %q, want %q", h.audit.entries[0].Action, AuditActionCRAReportDecided)
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
