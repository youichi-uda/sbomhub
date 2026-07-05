package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// ----------------------------------------------------------------------------
// Handler-level fakes for the CRA submissions handler (M33 Wave B / F419).
// The handler is wired against narrow interfaces (see cra_submissions.go)
// so these tests never touch a real DB. fakeCRAAudit is shared with
// cra_reports_test.go (same package).
// ----------------------------------------------------------------------------

type fakeCRASubmissionRecorder struct {
	mu sync.Mutex

	cannedID    uuid.UUID
	recordInput *repository.CRASubmissionInput
	recordCalls int
	recordErr   error

	listResult     []repository.CRASubmission
	listErr        error
	listCalls      int
	lastListTenant uuid.UUID
	lastListReport uuid.UUID
}

func (f *fakeCRASubmissionRecorder) Record(_ context.Context, in repository.CRASubmissionInput) (*repository.CRASubmission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCalls++
	inCopy := in
	f.recordInput = &inCopy
	if f.recordErr != nil {
		return nil, f.recordErr
	}
	return &repository.CRASubmission{
		ID:              f.cannedID,
		TenantID:        in.TenantID,
		CRAReportID:     in.CRAReportID,
		Authority:       in.Authority,
		SubmittedAt:     in.SubmittedAt,
		SubmittedBy:     in.SubmittedBy,
		ReferenceNumber: in.ReferenceNumber,
		Notes:           in.Notes,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}, nil
}

func (f *fakeCRASubmissionRecorder) ListByReport(_ context.Context, tenantID, craReportID uuid.UUID) ([]repository.CRASubmission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	f.lastListTenant = tenantID
	f.lastListReport = craReportID
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResult, nil
}

type fakeCRASubmissionReportStore struct {
	mu sync.Mutex

	report *repository.CRAReport // nil → not found
	getErr error

	markCalls      int
	markErr        error
	lastMarkTenant uuid.UUID
	lastMarkReport uuid.UUID
}

func (f *fakeCRASubmissionReportStore) Get(_ context.Context, tenantID, id uuid.UUID) (*repository.CRAReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.report == nil {
		return nil, nil
	}
	if f.report.TenantID != tenantID {
		return nil, nil
	}
	dup := *f.report
	return &dup, nil
}

func (f *fakeCRASubmissionReportStore) MarkSubmitted(_ context.Context, tenantID, reportID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.markCalls++
	f.lastMarkTenant = tenantID
	f.lastMarkReport = reportID
	return f.markErr
}

// ----------------------------------------------------------------------------
// Harness + helpers
// ----------------------------------------------------------------------------

type craSubHarness struct {
	subs         *fakeCRASubmissionRecorder
	reports      *fakeCRASubmissionReportStore
	audit        *fakeCRAAudit
	handler      *CRASubmissionsHandler
	tenantID     uuid.UUID
	projectID    uuid.UUID
	reportID     uuid.UUID
	userID       uuid.UUID
	submissionID uuid.UUID
}

func newCRASubHarness() *craSubHarness {
	tenantID := uuid.New()
	projectID := uuid.New()
	reportID := uuid.New()
	userID := uuid.New()
	submissionID := uuid.New()

	subs := &fakeCRASubmissionRecorder{cannedID: submissionID}
	reports := &fakeCRASubmissionReportStore{}
	audit := &fakeCRAAudit{}
	h := NewCRASubmissionsHandler(subs, reports, audit)
	return &craSubHarness{
		subs:         subs,
		reports:      reports,
		audit:        audit,
		handler:      h,
		tenantID:     tenantID,
		projectID:    projectID,
		reportID:     reportID,
		userID:       userID,
		submissionID: submissionID,
	}
}

// seedReport installs a cra_reports row scoped to (tenant, project) with
// the given decision so loadReportScoped resolves it and the approved-only
// guard can be exercised.
func (h *craSubHarness) seedReport(decision string) {
	h.reports.report = &repository.CRAReport{
		ID:        h.reportID,
		TenantID:  h.tenantID,
		ProjectID: h.projectID,
		Decision:  decision,
		State:     "approved",
	}
}

// seedReportInProject installs a report scoped to a DIFFERENT project of
// the same tenant, so loadReportScoped 404s (cross-project probe).
func (h *craSubHarness) seedReportInProject(projectID uuid.UUID, decision string) {
	h.reports.report = &repository.CRAReport{
		ID:        h.reportID,
		TenantID:  h.tenantID,
		ProjectID: projectID,
		Decision:  decision,
		State:     "approved",
	}
}

func (h *craSubHarness) setAuth(c echo.Context, role string, withUser bool) {
	c.Set(middleware.ContextKeyTenantID, h.tenantID)
	if withUser {
		c.Set(middleware.ContextKeyUserID, h.userID)
	}
	c.Set(middleware.ContextKeyRole, role)
}

func (h *craSubHarness) newRecordCtx(body string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+h.reportID.String()+"/submissions",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), h.reportID.String())
	return c, rec
}

func (h *craSubHarness) newListCtx() (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+h.reportID.String()+"/submissions", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), h.reportID.String())
	return c, rec
}

// ----------------------------------------------------------------------------
// Record — happy path
// ----------------------------------------------------------------------------

func TestCRASubmissionsHandler_Record_HappyPath(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")

	ref := "ENISA-ACK-9931"
	wantSubmittedAt := "2026-07-01T09:30:00Z"
	body, _ := json.Marshal(map[string]interface{}{
		"authority":        "ENISA CSIRT",
		"submitted_at":     wantSubmittedAt,
		"reference_number": ref,
		"notes":            "72h detailed notification",
	})
	c, rec := h.newRecordCtx(string(body))
	h.setAuth(c, model.RoleAdmin, true)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("Record status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// Record called once with the right input.
	if h.subs.recordCalls != 1 {
		t.Fatalf("Record call count = %d, want 1", h.subs.recordCalls)
	}
	in := h.subs.recordInput
	if in.TenantID != h.tenantID {
		t.Errorf("Record input TenantID = %s, want %s", in.TenantID, h.tenantID)
	}
	if in.CRAReportID != h.reportID {
		t.Errorf("Record input CRAReportID = %s, want %s", in.CRAReportID, h.reportID)
	}
	if in.Authority != "ENISA CSIRT" {
		t.Errorf("Record input Authority = %q, want %q", in.Authority, "ENISA CSIRT")
	}
	if in.SubmittedBy == nil || *in.SubmittedBy != h.userID {
		t.Errorf("Record input SubmittedBy = %v, want %s", in.SubmittedBy, h.userID)
	}
	wantTime, _ := time.Parse(time.RFC3339, wantSubmittedAt)
	if !in.SubmittedAt.Equal(wantTime) {
		t.Errorf("Record input SubmittedAt = %v, want %v", in.SubmittedAt, wantTime)
	}
	if in.ReferenceNumber == nil || *in.ReferenceNumber != ref {
		t.Errorf("Record input ReferenceNumber = %v, want %q", in.ReferenceNumber, ref)
	}

	// MarkSubmitted called once with (tenant, report).
	if h.reports.markCalls != 1 {
		t.Fatalf("MarkSubmitted call count = %d, want 1", h.reports.markCalls)
	}
	if h.reports.lastMarkTenant != h.tenantID || h.reports.lastMarkReport != h.reportID {
		t.Errorf("MarkSubmitted args = (%s,%s), want (%s,%s)",
			h.reports.lastMarkTenant, h.reports.lastMarkReport, h.tenantID, h.reportID)
	}

	// Exactly one audit row with the right action / resource / resource_id.
	if got := len(h.audit.entries); got != 1 {
		t.Fatalf("expected 1 cra_submission_recorded audit entry, got %d", got)
	}
	entry := h.audit.entries[0]
	if entry.Action != model.AuditActionCRASubmissionRecorded {
		t.Errorf("audit action = %q, want %q", entry.Action, model.AuditActionCRASubmissionRecorded)
	}
	if entry.ResourceType != model.ResourceCRASubmission {
		t.Errorf("audit resource_type = %q, want %q", entry.ResourceType, model.ResourceCRASubmission)
	}
	if entry.ResourceID == nil || *entry.ResourceID != h.submissionID {
		t.Errorf("audit resource_id = %v, want %s (cra_submissions.id)", entry.ResourceID, h.submissionID)
	}
	if entry.UserID == nil || *entry.UserID != h.userID {
		t.Errorf("audit user_id = %v, want %s", entry.UserID, h.userID)
	}
	if entry.Details["cra_report_id"] != h.reportID.String() {
		t.Errorf("audit details cra_report_id = %v, want %s", entry.Details["cra_report_id"], h.reportID)
	}
	if entry.Details["authority"] != "ENISA CSIRT" {
		t.Errorf("audit details authority = %v, want %q", entry.Details["authority"], "ENISA CSIRT")
	}
	if entry.Details["has_reference"] != true {
		t.Errorf("audit details has_reference = %v, want true", entry.Details["has_reference"])
	}

	// M33 F419 (Phase D): the handler does NOT set the audit_resource_id
	// context key, because the audit middleware deliberately SKIPS POST
	// .../submissions (determineActionAndResource returns "" — see
	// TestDetermineActionAndResource_CRASubmissions_F419). The authoritative
	// join key is the domain row's ResourceID asserted above (== submissionID);
	// there is no best-effort middleware row to point anywhere, so leaving the
	// context key unset is correct (a set value would be dead state).
	if v := c.Get(middleware.ContextKeyAuditResourceID); v != nil {
		t.Errorf("audit_resource_id context key = %v, want unset (middleware skips "+
			"POST .../submissions; the domain audit row carries the submission id)", v)
	}

	// Response body echoes the created submission.
	var out repository.CRASubmission
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal 201 body: %v; body=%s", err, rec.Body.String())
	}
	if out.ID != h.submissionID {
		t.Errorf("201 body id = %s, want %s", out.ID, h.submissionID)
	}
	if out.CRAReportID != h.reportID {
		t.Errorf("201 body cra_report_id = %s, want %s", out.CRAReportID, h.reportID)
	}
	if out.Authority != "ENISA CSIRT" {
		t.Errorf("201 body authority = %q, want %q", out.Authority, "ENISA CSIRT")
	}
}

// Record without submitted_at defaults to server now (non-zero) and still 201.
func TestCRASubmissionsHandler_Record_DefaultSubmittedAt(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")

	body, _ := json.Marshal(map[string]string{"authority": "National CSIRT"})
	c, rec := h.newRecordCtx(string(body))
	h.setAuth(c, model.RoleAdmin, true)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("Record status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if h.subs.recordInput.SubmittedAt.IsZero() {
		t.Errorf("SubmittedAt should default to server now, got zero time")
	}
	// No reference number → has_reference false.
	if h.audit.entries[0].Details["has_reference"] != false {
		t.Errorf("has_reference = %v, want false", h.audit.entries[0].Details["has_reference"])
	}
}

// ----------------------------------------------------------------------------
// Record — approved-only guard (409, no write)
// ----------------------------------------------------------------------------

func TestCRASubmissionsHandler_Record_NotApproved_Returns409_NoWrite(t *testing.T) {
	for _, decision := range []string{"pending", "rejected", "edited"} {
		t.Run(decision, func(t *testing.T) {
			h := newCRASubHarness()
			h.seedReport(decision)

			body, _ := json.Marshal(map[string]string{"authority": "ENISA CSIRT"})
			c, rec := h.newRecordCtx(string(body))
			h.setAuth(c, model.RoleAdmin, true)

			if err := h.handler.Record(c); err != nil {
				t.Fatalf("Record returned unexpected error: %v", err)
			}
			if rec.Code != http.StatusConflict {
				t.Fatalf("decision=%s status = %d, want 409; body=%s", decision, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "only approved") {
				t.Errorf("409 body should explain approved-only, got %s", rec.Body.String())
			}
			if h.subs.recordCalls != 0 {
				t.Errorf("Record MUST NOT run for non-approved report, got %d", h.subs.recordCalls)
			}
			if h.reports.markCalls != 0 {
				t.Errorf("MarkSubmitted MUST NOT run for non-approved report, got %d", h.reports.markCalls)
			}
			if len(h.audit.entries) != 0 {
				t.Errorf("audit MUST NOT be emitted for non-approved report, got %d", len(h.audit.entries))
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Record — input validation
// ----------------------------------------------------------------------------

func TestCRASubmissionsHandler_Record_EmptyAuthority_Returns400(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")

	body, _ := json.Marshal(map[string]string{"authority": "   "})
	c, rec := h.newRecordCtx(string(body))
	h.setAuth(c, model.RoleAdmin, true)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty authority status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if h.subs.recordCalls != 0 {
		t.Errorf("Record MUST NOT run for empty authority, got %d", h.subs.recordCalls)
	}
}

func TestCRASubmissionsHandler_Record_BadSubmittedAt_Returns400(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")

	body, _ := json.Marshal(map[string]string{
		"authority":    "ENISA CSIRT",
		"submitted_at": "2026/07/01 09:30", // not RFC3339
	})
	c, rec := h.newRecordCtx(string(body))
	h.setAuth(c, model.RoleAdmin, true)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad submitted_at status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "submitted_at") {
		t.Errorf("400 body should mention submitted_at, got %s", rec.Body.String())
	}
	if h.subs.recordCalls != 0 {
		t.Errorf("Record MUST NOT run for bad submitted_at, got %d", h.subs.recordCalls)
	}
}

// ----------------------------------------------------------------------------
// Record — auth guards
// ----------------------------------------------------------------------------

func TestCRASubmissionsHandler_Record_MissingUser_Returns403(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")

	body, _ := json.Marshal(map[string]string{"authority": "ENISA CSIRT"})
	c, rec := h.newRecordCtx(string(body))
	// Admin role (CanWrite true) but no user id → 403 user identity required.
	h.setAuth(c, model.RoleAdmin, false)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing user status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "user identity required") {
		t.Errorf("403 body should mention user identity required, got %s", rec.Body.String())
	}
	if h.subs.recordCalls != 0 {
		t.Errorf("Record MUST NOT run without user identity, got %d", h.subs.recordCalls)
	}
}

func TestCRASubmissionsHandler_Record_ReadOnly_Returns403(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")

	body, _ := json.Marshal(map[string]string{"authority": "ENISA CSIRT"})
	c, rec := h.newRecordCtx(string(body))
	h.setAuth(c, model.RoleViewer, true)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read-only status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if h.subs.recordCalls != 0 {
		t.Errorf("Record MUST NOT run for read-only role, got %d", h.subs.recordCalls)
	}
}

func TestCRASubmissionsHandler_Record_NoAuth_Returns401(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")

	body, _ := json.Marshal(map[string]string{"authority": "ENISA CSIRT"})
	c, rec := h.newRecordCtx(string(body))
	// No auth context set at all.

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// Record — report not found / cross-project → 404
// ----------------------------------------------------------------------------

func TestCRASubmissionsHandler_Record_ReportNotFound_Returns404(t *testing.T) {
	h := newCRASubHarness()
	// No report seeded → Get returns nil.

	body, _ := json.Marshal(map[string]string{"authority": "ENISA CSIRT"})
	c, rec := h.newRecordCtx(string(body))
	h.setAuth(c, model.RoleAdmin, true)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("not-found status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if h.subs.recordCalls != 0 {
		t.Errorf("Record MUST NOT run when report not found, got %d", h.subs.recordCalls)
	}
}

func TestCRASubmissionsHandler_Record_CrossProject_Returns404(t *testing.T) {
	h := newCRASubHarness()
	otherProject := uuid.New()
	h.seedReportInProject(otherProject, "approved") // approved, but different project

	body, _ := json.Marshal(map[string]string{"authority": "ENISA CSIRT"})
	c, rec := h.newRecordCtx(string(body))
	h.setAuth(c, model.RoleAdmin, true)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-project status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), otherProject.String()) {
		t.Errorf("404 body must not leak foreign project id: %s", rec.Body.String())
	}
	if h.subs.recordCalls != 0 {
		t.Errorf("Record MUST NOT run for cross-project report, got %d", h.subs.recordCalls)
	}
}

// ----------------------------------------------------------------------------
// Record — audit-or-nothing (F32): audit failure → 500
// ----------------------------------------------------------------------------

func TestCRASubmissionsHandler_Record_AuditFailure_Returns500_F32(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")
	h.audit.err = errors.New("audit storm — F32 regression scenario")

	body, _ := json.Marshal(map[string]string{"authority": "ENISA CSIRT"})
	c, rec := h.newRecordCtx(string(body))
	h.setAuth(c, model.RoleAdmin, true)

	if err := h.handler.Record(c); err != nil {
		t.Fatalf("Record returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("F32: audit failure status = %d, want 500 (so TenantTx rolls back); body=%s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "audit trail") {
		t.Errorf("F32: 500 body should mention audit trail, got %s", rec.Body.String())
	}
	// Record + MarkSubmitted ran in-memory (the fake has no tx), but the
	// 500 is exactly what TenantTx needs to roll them back in production.
	// Audit MUST have been attempted exactly once.
	if h.subs.recordCalls != 1 {
		t.Errorf("F32: Record call count = %d, want 1 (audit runs AFTER)", h.subs.recordCalls)
	}
	if h.reports.markCalls != 1 {
		t.Errorf("F32: MarkSubmitted call count = %d, want 1 (audit runs AFTER)", h.reports.markCalls)
	}
	if got := len(h.audit.entries); got != 1 {
		t.Errorf("F32: audit.Log should be attempted once (it then fails), got %d entries", got)
	}
}

// ----------------------------------------------------------------------------
// List
// ----------------------------------------------------------------------------

func TestCRASubmissionsHandler_List_HappyPath(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")
	h.subs.listResult = []repository.CRASubmission{
		{ID: uuid.New(), TenantID: h.tenantID, CRAReportID: h.reportID, Authority: "ENISA CSIRT", SubmittedAt: time.Now().UTC()},
		{ID: uuid.New(), TenantID: h.tenantID, CRAReportID: h.reportID, Authority: "National CSIRT", SubmittedAt: time.Now().UTC()},
	}

	c, rec := h.newListCtx()
	h.setAuth(c, model.RoleViewer, true)

	if err := h.handler.List(c); err != nil {
		t.Fatalf("List returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("List status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out craSubmissionListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal list body: %v; body=%s", err, rec.Body.String())
	}
	if len(out.Submissions) != 2 {
		t.Errorf("List returned %d submissions, want 2", len(out.Submissions))
	}
	if h.subs.lastListTenant != h.tenantID || h.subs.lastListReport != h.reportID {
		t.Errorf("ListByReport args = (%s,%s), want (%s,%s)",
			h.subs.lastListTenant, h.subs.lastListReport, h.tenantID, h.reportID)
	}
}

func TestCRASubmissionsHandler_List_Empty_ReturnsEmptyArrayNotNull(t *testing.T) {
	h := newCRASubHarness()
	h.seedReport("approved")
	h.subs.listResult = nil // repo would return []; assert handler normalises

	c, rec := h.newListCtx()
	h.setAuth(c, model.RoleViewer, true)

	if err := h.handler.List(c); err != nil {
		t.Fatalf("List returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("List status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"submissions":[]`) {
		t.Errorf("empty list body should be {\"submissions\":[]}, got %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "null") {
		t.Errorf("empty list body must not contain null: %s", rec.Body.String())
	}
}

func TestCRASubmissionsHandler_List_ReportNotFound_Returns404(t *testing.T) {
	h := newCRASubHarness()
	// No report seeded.

	c, rec := h.newListCtx()
	h.setAuth(c, model.RoleViewer, true)

	if err := h.handler.List(c); err != nil {
		t.Fatalf("List returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("List not-found status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if h.subs.listCalls != 0 {
		t.Errorf("ListByReport MUST NOT run when report not found, got %d", h.subs.listCalls)
	}
}
