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
	metisvc "github.com/sbomhub/sbomhub/internal/service/meti"
	"github.com/sbomhub/sbomhub/internal/service/meti/criteria"
)

// ----------------------------------------------------------------------------
// Handler-level fakes. The MetiHandler is wired against narrow
// interfaces (see meti.go) so the evaluator does not need real
// repositories and the store does not need a real PostgreSQL
// connection — mirrors the CRA report fake pattern.
// ----------------------------------------------------------------------------

type fakeMetiStore struct {
	mu sync.Mutex

	// keyed by (project_id, criterion_id) so the (tenant, project,
	// criterion) lookup the handler uses is exercised faithfully —
	// adding a stray tenant_id mismatch row exposes any handler-side
	// scoping regression.
	byKey   map[string]repository.MetiAssessment
	listErr error
	getErr  error
	overErr error
	upsErr  error
	cntErr  error

	upserts        []repository.MetiAssessment
	overrides      []repository.MetiAssessmentOverrideInput
	overrideCalls  int
	lastFilter     repository.MetiAssessmentListFilter
	listCalled     bool
	countCalled    bool
}

func newFakeMetiStore() *fakeMetiStore {
	return &fakeMetiStore{byKey: make(map[string]repository.MetiAssessment)}
}

func metiKey(projectID uuid.UUID, criterionID string) string {
	return projectID.String() + "|" + criterionID
}

func (f *fakeMetiStore) Upsert(_ context.Context, a *repository.MetiAssessment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upsErr != nil {
		return f.upsErr
	}
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.EvaluatedAt.IsZero() {
		a.EvaluatedAt = time.Now().UTC()
	}
	a.CreatedAt = time.Now().UTC()
	a.UpdatedAt = a.CreatedAt
	// Preserve existing override_* if a row already exists (matches
	// the real repository's "ON CONFLICT DO UPDATE preserves override"
	// invariant).
	if prior, ok := f.byKey[metiKey(a.ProjectID, a.CriterionID)]; ok {
		a.OverrideStatus = prior.OverrideStatus
		a.OverrideBy = prior.OverrideBy
		a.OverrideAt = prior.OverrideAt
		a.OverrideNote = prior.OverrideNote
		a.ImprovementAction = prior.ImprovementAction
		a.ID = prior.ID
		a.CreatedAt = prior.CreatedAt
	}
	f.byKey[metiKey(a.ProjectID, a.CriterionID)] = *a
	f.upserts = append(f.upserts, *a)
	return nil
}

func (f *fakeMetiStore) Get(_ context.Context, tenantID, projectID uuid.UUID, criterionID string) (*repository.MetiAssessment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	r, ok := f.byKey[metiKey(projectID, criterionID)]
	if !ok || r.TenantID != tenantID {
		return nil, nil
	}
	dup := r
	return &dup, nil
}

func (f *fakeMetiStore) ListByProject(_ context.Context, tenantID, projectID uuid.UUID, filter repository.MetiAssessmentListFilter) ([]repository.MetiAssessment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalled = true
	f.lastFilter = filter
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]repository.MetiAssessment, 0)
	for _, r := range f.byKey {
		if r.TenantID != tenantID || r.ProjectID != projectID {
			continue
		}
		if filter.CriterionPhase != "" && r.CriterionPhase != filter.CriterionPhase {
			continue
		}
		if filter.Status != "" && r.Status != filter.Status {
			continue
		}
		if filter.HasOverride != nil {
			if *filter.HasOverride && r.OverrideStatus == "" {
				continue
			}
			if !*filter.HasOverride && r.OverrideStatus != "" {
				continue
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeMetiStore) CountByProject(_ context.Context, tenantID, projectID uuid.UUID, filter repository.MetiAssessmentListFilter) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.countCalled = true
	if f.cntErr != nil {
		return 0, f.cntErr
	}
	n := 0
	for _, r := range f.byKey {
		if r.TenantID != tenantID || r.ProjectID != projectID {
			continue
		}
		if filter.CriterionPhase != "" && r.CriterionPhase != filter.CriterionPhase {
			continue
		}
		if filter.Status != "" && r.Status != filter.Status {
			continue
		}
		if filter.HasOverride != nil {
			if *filter.HasOverride && r.OverrideStatus == "" {
				continue
			}
			if !*filter.HasOverride && r.OverrideStatus != "" {
				continue
			}
		}
		n++
	}
	return n, nil
}

func (f *fakeMetiStore) OverrideStatus(_ context.Context, tenantID, projectID uuid.UUID, criterionID string, upd repository.MetiAssessmentOverrideInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.overrideCalls++
	if f.overErr != nil {
		return f.overErr
	}
	r, ok := f.byKey[metiKey(projectID, criterionID)]
	if !ok || r.TenantID != tenantID {
		return fmt.Errorf("override meti_assessments: %w", sql.ErrNoRows)
	}
	// State-machine guard mirror: real repo's WHERE override_status
	// IS NULL clause matches zero rows for an already-overridden row.
	if r.OverrideStatus != "" {
		return fmt.Errorf("override meti_assessments: %w", sql.ErrNoRows)
	}
	r.OverrideStatus = upd.OverrideStatus
	by := upd.OverrideBy
	r.OverrideBy = &by
	at := time.Now().UTC()
	if !upd.OverrideAt.IsZero() {
		at = upd.OverrideAt
	}
	r.OverrideAt = &at
	r.OverrideNote = upd.OverrideNote
	if upd.ImprovementAction != nil {
		r.ImprovementAction = *upd.ImprovementAction
	}
	r.UpdatedAt = at
	f.byKey[metiKey(projectID, criterionID)] = r
	f.overrides = append(f.overrides, upd)
	return nil
}

type fakeMetiEvaluator struct {
	mu       sync.Mutex
	results  []metisvc.CriterionResult
	err      error
	calls    int
	lastT    uuid.UUID
	lastP    uuid.UUID
}

func (f *fakeMetiEvaluator) Evaluate(_ context.Context, tenantID, projectID uuid.UUID) ([]metisvc.CriterionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastT = tenantID
	f.lastP = projectID
	if f.err != nil {
		return nil, f.err
	}
	// Copy so callers cannot mutate the fake's slice.
	out := make([]metisvc.CriterionResult, len(f.results))
	copy(out, f.results)
	return out, nil
}

type fakeMetiAudit struct {
	mu      sync.Mutex
	entries []model.CreateAuditLogInput
	err     error
}

func (f *fakeMetiAudit) Log(_ context.Context, input *model.CreateAuditLogInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, *input)
	return f.err
}

// ----------------------------------------------------------------------------
// Harness
// ----------------------------------------------------------------------------

type metiHarness struct {
	store     *fakeMetiStore
	evaluator *fakeMetiEvaluator
	audit     *fakeMetiAudit
	handler   *MetiHandler
	tenantID  uuid.UUID
	projectID uuid.UUID
	userID    uuid.UUID
}

func newMetiHarness() *metiHarness {
	tenantID := uuid.New()
	projectID := uuid.New()
	userID := uuid.New()
	store := newFakeMetiStore()
	evaluator := &fakeMetiEvaluator{}
	audit := &fakeMetiAudit{}
	h := NewMetiHandler(store, evaluator, audit)
	return &metiHarness{
		store:     store,
		evaluator: evaluator,
		audit:     audit,
		handler:   h,
		tenantID:  tenantID,
		projectID: projectID,
		userID:    userID,
	}
}

func (h *metiHarness) ctxWithRole(c echo.Context, role string) {
	c.Set(middleware.ContextKeyTenantID, h.tenantID)
	c.Set(middleware.ContextKeyUserID, h.userID)
	c.Set(middleware.ContextKeyRole, role)
}

func (h *metiHarness) seedRow(criterionID, phase, status string) repository.MetiAssessment {
	r := repository.MetiAssessment{
		ID:             uuid.New(),
		TenantID:       h.tenantID,
		ProjectID:      h.projectID,
		CriterionID:    criterionID,
		CriterionPhase: phase,
		Status:         status,
		Evidence:       json.RawMessage(`[]`),
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		EvaluatedAt:    time.Now().UTC(),
	}
	h.store.byKey[metiKey(h.projectID, criterionID)] = r
	return r
}

// realCriterionID returns an id known to the production catalog so
// the F26 unknown-criterion guard in OverrideAssessment does not
// reject the request before we exercise the code path under test.
const (
	realCriterionID    = "meti.env_setup.01"
	realCriterionPhase = "env_setup"
)

// ----------------------------------------------------------------------------
// Happy paths
// ----------------------------------------------------------------------------

func TestMetiHandler_ListAssessments_HappyPath_EmitsXTotalCount_F28(t *testing.T) {
	h := newMetiHarness()
	h.seedRow("meti.env_setup.01", "env_setup", criteria.StatusAchieved)
	h.seedRow("meti.env_setup.02", "env_setup", criteria.StatusNeedsReview)
	h.seedRow("meti.sbom_creation.01", "sbom_creation", criteria.StatusNotAchieved)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("X-Total-Count = %q, want %q", got, "3")
	}
	if !h.store.countCalled {
		t.Errorf("CountByProject should be invoked for X-Total-Count")
	}
}

func TestMetiHandler_RefreshAssessment_HappyPath_UpsertsAndAudits(t *testing.T) {
	h := newMetiHarness()
	h.evaluator.results = []metisvc.CriterionResult{
		{
			CriterionID:      "meti.env_setup.01",
			Phase:            "env_setup",
			Status:           criteria.StatusAchieved,
			Evidence:         json.RawMessage(`[]`),
			EvaluatorVersion: metisvc.EvaluatorVersion,
			EvaluatedAt:      time.Now().UTC(),
		},
		{
			CriterionID:      "meti.env_setup.02",
			Phase:            "env_setup",
			Status:           criteria.StatusNeedsReview,
			Evidence:         json.RawMessage(`[]`),
			EvaluatorVersion: metisvc.EvaluatorVersion,
			EvaluatedAt:      time.Now().UTC(),
		},
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RefreshAssessment(c); err != nil {
		t.Fatalf("RefreshAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if h.evaluator.calls != 1 {
		t.Errorf("evaluator.calls = %d, want 1", h.evaluator.calls)
	}
	if got := len(h.store.upserts); got != 2 {
		t.Errorf("upserts = %d, want 2", got)
	}
	if got := len(h.audit.entries); got != 1 {
		t.Fatalf("expected 1 meti_assessment_refreshed audit entry, got %d", got)
	}
	if h.audit.entries[0].Action != AuditActionMetiAssessmentRefreshed {
		t.Errorf("audit action = %q, want %q", h.audit.entries[0].Action, AuditActionMetiAssessmentRefreshed)
	}
	if h.audit.entries[0].ResourceType != ResourceTypeMetiAssessment {
		t.Errorf("audit resource_type = %q, want %q", h.audit.entries[0].ResourceType, ResourceTypeMetiAssessment)
	}
}

func TestMetiHandler_OverrideAssessment_HappyPath_EmitsAudit(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)

	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "checked manually with the vendor",
	})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.OverrideAssessment(c); err != nil {
		t.Fatalf("OverrideAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.overrideCalls != 1 {
		t.Errorf("override calls = %d, want 1", h.store.overrideCalls)
	}
	if got := len(h.audit.entries); got != 1 {
		t.Fatalf("expected 1 meti_assessment_overridden audit entry, got %d", got)
	}
	if h.audit.entries[0].Action != AuditActionMetiAssessmentOverridden {
		t.Errorf("audit action = %q, want %q", h.audit.entries[0].Action, AuditActionMetiAssessmentOverridden)
	}
}

func TestMetiHandler_ListImprovementActions_HappyPath_FiltersAchieved(t *testing.T) {
	h := newMetiHarness()
	h.seedRow("meti.env_setup.01", "env_setup", criteria.StatusAchieved)
	h.seedRow("meti.env_setup.02", "env_setup", criteria.StatusNeedsReview)
	h.seedRow("meti.env_setup.03", "env_setup", criteria.StatusNotAchieved)
	// Operator override flips an evaluator "achieved" into an action item.
	o := h.seedRow("meti.env_setup.04", "env_setup", criteria.StatusAchieved)
	o.OverrideStatus = criteria.StatusNotAchieved
	by := h.userID
	o.OverrideBy = &by
	h.store.byKey[metiKey(h.projectID, "meti.env_setup.04")] = o
	// Operator override flips an evaluator "not_achieved" into achieved → drops out.
	o2 := h.seedRow("meti.env_setup.05", "env_setup", criteria.StatusNotAchieved)
	o2.OverrideStatus = criteria.StatusAchieved
	o2.OverrideBy = &by
	h.store.byKey[metiKey(h.projectID, "meti.env_setup.05")] = o2

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/improvement-actions", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListImprovementActions(c); err != nil {
		t.Fatalf("ListImprovementActions returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp metiImprovementActionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	// .02 needs_review + .03 not_achieved + .04 overridden->not_achieved = 3
	// .01 achieved + .05 overridden->achieved = excluded
	if got := len(resp.Actions); got != 3 {
		t.Errorf("actions = %d, want 3; body=%s", got, rec.Body.String())
	}
	for _, a := range resp.Actions {
		if a.EffectiveStatus == criteria.StatusAchieved {
			t.Errorf("achieved item leaked into actions: %+v", a)
		}
	}
	if got := rec.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("X-Total-Count = %q, want %q", got, "3")
	}
}

// ----------------------------------------------------------------------------
// F15 — read-only role rejected on write endpoints
// ----------------------------------------------------------------------------

func TestMetiHandler_RefreshAssessment_ReadOnly_Returns403_F15(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.RefreshAssessment(c); err != nil {
		t.Fatalf("RefreshAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F15: read-only refresh status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if h.evaluator.calls != 0 {
		t.Errorf("F15: evaluator must not run for read-only role")
	}
}

func TestMetiHandler_OverrideAssessment_ReadOnly_Returns403_F15(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	body, _ := json.Marshal(metiOverrideRequest{OverrideStatus: criteria.StatusAchieved})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.OverrideAssessment(c); err != nil {
		t.Fatalf("OverrideAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F15: read-only override status = %d, want 403", rec.Code)
	}
	if h.store.overrideCalls != 0 {
		t.Errorf("F15: OverrideStatus must not run for read-only role")
	}
}

// ----------------------------------------------------------------------------
// F24 / F27 — pagination clamp + offset cap
// ----------------------------------------------------------------------------

func TestMetiHandler_ListAssessments_LimitOverflow_Returns400_F24(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment?limit=2147483647", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F24: limit overflow status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "limit exceeds maximum") {
		t.Errorf("F24: body should mention 'limit exceeds maximum', got %s", rec.Body.String())
	}
	if h.store.listCalled {
		t.Errorf("F24: ListByProject must NOT run when limit is rejected")
	}
}

func TestMetiHandler_ListAssessments_OffsetOverflow_Returns400_F27(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment?offset=2147483647", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F27: offset overflow status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "offset exceeds maximum") {
		t.Errorf("F27: body should mention 'offset exceeds maximum', got %s", rec.Body.String())
	}
}

func TestMetiHandler_ListAssessments_LimitAtBoundary_Passes(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment?limit="+strconv.Itoa(MaxMetiAssessmentsListLimit), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("boundary limit status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.lastFilter.Limit != MaxMetiAssessmentsListLimit {
		t.Errorf("filter.Limit at boundary = %d, want %d",
			h.store.lastFilter.Limit, MaxMetiAssessmentsListLimit)
	}
}

// ----------------------------------------------------------------------------
// F26 — query-param allow-list rejection
// ----------------------------------------------------------------------------

func TestMetiHandler_ListAssessments_InvalidPhase_Returns400(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment?phase=not_a_phase", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid phase status = %d, want 400", rec.Code)
	}
	if h.store.listCalled {
		t.Errorf("ListByProject must NOT run when phase is rejected")
	}
}

func TestMetiHandler_ListAssessments_InvalidStatus_Returns400(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment?status=maybe", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400", rec.Code)
	}
}

func TestMetiHandler_ListAssessments_InvalidHasOverride_Returns400(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment?has_override=yes", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid has_override status = %d, want 400", rec.Code)
	}
}

// ----------------------------------------------------------------------------
// F31 — state machine: re-override on an already-overridden row → 409
// ----------------------------------------------------------------------------

func TestMetiHandler_OverrideAssessment_AlreadyOverridden_Returns409_F31(t *testing.T) {
	h := newMetiHarness()
	seeded := h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	// Flip the seeded row into "already overridden" so the F31 guard
	// trips at the handler layer BEFORE the UPDATE.
	seeded.OverrideStatus = criteria.StatusAchieved
	by := h.userID
	seeded.OverrideBy = &by
	h.store.byKey[metiKey(h.projectID, realCriterionID)] = seeded

	body, _ := json.Marshal(metiOverrideRequest{OverrideStatus: criteria.StatusNotAchieved})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.OverrideAssessment(c); err != nil {
		t.Fatalf("OverrideAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("F31: already-overridden status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already been overridden") {
		t.Errorf("F31: 409 body should mention 'already been overridden'; got %s", rec.Body.String())
	}
	if h.store.overrideCalls != 0 {
		t.Errorf("F31: OverrideStatus MUST NOT run when row is already overridden, got %d", h.store.overrideCalls)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F31: audit row MUST NOT be emitted when override is rejected, got %d", len(h.audit.entries))
	}
}

// F31 TOCTOU: the row was not overridden at handler pre-check time but
// a concurrent request applied an override between the Get and the
// UPDATE. The repository surfaces wrapped sql.ErrNoRows and the
// handler maps it to the same 409.
func TestMetiHandler_OverrideAssessment_AlreadyOverridden_TOCTOU_Returns409_F31(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	// Pre-check sees override_status = "" → passes; UPDATE in repo
	// (simulated) returns wrapped sql.ErrNoRows.
	h.store.overErr = fmt.Errorf("update meti_assessments override: %w", sql.ErrNoRows)

	body, _ := json.Marshal(metiOverrideRequest{OverrideStatus: criteria.StatusAchieved})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.OverrideAssessment(c); err != nil {
		t.Fatalf("OverrideAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("F31 TOCTOU: status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F31 TOCTOU: audit row MUST NOT land when UPDATE rejected, got %d", len(h.audit.entries))
	}
}

// ----------------------------------------------------------------------------
// F32 — audit failure rolls back: refresh + override both honour
// audit-or-nothing
// ----------------------------------------------------------------------------

func TestMetiHandler_RefreshAssessment_AuditFailure_Returns500_F32(t *testing.T) {
	h := newMetiHarness()
	h.evaluator.results = []metisvc.CriterionResult{
		{
			CriterionID:      "meti.env_setup.01",
			Phase:            "env_setup",
			Status:           criteria.StatusAchieved,
			Evidence:         json.RawMessage(`[]`),
			EvaluatorVersion: metisvc.EvaluatorVersion,
		},
	}
	h.audit.err = errors.New("audit storm — F32 regression scenario")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RefreshAssessment(c); err != nil {
		t.Fatalf("RefreshAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("F32: refresh audit failure status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "audit trail") {
		t.Errorf("F32: 500 body should mention 'audit trail'; got %s", rec.Body.String())
	}
}

func TestMetiHandler_OverrideAssessment_AuditFailure_Returns500_F32(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	h.audit.err = errors.New("audit storm — F32 regression scenario")

	body, _ := json.Marshal(metiOverrideRequest{OverrideStatus: criteria.StatusAchieved})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.OverrideAssessment(c); err != nil {
		t.Fatalf("OverrideAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("F32: override audit failure status = %d, want 500", rec.Code)
	}
	// Audit was attempted exactly once after the override write.
	if got := len(h.audit.entries); got != 1 {
		t.Errorf("F32: audit.Log should be attempted once, got %d", got)
	}
}

// ----------------------------------------------------------------------------
// F26 — unknown criterion id rejected with generic 404
// ----------------------------------------------------------------------------

func TestMetiHandler_OverrideAssessment_UnknownCriterion_Returns404(t *testing.T) {
	h := newMetiHarness()
	body, _ := json.Marshal(metiOverrideRequest{OverrideStatus: criteria.StatusAchieved})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/meti.fake.99/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), "meti.fake.99")
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.OverrideAssessment(c); err != nil {
		t.Fatalf("OverrideAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown criterion status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.overrideCalls != 0 {
		t.Errorf("OverrideStatus must NOT run for an unknown criterion id")
	}
}

func TestMetiHandler_OverrideAssessment_NoRowYet_Returns404(t *testing.T) {
	h := newMetiHarness()
	// realCriterionID is in the catalog (passes F26) but no
	// meti_assessments row exists for it yet (operator must /refresh first).
	body, _ := json.Marshal(metiOverrideRequest{OverrideStatus: criteria.StatusAchieved})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.OverrideAssessment(c); err != nil {
		t.Fatalf("OverrideAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing-row status = %d, want 404", rec.Code)
	}
}

// ----------------------------------------------------------------------------
// F4 — invalid request body / params rejected with 400
// ----------------------------------------------------------------------------

func TestMetiHandler_OverrideAssessment_InvalidStatus_Returns400(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	body, _ := json.Marshal(metiOverrideRequest{OverrideStatus: "wrong"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.OverrideAssessment(c); err != nil {
		t.Fatalf("OverrideAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status body = %d, want 400", rec.Code)
	}
}

func TestMetiHandler_ListAssessments_InvalidProjectID_Returns400(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/not-a-uuid/meti/assessment", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("not-a-uuid")
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid project_id status = %d, want 400", rec.Code)
	}
}

// ----------------------------------------------------------------------------
// No auth context → 401 (defensive)
// ----------------------------------------------------------------------------

func TestMetiHandler_NoAuth_Returns401(t *testing.T) {
	h := newMetiHarness()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	// Intentionally do not set any auth context.

	if err := h.handler.ListAssessments(c); err != nil {
		t.Fatalf("ListAssessments returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth status = %d, want 401", rec.Code)
	}
}

// ----------------------------------------------------------------------------
// Refresh preserves operator overrides across re-evaluation
// ----------------------------------------------------------------------------

func TestMetiHandler_RefreshAssessment_PreservesOverrides(t *testing.T) {
	h := newMetiHarness()
	// Pre-seed an overridden row: evaluator originally said needs_review,
	// operator manually set "achieved".
	seeded := h.seedRow("meti.env_setup.01", "env_setup", criteria.StatusNeedsReview)
	seeded.OverrideStatus = criteria.StatusAchieved
	by := h.userID
	seeded.OverrideBy = &by
	seeded.OverrideNote = "vendor confirmed"
	h.store.byKey[metiKey(h.projectID, "meti.env_setup.01")] = seeded

	// Re-evaluation downgrades the verdict but the override must survive.
	h.evaluator.results = []metisvc.CriterionResult{
		{
			CriterionID:      "meti.env_setup.01",
			Phase:            "env_setup",
			Status:           criteria.StatusNotAchieved, // different from prior
			Evidence:         json.RawMessage(`[]`),
			EvaluatorVersion: metisvc.EvaluatorVersion,
		},
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(h.projectID.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.RefreshAssessment(c); err != nil {
		t.Fatalf("RefreshAssessment returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	post := h.store.byKey[metiKey(h.projectID, "meti.env_setup.01")]
	if post.Status != criteria.StatusNotAchieved {
		t.Errorf("evaluator status not refreshed: %q, want %q", post.Status, criteria.StatusNotAchieved)
	}
	if post.OverrideStatus != criteria.StatusAchieved {
		t.Errorf("override not preserved: %q, want %q", post.OverrideStatus, criteria.StatusAchieved)
	}
	if post.OverrideNote != "vendor confirmed" {
		t.Errorf("override note not preserved: %q", post.OverrideNote)
	}
}
