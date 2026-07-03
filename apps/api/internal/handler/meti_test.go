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

// fakeMetiProjectStore is the in-memory MetiProjectReader the F37
// regression tests exercise. The default behaviour is "this single
// project exists in this single tenant" so the existing pre-F37 tests
// continue to pass; the F37 negative-path tests flip notFound = true
// to simulate "project absent or cross-tenant".
type fakeMetiProjectStore struct {
	mu        sync.Mutex
	tenantID  uuid.UUID
	projectID uuid.UUID
	notFound  bool
	err       error
	calls     int
	lastT     uuid.UUID
	lastP     uuid.UUID
}

func (f *fakeMetiProjectStore) GetByTenant(_ context.Context, tenantID, projectID uuid.UUID) (*model.Project, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastT = tenantID
	f.lastP = projectID
	if f.err != nil {
		return nil, f.err
	}
	if f.notFound {
		return nil, sql.ErrNoRows
	}
	if tenantID != f.tenantID || projectID != f.projectID {
		return nil, sql.ErrNoRows
	}
	return &model.Project{ID: projectID, Name: "test"}, nil
}

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
	byKey    map[string]repository.MetiAssessment
	listErr  error
	getErr   error
	overErr  error
	upsErr   error
	cntErr   error
	clearErr error

	upserts       []repository.MetiAssessment
	overrides     []repository.MetiAssessmentOverrideInput
	overrideCalls int
	clearCalls    int
	lastFilter    repository.MetiAssessmentListFilter
	listCalled    bool
	countCalled   bool
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

func (f *fakeMetiStore) ClearOverride(_ context.Context, tenantID, projectID uuid.UUID, criterionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clearCalls++
	if f.clearErr != nil {
		return f.clearErr
	}
	r, ok := f.byKey[metiKey(projectID, criterionID)]
	if !ok || r.TenantID != tenantID {
		return fmt.Errorf("clear meti_assessments override: %w", sql.ErrNoRows)
	}
	// State-machine guard mirror: real repo's WHERE override_status
	// IS NOT NULL clause matches zero rows for a non-overridden row.
	if r.OverrideStatus == "" {
		return fmt.Errorf("clear meti_assessments override: %w", sql.ErrNoRows)
	}
	r.OverrideStatus = ""
	r.OverrideBy = nil
	r.OverrideAt = nil
	r.OverrideNote = ""
	r.UpdatedAt = time.Now().UTC()
	f.byKey[metiKey(projectID, criterionID)] = r
	return nil
}

type fakeMetiEvaluator struct {
	mu      sync.Mutex
	results []metisvc.CriterionResult
	err     error
	calls   int
	lastT   uuid.UUID
	lastP   uuid.UUID
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
	projects  *fakeMetiProjectStore
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
	// F37: by default the project IS in the tenant so all pre-existing
	// happy-path / negative-path tests keep their previous behaviour.
	// The F37 regression tests flip projects.notFound to simulate the
	// cross-tenant / nonexistent project probe.
	projects := &fakeMetiProjectStore{tenantID: tenantID, projectID: projectID}
	h := NewMetiHandler(store, evaluator, audit, projects)
	return &metiHarness{
		store:     store,
		evaluator: evaluator,
		audit:     audit,
		projects:  projects,
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
	if h.audit.entries[0].Action != model.AuditActionMETIAssessmentRefreshed {
		t.Errorf("audit action = %q, want %q", h.audit.entries[0].Action, model.AuditActionMETIAssessmentRefreshed)
	}
	if h.audit.entries[0].ResourceType != model.ResourceMETIAssessment {
		t.Errorf("audit resource_type = %q, want %q", h.audit.entries[0].ResourceType, model.ResourceMETIAssessment)
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
	if h.audit.entries[0].Action != model.AuditActionMETIAssessmentOverridden {
		t.Errorf("audit action = %q, want %q", h.audit.entries[0].Action, model.AuditActionMETIAssessmentOverridden)
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
	// Body carries a valid note so the 403 is triggered by RoleViewer
	// (RequireWrite check) and NOT by the F34 note-required guard.
	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "manual override rationale",
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

	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusNotAchieved,
		OverrideNote:   "manual override rationale",
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

	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "manual override rationale",
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

	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "manual override rationale",
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
	// F26 unknown-criterion check fires BEFORE bind/validation, so the
	// note value here does not matter — keep a valid one for clarity.
	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "manual override rationale",
	})
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
	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "manual override rationale",
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
	// Note is valid so the 400 must come from the status validation.
	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: "wrong",
		OverrideNote:   "manual override rationale",
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

// ----------------------------------------------------------------------------
// F34 — override_note required + bounded (auditor review)
// ----------------------------------------------------------------------------

// TestMetiHandler_Override_EmptyNote_Rejected_F34 pins the F34 fix:
// a manual override without a human rationale must be rejected with
// 400 BEFORE the OverrideStatus UPDATE runs. Without the guard, an
// override with empty note silently wins over the evaluator in
// Evidence Pack output with no audit-grade explanation.
func TestMetiHandler_Override_EmptyNote_Rejected_F34(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		// OverrideNote intentionally empty
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
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F34: empty-note status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "override_note is required") {
		t.Errorf("F34: 400 body should mention 'override_note is required'; got %s", rec.Body.String())
	}
	if h.store.overrideCalls != 0 {
		t.Errorf("F34: OverrideStatus MUST NOT run when note is rejected, got %d", h.store.overrideCalls)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F34: audit row MUST NOT be emitted when override is rejected, got %d", len(h.audit.entries))
	}
}

// TestMetiHandler_Override_OnlyWhitespaceNote_Rejected_F34 pins the
// trim-then-validate rule. A whitespace-only note is semantically
// empty for the auditor and must be rejected.
func TestMetiHandler_Override_OnlyWhitespaceNote_Rejected_F34(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "   \t\n  ",
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
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F34: whitespace-only note status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.overrideCalls != 0 {
		t.Errorf("F34: OverrideStatus MUST NOT run for whitespace-only note, got %d", h.store.overrideCalls)
	}
}

// TestMetiHandler_Override_NoteTooLong_Rejected_F34 pins the max-len
// cap. A 4097-char note must be rejected so audit_logs.details JSONB
// stays bounded against a probe submitting a multi-MB note.
func TestMetiHandler_Override_NoteTooLong_Rejected_F34(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	oversized := strings.Repeat("x", MaxMetiOverrideNoteLen+1)
	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   oversized,
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
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F34: oversized-note status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "1-4096") {
		t.Errorf("F34: 400 body should mention '1-4096'; got %s", rec.Body.String())
	}
	if h.store.overrideCalls != 0 {
		t.Errorf("F34: OverrideStatus MUST NOT run for oversized note, got %d", h.store.overrideCalls)
	}
}

// TestMetiHandler_Override_ValidNote_Accepted_F34 is the regression-
// preventing happy path: a normal valid note still lands the override
// + audit row. Without this, a future "tighten the validator" change
// could make every override 400 and we would not notice through the
// negative-only F34 cases above.
func TestMetiHandler_Override_ValidNote_Accepted_F34(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "vendor confirmed via signed advisory 2026-06-24",
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
		t.Fatalf("F34: valid-note status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.overrideCalls != 1 {
		t.Errorf("F34: OverrideStatus call count = %d, want 1", h.store.overrideCalls)
	}
	if got := len(h.audit.entries); got != 1 {
		t.Fatalf("F34: audit entry count = %d, want 1", got)
	}
	// The persisted note must be the trimmed form (we expect no
	// surrounding whitespace here, so trim leaves it unchanged).
	post := h.store.byKey[metiKey(h.projectID, realCriterionID)]
	if post.OverrideNote != "vendor confirmed via signed advisory 2026-06-24" {
		t.Errorf("F34: persisted note mismatch: %q", post.OverrideNote)
	}
}

// ----------------------------------------------------------------------------
// F33 — DELETE clear-override endpoint
// ----------------------------------------------------------------------------

// TestMetiHandler_ClearOverride_Success_F33 pins the happy path:
// DELETE /override on a row with a prior override clears the
// override_* lifecycle fields, leaves the evaluator-owned columns
// alone, and emits a `meti_assessment_override_cleared` audit row.
// Without this verb (M3 review #F33), an erroneous override is a
// one-way trip that continues to win in Evidence Pack output with no
// way to correct it.
func TestMetiHandler_ClearOverride_Success_F33(t *testing.T) {
	h := newMetiHarness()
	seeded := h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	// Flip the seeded row to an overridden state we then clear.
	seeded.OverrideStatus = criteria.StatusAchieved
	by := h.userID
	seeded.OverrideBy = &by
	at := time.Now().UTC()
	seeded.OverrideAt = &at
	seeded.OverrideNote = "previous override that turned out to be wrong"
	h.store.byKey[metiKey(h.projectID, realCriterionID)] = seeded

	body, _ := json.Marshal(metiClearOverrideRequest{
		Note: "re-evaluated, original override was wrong",
	})
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.ClearOverride(c); err != nil {
		t.Fatalf("ClearOverride returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("F33: clear status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.clearCalls != 1 {
		t.Errorf("F33: ClearOverride call count = %d, want 1", h.store.clearCalls)
	}
	post := h.store.byKey[metiKey(h.projectID, realCriterionID)]
	if post.OverrideStatus != "" || post.OverrideBy != nil || post.OverrideNote != "" || post.OverrideAt != nil {
		t.Errorf("F33: override fields not cleared: %+v", post)
	}
	// Evaluator-owned status preserved.
	if post.Status != criteria.StatusNeedsReview {
		t.Errorf("F33: evaluator status corrupted by clear: %q", post.Status)
	}
	if got := len(h.audit.entries); got != 1 {
		t.Fatalf("F33: audit entry count = %d, want 1", got)
	}
	entry := h.audit.entries[0]
	if entry.Action != model.AuditActionMETIAssessmentOverrideCleared {
		t.Errorf("F33: audit action = %q, want %q", entry.Action, model.AuditActionMETIAssessmentOverrideCleared)
	}
	if entry.ResourceType != model.ResourceMETIAssessment {
		t.Errorf("F33: audit resource_type = %q, want %q", entry.ResourceType, model.ResourceMETIAssessment)
	}
	if entry.Details["prior_override_status"] != criteria.StatusAchieved {
		t.Errorf("F33: prior_override_status in audit details = %v, want %q", entry.Details["prior_override_status"], criteria.StatusAchieved)
	}
}

// TestMetiHandler_ClearOverride_NoOverride_F33 pins the 404 response
// when the row has no override to clear. Same generic body as
// "criterion id unknown" / "row missing" so the response is not an
// oracle for override state.
func TestMetiHandler_ClearOverride_NoOverride_F33(t *testing.T) {
	h := newMetiHarness()
	// Row exists but has never been overridden.
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)

	body, _ := json.Marshal(metiClearOverrideRequest{Note: "clearing"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.ClearOverride(c); err != nil {
		t.Fatalf("ClearOverride returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("F33: no-override status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.clearCalls != 0 {
		t.Errorf("F33: ClearOverride MUST NOT run when no override exists, got %d", h.store.clearCalls)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F33: audit row MUST NOT be emitted when clear is rejected, got %d", len(h.audit.entries))
	}
}

// TestMetiHandler_ClearOverride_RequiresWrite_F33 pins the
// RequireWrite role guard at the handler layer (defence in depth on
// top of the middleware). A read-only API key cannot drop an
// override.
func TestMetiHandler_ClearOverride_RequiresWrite_F33(t *testing.T) {
	h := newMetiHarness()
	seeded := h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	seeded.OverrideStatus = criteria.StatusAchieved
	by := h.userID
	seeded.OverrideBy = &by
	h.store.byKey[metiKey(h.projectID, realCriterionID)] = seeded

	body, _ := json.Marshal(metiClearOverrideRequest{Note: "clearing"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleViewer)

	if err := h.handler.ClearOverride(c); err != nil {
		t.Fatalf("ClearOverride returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F33: read-only clear status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.clearCalls != 0 {
		t.Errorf("F33: ClearOverride MUST NOT run for read-only role, got %d", h.store.clearCalls)
	}
}

// TestMetiHandler_ClearOverride_RequireNote_F33 pins the F33+F34
// requirement that the clear request body carries a non-empty note.
// Without this, an operator could drop an override silently — exactly
// the gap F33 is closing.
func TestMetiHandler_ClearOverride_RequireNote_F33(t *testing.T) {
	h := newMetiHarness()
	seeded := h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	seeded.OverrideStatus = criteria.StatusAchieved
	by := h.userID
	seeded.OverrideBy = &by
	h.store.byKey[metiKey(h.projectID, realCriterionID)] = seeded

	body, _ := json.Marshal(metiClearOverrideRequest{Note: ""})
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.ClearOverride(c); err != nil {
		t.Fatalf("ClearOverride returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F33: empty-note status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "override_note is required") {
		t.Errorf("F33: 400 body should mention 'override_note is required'; got %s", rec.Body.String())
	}
	if h.store.clearCalls != 0 {
		t.Errorf("F33: ClearOverride MUST NOT run when note is rejected, got %d", h.store.clearCalls)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F33: audit row MUST NOT be emitted when note is rejected, got %d", len(h.audit.entries))
	}
}

// ----------------------------------------------------------------------------
// F37 — project-in-tenant boundary on every METI endpoint
// ----------------------------------------------------------------------------
//
// The meti_assessments table treats project_id as a soft reference (no
// FK). Pre-F37, the handler parsed the path :id and immediately ran
// the evaluator / repository call against the (tenant, projectID)
// pair, so a probe caller could:
//
//   - POST /refresh with a random UUID → persist 32 evaluator rows
//     under a project that does not exist in the tenant (or worse,
//     belongs to another tenant in a shared-cluster deployment).
//   - GET  /assessment with a sibling tenant's project UUID → read
//     whatever rows happened to exist (RLS would catch this in
//     production but the handler must not rely on RLS alone — F37
//     defence-in-depth).
//   - PUT  /override / DELETE /override / GET /improvement-actions
//     → same cross-project / nonexistent-project trap.
//
// The fix injects a MetiProjectReader and calls GetByTenant before any
// meti_assessments operation. The tests below pin each endpoint
// returning 404 (generic body — F10 carry-over) and NOT touching the
// store / evaluator / audit when the project is absent or
// cross-tenant.

func TestMetiHandler_RefreshAssessment_ProjectNotInTenant_Returns404_F37(t *testing.T) {
	h := newMetiHarness()
	h.projects.notFound = true

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
	if rec.Code != http.StatusNotFound {
		t.Fatalf("F37: refresh against missing project status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "project not found") {
		t.Errorf("F37: 404 body should mention 'project not found'; got %s", rec.Body.String())
	}
	if h.projects.calls != 1 {
		t.Errorf("F37: project lookup must run exactly once, got %d", h.projects.calls)
	}
	if h.evaluator.calls != 0 {
		t.Errorf("F37: evaluator MUST NOT run when project is absent, got %d", h.evaluator.calls)
	}
	if got := len(h.store.upserts); got != 0 {
		t.Errorf("F37: store.Upsert MUST NOT run when project is absent, got %d", got)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F37: audit row MUST NOT be emitted when project is absent, got %d", len(h.audit.entries))
	}
}

func TestMetiHandler_GetAssessment_ProjectNotInTenant_Returns404_F37(t *testing.T) {
	h := newMetiHarness()
	h.projects.notFound = true
	// Seed a row so we can confirm ListByProject is NOT called even
	// when the store has matching data — the project check fires first.
	h.seedRow("meti.env_setup.01", "env_setup", criteria.StatusAchieved)

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
	if rec.Code != http.StatusNotFound {
		t.Fatalf("F37: list against missing project status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.listCalled {
		t.Errorf("F37: ListByProject MUST NOT run when project is absent")
	}
	if h.store.countCalled {
		t.Errorf("F37: CountByProject MUST NOT run when project is absent")
	}
}

func TestMetiHandler_OverrideAssessment_ProjectNotInTenant_Returns404_F37(t *testing.T) {
	h := newMetiHarness()
	h.projects.notFound = true
	// Seed the criterion row so the F26 / F31 guards would normally
	// pass — this confirms the F37 check fires BEFORE those guards.
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)

	body, _ := json.Marshal(metiOverrideRequest{
		OverrideStatus: criteria.StatusAchieved,
		OverrideNote:   "manual override rationale",
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
	if rec.Code != http.StatusNotFound {
		t.Fatalf("F37: override against missing project status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.overrideCalls != 0 {
		t.Errorf("F37: OverrideStatus MUST NOT run when project is absent, got %d", h.store.overrideCalls)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F37: audit row MUST NOT be emitted when project is absent, got %d", len(h.audit.entries))
	}
}

func TestMetiHandler_ClearOverride_ProjectNotInTenant_Returns404_F37(t *testing.T) {
	h := newMetiHarness()
	h.projects.notFound = true
	// Seed an overridden row so the F33 guard would normally pass.
	seeded := h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	seeded.OverrideStatus = criteria.StatusAchieved
	by := h.userID
	seeded.OverrideBy = &by
	h.store.byKey[metiKey(h.projectID, realCriterionID)] = seeded

	body, _ := json.Marshal(metiClearOverrideRequest{Note: "re-evaluated"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.ClearOverride(c); err != nil {
		t.Fatalf("ClearOverride returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("F37: clear-override against missing project status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.clearCalls != 0 {
		t.Errorf("F37: ClearOverride MUST NOT run when project is absent, got %d", h.store.clearCalls)
	}
	if len(h.audit.entries) != 0 {
		t.Errorf("F37: audit row MUST NOT be emitted when project is absent, got %d", len(h.audit.entries))
	}
}

func TestMetiHandler_GetImprovementActions_ProjectNotInTenant_Returns404_F37(t *testing.T) {
	h := newMetiHarness()
	h.projects.notFound = true
	// Seed a non-achieved row so the action list would normally have
	// content — confirms the F37 check fires BEFORE the read.
	h.seedRow("meti.env_setup.01", "env_setup", criteria.StatusNotAchieved)

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
	if rec.Code != http.StatusNotFound {
		t.Fatalf("F37: improvement-actions against missing project status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if h.store.listCalled {
		t.Errorf("F37: ListByProject MUST NOT run when project is absent")
	}
}

// TestMetiHandler_RefreshAssessment_ValidProject_Accepted_F37 is the
// positive-companion regression that pins the F37 lookup wired into the
// happy path. Without it, a future "tighten the project check" change
// could make every refresh 404 and we would not notice through the
// negative-only F37 cases above. The earlier happy-path test
// (TestMetiHandler_RefreshAssessment_HappyPath_UpsertsAndAudits) covers
// the same code path but does NOT explicitly assert that the project
// lookup actually fired — this test does.
func TestMetiHandler_RefreshAssessment_ValidProject_Accepted_F37(t *testing.T) {
	h := newMetiHarness()
	// Default fakeMetiProjectStore returns the project; do not flip
	// notFound. The single evaluator row keeps the test cheap while
	// still exercising the Upsert + audit happy path.
	h.evaluator.results = []metisvc.CriterionResult{
		{
			CriterionID:      "meti.env_setup.01",
			Phase:            "env_setup",
			Status:           criteria.StatusAchieved,
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
		t.Fatalf("F37: valid-project refresh status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if h.projects.calls != 1 {
		t.Errorf("F37: project lookup must run exactly once, got %d", h.projects.calls)
	}
	if h.projects.lastT != h.tenantID || h.projects.lastP != h.projectID {
		t.Errorf("F37: project lookup scoped wrong; got (%s,%s) want (%s,%s)",
			h.projects.lastT, h.projects.lastP, h.tenantID, h.projectID)
	}
	if h.evaluator.calls != 1 {
		t.Errorf("F37: evaluator must run after project check, got %d", h.evaluator.calls)
	}
	if got := len(h.store.upserts); got != 1 {
		t.Errorf("F37: upserts = %d, want 1", got)
	}
	if got := len(h.audit.entries); got != 1 {
		t.Errorf("F37: audit entries = %d, want 1", got)
	}
}
