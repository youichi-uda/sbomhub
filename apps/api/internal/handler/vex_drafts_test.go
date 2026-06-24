package handler

import (
	"context"
	"encoding/json"
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
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

// ----------------------------------------------------------------------------
// Handler-level fakes for the triage interfaces. The handler embeds a
// concrete *triage.Runner so we wire one up with these in-memory stores;
// triage.NewRunner enforces non-nil dependencies but the F7 test only
// exercises the handler's pre-flight ProjectID check, so the LLM / advisory
// / reachability fakes can stay trivial (the runner is never reached).
// ----------------------------------------------------------------------------

// fakeVexDraftStore satisfies triage.VexDraftStore. Insert/Update are
// stubbed out — the F7 cross-project test never reaches them because the
// handler returns 404 before delegating to runner.Run.
type fakeVexDraftStore struct {
	mu       sync.Mutex
	inserted []repository.VEXDraft
}

func (s *fakeVexDraftStore) Insert(_ context.Context, d *repository.VEXDraft) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	s.inserted = append(s.inserted, *d)
	return nil
}

func (s *fakeVexDraftStore) Get(_ context.Context, tenantID, draftID uuid.UUID) (*repository.VEXDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.inserted {
		if s.inserted[i].ID == draftID && s.inserted[i].TenantID == tenantID {
			d := s.inserted[i]
			return &d, nil
		}
	}
	return nil, nil
}

func (s *fakeVexDraftStore) ListByProject(_ context.Context, tenantID, projectID uuid.UUID, _ repository.VEXDraftListFilter) ([]repository.VEXDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]repository.VEXDraft, 0)
	for _, d := range s.inserted {
		if d.TenantID == tenantID && d.ProjectID == projectID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *fakeVexDraftStore) UpdateDecision(_ context.Context, _, _ uuid.UUID, _ repository.VEXDraftDecisionUpdate) error {
	return nil
}

type fakeAdvisoryReader struct{}

func (a *fakeAdvisoryReader) GetByCVE(_ context.Context, _ uuid.UUID, _ string) ([]triage.AdvisoryExcerptRow, error) {
	return nil, nil
}

type fakeReachabilityReader struct{}

func (r *fakeReachabilityReader) ListByProject(_ context.Context, _, _ uuid.UUID, _ triage.ReachabilityFilter) ([]triage.ReachabilityRow, error) {
	return nil, nil
}

type fakeLLMCallWriter struct{}

func (l *fakeLLMCallWriter) Insert(_ context.Context, _ *triage.LLMCallRecord) error { return nil }

type fakeAuditWriter struct{}

func (a *fakeAuditWriter) Log(_ context.Context, _ *model.CreateAuditLogInput) error { return nil }

// disabledProvider returns the concrete llm.DisabledProvider so
// triage.NewRunner's "Provider is required" guard is satisfied. The F7
// path never executes Complete because the handler short-circuits on
// the cross-project check; the same-project positive test reaches
// runAIDisabled which also does not call out to a real LLM.
func disabledProvider() llm.Provider {
	return &llm.DisabledProvider{Reason: "test runner — disabled provider"}
}

// ----------------------------------------------------------------------------
// F7 regression — Reanalyse must not cross project boundaries
// ----------------------------------------------------------------------------

// TestVEXDraftsHandler_Reanalyse_CrossProjectDraft_Returns404 pins the F7
// contract (Codex M1 round 2): runner.GetDraft is scoped by
// (tenant, draft_id) only — no project_id boundary. Without the handler's
// pre-flight ProjectID equality check a draft created in project A could
// be reanalysed under project B's URL, producing a new draft pointing at
// project B but reusing project A's component_id (vex_drafts has no
// composite FK over project_id / component_id). The handler MUST refuse
// with 404.
func TestVEXDraftsHandler_Reanalyse_CrossProjectDraft_Returns404(t *testing.T) {
	tenantID := uuid.New()
	projectA := uuid.New()
	projectB := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	draftID := uuid.New()

	// Seed a draft in project A.
	store := &fakeVexDraftStore{
		inserted: []repository.VEXDraft{{
			ID:              draftID,
			TenantID:        tenantID,
			ProjectID:       projectA,
			ComponentID:     componentID,
			VulnerabilityID: vulnID,
			CVEID:           "CVE-2026-0300",
			State:           "not_affected",
			Justification:   "code_not_reachable",
			Detail:          "Imported but unreachable",
			Evidence:        json.RawMessage(`[{"kind":"llm_rationale","source":"llm"}]`),
			Decision:        triage.DecisionPending,
			CreatedAt:       time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
		}},
	}

	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:       store,
		Advisories:   &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{},
		Audit:        &fakeAuditWriter{},
		// Use the disabled provider — handler returns 404 before any LLM
		// call is even contemplated, so this concrete instance is only
		// here to satisfy NewRunner's non-nil constructor check.
		Provider:  disabledProvider(),
		Threshold: 0.7,
	})
	h := NewVexDraftsHandler(runner)

	// Drive the handler with projectB in the URL but a draft that lives
	// in projectA.
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectB.String()+"/vex-drafts/"+draftID.String()+"/reanalyse",
		strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "draft_id")
	c.SetParamValues(projectB.String(), draftID.String())

	// Tenant + role context — without these the handler bails out with
	// 401/403 before reaching the cross-project check we're pinning.
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleAdmin)

	if err := h.Reanalyse(c); err != nil {
		t.Fatalf("Reanalyse returned unexpected error: %v", err)
	}

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-project reanalyse, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "project scope") &&
		!strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("expected error body to mention project-scope rejection, got %s", rec.Body.String())
	}
	// No new draft must have been inserted via reanalyse — the source
	// draft seeded in setup is the only row in the fake store.
	if got := len(store.inserted); got != 1 {
		t.Errorf("cross-project reanalyse must NOT insert a new draft, store has %d rows", got)
	}
}

// TestVEXDraftsHandler_Reanalyse_SameProject_Proceeds is the positive
// companion to the F7 cross-project test: when the URL project_id matches
// the source draft's project_id, the handler proceeds past the boundary
// check (it may then surface other errors from the runner, but the 404
// "project scope" body must NOT appear).
func TestVEXDraftsHandler_Reanalyse_SameProject_Proceeds(t *testing.T) {
	tenantID := uuid.New()
	projectA := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	draftID := uuid.New()

	store := &fakeVexDraftStore{
		inserted: []repository.VEXDraft{{
			ID:              draftID,
			TenantID:        tenantID,
			ProjectID:       projectA,
			ComponentID:     componentID,
			VulnerabilityID: vulnID,
			CVEID:           "CVE-2026-0301",
			State:           "under_investigation",
			Evidence:        json.RawMessage(`[{"kind":"llm_rationale","source":"llm"}]`),
			Decision:        triage.DecisionPending,
		}},
	}

	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:       store,
		Advisories:   &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{},
		Audit:        &fakeAuditWriter{},
		Provider:     disabledProvider(),
		Threshold:    0.7,
		// A resolver returning componentID so the F6 membership check
		// also passes for the reanalyse path.
		ComponentVulnerabilities: &fakeComponentResolver{ids: []uuid.UUID{componentID}},
	})
	h := NewVexDraftsHandler(runner)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectA.String()+"/vex-drafts/"+draftID.String()+"/reanalyse",
		strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "draft_id")
	c.SetParamValues(projectA.String(), draftID.String())

	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleAdmin)

	if err := h.Reanalyse(c); err != nil {
		t.Fatalf("Reanalyse returned unexpected error: %v", err)
	}

	// In the same-project case the AI-disabled runner persists an
	// under_investigation draft and returns 201.
	if rec.Code == http.StatusNotFound &&
		strings.Contains(rec.Body.String(), "project scope") {
		t.Fatalf("same-project reanalyse should NOT be rejected by the F7 check, got 404 body=%s", rec.Body.String())
	}
}

// fakeComponentResolver satisfies triage.ComponentVulnerabilityResolver.
type fakeComponentResolver struct {
	ids []uuid.UUID
}

func (r *fakeComponentResolver) ListIDsByVulnerability(_ context.Context, _, _, _ uuid.UUID) ([]uuid.UUID, error) {
	return r.ids, nil
}

// ----------------------------------------------------------------------------
// F10 regression — 404 body must be identical for both sentinel reasons
// ----------------------------------------------------------------------------
//
// Codex M1 round 3 #F10: mapRunnerError previously returned
// {"error": err.Error()} for both 404 sentinels, yielding distinct
// bodies ("triage: vulnerability not found in tenant scope" vs
// "triage: component not in vulnerability scope"). A probe caller could
// then distinguish "vulnerability does not exist in this tenant" from
// "the (vulnerability, component) link is wrong" — leaking tenant
// internals through the 404 body. The handler MUST emit a single
// generic body for both cases. The precise reason stays in server logs.
func TestVEXDraftsHandler_RunTriage_404Body_IsGeneric(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	componentInScope := uuid.New()
	componentOutOfScope := uuid.New()

	// Case 1 — vulnerability has no components in tenant scope.
	runnerNoVuln := triage.NewRunner(triage.RunnerConfig{
		Drafts:                   &fakeVexDraftStore{},
		Advisories:               &fakeAdvisoryReader{},
		Reachability:             &fakeReachabilityReader{},
		LLMCalls:                 &fakeLLMCallWriter{},
		Audit:                    &fakeAuditWriter{},
		Provider:                 disabledProvider(),
		Threshold:                0.7,
		ComponentVulnerabilities: &fakeComponentResolver{ids: nil},
	})
	bodyNoVuln := runTriageAndCapture404(t, runnerNoVuln, tenantID, projectID, vulnID, &componentInScope)

	// Case 2 — caller-supplied component outside vulnerability scope.
	runnerOutOfScope := triage.NewRunner(triage.RunnerConfig{
		Drafts:                   &fakeVexDraftStore{},
		Advisories:               &fakeAdvisoryReader{},
		Reachability:             &fakeReachabilityReader{},
		LLMCalls:                 &fakeLLMCallWriter{},
		Audit:                    &fakeAuditWriter{},
		Provider:                 disabledProvider(),
		Threshold:                0.7,
		ComponentVulnerabilities: &fakeComponentResolver{ids: []uuid.UUID{componentInScope}},
	})
	bodyOutOfScope := runTriageAndCapture404(t, runnerOutOfScope, tenantID, projectID, vulnID, &componentOutOfScope)

	if bodyNoVuln != bodyOutOfScope {
		t.Fatalf("F10: 404 bodies must be identical for both sentinels.\n  vuln-not-in-tenant : %s\n  comp-out-of-scope  : %s",
			bodyNoVuln, bodyOutOfScope)
	}
	// Body must NOT contain either sentinel reason string verbatim.
	for _, leak := range []string{"vulnerability not found in tenant scope", "component not in vulnerability scope"} {
		if strings.Contains(bodyNoVuln, leak) {
			t.Errorf("F10: generic 404 body must not contain sentinel reason %q; got %s", leak, bodyNoVuln)
		}
	}
}

// runTriageAndCapture404 drives RunTriage with the given input and asserts
// a 404 response, returning the response body for cross-case comparison.
func runTriageAndCapture404(t *testing.T, runner *triage.Runner, tenantID, projectID, vulnID uuid.UUID, componentID *uuid.UUID) string {
	t.Helper()
	h := NewVexDraftsHandler(runner)

	body := map[string]string{
		"vulnerability_id": vulnID.String(),
		"cve_id":           "CVE-2026-0500",
	}
	if componentID != nil {
		body["component_id"] = componentID.String()
	}
	raw, _ := json.Marshal(body)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectID.String()+"/triage/run",
		strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleAdmin)

	if err := h.RunTriage(c); err != nil {
		t.Fatalf("RunTriage returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
	return strings.TrimSpace(rec.Body.String())
}
