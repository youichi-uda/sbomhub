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
// F8 regression — GetDraft must enforce route-project boundary
// ----------------------------------------------------------------------------
//
// Codex M1 round 3 #F8: GET /api/v1/projects/:id/vex-drafts/:draft_id
// previously parsed but discarded c.Param("id") and called
// h.runner.GetDraft(tenantID, draftID); repository.Get scopes by
// (tenant, draft_id) only. A tenant operator could therefore enumerate
// drafts from another project of the same tenant by guessing draft IDs
// against a project they belong to. The handler MUST refuse with 404
// when the loaded draft's ProjectID does not match the URL's project_id.
func TestVEXDraftsHandler_GetDraft_CrossProjectDraft_Returns404(t *testing.T) {
	tenantID := uuid.New()
	projectA := uuid.New()
	projectB := uuid.New()
	draftID := uuid.New()

	store := &fakeVexDraftStore{
		inserted: []repository.VEXDraft{{
			ID:              draftID,
			TenantID:        tenantID,
			ProjectID:       projectA,
			ComponentID:     uuid.New(),
			VulnerabilityID: uuid.New(),
			CVEID:           "CVE-2026-0400",
			State:           "not_affected",
			Justification:   "code_not_reachable",
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
	})
	h := NewVexDraftsHandler(runner)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+projectB.String()+"/vex-drafts/"+draftID.String(),
		nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "draft_id")
	c.SetParamValues(projectB.String(), draftID.String())

	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleAdmin)

	if err := h.GetDraft(c); err != nil {
		t.Fatalf("GetDraft returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-project GET, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	// Body must NOT leak the draft's actual project / component / cve.
	body := rec.Body.String()
	if strings.Contains(body, projectA.String()) ||
		strings.Contains(body, "CVE-2026-0400") {
		t.Errorf("404 body must not leak draft contents: %s", body)
	}
}

// ----------------------------------------------------------------------------
// F9 regression — Decide must enforce route-project boundary
// ----------------------------------------------------------------------------
//
// Codex M1 round 3 #F9: PUT /api/v1/projects/:id/vex-drafts/:draft_id/decision
// previously parsed but discarded c.Param("id") and called
// runner.UpdateDecision(tenantID, draftID); the update + sync-to-
// vex_statements then ran against the draft's *own* project_id, so a
// caller scoped to project B could approve / edit / reject a draft
// belonging to project A and mirror the verdict into vex_statements
// under project A. The handler MUST refuse with 404 when the loaded
// draft's ProjectID does not match the URL's project_id, and the sync
// fan-out MUST NOT fire.
func TestVEXDraftsHandler_Decide_CrossProjectDraft_Returns404(t *testing.T) {
	tenantID := uuid.New()
	projectA := uuid.New()
	projectB := uuid.New()
	draftID := uuid.New()

	store := &fakeVexDraftStore{
		inserted: []repository.VEXDraft{{
			ID:              draftID,
			TenantID:        tenantID,
			ProjectID:       projectA,
			ComponentID:     uuid.New(),
			VulnerabilityID: uuid.New(),
			CVEID:           "CVE-2026-0401",
			State:           "not_affected",
			Justification:   "code_not_reachable",
			Evidence:        json.RawMessage(`[{"kind":"llm_rationale","source":"llm"}]`),
			Decision:        triage.DecisionPending,
		}},
	}

	// Wire a VEXSync fake so we can assert it NEVER receives a call when
	// the cross-project decision is rejected.
	sync := &fakeVEXSyncRecorder{}
	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:       store,
		Advisories:   &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{},
		Audit:        &fakeAuditWriter{},
		VEXSync:      sync,
		Provider:     disabledProvider(),
		Threshold:    0.7,
	})
	h := NewVexDraftsHandler(runner)

	bodyBytes, _ := json.Marshal(map[string]string{"decision": triage.DecisionApproved})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+projectB.String()+"/vex-drafts/"+draftID.String()+"/decision",
		strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "draft_id")
	c.SetParamValues(projectB.String(), draftID.String())

	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleAdmin)

	if err := h.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-project decide, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	// Sync to vex_statements MUST NOT have fired — that would have
	// mirrored the unauthorised verdict into the draft's real project.
	if got := len(sync.created); got != 0 {
		t.Fatalf("cross-project decide must NOT call vex_statements sync, got %d calls", got)
	}
	// And the draft's decision in the store should still be pending.
	if d, _ := store.Get(context.Background(), tenantID, draftID); d == nil || d.Decision != triage.DecisionPending {
		t.Errorf("cross-project decide must not mutate the draft decision; got %+v", d)
	}
}

// fakeVEXSyncRecorder is a minimal triage.VEXStatementSync that records
// every CreateStatement call so the F9 test can assert it received zero
// invocations.
type fakeVEXSyncRecorder struct {
	created []triage.VEXStatementSyncInput
}

func (s *fakeVEXSyncRecorder) CreateStatement(_ context.Context, input triage.VEXStatementSyncInput) error {
	s.created = append(s.created, input)
	return nil
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

// ----------------------------------------------------------------------------
// F14 regression — triage / vex-drafts routes must be reachable for the
// API-key auth path (MultiAuth) used by the CLI
// ----------------------------------------------------------------------------
//
// Codex M1 round 6 #F14: the CLI's `sbomhub triage` command sends
// `Authorization: Bearer sbh_<api_key>` to /api/v1/projects/:id/triage/run
// and /api/v1/projects/:id/vex-drafts/:draft_id/decision. Before this
// fix:
//   - the five triage routes were registered on the Clerk-only `auth`
//     group, so MultiAuth was not in the chain at all and every API-key
//     call returned 401 from the Clerk JWT verifier; and
//   - even if a route was moved under MultiAuth, the API-key path set
//     no role on the request, so TenantContext.CanWrite() returned false
//     and RunTriage / Decide / Reanalyse failed with 403.
//
// These three tests pin the post-fix contract at the handler boundary:
// when MultiAuth's API-key path runs (we simulate its outputs by setting
// the same context keys it now writes — ContextKeyRole = RoleMember from
// roleFromAPIKeyPermissions("write"), ContextKeyUserID = synthetic
// per-tenant user), the handler proceeds past the auth gate. The
// route-wiring-side companion check lives in
// internal/middleware/multiauth_test.go (TestRoleFromAPIKeyPermissions_F14).

// TestVEXDraftsHandler_RunTriage_APIKeyAuth_Allowed verifies the F14 fix
// at the handler boundary: a request arriving with the context an
// API-key MultiAuth call now produces (tenant + synthetic user +
// RoleMember) must NOT be rejected by the CanWrite() / "unauthorized"
// guard. Before #F14 the handler returned 403 because ContextKeyRole was
// unset under the API-key auth path.
//
// We do not assert a 201 status here — the runner is wired with the
// disabled provider, so it persists an under_investigation draft only
// when the resolver yields a component. The contract under test is the
// auth-gate behaviour: the response code must NOT be 401 / 403, and the
// body must NOT be the "unauthorized" / "write permission required"
// sentinels that #F14 was supposed to remove.
func TestVEXDraftsHandler_RunTriage_APIKeyAuth_Allowed(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	apiKeyUserID := uuid.New() // synthetic per-tenant API-key user

	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:                   &fakeVexDraftStore{},
		Advisories:               &fakeAdvisoryReader{},
		Reachability:             &fakeReachabilityReader{},
		LLMCalls:                 &fakeLLMCallWriter{},
		Audit:                    &fakeAuditWriter{},
		Provider:                 disabledProvider(),
		Threshold:                0.7,
		ComponentVulnerabilities: &fakeComponentResolver{ids: []uuid.UUID{componentID}},
	})
	h := NewVexDraftsHandler(runner)

	body := map[string]string{
		"vulnerability_id": vulnID.String(),
		"cve_id":           "CVE-2026-0600",
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

	// Simulate the post-#F14 MultiAuth API-key path. Role comes from
	// roleFromAPIKeyPermissions("write") = RoleMember; UserID is the
	// synthetic per-tenant user GetOrCreateAPIKeyUser returns.
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, apiKeyUserID)
	c.Set(middleware.ContextKeyRole, model.RoleMember)

	if err := h.RunTriage(c); err != nil {
		t.Fatalf("RunTriage returned unexpected error: %v", err)
	}

	// The bug under test is 401 / 403 specifically. Other failure codes
	// (e.g. 404 from a resolver corner case) would still be regressions
	// vs the previous green path, but the #F14 fix is about removing the
	// auth-gate block, not the runner's downstream behaviour.
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("F14: RunTriage must not reject API-key auth context with %d; body=%s",
			rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "write permission required") {
		t.Fatalf("F14: RunTriage body still mentions write-permission gate: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "unauthorized") {
		t.Fatalf("F14: RunTriage body still mentions unauthorized: %s", rec.Body.String())
	}
}

// TestVEXDraftsHandler_Decide_APIKeyAuth_Allowed mirrors the RunTriage
// test for the decision endpoint. Decide additionally enforces a
// non-nil UserID (via userIDOrNil + the "user identity required" 403
// branch), so this test also confirms the synthetic API-key user
// satisfies that guard.
func TestVEXDraftsHandler_Decide_APIKeyAuth_Allowed(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	vulnID := uuid.New()
	draftID := uuid.New()
	apiKeyUserID := uuid.New()

	// Seed a pending draft in the project so Decide has something to
	// transition. The decision payload approves it.
	store := &fakeVexDraftStore{
		inserted: []repository.VEXDraft{{
			ID:              draftID,
			TenantID:        tenantID,
			ProjectID:       projectID,
			ComponentID:     componentID,
			VulnerabilityID: vulnID,
			CVEID:           "CVE-2026-0601",
			State:           "not_affected",
			Justification:   "code_not_reachable",
			Detail:          "synthetic",
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
		Provider:     disabledProvider(),
		Threshold:    0.7,
	})
	h := NewVexDraftsHandler(runner)

	body := map[string]string{"decision": triage.DecisionApproved}
	raw, _ := json.Marshal(body)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+projectID.String()+"/vex-drafts/"+draftID.String()+"/decision",
		strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "draft_id")
	c.SetParamValues(projectID.String(), draftID.String())

	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, apiKeyUserID)
	c.Set(middleware.ContextKeyRole, model.RoleMember)

	if err := h.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("F14: Decide must not reject API-key auth context with %d; body=%s",
			rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "user identity required") {
		t.Fatalf("F14: Decide body still mentions user-identity gate: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "write permission required") {
		t.Fatalf("F14: Decide body still mentions write-permission gate: %s", rec.Body.String())
	}
}

// TestVEXDraftsHandler_RunTriage_ReadOnlyAPIKey_Rejected is the
// handler-side companion to the F15 RequireWrite route guard. The
// triage routes are now wrapped in appmw.RequireWrite() at
// cmd/server/main.go, so a read-scoped sbh_... key (RoleViewer)
// never reaches the handler. The handler still keeps its own
// CanWrite() check as defence-in-depth — this test exercises that
// in-handler guard directly so we catch a regression where a future
// refactor removes the RequireWrite middleware AND the handler check
// in the same commit.
//
// The route-level guard test lives in
// internal/middleware/role_guard_test.go::TestRequireWrite_F15_ReadOnlyAPIKeyRejected
// (matrix + read-only API-key simulation). Together the two pins
// require both layers to regress before a read-scoped key can drive
// triage/run.
func TestVEXDraftsHandler_RunTriage_ReadOnlyAPIKey_Rejected(t *testing.T) {
	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:                   &fakeVexDraftStore{},
		Advisories:               &fakeAdvisoryReader{},
		Reachability:             &fakeReachabilityReader{},
		LLMCalls:                 &fakeLLMCallWriter{},
		Audit:                    &fakeAuditWriter{},
		Provider:                 disabledProvider(),
		Threshold:                0.7,
		ComponentVulnerabilities: &fakeComponentResolver{ids: []uuid.UUID{uuid.New()}},
	})
	h := NewVexDraftsHandler(runner)

	projectID := uuid.New()
	body := map[string]string{
		"vulnerability_id": uuid.NewString(),
		"cve_id":           "CVE-2026-0700",
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

	// Simulate MultiAuth's read-scoped API-key path: tenant set,
	// synthetic user set, role = RoleViewer (what
	// roleFromAPIKeyPermissions("read") returns).
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleViewer)

	if err := h.RunTriage(c); err != nil {
		t.Fatalf("RunTriage returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F15: RunTriage with RoleViewer must return 403, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
}

// TestVEXDraftsHandler_Decide_ReadOnlyAPIKey_Rejected mirrors the
// RunTriage F15 test for the decision endpoint. Both write surfaces
// must refuse a read-scoped API key — F15 is about every triage write
// route, not just RunTriage.
func TestVEXDraftsHandler_Decide_ReadOnlyAPIKey_Rejected(t *testing.T) {
	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:       &fakeVexDraftStore{},
		Advisories:   &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{},
		Audit:        &fakeAuditWriter{},
		Provider:     disabledProvider(),
		Threshold:    0.7,
	})
	h := NewVexDraftsHandler(runner)

	projectID := uuid.New()
	draftID := uuid.New()
	body := map[string]string{"decision": triage.DecisionApproved}
	raw, _ := json.Marshal(body)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+projectID.String()+"/vex-drafts/"+draftID.String()+"/decision",
		strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "draft_id")
	c.SetParamValues(projectID.String(), draftID.String())

	c.Set(middleware.ContextKeyTenantID, uuid.New())
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleViewer)

	if err := h.Decide(c); err != nil {
		t.Fatalf("Decide returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F15: Decide with RoleViewer must return 403, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
}

// TestVEXDraftsHandler_RunTriage_NoAuthContext_Returns401 pins the
// negative direction of #F14: a request with no tenant context (the
// state both the Clerk JWT failure path and an entirely-missing
// Authorization header produce) must still be rejected with 401. The
// fix moves triage routes from `auth` (Clerk-only) to a MultiAuth chain;
// the regression-prevention contract is that MultiAuth still refuses
// unauthenticated requests, not that the handler itself becomes
// auth-less.
func TestVEXDraftsHandler_RunTriage_NoAuthContext_Returns401(t *testing.T) {
	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:       &fakeVexDraftStore{},
		Advisories:   &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{},
		Audit:        &fakeAuditWriter{},
		Provider:     disabledProvider(),
		Threshold:    0.7,
	})
	h := NewVexDraftsHandler(runner)

	projectID := uuid.New()
	body := map[string]string{
		"vulnerability_id": uuid.NewString(),
		"cve_id":           "CVE-2026-0602",
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

	// Intentionally do not set any auth context keys — this simulates a
	// request that did not pass through MultiAuth (e.g. a misconfigured
	// route registration that bypassed it). The handler's own guard
	// must still refuse.

	if err := h.RunTriage(c); err != nil {
		t.Fatalf("RunTriage returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("F14: RunTriage without auth context must return 401, got %d (body=%s)",
			rec.Code, rec.Body.String())
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

// ----------------------------------------------------------------------------
// F25 regression — RunTriage must surface ErrFanOutExceeded as 413
// ----------------------------------------------------------------------------
//
// Codex M1 round 16 #F25 (high / DoS): when the caller omits
// component_id, runner.resolveComponentIDs now rejects any resolver
// that returns more components than r.maxFanOut with the
// ErrFanOutExceeded sentinel. The handler MUST map that sentinel to
// 413 Payload Too Large with a body that hints the caller can retry
// with an explicit component_id. The runner-level regression
// (TestRunner_Run_FanOutExceedsCap_F25_Rejected) pins the sentinel
// path; this test pins the HTTP mapping.
func TestVEXDraftsHandler_RunTriage_FanOutExceededMaps413_F25(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()

	// 21 components in scope, cap=20 (the runner's default) — fan-out
	// trips. ComponentID is intentionally omitted in the request body
	// below so the runner takes the fan-out path.
	ids := make([]uuid.UUID, 21)
	for i := range ids {
		ids[i] = uuid.New()
	}

	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:                   &fakeVexDraftStore{},
		Advisories:               &fakeAdvisoryReader{},
		Reachability:             &fakeReachabilityReader{},
		LLMCalls:                 &fakeLLMCallWriter{},
		Audit:                    &fakeAuditWriter{},
		Provider:                 disabledProvider(),
		Threshold:                0.7,
		ComponentVulnerabilities: &fakeComponentResolver{ids: ids},
		MaxFanOut:                20, // explicit so the test is robust to env override
	})
	h := NewVexDraftsHandler(runner)

	body := map[string]string{
		"vulnerability_id": vulnID.String(),
		"cve_id":           "CVE-2026-0F25H",
		// No component_id — exercise the fan-out path.
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
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("F25: ErrFanOutExceeded must surface as 413, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	// Body must contain the actionable hint ("supply component_id") so the
	// CLI can render a useful error.
	if !strings.Contains(rec.Body.String(), "component_id") {
		t.Errorf("F25: 413 body must hint at the component_id bypass, got %s", rec.Body.String())
	}
	// Body must NOT leak the precise resolved-count / cap (kept in logs).
	if strings.Contains(rec.Body.String(), "21") || strings.Contains(rec.Body.String(), "cap is") {
		t.Errorf("F25: 413 body must not leak topology (resolved-count / cap), got %s", rec.Body.String())
	}
}

// ----------------------------------------------------------------------------
// F24 regression — ListDrafts must clamp the `limit` query parameter
// ----------------------------------------------------------------------------
//
// Codex M1 round 15 #F24 (high / DoS): GET /api/v1/projects/:id/vex-drafts
// previously parsed any positive int from `?limit=` and reflected it
// straight into the repository's SQL `LIMIT $N`. A single API-key-
// reachable request such as `?limit=2147483647` could force a full-table
// page scan + in-memory row accumulation + JSON-marshaling, which on a
// tenant with a non-trivial backlog reduces to a cheap DoS primitive
// usable with read-only API keys. The handler now:
//   - rejects any limit > MaxListLimit (500) with 400 BEFORE the query
//     runs (the user-facing failure makes the probe loud in logs); and
//   - falls back to DefaultListLimit (100) on missing / zero / negative
//     / unparseable values so legitimate clients without an explicit
//     page size do not see an empty result.
//
// The repository-side companion clamp (defense in depth against future
// internal callers that bypass the handler) lives in
// internal/repository/vex_drafts_test.go::
// TestVEXDraftsRepo_ListByProject_LimitClamp_F24.

// listDraftsHandlerForF24 wires a runner whose fake store records the
// VEXDraftListFilter the handler hands down. Tests inspect filter.Limit
// to confirm the handler's clamp/default behaviour reaches the repo
// layer (rather than just inspecting the HTTP response code).
type recordingDraftStore struct {
	fakeVexDraftStore
	lastFilter repository.VEXDraftListFilter
	called     bool
}

func (s *recordingDraftStore) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.VEXDraftListFilter) ([]repository.VEXDraft, error) {
	s.called = true
	s.lastFilter = filter
	return s.fakeVexDraftStore.ListByProject(ctx, tenantID, projectID, filter)
}

func listDraftsHandlerForF24(t *testing.T) (*VexDraftsHandler, *recordingDraftStore) {
	t.Helper()
	store := &recordingDraftStore{}
	runner := triage.NewRunner(triage.RunnerConfig{
		Drafts:       store,
		Advisories:   &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{},
		Audit:        &fakeAuditWriter{},
		Provider:     disabledProvider(),
		Threshold:    0.7,
	})
	return NewVexDraftsHandler(runner), store
}

func driveListDrafts(t *testing.T, h *VexDraftsHandler, tenantID, projectID uuid.UUID, query string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	url := "/api/v1/projects/" + projectID.String() + "/vex-drafts"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleViewer)
	if err := h.ListDrafts(c); err != nil {
		t.Fatalf("ListDrafts returned unexpected error: %v", err)
	}
	return rec
}

// TestVEXDraftsHandler_ListDrafts_UnboundedLimit_Rejected_F24 pins the
// core #F24 contract: an attacker-chosen huge limit must be rejected at
// the handler boundary before the repository runs, so the DB never
// receives `LIMIT 2147483647`.
func TestVEXDraftsHandler_ListDrafts_UnboundedLimit_Rejected_F24(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	h, store := listDraftsHandlerForF24(t)
	rec := driveListDrafts(t, h, tenantID, projectID, "limit=2147483647")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F24: unbounded limit must return 400, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "limit exceeds maximum") {
		t.Errorf("F24: expected 'limit exceeds maximum' in body, got %s", rec.Body.String())
	}
	if store.called {
		t.Errorf("F24: repository ListByProject MUST NOT be invoked when limit is rejected; was called with filter=%+v",
			store.lastFilter)
	}
}

// TestVEXDraftsHandler_ListDrafts_ZeroLimit_Default_F24 pins the
// fallback: `?limit=0` (and analogously a missing limit) must NOT be
// treated as "unbounded" — the handler defaults to DefaultListLimit so
// the repository receives a known-small bound.
func TestVEXDraftsHandler_ListDrafts_ZeroLimit_Default_F24(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	h, store := listDraftsHandlerForF24(t)
	rec := driveListDrafts(t, h, tenantID, projectID, "limit=0")

	if rec.Code != http.StatusOK {
		t.Fatalf("F24: limit=0 must succeed with default, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if !store.called {
		t.Fatalf("F24: repository ListByProject should be invoked for limit=0 (default path)")
	}
	if store.lastFilter.Limit != DefaultListLimit {
		t.Errorf("F24: limit=0 must default to %d at the handler boundary, got %d",
			DefaultListLimit, store.lastFilter.Limit)
	}
}

// TestVEXDraftsHandler_ListDrafts_NegativeLimit_Default_F24 mirrors the
// zero-limit fallback for an explicitly negative value. The fix must
// not treat negative numbers as "ignore the cap" — they fall back to
// DefaultListLimit just like zero.
func TestVEXDraftsHandler_ListDrafts_NegativeLimit_Default_F24(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	h, store := listDraftsHandlerForF24(t)
	rec := driveListDrafts(t, h, tenantID, projectID, "limit=-1")

	if rec.Code != http.StatusOK {
		t.Fatalf("F24: limit=-1 must succeed with default, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if !store.called {
		t.Fatalf("F24: repository ListByProject should be invoked for limit=-1 (default path)")
	}
	if store.lastFilter.Limit != DefaultListLimit {
		t.Errorf("F24: limit=-1 must default to %d at the handler boundary, got %d",
			DefaultListLimit, store.lastFilter.Limit)
	}
}

// TestVEXDraftsHandler_ListDrafts_MaxLimit_Allowed_F24 pins the upper
// boundary: requests at exactly MaxListLimit must succeed (off-by-one
// trap — a `>` vs `>=` typo in the clamp would reject the boundary).
func TestVEXDraftsHandler_ListDrafts_MaxLimit_Allowed_F24(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	h, store := listDraftsHandlerForF24(t)
	rec := driveListDrafts(t, h, tenantID, projectID, "limit=500")

	if rec.Code != http.StatusOK {
		t.Fatalf("F24: limit=%d (boundary) must succeed, got %d (body=%s)",
			MaxListLimit, rec.Code, rec.Body.String())
	}
	if !store.called {
		t.Fatalf("F24: repository ListByProject should be invoked at the boundary")
	}
	if store.lastFilter.Limit != MaxListLimit {
		t.Errorf("F24: boundary limit must pass through to the repo verbatim, got %d (want %d)",
			store.lastFilter.Limit, MaxListLimit)
	}
}
