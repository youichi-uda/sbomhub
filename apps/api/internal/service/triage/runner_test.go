package triage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// ----------------------------------------------------------------------------
// In-memory fakes (one per interface declared in runner.go)
// ----------------------------------------------------------------------------
//
// The fakes intentionally satisfy the runner's narrow interfaces (not
// the underlying Postgres-backed repositories) so the tests stay in
// pure Go. agent A's *repository.VEXDraftsRepository will satisfy
// VexDraftStore in production wiring; here we substitute an in-memory
// store keyed by (tenant_id, draft_id).

type fakeVexDraftStore struct {
	mu       sync.Mutex
	inserted []repository.VEXDraft
	updates  []vexDraftUpdate
}

type vexDraftUpdate struct {
	tenantID uuid.UUID
	draftID  uuid.UUID
	update   repository.VEXDraftDecisionUpdate
}

func (s *fakeVexDraftStore) Insert(_ context.Context, d *repository.VEXDraft) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.Decision == "" {
		d.Decision = "pending"
	}
	now := time.Now().UTC()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	if d.UpdatedAt.IsZero() {
		d.UpdatedAt = now
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

func (s *fakeVexDraftStore) ListByProject(_ context.Context, tenantID, projectID uuid.UUID, filter repository.VEXDraftListFilter) ([]repository.VEXDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]repository.VEXDraft, 0)
	for _, d := range s.inserted {
		if d.TenantID != tenantID || d.ProjectID != projectID {
			continue
		}
		if filter.CVEID != "" && d.CVEID != filter.CVEID {
			continue
		}
		if filter.Decision != "" && d.Decision != filter.Decision {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

func (s *fakeVexDraftStore) UpdateDecision(_ context.Context, tenantID, draftID uuid.UUID, update repository.VEXDraftDecisionUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.inserted {
		if s.inserted[i].ID != draftID || s.inserted[i].TenantID != tenantID {
			continue
		}
		s.inserted[i].Decision = update.Decision
		decBy := update.DecisionBy
		s.inserted[i].DecisionBy = &decBy
		t := update.DecisionAt
		if t.IsZero() {
			t = time.Now().UTC()
		}
		s.inserted[i].DecisionAt = &t
		s.inserted[i].DecisionNote = update.DecisionNote
		// Mirror agent A's COALESCE-overwrite semantics: a non-nil
		// pointer overwrites, nil preserves.
		if update.EditedState != nil {
			s.inserted[i].State = *update.EditedState
		}
		if update.EditedJustification != nil {
			s.inserted[i].Justification = *update.EditedJustification
		}
		if update.EditedDetail != nil {
			s.inserted[i].Detail = *update.EditedDetail
		}
		s.inserted[i].UpdatedAt = t
		s.updates = append(s.updates, vexDraftUpdate{tenantID: tenantID, draftID: draftID, update: update})
		return nil
	}
	return nil
}

type fakeAdvisoryReader struct {
	rows []AdvisoryExcerptRow
}

func (a *fakeAdvisoryReader) GetByCVE(_ context.Context, _ uuid.UUID, cveID string) ([]AdvisoryExcerptRow, error) {
	out := make([]AdvisoryExcerptRow, 0)
	for _, r := range a.rows {
		if r.CVEID == cveID {
			out = append(out, r)
		}
	}
	return out, nil
}

type fakeReachabilityReader struct {
	rows []ReachabilityRow
}

func (r *fakeReachabilityReader) ListByProject(_ context.Context, _ uuid.UUID, _ uuid.UUID, filter ReachabilityFilter) ([]ReachabilityRow, error) {
	out := make([]ReachabilityRow, 0)
	for _, row := range r.rows {
		if filter.CVEID != "" && row.CVEID != filter.CVEID {
			continue
		}
		if filter.ComponentID != nil && row.ComponentID != *filter.ComponentID {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

type fakeLLMCallWriter struct {
	mu      sync.Mutex
	records []LLMCallRecord
}

func (l *fakeLLMCallWriter) Insert(_ context.Context, c *LLMCallRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, *c)
	return nil
}

type fakeAuditWriter struct {
	mu      sync.Mutex
	entries []model.CreateAuditLogInput
	// err, when non-nil, is returned by every Log call AFTER recording the
	// would-be entry. Used by the audit-failure regression tests to assert
	// that runner errors propagate (PRODUCT_REBOOT_PLAN.md §8.5: audit
	// rows must land or the whole VEX-draft write rolls back).
	err error
}

func (a *fakeAuditWriter) Log(_ context.Context, input *model.CreateAuditLogInput) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, *input)
	return a.err
}

type fakeVEXSync struct {
	mu      sync.Mutex
	created []VEXStatementSyncInput
	err     error
}

func (s *fakeVEXSync) CreateStatement(_ context.Context, input VEXStatementSyncInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.created = append(s.created, input)
	return nil
}

// ----------------------------------------------------------------------------
// Stub LLM provider
// ----------------------------------------------------------------------------

type stubProvider struct {
	resp     *llm.CompleteResponse
	err      error
	captured llm.CompleteRequest
}

func (p *stubProvider) Name() string  { return "stub" }
func (p *stubProvider) Model() string { return "stub-model" }
func (p *stubProvider) Complete(_ context.Context, req llm.CompleteRequest) (*llm.CompleteResponse, error) {
	p.captured = req
	if p.err != nil {
		return nil, p.err
	}
	return p.resp, nil
}
func (p *stubProvider) Embed(_ context.Context, _ llm.EmbedRequest) (*llm.EmbedResponse, error) {
	return nil, llm.ErrNotImplemented
}
func (p *stubProvider) Capabilities() llm.Capabilities { return llm.Capabilities{} }

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func canonicalLLMResponse() string {
	body, _ := json.Marshal(map[string]interface{}{
		"state":         "not_affected",
		"justification": "code_not_reachable",
		"detail":        "Vulnerable symbol is imported but never called from the project's entry points.",
		"confidence":    0.9,
		"evidence": []map[string]interface{}{
			{
				"kind":        "advisory_excerpt",
				"raw_snippet": "Vulnerable function github.com/example/pkg.Foo accepts attacker-controlled input.",
				"source":      "advisory_parser",
			},
			{
				"kind":        "symbol_ref",
				"symbol":      "github.com/example/pkg.Foo",
				"description": "Imported by transitive dependency but not present in callgraph from main().",
				"source":      "reachability",
				"note":        "import_only",
			},
		},
	})
	return string(body)
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

func TestRunner_Run_HappyPath_InsertsDraftLLMCallAndAudit(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	componentID := uuid.New()
	userID := uuid.New()

	drafts := &fakeVexDraftStore{}
	advisories := &fakeAdvisoryReader{rows: []AdvisoryExcerptRow{{
		ID: uuid.New(), CVEID: "CVE-2026-0001", Source: "ghsa",
		RawExcerpt: "GHSA advisory excerpt for CVE-2026-0001",
	}}}
	reach := &fakeReachabilityReader{rows: []ReachabilityRow{{
		ID: uuid.New(), ComponentID: componentID, CVEID: "CVE-2026-0001",
		Ecosystem: "go", Status: "import_only",
	}}}
	llmCalls := &fakeLLMCallWriter{}
	audit := &fakeAuditWriter{}
	stub := &stubProvider{resp: &llm.CompleteResponse{
		Content:      canonicalLLMResponse(),
		InputTokens:  100,
		OutputTokens: 50,
		Model:        "stub-model",
		FinishReason: "stop",
	}}

	r := NewRunner(RunnerConfig{
		Drafts:       drafts,
		Advisories:   advisories,
		Reachability: reach,
		LLMCalls:     llmCalls,
		Audit:        audit,
		Provider:     stub,
		Threshold:    0.7,
		Clock:        fixedClock(now),
		// F6: caller-supplied component_id must be cross-checked against
		// the resolver's authoritative (tenant, project, vulnerability)
		// → []component_id set. Wire a permissive resolver here so the
		// supplied componentID is accepted.
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		// F12: re-resolve the authoritative cve_id from
		// (tenant, vulnerability) and reject mismatches. The happy-path
		// fake returns the same cve id the test sends in RunInput.
		VulnerabilityCVE: okVulnCVE("CVE-2026-0001"),
	})

	uid := userID
	res, err := r.Run(context.Background(), RunInput{
		TenantID:        tenantID,
		ProjectID:       projectID,
		VulnerabilityID: vulnID,
		CVEID:           "CVE-2026-0001",
		ComponentID:     &componentID,
		UserID:          &uid,
		IPAddress:       "127.0.0.1",
		UserAgent:       "go-test",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if res == nil || res.Draft == nil {
		t.Fatal("expected non-nil result + draft")
	}

	// Draft persisted with expected fields.
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 inserted draft, got %d", got)
	}
	d := drafts.inserted[0]
	if d.TenantID != tenantID {
		t.Errorf("tenant_id mismatch: got %v want %v", d.TenantID, tenantID)
	}
	if d.ProjectID != projectID {
		t.Errorf("project_id mismatch")
	}
	if d.ComponentID != componentID {
		t.Errorf("component_id mismatch: got %v want %v", d.ComponentID, componentID)
	}
	if d.CVEID != "CVE-2026-0001" {
		t.Errorf("cve_id mismatch: got %s", d.CVEID)
	}
	if d.State != "not_affected" {
		t.Errorf("state mismatch: got %s want not_affected", d.State)
	}
	if d.Justification != "code_not_reachable" {
		t.Errorf("justification mismatch: got %s", d.Justification)
	}
	if d.Confidence == nil || *d.Confidence != 0.9 {
		t.Errorf("confidence mismatch: got %v", d.Confidence)
	}
	if d.Decision != DecisionPending {
		t.Errorf("decision mismatch: got %s want pending", d.Decision)
	}
	if d.Provider != "stub" {
		t.Errorf("provider mismatch: got %s", d.Provider)
	}
	if d.PromptHash == "" || d.ResponseHash == "" {
		t.Errorf("prompt/response hash should be populated")
	}
	if d.AdvisoryExcerptID == nil {
		t.Errorf("expected advisory_excerpt_id FK to be set")
	}
	if d.ReachabilityResultID == nil {
		t.Errorf("expected reachability_result_id FK to be set")
	}
	if d.LLMCallID == nil {
		t.Errorf("expected llm_call_id FK to be set")
	}

	// Result carries threshold + clamped (out-of-band, since schema does
	// not include those columns).
	if res.Threshold != 0.7 {
		t.Errorf("result.Threshold mismatch: got %v", res.Threshold)
	}
	if res.Clamped {
		t.Errorf("did not expect clamp at conf=0.9 / threshold=0.7")
	}

	// LLM call persisted.
	if got := len(llmCalls.records); got != 1 {
		t.Fatalf("expected 1 llm_calls record, got %d", got)
	}
	rec := llmCalls.records[0]
	if rec.Purpose != LLMCallPurposeVexTriage {
		t.Errorf("llm_calls purpose mismatch: got %s", rec.Purpose)
	}
	if rec.InputTokens != 100 || rec.OutputTokens != 50 {
		t.Errorf("token counts mismatch: got in=%d out=%d", rec.InputTokens, rec.OutputTokens)
	}
	if rec.PromptHash != d.PromptHash {
		t.Errorf("prompt_hash mismatch between draft and llm_calls")
	}
	if rec.TriageTargetCVE != "CVE-2026-0001" {
		t.Errorf("llm_calls triage_target_cve mismatch: got %s", rec.TriageTargetCVE)
	}
	if rec.TriageTargetComponentID == nil || *rec.TriageTargetComponentID != componentID {
		t.Errorf("llm_calls triage_target_component_id mismatch")
	}

	// Audit log emitted.
	if got := len(audit.entries); got != 1 {
		t.Fatalf("expected 1 audit entry, got %d", got)
	}
	a := audit.entries[0]
	if a.Action != AuditActionVexDraftAIGenerated {
		t.Errorf("audit action mismatch: got %s", a.Action)
	}
	if a.ResourceType != ResourceTypeVexDraft {
		t.Errorf("audit resource_type mismatch: got %s", a.ResourceType)
	}
	if a.ResourceID == nil || *a.ResourceID != d.ID {
		t.Errorf("audit resource_id mismatch")
	}
	if a.TenantID == nil || *a.TenantID != tenantID {
		t.Errorf("audit tenant_id mismatch")
	}
	if got, _ := a.Details["clamped"].(bool); got {
		t.Errorf("audit clamped should be false at conf=0.9 / threshold=0.7")
	}

	// Provider received the JSON-mode system prompt + low temperature.
	if !stub.captured.JSONMode {
		t.Errorf("expected JSONMode=true on LLM request")
	}
	if !strings.Contains(stub.captured.System, "SBOMHub's AI VEX triage assistant") {
		t.Errorf("system prompt missing triage steering")
	}
}

func TestRunner_Run_BelowThreshold_ClampsToUnderInvestigation(t *testing.T) {
	tenantID := uuid.New()
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.3)}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0002"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: tenantID, ProjectID: uuid.New(), VulnerabilityID: uuid.New(),
		CVEID: "CVE-2026-0002", ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 draft, got %d", got)
	}
	d := drafts.inserted[0]
	if d.State != "under_investigation" {
		t.Errorf("expected clamped state, got %s", d.State)
	}
	if !res.Clamped {
		t.Errorf("expected RunResult.Clamped=true")
	}
}

func TestRunner_Run_EmptyEvidence_Returns422Compatible(t *testing.T) {
	// Hand-craft an LLM response that parses but carries no evidence.
	body, _ := json.Marshal(map[string]interface{}{
		"state":      "affected",
		"confidence": 0.8,
		"evidence":   []map[string]interface{}{},
	})
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: string(body)}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0003"),
	})
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0003",
		ComponentID: &componentID,
	})
	if !errors.Is(err, ErrEmptyEvidence) {
		t.Fatalf("expected ErrEmptyEvidence, got %v", err)
	}
	if got := len(drafts.inserted); got != 0 {
		t.Errorf("expected no draft persisted on empty-evidence rejection, got %d", got)
	}
}

// TestRunner_Run_LLMTransientError_PersistsCallWithErrorMessageAndReturnsErr
// covers the case where the provider returns a non-Disabled error (e.g. 5xx
// from the upstream LLM). The runner must persist the llm_calls record with
// the error_message populated so operators can trace failed cycles, then
// surface a wrapped error so the handler maps it to 5xx.
//
// (The original variant of this test exercised *llm.DisabledError. After
// the F4 fix that path no longer errors — the runner instead persists an
// under_investigation draft and returns AIDisabled=true. See
// TestRunner_Run_AIDisabled_PersistsUnderInvestigationDraft for the
// new contract.)
func TestRunner_Run_LLMTransientError_PersistsCallWithErrorMessageAndReturnsErr(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{err: errors.New("upstream LLM 503 (transient)")}
	llmCalls := &fakeLLMCallWriter{}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: llmCalls,
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0004"),
	})
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0004",
		ComponentID: &componentID,
	})
	if err == nil {
		t.Fatalf("expected error when provider returns a transient failure")
	}
	if got := len(llmCalls.records); got != 1 {
		t.Fatalf("expected llm_calls audit row even on failure, got %d", got)
	}
	if llmCalls.records[0].ErrorMessage == "" {
		t.Errorf("expected error_message to be populated for failed call")
	}
	if got := len(drafts.inserted); got != 0 {
		t.Errorf("expected no draft persisted on LLM failure, got %d", got)
	}
}

// TestRunner_Run_MissingComponentID_WithoutResolver_Returns400 verifies
// that without a ComponentVulnerabilityResolver and without an explicit
// ComponentID, the runner still refuses to fabricate a component_id. The
// production wiring always supplies a resolver, but tests that need the
// legacy behaviour can opt out by leaving the field nil.
func TestRunner_Run_MissingComponentID_WithoutResolver_Returns400(t *testing.T) {
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	r := NewRunner(RunnerConfig{
		Drafts: &fakeVexDraftStore{}, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		// ComponentVulnerabilities deliberately omitted.
	})
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0099",
		// ComponentID omitted
	})
	if err == nil {
		t.Fatalf("expected error when component_id is missing and no resolver wired")
	}
	if !strings.Contains(err.Error(), "component_id") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunner_UpdateDecision_Approve_SyncsToVEXStatementsAndAudits(t *testing.T) {
	tenantID := uuid.New()
	draftID := uuid.New()
	vulnID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()

	drafts := &fakeVexDraftStore{inserted: []repository.VEXDraft{{
		ID: draftID, TenantID: tenantID, ProjectID: projectID,
		ComponentID:     componentID,
		VulnerabilityID: vulnID, CVEID: "CVE-2026-0005",
		State: "not_affected", Justification: "code_not_reachable",
		Detail:   "Imported but unreachable",
		Decision: DecisionPending,
	}}}
	audit := &fakeAuditWriter{}
	sync := &fakeVEXSync{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: audit, VEXSync: sync,
		Provider: &stubProvider{}, Threshold: 0.7,
	})

	userID := uuid.New()
	uid := userID
	updated, err := r.UpdateDecision(context.Background(), DecisionInput{
		TenantID: tenantID, DraftID: draftID, UserID: &uid,
		Decision: DecisionApproved,
		Note:     "reviewed with security team",
	})
	if err != nil {
		t.Fatalf("UpdateDecision error: %v", err)
	}
	if updated.Decision != DecisionApproved {
		t.Errorf("decision mismatch: got %s", updated.Decision)
	}

	// VEX statement mirrored.
	if got := len(sync.created); got != 1 {
		t.Fatalf("expected vex_statements sync, got %d", got)
	}
	sc := sync.created[0]
	if sc.VulnerabilityID != vulnID {
		t.Errorf("sync vuln mismatch")
	}
	if sc.Status != model.VEXStatusNotAffected {
		t.Errorf("sync status mismatch: got %s", sc.Status)
	}

	// Audit row.
	if got := len(audit.entries); got != 1 {
		t.Fatalf("expected 1 audit entry, got %d", got)
	}
	if audit.entries[0].Action != AuditActionVexDraftApproved {
		t.Errorf("audit action mismatch: got %s", audit.entries[0].Action)
	}
}

func TestRunner_UpdateDecision_Edit_RequiresEditedState(t *testing.T) {
	tenantID := uuid.New()
	draftID := uuid.New()
	componentID := uuid.New()
	drafts := &fakeVexDraftStore{inserted: []repository.VEXDraft{{
		ID: draftID, TenantID: tenantID, ProjectID: uuid.New(),
		ComponentID:     componentID,
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0006",
		State: "under_investigation", Decision: DecisionPending,
	}}}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: &stubProvider{}, Threshold: 0.7,
	})
	uid := uuid.New()
	_, err := r.UpdateDecision(context.Background(), DecisionInput{
		TenantID: tenantID, DraftID: draftID, UserID: &uid,
		Decision: DecisionEdited,
	})
	if err == nil {
		t.Fatalf("expected error when edited_state missing")
	}
	if !strings.Contains(err.Error(), "edited_state is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunner_UpdateDecision_EditNotAffected_RequiresJustification(t *testing.T) {
	tenantID := uuid.New()
	draftID := uuid.New()
	componentID := uuid.New()
	drafts := &fakeVexDraftStore{inserted: []repository.VEXDraft{{
		ID: draftID, TenantID: tenantID, ProjectID: uuid.New(),
		ComponentID:     componentID,
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0007",
		State: "under_investigation", Decision: DecisionPending,
	}}}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: &stubProvider{}, Threshold: 0.7,
	})
	uid := uuid.New()
	_, err := r.UpdateDecision(context.Background(), DecisionInput{
		TenantID: tenantID, DraftID: draftID, UserID: &uid,
		Decision: DecisionEdited, EditedState: "not_affected",
	})
	if err == nil {
		t.Fatalf("expected error when edited_justification missing for not_affected")
	}
}

func TestRunner_UpdateDecision_Reject_AuditsNoVEXSync(t *testing.T) {
	tenantID := uuid.New()
	draftID := uuid.New()
	componentID := uuid.New()
	drafts := &fakeVexDraftStore{inserted: []repository.VEXDraft{{
		ID: draftID, TenantID: tenantID, ProjectID: uuid.New(),
		ComponentID:     componentID,
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0008",
		State: "affected", Decision: DecisionPending,
	}}}
	audit := &fakeAuditWriter{}
	sync := &fakeVEXSync{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: audit, VEXSync: sync,
		Provider: &stubProvider{}, Threshold: 0.7,
	})
	uid := uuid.New()
	_, err := r.UpdateDecision(context.Background(), DecisionInput{
		TenantID: tenantID, DraftID: draftID, UserID: &uid,
		Decision: DecisionRejected, Note: "not actionable",
	})
	if err != nil {
		t.Fatalf("UpdateDecision error: %v", err)
	}
	if got := len(sync.created); got != 0 {
		t.Errorf("rejected drafts should not sync to vex_statements")
	}
	if got := len(audit.entries); got != 1 || audit.entries[0].Action != AuditActionVexDraftRejected {
		t.Errorf("expected vex_draft_rejected audit row")
	}
}

func TestRunner_UpdateDecision_Edit_PropagatesOverwrites(t *testing.T) {
	tenantID := uuid.New()
	draftID := uuid.New()
	componentID := uuid.New()
	drafts := &fakeVexDraftStore{inserted: []repository.VEXDraft{{
		ID: draftID, TenantID: tenantID, ProjectID: uuid.New(),
		ComponentID:     componentID,
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0010",
		State: "not_affected", Justification: "code_not_reachable",
		Detail: "AI rationale", Decision: DecisionPending,
	}}}
	sync := &fakeVEXSync{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, VEXSync: sync,
		Provider: &stubProvider{}, Threshold: 0.7,
	})
	uid := uuid.New()
	updated, err := r.UpdateDecision(context.Background(), DecisionInput{
		TenantID: tenantID, DraftID: draftID, UserID: &uid,
		Decision:     DecisionEdited,
		EditedState:  "affected",
		EditedDetail: "Human reviewer disagrees with AI; production observed traffic to vulnerable endpoint.",
		Note:         "manual review override",
	})
	if err != nil {
		t.Fatalf("UpdateDecision error: %v", err)
	}
	if updated.State != "affected" {
		t.Errorf("expected state overwritten to affected, got %s", updated.State)
	}
	if updated.Detail != "Human reviewer disagrees with AI; production observed traffic to vulnerable endpoint." {
		t.Errorf("expected detail overwritten, got %q", updated.Detail)
	}
	if got := len(sync.created); got != 1 {
		t.Errorf("edited draft should sync to vex_statements (got %d)", got)
	}
}

func TestRunner_Run_Reanalyse_EmitsReanalysedAudit(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.85)}}
	drafts := &fakeVexDraftStore{}
	audit := &fakeAuditWriter{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: audit, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0009"),
	})
	original := uuid.New()
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(), VulnerabilityID: uuid.New(),
		CVEID: "CVE-2026-0009", ComponentID: &componentID,
		Reanalyse: true, ReanalyseFromDraft: &original,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(audit.entries); got != 1 || audit.entries[0].Action != AuditActionVexDraftReanalysed {
		t.Fatalf("expected vex_draft_reanalysed audit, got %v", audit.entries)
	}
	if got, _ := audit.entries[0].Details["reanalyse_from"].(string); got != original.String() {
		t.Errorf("reanalyse_from missing in audit details: got %q", got)
	}
}

func TestRunner_Run_RejectsMissingInputs(t *testing.T) {
	r := NewRunner(RunnerConfig{
		Drafts: &fakeVexDraftStore{}, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: &stubProvider{}, Threshold: 0.7,
	})
	cases := []RunInput{
		{ProjectID: uuid.New(), VulnerabilityID: uuid.New(), CVEID: "CVE-X"},
		{TenantID: uuid.New(), VulnerabilityID: uuid.New(), CVEID: "CVE-X"},
		{TenantID: uuid.New(), ProjectID: uuid.New(), CVEID: "CVE-X"},
		{TenantID: uuid.New(), ProjectID: uuid.New(), VulnerabilityID: uuid.New()},
	}
	for i, in := range cases {
		if _, err := r.Run(context.Background(), in); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

// ----------------------------------------------------------------------------
// Audit atomicity regression tests (Codex M1 round 1 #F5)
// ----------------------------------------------------------------------------
//
// PRODUCT_REBOOT_PLAN.md §8.5 requires that the VEX-draft lifecycle
// audit row (vex_draft_ai_generated / approved / edited / rejected /
// reanalysed) be persisted alongside the draft / decision write. Until
// the F5 fix, writeAudit logged failures and swallowed them — meaning a
// transient audit_logs INSERT failure would let the request commit a
// draft with no audit trail, silently violating §8.5.
//
// The contract the runner now enforces:
//
//   1. audit.Log returning a non-nil error makes Run() / UpdateDecision()
//      return a wrapped error to the caller. The caller (handler) maps
//      it to 5xx, and TenantTx (apps/api/internal/middleware/tx.go)
//      rolls back the request — so the draft INSERT / decision UPDATE
//      and the would-be audit row are dropped together.
//   2. The fake stores used here are not transactional, so the in-memory
//      `inserted` slice still shows the draft row even after Run returns
//      an error. That mirrors what the real *repository.VEXDraftsRepository
//      sees mid-transaction: the write happened on the tx-bound connection
//      but is rolled back at request finalisation. Asserting on the
//      runner's returned error is sufficient to prove the new contract.

func TestRunner_Run_AuditFailure_PropagatesError(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}
	audit := &fakeAuditWriter{err: errors.New("audit_logs INSERT failed: connection reset")}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: audit, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0050"),
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0050",
		ComponentID: &componentID,
	})
	if err == nil {
		t.Fatalf("Run must propagate audit failures (PRODUCT_REBOOT_PLAN.md §8.5: VEX-draft writes are not allowed to commit without their audit row)")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Errorf("expected audit error wrap, got %v", err)
	}
	// The fake recorded the attempt — proves we did reach writeAudit, not
	// some earlier validation path. (We do not assert on drafts.inserted:
	// the in-memory fake is non-transactional; production rollback is the
	// TenantTx middleware's job, exercised by middleware/tx_test.go.)
	if got := len(audit.entries); got != 1 {
		t.Errorf("expected one audit attempt before failure, got %d", got)
	}
}

func TestRunner_UpdateDecision_AuditFailure_PropagatesError(t *testing.T) {
	tenantID := uuid.New()
	draftID := uuid.New()
	componentID := uuid.New()
	drafts := &fakeVexDraftStore{inserted: []repository.VEXDraft{{
		ID: draftID, TenantID: tenantID, ProjectID: uuid.New(),
		ComponentID:     componentID,
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0051",
		State: "affected", Decision: DecisionPending,
	}}}
	audit := &fakeAuditWriter{err: errors.New("audit_logs INSERT failed: deadlock")}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: audit, Provider: &stubProvider{}, Threshold: 0.7,
		// VEXSync deliberately nil — rejected decision does not sync, so
		// the audit step is the only thing between the UPDATE and return.
	})
	uid := uuid.New()
	_, err := r.UpdateDecision(context.Background(), DecisionInput{
		TenantID: tenantID, DraftID: draftID, UserID: &uid,
		Decision: DecisionRejected, Note: "not actionable",
	})
	if err == nil {
		t.Fatalf("UpdateDecision must propagate audit failures (PRODUCT_REBOOT_PLAN.md §8.5)")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Errorf("expected audit error wrap, got %v", err)
	}
	if got := len(audit.entries); got != 1 {
		t.Errorf("expected one audit attempt before failure, got %d", got)
	}
}

func TestRunner_Run_Reanalyse_AuditFailure_PropagatesError(t *testing.T) {
	// Reanalyse runs the same code path as Run but emits the
	// `vex_draft_reanalysed` audit action — make sure the propagation
	// holds for the reanalyse variant too so the regression cannot
	// reappear on that branch alone.
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.85)}}
	audit := &fakeAuditWriter{err: errors.New("audit_logs INSERT failed: tenant guc unset")}
	r := NewRunner(RunnerConfig{
		Drafts: &fakeVexDraftStore{}, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: audit, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0052"),
	})
	original := uuid.New()
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(), VulnerabilityID: uuid.New(),
		CVEID: "CVE-2026-0052", ComponentID: &componentID,
		Reanalyse: true, ReanalyseFromDraft: &original,
	})
	if err == nil {
		t.Fatalf("reanalyse Run must propagate audit failures (PRODUCT_REBOOT_PLAN.md §8.5)")
	}
}

// ----------------------------------------------------------------------------
// Per-tenant provider + component_id resolution + AI-disabled draft
// (Codex M1 round 1 #F2 / #F3 / #F4)
// ----------------------------------------------------------------------------
//
// PRODUCT_REBOOT_PLAN.md §7.1 + LLM_PROVIDER_DESIGN.md §4 say AI VEX triage
// MUST honour per-tenant BYOK (#F2), MUST resolve component_id from
// (tenant, project, vulnerability_id) when the caller omits it (#F3), and
// MUST persist an under_investigation draft + audit row when AI is disabled
// rather than silently counting locally on the CLI (#F4).
//
// Until this fix:
//   - the runner only ever called the server-startup env provider, ignoring
//     tenant_llm_config (Codex #F2),
//   - the runner refused to run unless the caller supplied component_id, so
//     the CLI either had to send one (which it could not derive from
//     /vulnerabilities) or fall into a 400 (#F3),
//   - the runner propagated llm.DisabledError back to the CLI which then
//     incremented a local counter without persisting a draft — leaving no
//     audit trail (#F4).
//
// The tests below pin the new contract:
//   1. ProviderResolver overrides the default Provider per-request.
//   2. Missing ComponentID is resolved via ComponentVulnerabilityResolver;
//      one row → one draft, multiple rows → fan-out one draft per component.
//   3. DisabledProvider triggers the under_investigation draft + audit
//      action `vex_draft_ai_disabled` and never calls LLM.

// fakeTenantProviderResolver captures the tenant id passed to the resolver
// so the test can verify the runner asks per-request (not per-startup).
type fakeProviderResolver struct {
	called    int
	gotTenant uuid.UUID
	provider  llm.Provider
	err       error
}

func (r *fakeProviderResolver) resolve(_ context.Context, tenantID uuid.UUID) (llm.Provider, error) {
	r.called++
	r.gotTenant = tenantID
	return r.provider, r.err
}

// fakeComponentVulnResolver supplies a canned []componentID for the runner.
type fakeComponentVulnResolver struct {
	called int
	ids    []uuid.UUID
	err    error
}

func (r *fakeComponentVulnResolver) ListIDsByVulnerability(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ uuid.UUID) ([]uuid.UUID, error) {
	r.called++
	return r.ids, r.err
}

// fakeVulnerabilityCVELookup returns a canned cve_id for the supplied
// vulnerability_id (M1 Codex review #F12 regression coverage). When err
// is non-nil it is returned in place of the cve_id so the test can
// exercise the data-integrity 5xx branch.
//
// `cveID` is the value the runner's resolveAuthoritativeCVEID will see
// as the "authoritative" cve. Tests that want a happy-path Run() wire a
// fake whose cveID equals the RunInput.CVEID they intend to send; the
// F12 rejection test wires a fake whose cveID differs from the supplied
// RunInput.CVEID and asserts ErrCVEIDMismatch.
type fakeVulnerabilityCVELookup struct {
	called  int
	gotVuln uuid.UUID
	cveID   string
	err     error
}

func (f *fakeVulnerabilityCVELookup) GetCVEIDByID(_ context.Context, vulnID uuid.UUID) (string, error) {
	f.called++
	f.gotVuln = vulnID
	return f.cveID, f.err
}

// okVulnCVE is a tiny convenience that returns a permissive lookup
// matching the supplied CVE id. Most existing tests use a fixed CVE id
// per case ("CVE-2026-XXXX") so they can wire `VulnerabilityCVE:
// okVulnCVE("CVE-2026-XXXX")` with the same string.
func okVulnCVE(cveID string) *fakeVulnerabilityCVELookup {
	return &fakeVulnerabilityCVELookup{cveID: cveID}
}

// TestRunner_Run_PerTenantProviderResolved verifies F2: a per-request
// ProviderResolver overrides the default Provider so a tenant's
// /settings/llm BYOK key actually drives the triage call (rather than
// the env-configured default).
func TestRunner_Run_PerTenantProviderResolved(t *testing.T) {
	tenantID := uuid.New()
	componentID := uuid.New()

	defaultStub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	tenantStub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "affected", "", 0.95)}}
	resolver := &fakeProviderResolver{provider: tenantStub}

	r := NewRunner(RunnerConfig{
		Drafts: &fakeVexDraftStore{}, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: defaultStub, Threshold: 0.7,
		ProviderResolver:         resolver.resolve,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0100"),
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: tenantID, ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0100",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if resolver.called != 1 {
		t.Errorf("ProviderResolver called %d times, want 1 (per-request resolve)", resolver.called)
	}
	if resolver.gotTenant != tenantID {
		t.Errorf("ProviderResolver got tenant %v, want %v", resolver.gotTenant, tenantID)
	}
	// Only the tenant-scoped provider should have been invoked; the
	// default stub stays untouched (its captured request stays at zero
	// value).
	if tenantStub.captured.Purpose == "" {
		t.Errorf("expected tenant-scoped provider to receive the LLM request")
	}
	if defaultStub.captured.Purpose != "" {
		t.Errorf("default provider should NOT have been called when ProviderResolver returned a tenant override")
	}
}

// TestRunner_Run_ResolveComponentIDFromVulnerability verifies F3: the
// runner consults ComponentVulnerabilityResolver when ComponentID is nil
// and uses the resolved id for the draft.
func TestRunner_Run_ResolveComponentIDFromVulnerability(t *testing.T) {
	componentID := uuid.New()
	resolver := &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}}
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: resolver,
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0101"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0101",
		// ComponentID omitted on purpose — the resolver should fill it.
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if resolver.called != 1 {
		t.Errorf("resolver.called = %d, want 1", resolver.called)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 draft inserted, got %d", got)
	}
	if drafts.inserted[0].ComponentID != componentID {
		t.Errorf("draft.ComponentID = %v, want %v", drafts.inserted[0].ComponentID, componentID)
	}
	if res.Draft == nil || res.Draft.ComponentID != componentID {
		t.Errorf("result Draft.ComponentID mismatch")
	}
}

// TestRunner_Run_FanOutOverMultipleComponents verifies F3 fan-out: when
// multiple components in the project are affected by the same
// vulnerability, the runner persists one draft per component rather than
// picking one arbitrarily.
func TestRunner_Run_FanOutOverMultipleComponents(t *testing.T) {
	c1, c2, c3 := uuid.New(), uuid.New(), uuid.New()
	resolver := &fakeComponentVulnResolver{ids: []uuid.UUID{c1, c2, c3}}
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}
	audit := &fakeAuditWriter{}
	llmCalls := &fakeLLMCallWriter{}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: llmCalls,
		Audit: audit, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: resolver,
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0102"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0102",
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 3 {
		t.Fatalf("expected 3 drafts (fan-out), got %d", got)
	}
	if got := len(res.Drafts); got != 3 {
		t.Errorf("RunResult.Drafts len = %d, want 3", got)
	}
	if res.Draft == nil {
		t.Errorf("RunResult.Draft (primary) should be the first fan-out draft")
	}
	gotIDs := map[uuid.UUID]struct{}{
		drafts.inserted[0].ComponentID: {},
		drafts.inserted[1].ComponentID: {},
		drafts.inserted[2].ComponentID: {},
	}
	for _, want := range []uuid.UUID{c1, c2, c3} {
		if _, ok := gotIDs[want]; !ok {
			t.Errorf("expected draft for component %v, did not find one", want)
		}
	}
	// Each draft must carry its own vex_draft_ai_generated audit row.
	if got := len(audit.entries); got != 3 {
		t.Errorf("expected 3 audit entries (one per draft), got %d", got)
	}
	for _, a := range audit.entries {
		if a.Action != AuditActionVexDraftAIGenerated {
			t.Errorf("audit action = %s, want vex_draft_ai_generated", a.Action)
		}
	}
}

// TestRunner_Run_VulnerabilityNotInTenant_Returns404 verifies F3: when
// the resolver returns no components, the runner returns a typed error
// the handler can map to 404 ("vulnerability not found in tenant scope").
func TestRunner_Run_VulnerabilityNotInTenant_Returns404(t *testing.T) {
	resolver := &fakeComponentVulnResolver{ids: nil}
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: resolver,
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0103",
	})
	if err == nil {
		t.Fatalf("expected error when no components are linked to the vulnerability")
	}
	if !errors.Is(err, ErrVulnerabilityNotInTenant) {
		t.Errorf("error %v should wrap ErrVulnerabilityNotInTenant", err)
	}
	if got := len(drafts.inserted); got != 0 {
		t.Errorf("expected no draft persisted on 404, got %d", got)
	}
}

// TestRunner_Run_AIDisabled_PersistsUnderInvestigationDraft verifies F4:
// a DisabledProvider triggers a server-side under_investigation draft
// rather than bubbling a 503 up to the CLI. Evidence carries the
// "ai_disabled" sentinel and the audit row uses action
// `vex_draft_ai_disabled` so compliance reviewers can distinguish
// AI-skipped drafts from real AI verdicts.
func TestRunner_Run_AIDisabled_PersistsUnderInvestigationDraft(t *testing.T) {
	tenantID := uuid.New()
	componentID := uuid.New()

	disabled := &llm.DisabledProvider{Reason: "BYOK key not configured"}
	drafts := &fakeVexDraftStore{}
	audit := &fakeAuditWriter{}
	llmCalls := &fakeLLMCallWriter{}
	advisories := &fakeAdvisoryReader{}
	reach := &fakeReachabilityReader{}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: advisories,
		Reachability: reach, LLMCalls: llmCalls,
		Audit: audit, Provider: disabled, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0104"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: tenantID, ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0104",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v (AI-disabled path must succeed with a draft, not return an error)", err)
	}
	if res == nil || !res.AIDisabled {
		t.Fatalf("expected RunResult.AIDisabled=true; got %+v", res)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 under_investigation draft, got %d", got)
	}
	d := drafts.inserted[0]
	if d.State != string(StateUnderInvestigation) {
		t.Errorf("state = %q, want under_investigation", d.State)
	}
	if d.Confidence == nil || *d.Confidence != 0.0 {
		t.Errorf("confidence = %v, want 0.0 pointer", d.Confidence)
	}
	if d.Provider != "disabled" {
		t.Errorf("draft.Provider = %q, want disabled", d.Provider)
	}
	// Evidence must carry the ai_disabled kind sentinel so the UI can
	// distinguish "AI skipped" from "AI rendered an under_investigation".
	if !strings.Contains(string(d.Evidence), "ai_disabled") {
		t.Errorf("evidence missing ai_disabled marker: %s", string(d.Evidence))
	}
	// No LLM call must be attempted on the AI-disabled path — that would
	// just waste a network round-trip.
	if got := len(llmCalls.records); got != 0 {
		t.Errorf("expected 0 llm_calls records on AI-disabled path, got %d", got)
	}
	if got := len(audit.entries); got != 1 {
		t.Fatalf("expected 1 audit entry, got %d", got)
	}
	if audit.entries[0].Action != AuditActionVexDraftAIDisabled {
		t.Errorf("audit action = %s, want %s", audit.entries[0].Action, AuditActionVexDraftAIDisabled)
	}
}

// TestRunner_Run_CallerSuppliedComponentIDOutsideVulnerabilityScope_Rejected
// pins the F6 contract (Codex M1 round 2): when a caller supplies a
// ComponentID that is NOT among the (tenant, project, vulnerability) →
// []component_id set resolved by ComponentVulnerabilityResolver, the
// runner MUST refuse to persist the draft and return
// ErrComponentNotInVulnerabilityScope. The handler maps this to 404.
//
// Without the F6 fix vex_drafts (which stores project_id / component_id
// / vulnerability_id as soft references, no composite FK) would happily
// accept a drift draft pointing at a stranger component from a
// neighbouring project — silently bypassing tenant project membership.
func TestRunner_Run_CallerSuppliedComponentIDOutsideVulnerabilityScope_Rejected(t *testing.T) {
	// The vulnerability links to component c1 in this project; the caller
	// (maliciously or buggily) supplies stranger component c2 instead.
	c1 := uuid.New()
	stranger := uuid.New()
	resolver := &fakeComponentVulnResolver{ids: []uuid.UUID{c1}}

	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}
	audit := &fakeAuditWriter{}
	llmCalls := &fakeLLMCallWriter{}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: llmCalls,
		Audit: audit, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: resolver,
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0200"),
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0200",
		ComponentID: &stranger,
	})
	if err == nil {
		t.Fatalf("expected error when caller supplies component_id outside the vulnerability scope")
	}
	if !errors.Is(err, ErrComponentNotInVulnerabilityScope) {
		t.Errorf("error %v should wrap ErrComponentNotInVulnerabilityScope", err)
	}
	if got := len(drafts.inserted); got != 0 {
		t.Errorf("expected no draft persisted on rejection, got %d", got)
	}
	if got := len(llmCalls.records); got != 0 {
		t.Errorf("expected no llm_calls persisted on rejection (provider must never run), got %d", got)
	}
	if got := len(audit.entries); got != 0 {
		t.Errorf("expected no audit row on rejection, got %d", got)
	}
	if resolver.called != 1 {
		t.Errorf("resolver.called = %d, want 1 (membership check must consult the resolver)", resolver.called)
	}
}

// TestRunner_Run_CallerSuppliedComponentIDInScope_Accepted is the
// positive companion to the F6 rejection test: when the caller-supplied
// ComponentID IS in the resolved set, the runner accepts it and creates
// exactly one draft for that component (no fan-out across the other
// components in scope).
func TestRunner_Run_CallerSuppliedComponentIDInScope_Accepted(t *testing.T) {
	c1, c2 := uuid.New(), uuid.New()
	resolver := &fakeComponentVulnResolver{ids: []uuid.UUID{c1, c2}}
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: resolver,
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0201"),
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0201",
		ComponentID: &c1,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 draft (single-component scope), got %d", got)
	}
	if drafts.inserted[0].ComponentID != c1 {
		t.Errorf("draft.ComponentID = %v, want %v", drafts.inserted[0].ComponentID, c1)
	}
}

// TestRunner_Run_AIDisabled_FanOutAcrossComponents combines F3+F4: when
// AI is disabled AND multiple components are affected, the runner must
// still create one under_investigation draft per component so the audit
// trail covers every (component, vuln) pair.
func TestRunner_Run_AIDisabled_FanOutAcrossComponents(t *testing.T) {
	c1, c2 := uuid.New(), uuid.New()
	resolver := &fakeComponentVulnResolver{ids: []uuid.UUID{c1, c2}}
	disabled := &llm.DisabledProvider{Reason: "BYOK key not configured"}
	drafts := &fakeVexDraftStore{}
	audit := &fakeAuditWriter{}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: audit, Provider: disabled, Threshold: 0.7,
		ComponentVulnerabilities: resolver,
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0105"),
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0105",
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 2 {
		t.Fatalf("expected 2 under_investigation drafts (one per component), got %d", got)
	}
	if got := len(audit.entries); got != 2 {
		t.Errorf("expected 2 audit entries, got %d", got)
	}
	for _, a := range audit.entries {
		if a.Action != AuditActionVexDraftAIDisabled {
			t.Errorf("audit action = %s, want %s", a.Action, AuditActionVexDraftAIDisabled)
		}
	}
}

// ----------------------------------------------------------------------------
// Fan-out reachability FK regression (Codex M1 round 3 #F11)
// ----------------------------------------------------------------------------
//
// Until the F11 fix, runner.Run() computed `reachFK` once from
// reach[0].ID before the component loop and assigned that same FK to
// every fan-out draft. With multiple components affected by the same
// vulnerability — each with its own reachability_results row — this
// pointed all of component B / C / ...'s drafts at component A's
// evidence row. The draft viewer then surfaced the wrong "imported but
// unreachable from main()" rationale for components where the
// reachability analyser reached the opposite conclusion.
//
// The contract the runner now enforces:
//   - Build a map[component_id]reachability_result_id from the fetched
//     reachability rows.
//   - For each fan-out component, look up its FK from the map; if no
//     matching reachability row exists, the draft's
//     ReachabilityResultID stays nil (NOT pointing at a stranger).

func TestRunner_Run_FanOut_PerComponentReachabilityFK(t *testing.T) {
	c1 := uuid.New()
	c2 := uuid.New()
	c3 := uuid.New() // no reachability row — FK must stay nil

	reachA := uuid.New()
	reachB := uuid.New()
	cve := "CVE-2026-0600"

	resolver := &fakeComponentVulnResolver{ids: []uuid.UUID{c1, c2, c3}}
	reach := &fakeReachabilityReader{rows: []ReachabilityRow{
		{ID: reachA, ComponentID: c1, CVEID: cve, Ecosystem: "go", Status: "import_only"},
		{ID: reachB, ComponentID: c2, CVEID: cve, Ecosystem: "go", Status: "reachable"},
		// c3 has no reachability row on purpose.
	}}
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}

	r := NewRunner(RunnerConfig{
		Drafts:                   drafts,
		Advisories:               &fakeAdvisoryReader{},
		Reachability:             reach,
		LLMCalls:                 &fakeLLMCallWriter{},
		Audit:                    &fakeAuditWriter{},
		Provider:                 stub,
		Threshold:                0.7,
		ComponentVulnerabilities: resolver,
		VulnerabilityCVE:         okVulnCVE(cve),
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: cve,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 3 {
		t.Fatalf("expected 3 fan-out drafts, got %d", got)
	}

	// Index by component_id so the assertion is order-independent.
	byComp := map[uuid.UUID]repository.VEXDraft{}
	for _, d := range drafts.inserted {
		byComp[d.ComponentID] = d
	}

	// c1 must point at reachA — NOT reachB and NOT nil.
	if d, ok := byComp[c1]; !ok {
		t.Fatalf("missing draft for component c1")
	} else if d.ReachabilityResultID == nil || *d.ReachabilityResultID != reachA {
		t.Errorf("c1 draft ReachabilityResultID = %v, want %v", uuidValOrNil(d.ReachabilityResultID), reachA)
	}

	// c2 must point at reachB — NOT reachA (the pre-F11 bug). This is
	// the load-bearing assertion: pre-fix, c2's FK was reachA because
	// reachFK was sampled from reach[0] before the loop.
	if d, ok := byComp[c2]; !ok {
		t.Fatalf("missing draft for component c2")
	} else if d.ReachabilityResultID == nil || *d.ReachabilityResultID != reachB {
		t.Errorf("c2 draft ReachabilityResultID = %v, want %v (pre-F11 bug would surface reachA=%v here)",
			uuidValOrNil(d.ReachabilityResultID), reachB, reachA)
	}

	// c3 has no reachability row, so its FK MUST be nil. Pre-F11, it
	// would also have pointed at reachA.
	if d, ok := byComp[c3]; !ok {
		t.Fatalf("missing draft for component c3")
	} else if d.ReachabilityResultID != nil {
		t.Errorf("c3 draft ReachabilityResultID = %v, want nil (no reachability row for c3; must NOT borrow another component's FK)",
			*d.ReachabilityResultID)
	}
}

// uuidValOrNil formats a *uuid.UUID for assertion messages without
// nil-deref panics.
func uuidValOrNil(p *uuid.UUID) string {
	if p == nil {
		return "<nil>"
	}
	return p.String()
}

// ----------------------------------------------------------------------------
// Caller-supplied cve_id bypass regression (Codex M1 round 4 #F12)
// ----------------------------------------------------------------------------
//
// Until the F12 fix, runner.Run accepted both VulnerabilityID and CVEID
// from the request, validated VulnerabilityID against the (tenant,
// project) graph via ComponentVulnerabilityResolver, then used the
// caller-supplied CVEID to fetch advisory_excerpts and reachability_results
// and to populate the draft's cve_id column. A caller who knew an
// in-scope vulnerability_id could pair it with an arbitrary CVE-XXXX-YYYY
// string and have the runner build prompts + persist drafts using
// stranger evidence — the draft's vulnerability_id and cve_id ended up
// pointing at different vulnerabilities, and the LLM prompt was assembled
// from advisory text that had nothing to do with the targeted vuln.
//
// The contract the runner now enforces:
//
//   1. Run consults VulnerabilityCVELookup.GetCVEIDByID(vulnerability_id)
//      after resolveComponentIDs has vouched for tenant scope.
//   2. If the resolved cve_id disagrees with RunInput.CVEID, Run returns
//      a wrapped ErrCVEIDMismatch. No advisory / reachability fetch, no
//      LLM call, no draft INSERT, no llm_calls INSERT, no audit row.
//   3. On match, Run uses the resolved cve_id for every downstream
//      access (advisory_excerpts fetch, reachability fetch, draft
//      column, audit details) so the supplied value cannot drift out
//      through a code path that re-uses RunInput.CVEID.

func TestRunner_Run_MismatchedCVEID_Rejected(t *testing.T) {
	// Vulnerability A is in scope (resolver knows it links to componentID),
	// but the caller supplies CVE-2024-9999 while the authoritative cve_id
	// for that vulnerability is CVE-2024-1111 — classic F12 bypass attempt.
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}
	audit := &fakeAuditWriter{}
	llmCalls := &fakeLLMCallWriter{}
	advisories := &fakeAdvisoryReader{}
	reach := &fakeReachabilityReader{}
	vulnLookup := &fakeVulnerabilityCVELookup{cveID: "CVE-2024-1111"}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: advisories,
		Reachability: reach, LLMCalls: llmCalls,
		Audit: audit, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         vulnLookup,
	})

	vulnID := uuid.New()
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: vulnID,
		CVEID:           "CVE-2024-9999", // attacker-supplied, does NOT match
		ComponentID:     &componentID,
	})
	if err == nil {
		t.Fatalf("Run must reject mismatched caller-supplied cve_id (F12: caller paired in-scope vuln id with stranger CVE)")
	}
	if !errors.Is(err, ErrCVEIDMismatch) {
		t.Errorf("error %v should wrap ErrCVEIDMismatch", err)
	}
	// The lookup MUST have been consulted exactly once with the supplied
	// vulnerability_id — proves the runner is not skipping the check.
	if vulnLookup.called != 1 {
		t.Errorf("vulnLookup.called = %d, want 1 (cve re-resolve must consult the lookup)", vulnLookup.called)
	}
	if vulnLookup.gotVuln != vulnID {
		t.Errorf("vulnLookup.gotVuln = %v, want %v (lookup must be by RunInput.VulnerabilityID)", vulnLookup.gotVuln, vulnID)
	}
	// Nothing else may have happened — the rejection MUST land before
	// the LLM call, the draft INSERT, and the audit write.
	if got := len(drafts.inserted); got != 0 {
		t.Errorf("expected no draft persisted on cve mismatch, got %d", got)
	}
	if got := len(llmCalls.records); got != 0 {
		t.Errorf("expected no llm_calls persisted on cve mismatch (provider must never run), got %d", got)
	}
	if got := len(audit.entries); got != 0 {
		t.Errorf("expected no audit row on cve mismatch, got %d", got)
	}
	if stub.captured.Purpose != "" {
		t.Errorf("LLM provider must not be invoked on cve mismatch (got Purpose=%q)", stub.captured.Purpose)
	}
}

// TestRunner_Run_MatchedCVEID_Accepted is the positive companion to the
// rejection test: when the caller-supplied CVE matches the authoritative
// cve_id for the vulnerability row, Run() proceeds normally and the
// draft persists with the resolved CVE (regression-proof against future
// refactors that might drop the supplied value but accidentally also
// drop the lookup result).
func TestRunner_Run_MatchedCVEID_Accepted(t *testing.T) {
	componentID := uuid.New()
	cve := "CVE-2024-2222"
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	drafts := &fakeVexDraftStore{}
	vulnLookup := &fakeVulnerabilityCVELookup{cveID: cve}

	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         vulnLookup,
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           cve,
		ComponentID:     &componentID,
	})
	if err != nil {
		t.Fatalf("Run error on matched cve_id: %v", err)
	}
	if vulnLookup.called != 1 {
		t.Errorf("vulnLookup.called = %d, want 1", vulnLookup.called)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 draft, got %d", got)
	}
	if drafts.inserted[0].CVEID != cve {
		t.Errorf("draft.CVEID = %q, want %q (draft must carry the authoritative cve)", drafts.inserted[0].CVEID, cve)
	}
}

// TestRunner_Run_MissingVulnerabilityCVELookup_Rejected pins the
// fail-closed contract: when production wiring forgets to supply a
// VulnerabilityCVELookup, the runner refuses to fabricate trust in the
// caller-supplied CVEID. This mirrors the resolveComponentIDs misconfig
// posture and surfaces the misconfig loudly via mapRunnerError's
// "is required" → 400 heuristic.
func TestRunner_Run_MissingVulnerabilityCVELookup_Rejected(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	r := NewRunner(RunnerConfig{
		Drafts: &fakeVexDraftStore{}, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		// VulnerabilityCVE deliberately omitted.
	})
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0300",
		ComponentID: &componentID,
	})
	if err == nil {
		t.Fatalf("expected error when VulnerabilityCVELookup is not wired (fail-closed)")
	}
	if !strings.Contains(err.Error(), "cve lookup") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Tiny helper used by multiple test cases above.
// ----------------------------------------------------------------------------

func jsonResp(t *testing.T, state, just string, conf float64) string {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"state":         state,
		"justification": just,
		"confidence":    conf,
		"detail":        "test rationale",
		"evidence": []map[string]interface{}{
			{"kind": "llm_rationale", "description": "synthetic test evidence", "source": "llm"},
		},
	})
	if err != nil {
		t.Fatalf("jsonResp marshal: %v", err)
	}
	return string(body)
}
