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
}

func (a *fakeAuditWriter) Log(_ context.Context, input *model.CreateAuditLogInput) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, *input)
	return nil
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

func TestRunner_Run_LLMDisabled_PersistsCallWithErrorMessageAndReturnsErr(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{err: &llm.DisabledError{Reason: "BYOK not configured"}}
	llmCalls := &fakeLLMCallWriter{}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: llmCalls,
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
	})
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0004",
		ComponentID: &componentID,
	})
	if err == nil {
		t.Fatalf("expected error when provider is disabled")
	}
	var disabled *llm.DisabledError
	if !errors.As(err, &disabled) {
		t.Errorf("expected wrapped *llm.DisabledError, got %T", err)
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

func TestRunner_Run_MissingComponentID_Returns400(t *testing.T) {
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: jsonResp(t, "not_affected", "code_not_reachable", 0.9)}}
	r := NewRunner(RunnerConfig{
		Drafts: &fakeVexDraftStore{}, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: &fakeLLMCallWriter{},
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
	})
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0099",
		// ComponentID omitted
	})
	if err == nil {
		t.Fatalf("expected error when component_id is missing")
	}
	if !strings.Contains(err.Error(), "component_id is required") {
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
		Detail: "Imported but unreachable",
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
		Decision:            DecisionEdited,
		EditedState:         "affected",
		EditedDetail:        "Human reviewer disagrees with AI; production observed traffic to vulnerable endpoint.",
		Note:                "manual review override",
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
