package cra

// runner_test.go — Wave M2-3 regression coverage for the CRA report
// drafting runner. Mirrors the triage runner test surface so the F1-F26
// fix patterns established in M1 are pinned for CRA too:
//
//   TestRunner_Run_HappyPaths_AllReportTypeLangCombos  — 3 report × 2 lang = 6
//   TestRunner_Run_AIDisabled_PersistsPlaceholderDraft — F4
//   TestRunner_Run_PerTenantProviderResolved           — F2
//   TestRunner_Run_Stage3_TOCTOU_RevalidatesCVE        — F19 TOCTOU
//   TestRunner_Run_MismatchedCVEID_Rejected            — F12
//   TestRunner_Run_AutoPicksApprovedVEXDraft           — auto-source
//   TestRunner_Run_SourceVEXDraftCrossProject_Rejected — F7/F8/F9
//
// Fakes are in-memory and satisfy the narrow interfaces declared in
// runner.go so the tests stay pure Go (no Postgres). The production
// wiring (Wave M2-4) passes the concrete *repository.* types through
// the same interfaces.

import (
	"context"
	"database/sql"
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
// In-memory fakes
// ----------------------------------------------------------------------------

type fakeVEXDraftReader struct {
	mu       sync.Mutex
	byID     map[uuid.UUID]repository.VEXDraft
	byProj   []repository.VEXDraft // for ListByProject
	getErr   error
	listErr  error
	getCalls int
	listCnt  int
}

func (f *fakeVEXDraftReader) Get(_ context.Context, tenantID, draftID uuid.UUID) (*repository.VEXDraft, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	d, ok := f.byID[draftID]
	if !ok {
		return nil, nil
	}
	if d.TenantID != tenantID {
		return nil, nil
	}
	dup := d
	return &dup, nil
}

func (f *fakeVEXDraftReader) ListByProject(_ context.Context, tenantID, projectID uuid.UUID, filter repository.VEXDraftListFilter) ([]repository.VEXDraft, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCnt++
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]repository.VEXDraft, 0)
	for _, d := range f.byProj {
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

type fakeAdvisoryReader struct {
	rows []repository.AdvisoryExcerpt
	err  error
}

func (f *fakeAdvisoryReader) GetByCVE(_ context.Context, _ uuid.UUID, cveID string) ([]repository.AdvisoryExcerpt, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]repository.AdvisoryExcerpt, 0)
	for _, a := range f.rows {
		if a.CVEID == cveID {
			out = append(out, a)
		}
	}
	return out, nil
}

type fakeReachabilityReader struct {
	rows []repository.ReachabilityResult
	err  error
}

func (f *fakeReachabilityReader) ListByProject(_ context.Context, _ uuid.UUID, _ uuid.UUID, filter repository.ReachabilityResultListFilter) ([]repository.ReachabilityResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]repository.ReachabilityResult, 0)
	for _, rr := range f.rows {
		if filter.CVEID != "" && rr.CVEID != filter.CVEID {
			continue
		}
		out = append(out, rr)
	}
	return out, nil
}

type fakeCRAReportWriter struct {
	mu       sync.Mutex
	inserted []repository.CRAReport
	err      error
}

func (f *fakeCRAReportWriter) Insert(_ context.Context, c *repository.CRAReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	f.inserted = append(f.inserted, *c)
	return nil
}

type fakeLLMCallWriter struct {
	mu      sync.Mutex
	records []repository.LLMCall
	err     error
}

func (f *fakeLLMCallWriter) Insert(_ context.Context, c *repository.LLMCall) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.records = append(f.records, *c)
	return nil
}

type fakeAuditWriter struct {
	mu      sync.Mutex
	entries []model.CreateAuditLogInput
	err     error
}

func (f *fakeAuditWriter) Log(_ context.Context, input *model.CreateAuditLogInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, *input)
	return f.err
}

// fakeVulnCVE returns sequenced cve_ids so a Stage 3 TOCTOU test can
// have the first call (Stage 1) succeed and the second call (Stage 3)
// return an error (vulnerability gone). When seq is non-nil it overrides
// the constant cveID and err.
type fakeVulnCVE struct {
	mu      sync.Mutex
	cveID   string
	err     error
	called  int
	gotVuln uuid.UUID
	seq     []vulnCVEResult
}

type vulnCVEResult struct {
	cveID string
	err   error
}

func (f *fakeVulnCVE) GetCVEIDByID(_ context.Context, vulnID uuid.UUID) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called++
	f.gotVuln = vulnID
	if f.seq != nil {
		idx := f.called - 1
		if idx >= len(f.seq) {
			idx = len(f.seq) - 1
		}
		return f.seq[idx].cveID, f.seq[idx].err
	}
	return f.cveID, f.err
}

// okVulnCVE returns a permissive lookup matching the supplied CVE id.
func okVulnCVE(cve string) *fakeVulnCVE {
	return &fakeVulnCVE{cveID: cve}
}

type fakeProviderResolver struct {
	mu        sync.Mutex
	called    int
	gotTenant uuid.UUID
	provider  llm.Provider
	err       error
}

func (r *fakeProviderResolver) resolve(_ context.Context, tenantID uuid.UUID) (llm.Provider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.called++
	r.gotTenant = tenantID
	return r.provider, r.err
}

// ----------------------------------------------------------------------------
// Stub LLM provider — mirrors triage stubProvider but lives in cra package
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

// canonicalLLMResponse returns a JSON body matching craLLMFields with
// every field populated so the rendered template exercises every
// optional block.
func canonicalLLMResponse(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(craLLMFields{
		VulnerabilitySummary:    "Remote attacker can corrupt heap via malformed input.",
		VulnerabilityDetail:     "The parser fails to validate length before memcpy.",
		RootCause:               "Missing bounds check in parse_packet().",
		ExploitationStatus:      "no known exploitation",
		ExploitationEvidence:    "CISA KEV does not list this CVE as of report time.",
		PreliminaryImpactScope:  "Affects all shipped firmware versions 1.x and 2.x.",
		ImmediateMitigations:    "Disable the network listener until the patch is applied.",
		MitigationSteps:         []string{"Apply patch 1.2.3", "Restart service"},
		RemediationPlan:         "Patch released in version 1.2.3 on 2026-06-25.",
		PermanentRemediation:    "Rewrote parse_packet() with explicit length validation.",
		PreventionMeasures:      []string{"Added fuzzing coverage for parser inputs"},
		UserNotificationSummary: "Email notice sent to all registered operators on 2026-06-25.",
	})
	if err != nil {
		t.Fatalf("failed to marshal canonical LLM response: %v", err)
	}
	return string(body)
}

// makeApprovedVEXDraft constructs an approved vex_drafts row that the
// runner can use as a source.
func makeApprovedVEXDraft(tenantID, projectID, vulnID, componentID uuid.UUID, cveID string) repository.VEXDraft {
	conf := 0.9
	return repository.VEXDraft{
		ID:              uuid.New(),
		TenantID:        tenantID,
		ProjectID:       projectID,
		ComponentID:     componentID,
		VulnerabilityID: vulnID,
		CVEID:           cveID,
		State:           "not_affected",
		Justification:   "code_not_reachable",
		Detail:          "Vulnerable symbol imported but unreachable.",
		Confidence:      &conf,
		Provider:        "stub",
		Model:           "stub-model",
		Evidence:        json.RawMessage(`[{"kind":"symbol_ref","symbol":"x.Foo"}]`),
		Decision:        "approved",
		CreatedAt:       time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC),
		UpdatedAt:       time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC),
	}
}

// newTestRunner wires a Runner with reasonable defaults for the test.
// Callers can override any of the fakes by mutating the returned
// pointers before calling Run.
type testHarness struct {
	runner      *Runner
	tenantID    uuid.UUID
	projectID   uuid.UUID
	vulnID      uuid.UUID
	componentID uuid.UUID
	cveID       string
	sourceDraft repository.VEXDraft
	drafts      *fakeVEXDraftReader
	advisories  *fakeAdvisoryReader
	reach       *fakeReachabilityReader
	craReports  *fakeCRAReportWriter
	llmCalls    *fakeLLMCallWriter
	audit       *fakeAuditWriter
	provider    *stubProvider
	vulnCVE     *fakeVulnCVE
	clockTime   time.Time
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	componentID := uuid.New()
	cveID := "CVE-2026-3100"

	sourceDraft := makeApprovedVEXDraft(tenantID, projectID, vulnID, componentID, cveID)

	drafts := &fakeVEXDraftReader{
		byID: map[uuid.UUID]repository.VEXDraft{sourceDraft.ID: sourceDraft},
	}
	advisories := &fakeAdvisoryReader{rows: []repository.AdvisoryExcerpt{{
		ID:         uuid.New(),
		TenantID:   tenantID,
		CVEID:      cveID,
		Source:     "ghsa",
		RawExcerpt: "GHSA advisory excerpt for " + cveID,
	}}}
	reach := &fakeReachabilityReader{rows: []repository.ReachabilityResult{{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ProjectID:   projectID,
		ComponentID: componentID,
		CVEID:       cveID,
		Ecosystem:   "go",
		Status:      "import_only",
	}}}
	craReports := &fakeCRAReportWriter{}
	llmCalls := &fakeLLMCallWriter{}
	audit := &fakeAuditWriter{}
	provider := &stubProvider{resp: &llm.CompleteResponse{
		Content:      canonicalLLMResponse(t),
		InputTokens:  120,
		OutputTokens: 80,
		FinishReason: "stop",
	}}
	vulnCVE := okVulnCVE(cveID)

	r := NewRunner(RunnerConfig{
		VEXDrafts:           drafts,
		AdvisoryExcerpts:    advisories,
		ReachabilityResults: reach,
		CRAReports:          craReports,
		LLMCalls:            llmCalls,
		VulnerabilityCVE:    vulnCVE,
		Audit:               audit,
		Provider:            provider,
		Clock:               fixedClock(now),
		GeneratedBy:         "SBOMHub/test",
	})

	return &testHarness{
		runner:      r,
		tenantID:    tenantID,
		projectID:   projectID,
		vulnID:      vulnID,
		componentID: componentID,
		cveID:       cveID,
		sourceDraft: sourceDraft,
		drafts:      drafts,
		advisories:  advisories,
		reach:       reach,
		craReports:  craReports,
		llmCalls:    llmCalls,
		audit:       audit,
		provider:    provider,
		vulnCVE:     vulnCVE,
		clockTime:   now,
	}
}

func (h *testHarness) baseInput() RunInput {
	uid := uuid.New()
	return RunInput{
		TenantID:         h.tenantID,
		ProjectID:        h.projectID,
		VulnerabilityID:  h.vulnID,
		CVEID:            h.cveID,
		SourceVEXDraftID: &h.sourceDraft.ID,
		UserID:           &uid,
		ProductName:      "AcmeRouter",
		ProductVersion:   "1.0.0",
		VendorName:       "Acme Inc.",
		ReporterName:     "Taro Yamada",
		ReporterRole:     "Security Officer",
		ContactEmail:     "psirt@example.com",
		AwarenessTime:    "2026-06-24T00:00:00Z",
		IPAddress:        "127.0.0.1",
		UserAgent:        "go-test",
	}
}

// ----------------------------------------------------------------------------
// Test 1: happy paths × 6 (3 report_type × 2 lang)
// ----------------------------------------------------------------------------

func TestRunner_Run_HappyPaths_AllReportTypeLangCombos(t *testing.T) {
	for _, rt := range SupportedReportTypes() {
		for _, lg := range SupportedLangs() {
			rt, lg := rt, lg
			t.Run(string(rt)+"_"+string(lg), func(t *testing.T) {
				h := newTestHarness(t)
				in := h.baseInput()
				in.ReportType = rt
				in.Lang = lg

				res, err := h.runner.Run(context.Background(), in)
				if err != nil {
					t.Fatalf("Run error: %v", err)
				}
				if res == nil || res.Report == nil {
					t.Fatal("expected non-nil result + report")
				}
				if res.AIDisabled {
					t.Errorf("AIDisabled should be false on happy path")
				}
				if got := len(h.craReports.inserted); got != 1 {
					t.Fatalf("expected 1 cra_reports insert, got %d", got)
				}
				r := h.craReports.inserted[0]
				if r.TenantID != h.tenantID {
					t.Errorf("tenant_id mismatch")
				}
				if r.ProjectID != h.projectID {
					t.Errorf("project_id mismatch")
				}
				if r.VulnerabilityID != h.vulnID {
					t.Errorf("vulnerability_id mismatch")
				}
				if r.CVEID != h.cveID {
					t.Errorf("cve_id mismatch: got %q", r.CVEID)
				}
				if r.ReportType != string(rt) {
					t.Errorf("report_type = %q, want %q", r.ReportType, rt)
				}
				if r.Lang != string(lg) {
					t.Errorf("lang = %q, want %q", r.Lang, lg)
				}
				if r.State != "draft" {
					t.Errorf("state = %q, want draft", r.State)
				}
				if r.Decision != "pending" {
					t.Errorf("decision = %q, want pending", r.Decision)
				}
				if r.Provider != "stub" {
					t.Errorf("provider = %q, want stub", r.Provider)
				}
				if r.SourceVEXDraftID == nil || *r.SourceVEXDraftID != h.sourceDraft.ID {
					t.Errorf("source_vex_draft_id mismatch")
				}
				if r.LLMCallID == nil || *r.LLMCallID == uuid.Nil {
					t.Errorf("llm_call_id should be set")
				}
				if r.DraftText == "" {
					t.Errorf("draft_text should not be empty")
				}
				// Sanity: language-specific marker in the rendered text.
				if lg == LangJA && !strings.Contains(r.DraftText, "CRA") {
					t.Errorf("ja draft missing CRA marker: %s", r.DraftText[:200])
				}
				if lg == LangEN && !strings.Contains(r.DraftText, "CRA") {
					t.Errorf("en draft missing CRA marker: %s", r.DraftText[:200])
				}
				// Evidence array must be a non-empty JSON array (DB CHECK
				// invariant — caught by repository.Insert validator if
				// missed).
				var evid []evidenceEntry
				if err := json.Unmarshal(r.Evidence, &evid); err != nil {
					t.Fatalf("evidence is not a JSON array: %v", err)
				}
				if len(evid) == 0 {
					t.Errorf("evidence must be non-empty")
				}
				// LLM call recorded.
				if got := len(h.llmCalls.records); got != 1 {
					t.Fatalf("expected 1 llm_calls record, got %d", got)
				}
				lc := h.llmCalls.records[0]
				if lc.Purpose != LLMCallPurposeCRADraft {
					t.Errorf("llm_calls.purpose = %q, want %q", lc.Purpose, LLMCallPurposeCRADraft)
				}
				if lc.CRAReportID == nil || *lc.CRAReportID != r.ID {
					t.Errorf("llm_calls.cra_report_id should join back to cra_report.id")
				}
				if lc.TriageTargetCVE != h.cveID {
					t.Errorf("llm_calls.triage_target_cve mismatch")
				}
				// Audit row.
				if got := len(h.audit.entries); got != 1 {
					t.Fatalf("expected 1 audit entry, got %d", got)
				}
				a := h.audit.entries[0]
				if a.Action != AuditActionCRAReportAIGenerated {
					t.Errorf("audit action = %q, want %q", a.Action, AuditActionCRAReportAIGenerated)
				}
				if a.ResourceType != model.ResourceCRAReport {
					t.Errorf("audit resource_type = %q, want %q", a.ResourceType, model.ResourceCRAReport)
				}
				// Provider request shape: JSONMode true, system prompt
				// references CRA.
				if !h.provider.captured.JSONMode {
					t.Errorf("expected JSONMode=true on LLM request")
				}
				if !strings.Contains(h.provider.captured.System, "CRA") {
					t.Errorf("system prompt missing CRA marker")
				}
			})
		}
	}
}

// ----------------------------------------------------------------------------
// Test 2: AI-disabled fallback (F4)
// ----------------------------------------------------------------------------

func TestRunner_Run_AIDisabled_PersistsPlaceholderDraft(t *testing.T) {
	h := newTestHarness(t)
	// Swap in a DisabledProvider via ProviderResolver — runner's
	// resolveProvider treats this as the AI-disabled path.
	disabled := &llm.DisabledProvider{Reason: "BYOK key not configured"}
	resolver := &fakeProviderResolver{provider: disabled}
	h.runner.providerResolver = resolver.resolve

	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA

	res, err := h.runner.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v (AI-disabled path must succeed with a draft)", err)
	}
	if res == nil || !res.AIDisabled {
		t.Fatalf("expected RunResult.AIDisabled=true; got %+v", res)
	}
	if got := len(h.craReports.inserted); got != 1 {
		t.Fatalf("expected 1 cra_reports insert, got %d", got)
	}
	r := h.craReports.inserted[0]
	if r.Provider != "disabled" {
		t.Errorf("provider = %q, want disabled", r.Provider)
	}
	if r.Model != "" {
		t.Errorf("model = %q, want empty (DisabledProvider.Model returns \"\")", r.Model)
	}
	// LLM call MUST NOT have been recorded (no call was made).
	if got := len(h.llmCalls.records); got != 0 {
		t.Errorf("expected 0 llm_calls records on AI-disabled path, got %d", got)
	}
	// Provider must NOT have been invoked.
	if h.provider.captured.Purpose != "" {
		t.Errorf("expected default provider to NOT be called on AI-disabled path (got Purpose=%q)", h.provider.captured.Purpose)
	}
	// Evidence must carry ai_disabled marker.
	if !strings.Contains(string(r.Evidence), "ai_disabled") {
		t.Errorf("evidence missing ai_disabled marker: %s", string(r.Evidence))
	}
	// Audit action MUST be the distinct ai_disabled flavour.
	if got := len(h.audit.entries); got != 1 {
		t.Fatalf("expected 1 audit entry, got %d", got)
	}
	if h.audit.entries[0].Action != AuditActionCRAReportAIDisabled {
		t.Errorf("audit action = %q, want %q", h.audit.entries[0].Action, AuditActionCRAReportAIDisabled)
	}
}

// ----------------------------------------------------------------------------
// Test 3: per-tenant provider resolve (F2)
// ----------------------------------------------------------------------------

func TestRunner_Run_PerTenantProviderResolved(t *testing.T) {
	h := newTestHarness(t)

	// Tenant-scoped provider returns a different JSON body so the test
	// can prove the runner used it (not the env-default stub).
	tenantStub := &stubProvider{resp: &llm.CompleteResponse{
		Content: `{"vulnerability_summary":"tenant-side summary"}`,
	}}
	resolver := &fakeProviderResolver{provider: tenantStub}
	h.runner.providerResolver = resolver.resolve

	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangEN

	_, err := h.runner.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if resolver.called != 1 {
		t.Errorf("ProviderResolver called %d times, want 1", resolver.called)
	}
	if resolver.gotTenant != h.tenantID {
		t.Errorf("ProviderResolver got tenant %v, want %v", resolver.gotTenant, h.tenantID)
	}
	if tenantStub.captured.Purpose != LLMCallPurposeCRADraft {
		t.Errorf("expected tenant-scoped provider to receive the LLM request (got Purpose=%q)", tenantStub.captured.Purpose)
	}
	if h.provider.captured.Purpose != "" {
		t.Errorf("default provider should NOT have been called (got Purpose=%q)", h.provider.captured.Purpose)
	}
	// The tenant-scoped JSON should have flowed into the rendered text.
	if got := len(h.craReports.inserted); got != 1 {
		t.Fatalf("expected 1 cra_reports insert, got %d", got)
	}
	if !strings.Contains(h.craReports.inserted[0].DraftText, "tenant-side summary") {
		t.Errorf("rendered draft missing tenant-side summary: %s", h.craReports.inserted[0].DraftText[:200])
	}
}

// ----------------------------------------------------------------------------
// Test 4: TOCTOU re-validate at Stage 3 (vulnerability disappeared)
// ----------------------------------------------------------------------------

func TestRunner_Run_Stage3_TOCTOU_RevalidatesCVE(t *testing.T) {
	h := newTestHarness(t)

	// Stage 1: returns the correct cve_id so the runner proceeds.
	// Stage 3: returns sql.ErrNoRows (vulnerability deleted while the
	//          LLM was running). The runner must surface the error and
	//          must NOT persist a cra_report row.
	h.vulnCVE.seq = []vulnCVEResult{
		{cveID: h.cveID, err: nil},
		{cveID: "", err: sql.ErrNoRows},
	}

	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA

	_, err := h.runner.Run(context.Background(), in)
	if err == nil {
		t.Fatalf("expected error when vulnerability disappears between Stage 1 and Stage 3")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		// resolveAuthoritativeCVEID wraps sql.ErrNoRows with fmt.Errorf
		// %w, so errors.Is should still find it. If the wrap chain
		// changes, the test will surface that explicitly.
		t.Errorf("error chain should include sql.ErrNoRows; got %v", err)
	}
	if got := len(h.craReports.inserted); got != 0 {
		t.Errorf("expected no cra_reports insert on TOCTOU rejection, got %d", got)
	}
	// LLM call may have already happened in Stage 2 — but the runner
	// rolls back in Stage 3 before llm_calls.Insert fires, so the
	// llm_calls table should also be empty.
	if got := len(h.llmCalls.records); got != 0 {
		t.Errorf("expected no llm_calls records on TOCTOU rejection (Stage 3 rolls back), got %d", got)
	}
	if got := len(h.audit.entries); got != 0 {
		t.Errorf("expected no audit row on TOCTOU rejection, got %d", got)
	}
	// vulnCVE lookup must have been consulted twice (Stage 1 + Stage 3).
	if h.vulnCVE.called != 2 {
		t.Errorf("vulnCVE.called = %d, want 2 (Stage 1 + Stage 3 TOCTOU)", h.vulnCVE.called)
	}
}

// ----------------------------------------------------------------------------
// Test 5: cve_id mismatch rejected at Stage 1 (F12)
// ----------------------------------------------------------------------------

func TestRunner_Run_MismatchedCVEID_Rejected(t *testing.T) {
	h := newTestHarness(t)
	// Authoritative cve_id is CVE-2026-3100 (set by newTestHarness), but
	// the caller supplies a stranger CVE id. The runner must reject
	// before fetching advisories / running the LLM.
	in := h.baseInput()
	in.CVEID = "CVE-2099-9999"
	in.ReportType = ReportTypeDetailedNotification
	in.Lang = LangEN

	_, err := h.runner.Run(context.Background(), in)
	if err == nil {
		t.Fatalf("expected error on cve_id mismatch (F12)")
	}
	if !errors.Is(err, ErrCVEIDMismatch) {
		t.Errorf("error %v should wrap ErrCVEIDMismatch", err)
	}
	if got := len(h.craReports.inserted); got != 0 {
		t.Errorf("expected no cra_reports insert on cve mismatch, got %d", got)
	}
	if got := len(h.llmCalls.records); got != 0 {
		t.Errorf("expected no llm_calls on cve mismatch, got %d", got)
	}
	if got := len(h.audit.entries); got != 0 {
		t.Errorf("expected no audit row on cve mismatch, got %d", got)
	}
	if h.provider.captured.Purpose != "" {
		t.Errorf("provider must not be called on cve mismatch (got Purpose=%q)", h.provider.captured.Purpose)
	}
}

// ----------------------------------------------------------------------------
// Test 6: source vex_draft 未指定で approved な vex_draft を自動取得
// ----------------------------------------------------------------------------

func TestRunner_Run_AutoPicksApprovedVEXDraft(t *testing.T) {
	h := newTestHarness(t)
	// Seed the ListByProject fake with an approved draft for (project, cve).
	approved := h.sourceDraft // already approved by makeApprovedVEXDraft
	h.drafts.byProj = []repository.VEXDraft{approved}
	// Also add a pending draft that the filter MUST exclude.
	pending := makeApprovedVEXDraft(h.tenantID, h.projectID, h.vulnID, h.componentID, h.cveID)
	pending.Decision = "pending"
	h.drafts.byProj = append(h.drafts.byProj, pending)

	in := h.baseInput()
	in.SourceVEXDraftID = nil // ← auto-pick path
	in.ReportType = ReportTypeFinalReport
	in.Lang = LangJA

	res, err := h.runner.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Report.SourceVEXDraftID == nil || *res.Report.SourceVEXDraftID != approved.ID {
		t.Errorf("SourceVEXDraftID = %v, want %v (auto-picked approved draft)", res.Report.SourceVEXDraftID, approved.ID)
	}
	if h.drafts.listCnt != 1 {
		t.Errorf("ListByProject called %d times, want 1", h.drafts.listCnt)
	}
	if h.drafts.getCalls != 0 {
		t.Errorf("Get should NOT have been called when SourceVEXDraftID is nil (got %d calls)", h.drafts.getCalls)
	}
}

// TestRunner_Run_AutoPick_NoApprovedDraft_Rejected pairs with the auto-
// pick happy path: when no approved draft exists for (project, cve),
// the runner returns ErrNoApprovedVEXDraft and persists nothing.
func TestRunner_Run_AutoPick_NoApprovedDraft_Rejected(t *testing.T) {
	h := newTestHarness(t)
	// Empty ListByProject — no approved draft.
	h.drafts.byProj = nil

	in := h.baseInput()
	in.SourceVEXDraftID = nil
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangEN

	_, err := h.runner.Run(context.Background(), in)
	if err == nil {
		t.Fatalf("expected ErrNoApprovedVEXDraft when no approved draft exists")
	}
	if !errors.Is(err, ErrNoApprovedVEXDraft) {
		t.Errorf("error %v should wrap ErrNoApprovedVEXDraft", err)
	}
	if got := len(h.craReports.inserted); got != 0 {
		t.Errorf("expected no cra_reports insert, got %d", got)
	}
}

// ----------------------------------------------------------------------------
// Test 7: source vex_draft cross-project rejected (F7/F8/F9)
// ----------------------------------------------------------------------------

func TestRunner_Run_SourceVEXDraftCrossProject_Rejected(t *testing.T) {
	h := newTestHarness(t)
	// Stranger draft belongs to a DIFFERENT project but same tenant.
	strangerProject := uuid.New()
	stranger := makeApprovedVEXDraft(h.tenantID, strangerProject, h.vulnID, h.componentID, h.cveID)
	h.drafts.byID[stranger.ID] = stranger

	in := h.baseInput()
	in.SourceVEXDraftID = &stranger.ID
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA

	_, err := h.runner.Run(context.Background(), in)
	if err == nil {
		t.Fatalf("expected error when source vex_draft belongs to a different project")
	}
	if !errors.Is(err, ErrSourceVEXDraftCrossProject) {
		t.Errorf("error %v should wrap ErrSourceVEXDraftCrossProject", err)
	}
	if got := len(h.craReports.inserted); got != 0 {
		t.Errorf("expected no cra_reports insert on cross-project rejection, got %d", got)
	}
	if got := len(h.llmCalls.records); got != 0 {
		t.Errorf("expected no llm_calls on cross-project rejection, got %d", got)
	}
	if h.provider.captured.Purpose != "" {
		t.Errorf("provider must not be called on cross-project rejection")
	}
}

// TestRunner_Run_SourceVEXDraftNotFound_Rejected is a small companion
// to the cross-project test: an unknown SourceVEXDraftID surfaces
// ErrSourceVEXDraftNotFound (mapped to 404 by the handler).
func TestRunner_Run_SourceVEXDraftNotFound_Rejected(t *testing.T) {
	h := newTestHarness(t)
	unknown := uuid.New()
	in := h.baseInput()
	in.SourceVEXDraftID = &unknown
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA

	_, err := h.runner.Run(context.Background(), in)
	if err == nil {
		t.Fatalf("expected ErrSourceVEXDraftNotFound on unknown source id")
	}
	if !errors.Is(err, ErrSourceVEXDraftNotFound) {
		t.Errorf("error %v should wrap ErrSourceVEXDraftNotFound", err)
	}
}

// ----------------------------------------------------------------------------
// Test (M2 Codex review #F30): source vex_draft with mismatched CVE id rejected
// ----------------------------------------------------------------------------

// TestRunner_Run_SourceVEXDraftCVEMismatch_Rejected_F30 pins the F30
// fix: when the caller explicitly attaches a source vex_draft whose
// CVE id does NOT match RunInput.CVEID, the runner must reject the
// drafting cycle with ErrSourceVEXDraftCVEMismatch and persist
// nothing. The previous warn-only behaviour let a caller draft a CRA
// report for CVE-X while attaching an approved VEX draft for a
// DIFFERENT CVE (CVE-Y) in the same project — the rendered
// regulatory submission would then claim evidence that did not in
// fact cover the CVE being reported.
func TestRunner_Run_SourceVEXDraftCVEMismatch_Rejected_F30(t *testing.T) {
	h := newTestHarness(t)
	// Make a draft for the SAME project (so the cross-project guard
	// does not fire first), but with a DIFFERENT CVE id.
	mismatched := makeApprovedVEXDraft(h.tenantID, h.projectID, h.vulnID, h.componentID, "CVE-2099-0001")
	h.drafts.byID[mismatched.ID] = mismatched

	in := h.baseInput()
	in.SourceVEXDraftID = &mismatched.ID
	in.CVEID = h.cveID // CVE-2026-3100 — differs from the draft's CVE-2099-0001
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA

	_, err := h.runner.Run(context.Background(), in)
	if err == nil {
		t.Fatalf("F30: expected error when source vex_draft cve_id does not match input cve_id")
	}
	if !errors.Is(err, ErrSourceVEXDraftCVEMismatch) {
		t.Errorf("F30: error %v should wrap ErrSourceVEXDraftCVEMismatch", err)
	}
	if got := len(h.craReports.inserted); got != 0 {
		t.Errorf("F30: expected no cra_reports insert on cve mismatch, got %d", got)
	}
	if got := len(h.llmCalls.records); got != 0 {
		t.Errorf("F30: expected no llm_calls on cve mismatch, got %d", got)
	}
	if got := len(h.audit.entries); got != 0 {
		t.Errorf("F30: expected no audit row on cve mismatch, got %d", got)
	}
	if h.provider.captured.Purpose != "" {
		t.Errorf("F30: provider must not be called on cve mismatch (got Purpose=%q)", h.provider.captured.Purpose)
	}
}

// TestRunner_Run_SourceVEXDraftEmptyCVE_Accepted_F30 documents the
// one carve-out in the F30 guard: a source draft with an empty cve_id
// column is still accepted (the guard's `draft.CVEID != ""` clause).
// Without this carve-out, legacy rows that pre-date the cve_id column
// would be unreachable. TODO(cra): confirm with PM whether empty-CVE
// drafts should also be hard-rejected once the legacy backfill is
// complete; for now the conservative behaviour matches the pre-F30
// allow-on-empty path (carve-out verified still present 2026-07-02,
// M24-3 F359: runner.go's guard reads `draft.CVEID != "" &&
// draft.CVEID != in.CVEID`).
func TestRunner_Run_SourceVEXDraftEmptyCVE_Accepted_F30(t *testing.T) {
	h := newTestHarness(t)
	legacy := makeApprovedVEXDraft(h.tenantID, h.projectID, h.vulnID, h.componentID, "")
	h.drafts.byID[legacy.ID] = legacy

	in := h.baseInput()
	in.SourceVEXDraftID = &legacy.ID
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA

	_, err := h.runner.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("F30 carve-out: empty draft cve_id should NOT trip the mismatch guard; got %v", err)
	}
	if got := len(h.craReports.inserted); got != 1 {
		t.Errorf("F30 carve-out: expected 1 cra_reports insert, got %d", got)
	}
}

// ----------------------------------------------------------------------------
// Test 8: audit failure rolls back Stage 3 (F5 audit-or-nothing)
// ----------------------------------------------------------------------------

func TestRunner_Run_AuditFailure_RollsBackStage3(t *testing.T) {
	h := newTestHarness(t)
	// Inject an audit failure so writeAudit returns an error inside
	// Stage 3. The TxManager (PassthroughTxManager in tests) propagates
	// the error; the test asserts that Run() surfaces it and that the
	// cra_report row that DID land via the fake's Insert is the only
	// in-memory side effect (in production the tx rollback would erase
	// the cra_report INSERT too; the fake cannot model rollback, so we
	// instead pin that the function returned an error which is what
	// drives the rollback in real DB land).
	h.audit.err = errors.New("audit storm")

	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangEN

	_, err := h.runner.Run(context.Background(), in)
	if err == nil {
		t.Fatalf("expected error when audit.Log fails (F5 audit-or-nothing)")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Errorf("error %v should mention audit", err)
	}
}

// ----------------------------------------------------------------------------
// Test (M34-A / F423): awareness_time persistence + parse contract
// ----------------------------------------------------------------------------

// TestRunner_Run_PersistsAwarenessTime_LLMPath pins that the operator-
// attested awareness instant (RunInput.AwarenessTime, RFC3339) is parsed
// and set on the persisted cra_reports row on the LLM path. baseInput
// supplies "2026-06-24T00:00:00Z"; the runner must persist that exact
// instant so the read-time deadline computation has a clock start.
func TestRunner_Run_PersistsAwarenessTime_LLMPath(t *testing.T) {
	h := newTestHarness(t)
	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangEN
	in.AwarenessTime = "2026-06-24T00:00:00Z"

	if _, err := h.runner.Run(context.Background(), in); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(h.craReports.inserted); got != 1 {
		t.Fatalf("expected 1 cra_reports insert, got %d", got)
	}
	got := h.craReports.inserted[0].AwarenessTime
	want := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	if got == nil {
		t.Fatalf("awareness_time not persisted (nil) on LLM path")
	}
	if !got.Equal(want) {
		t.Errorf("awareness_time = %v, want %v", got, want)
	}
}

// TestRunner_Run_PersistsAwarenessTime_AIDisabledPath pins the same
// contract on the AI-disabled path (no provider configured): the
// awareness instant is set on the placeholder draft too.
func TestRunner_Run_PersistsAwarenessTime_AIDisabledPath(t *testing.T) {
	h := newTestHarness(t)
	resolver := &fakeProviderResolver{provider: &llm.DisabledProvider{Reason: "BYOK key not configured"}}
	h.runner.providerResolver = resolver.resolve

	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA
	in.AwarenessTime = "2026-06-24T09:30:00Z"

	res, err := h.runner.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res == nil || !res.AIDisabled {
		t.Fatalf("expected AI-disabled result, got %+v", res)
	}
	if got := len(h.craReports.inserted); got != 1 {
		t.Fatalf("expected 1 cra_reports insert, got %d", got)
	}
	got := h.craReports.inserted[0].AwarenessTime
	want := time.Date(2026, 6, 24, 9, 30, 0, 0, time.UTC)
	if got == nil {
		t.Fatalf("awareness_time not persisted (nil) on AI-disabled path")
	}
	if !got.Equal(want) {
		t.Errorf("awareness_time = %v, want %v", got, want)
	}
}

// TestRunner_Run_EmptyAwarenessTime_NilColumn pins that a blank awareness
// field persists as a nil column (not a zero time) — the read-time
// deadline computation treats nil as not_applicable, which is the honest
// posture when the operator did not attest an awareness instant.
func TestRunner_Run_EmptyAwarenessTime_NilColumn(t *testing.T) {
	h := newTestHarness(t)
	in := h.baseInput()
	in.ReportType = ReportTypeDetailedNotification
	in.Lang = LangEN
	in.AwarenessTime = "   " // whitespace-only → nil

	if _, err := h.runner.Run(context.Background(), in); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(h.craReports.inserted); got != 1 {
		t.Fatalf("expected 1 cra_reports insert, got %d", got)
	}
	if got := h.craReports.inserted[0].AwarenessTime; got != nil {
		t.Errorf("expected nil awareness_time for blank input, got %v", got)
	}
}

// TestRunner_Run_MalformedAwarenessTime_Rejected pins that a non-empty
// but non-RFC3339 awareness value fails the drafting cycle loudly BEFORE
// any DB / LLM I/O, and persists nothing. RunReport surfaces this as an
// error (Wave B maps it to a 400).
func TestRunner_Run_MalformedAwarenessTime_Rejected(t *testing.T) {
	h := newTestHarness(t)
	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA
	in.AwarenessTime = "2026-06-24 09:00" // not RFC3339

	_, err := h.runner.Run(context.Background(), in)
	if err == nil {
		t.Fatalf("expected error on malformed awareness_time")
	}
	if !strings.Contains(err.Error(), "awareness_time") {
		t.Errorf("error %v should name awareness_time", err)
	}
	if got := len(h.craReports.inserted); got != 0 {
		t.Errorf("expected no cra_reports insert on malformed awareness_time, got %d", got)
	}
	if got := len(h.llmCalls.records); got != 0 {
		t.Errorf("expected no llm_calls on malformed awareness_time, got %d", got)
	}
	if h.provider.captured.Purpose != "" {
		t.Errorf("provider must not be called on malformed awareness_time (got Purpose=%q)", h.provider.captured.Purpose)
	}
}

// ----------------------------------------------------------------------------
// Test 9: buildCRASystemPrompt default arm (F359, M24-3)
// ----------------------------------------------------------------------------

// TestBuildCRASystemPrompt_UnknownReportType_LoudDefaultArm_F359 pins
// the F359 default arm directly: an unregistered ReportType must embed
// its raw wire value verbatim in the prompt text instead of silently
// dropping the report-type sentence (the pre-F359 switch had no
// default arm, so the sentence fragment "You produce structured JSON
// for an EU Article 14 " was left dangling with nothing after it).
// The production Run() path cannot reach this arm today —
// isValidReportType rejects unknown types before Stage 2, and Render()
// rejects unknown (reportType, lang) pairs with ErrUnknownTemplate —
// so this unit test is the only executable coverage of the arm.
//
// The bogus value below is deliberately NOT a registered wire value
// (and must never become one): the F341 direction-1c census pins which
// files may mention real report-type wire values, and this file is not
// in that census set.
func TestBuildCRASystemPrompt_UnknownReportType_LoudDefaultArm_F359(t *testing.T) {
	const bogus = ReportType("totally_bogus_report_type")

	got := buildCRASystemPrompt(bogus, LangEN)

	if !strings.Contains(got, `"totally_bogus_report_type"`) {
		t.Errorf("F359: prompt for an unregistered ReportType must embed "+
			"the raw wire value %q loudly; prompt head: %.200s",
			string(bogus), got)
	}
	if !strings.Contains(got, "unregistered type") {
		t.Errorf("F359: prompt must state factually that the type is "+
			"unregistered; prompt head: %.200s", got)
	}

	// Registered types must NOT trip the default arm — their dedicated
	// sentences survive unchanged.
	for rt, want := range map[ReportType]string{
		ReportTypeEarlyWarning:         "24-hour early warning report. ",
		ReportTypeDetailedNotification: "72-hour detailed notification report. ",
		ReportTypeFinalReport:          "post-remediation final report. ",
	} {
		p := buildCRASystemPrompt(rt, LangEN)
		if !strings.Contains(p, want) {
			t.Errorf("F359: registered type %q lost its prompt sentence %q",
				string(rt), want)
		}
		if strings.Contains(p, "unregistered type") {
			t.Errorf("F359: registered type %q must not trip the default arm",
				string(rt))
		}
	}
}
