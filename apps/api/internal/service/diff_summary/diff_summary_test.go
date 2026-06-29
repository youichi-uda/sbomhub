// Package diff_summary — unit tests for the M11-4 AI summary service.
//
// Strategy: stand up an in-memory diff.Service (the existing diff fakes
// already cover the deterministic compute path, so this suite only
// needs to verify the LLM stage + audit / llm_calls persistence shape).
// A small fake provider is used so we never touch a real LLM upstream.
package diff_summary

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/diff"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// ---------- fakes ----------

type fakeProjectRepo struct {
	owner map[uuid.UUID]uuid.UUID
}

func (f *fakeProjectRepo) GetByTenant(_ context.Context, tenantID, projectID uuid.UUID) (*model.Project, error) {
	if o, ok := f.owner[projectID]; ok && o == tenantID {
		return &model.Project{ID: projectID, Name: "t"}, nil
	}
	return nil, errSqlNoRows
}

var errSqlNoRows = errors.New("sql: no rows in result set")

type fakeSbomRepo struct {
	byID      map[uuid.UUID]model.Sbom
	byProject map[uuid.UUID][]model.Sbom
}

func (f *fakeSbomRepo) ListByProject(_ context.Context, p uuid.UUID) ([]model.Sbom, error) {
	out := make([]model.Sbom, len(f.byProject[p]))
	copy(out, f.byProject[p])
	return out, nil
}
func (f *fakeSbomRepo) GetByID(_ context.Context, id uuid.UUID) (*model.Sbom, error) {
	if s, ok := f.byID[id]; ok {
		cp := s
		return &cp, nil
	}
	return nil, errSqlNoRows
}

type fakeComponentRepo struct {
	components map[uuid.UUID][]model.Component
	vulns      map[uuid.UUID][]model.ComponentVulnerability
}

func (f *fakeComponentRepo) ListBySbom(_ context.Context, id uuid.UUID) ([]model.Component, error) {
	out := make([]model.Component, len(f.components[id]))
	copy(out, f.components[id])
	return out, nil
}
func (f *fakeComponentRepo) ListComponentVulnerabilitiesBySbom(_ context.Context, id uuid.UUID) ([]model.ComponentVulnerability, error) {
	out := make([]model.ComponentVulnerability, len(f.vulns[id]))
	copy(out, f.vulns[id])
	return out, nil
}

type fakeLicenseRepo struct {
	policies map[uuid.UUID][]model.LicensePolicy
}

func (f *fakeLicenseRepo) ListByProject(_ context.Context, p uuid.UUID) ([]model.LicensePolicy, error) {
	out := make([]model.LicensePolicy, len(f.policies[p]))
	copy(out, f.policies[p])
	return out, nil
}

type fakeProvider struct {
	name      string
	model     string
	resp      *llm.CompleteResponse
	err       error
	lastReq   llm.CompleteRequest
	completes int
}

func (p *fakeProvider) Name() string  { return p.name }
func (p *fakeProvider) Model() string { return p.model }
func (p *fakeProvider) Complete(_ context.Context, r llm.CompleteRequest) (*llm.CompleteResponse, error) {
	p.completes++
	p.lastReq = r
	if p.err != nil {
		return nil, p.err
	}
	return p.resp, nil
}
func (p *fakeProvider) Embed(_ context.Context, _ llm.EmbedRequest) (*llm.EmbedResponse, error) {
	return nil, llm.ErrNotImplemented
}
func (p *fakeProvider) Capabilities() llm.Capabilities { return llm.Capabilities{} }

type fakeLLMCalls struct {
	rows []repository.LLMCall
}

func (f *fakeLLMCalls) Insert(_ context.Context, c *repository.LLMCall) error {
	f.rows = append(f.rows, *c)
	return nil
}

type fakeAudit struct {
	rows []model.CreateAuditLogInput
}

func (f *fakeAudit) Log(_ context.Context, in *model.CreateAuditLogInput) error {
	f.rows = append(f.rows, *in)
	return nil
}

// ---------- fixtures ----------

type fixture struct {
	tenantID, projectID, fromID, toID uuid.UUID
	diffSvc                           *diff.Service
	llmCalls                          *fakeLLMCalls
	audit                             *fakeAudit
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	tenantID := uuid.New()
	projectID := uuid.New()
	fromID := uuid.New()
	toID := uuid.New()
	now := time.Now()
	fromSbom := model.Sbom{ID: fromID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", Version: "1.5", CreatedAt: now.Add(-2 * time.Hour)}
	toSbom := model.Sbom{ID: toID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", Version: "1.5", CreatedAt: now.Add(-1 * time.Hour)}

	fromComps := []model.Component{
		{ID: uuid.New(), Name: "lodash", Version: "4.17.20", Type: "library", Purl: "pkg:npm/lodash@4.17.20", License: "MIT"},
	}
	toComps := []model.Component{
		{ID: uuid.New(), Name: "lodash", Version: "4.17.21", Type: "library", Purl: "pkg:npm/lodash@4.17.21", License: "MIT"},
		{ID: uuid.New(), Name: "axios", Version: "1.6.0", Type: "library", Purl: "pkg:npm/axios@1.6.0", License: "MIT"},
	}
	fromVulns := []model.ComponentVulnerability{
		{ComponentID: fromComps[0].ID, ComponentName: "lodash", ComponentVersion: "4.17.20", CVEID: "CVE-2020-AAAA", Severity: "HIGH"},
	}
	toVulns := []model.ComponentVulnerability{}

	pr := &fakeProjectRepo{owner: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{fromID: fromSbom, toID: toSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {toSbom, fromSbom}},
	}
	cr := &fakeComponentRepo{
		components: map[uuid.UUID][]model.Component{fromID: fromComps, toID: toComps},
		vulns:      map[uuid.UUID][]model.ComponentVulnerability{fromID: fromVulns, toID: toVulns},
	}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{projectID: nil}}

	diffSvc := diff.NewService(pr, sr, cr, lr)

	return &fixture{
		tenantID: tenantID, projectID: projectID,
		fromID: fromID, toID: toID,
		diffSvc:  diffSvc,
		llmCalls: &fakeLLMCalls{},
		audit:    &fakeAudit{},
	}
}

// ---------- tests ----------

func TestGenerate_DisabledProvider_WritesPlaceholderAndAudit(t *testing.T) {
	f := newFixture(t)
	svc := NewService(Config{
		Diff:     f.diffSvc,
		Provider: &llm.DisabledProvider{Reason: "BYOK not configured"},
		LLMCalls: f.llmCalls,
		Audit:    f.audit,
	})

	resp, err := svc.Generate(context.Background(), Request{
		TenantID: f.tenantID, ProjectID: f.projectID,
		FromSbomID: f.fromID, ToSbomID: f.toID,
		Lang: "en",
	})
	if err != nil {
		t.Fatalf("Generate disabled: %v", err)
	}
	if !resp.AIDisabled {
		t.Errorf("expected AIDisabled=true, got %+v", resp)
	}
	if resp.Confidence != 0.0 {
		t.Errorf("expected confidence 0.0 on disabled path; got %f", resp.Confidence)
	}
	if !strings.Contains(resp.Summary, "BYOK") {
		t.Errorf("expected disabled placeholder to mention BYOK; got %q", resp.Summary)
	}
	if len(resp.Evidence) == 0 {
		t.Errorf("expected evidence pointers even on disabled path; got 0")
	}
	if len(f.llmCalls.rows) != 1 {
		t.Fatalf("expected 1 llm_calls row; got %d", len(f.llmCalls.rows))
	}
	if f.llmCalls.rows[0].Purpose != LLMCallPurposeDiffSummary {
		t.Errorf("llm_calls.purpose = %q, want %q", f.llmCalls.rows[0].Purpose, LLMCallPurposeDiffSummary)
	}
	if f.llmCalls.rows[0].ErrorMessage != "ai_disabled" {
		t.Errorf("disabled row should carry ErrorMessage=ai_disabled; got %q", f.llmCalls.rows[0].ErrorMessage)
	}
	if len(f.audit.rows) != 1 {
		t.Fatalf("expected 1 audit row; got %d", len(f.audit.rows))
	}
	if f.audit.rows[0].Action != AuditActionAIDisabled {
		t.Errorf("audit.Action = %q, want %q", f.audit.rows[0].Action, AuditActionAIDisabled)
	}
	if f.audit.rows[0].ResourceType != ResourceTypeSbomDiff {
		t.Errorf("audit.ResourceType = %q, want %q", f.audit.rows[0].ResourceType, ResourceTypeSbomDiff)
	}
}

func TestGenerate_SuccessfulLLM_PersistsAuditAndLLMCalls(t *testing.T) {
	f := newFixture(t)
	llmBody := []byte(`{"summary":"Updated lodash and added axios.","highlights":["lodash 4.17.20→4.17.21","Added axios@1.6.0","Resolved CVE-2020-AAAA"],"confidence":0.85}`)
	prov := &fakeProvider{
		name:  "openai",
		model: "gpt-5",
		resp: &llm.CompleteResponse{
			Content:      string(llmBody),
			Model:        "gpt-5",
			InputTokens:  100,
			OutputTokens: 200,
			RawResponse:  llmBody,
			FinishReason: "stop",
		},
	}
	svc := NewService(Config{
		Diff:     f.diffSvc,
		Provider: prov,
		LLMCalls: f.llmCalls,
		Audit:    f.audit,
	})

	resp, err := svc.Generate(context.Background(), Request{
		TenantID: f.tenantID, ProjectID: f.projectID,
		FromSbomID: f.fromID, ToSbomID: f.toID,
		Lang: "en",
	})
	if err != nil {
		t.Fatalf("Generate ok: %v", err)
	}
	if resp.AIDisabled {
		t.Errorf("expected AIDisabled=false")
	}
	if resp.Summary != "Updated lodash and added axios." {
		t.Errorf("summary mismatch: %q", resp.Summary)
	}
	if resp.Confidence != 0.85 {
		t.Errorf("confidence: got %f, want 0.85", resp.Confidence)
	}
	if resp.Provider != "openai" || resp.Model != "gpt-5" {
		t.Errorf("provider/model mismatch: %+v", resp)
	}
	if len(resp.Highlights) != 3 {
		t.Errorf("highlights count: got %d, want 3", len(resp.Highlights))
	}

	// llm_calls row
	if len(f.llmCalls.rows) != 1 {
		t.Fatalf("expected 1 llm_calls; got %d", len(f.llmCalls.rows))
	}
	row := f.llmCalls.rows[0]
	if row.Purpose != LLMCallPurposeDiffSummary {
		t.Errorf("purpose mismatch")
	}
	if row.PromptHash == "" {
		t.Errorf("expected prompt_hash populated")
	}
	if row.ResponseHash == "" {
		t.Errorf("expected response_hash populated")
	}
	if row.InputTokens != 100 || row.OutputTokens != 200 {
		t.Errorf("tokens not recorded: in=%d out=%d", row.InputTokens, row.OutputTokens)
	}

	// audit row
	if len(f.audit.rows) != 1 {
		t.Fatalf("expected 1 audit; got %d", len(f.audit.rows))
	}
	if f.audit.rows[0].Action != AuditActionAIGenerated {
		t.Errorf("audit.Action mismatch: %q", f.audit.rows[0].Action)
	}
	details, _ := json.Marshal(f.audit.rows[0].Details)
	if !strings.Contains(string(details), `"confidence":0.85`) {
		t.Errorf("audit details missing confidence: %s", string(details))
	}

	// prompt confirms purpose tagging
	if prov.lastReq.Purpose != LLMCallPurposeDiffSummary {
		t.Errorf("LLM Purpose: got %q, want %q", prov.lastReq.Purpose, LLMCallPurposeDiffSummary)
	}
}

func TestGenerate_LLMFails_WritesFailedAudit(t *testing.T) {
	f := newFixture(t)
	prov := &fakeProvider{
		name:  "openai",
		model: "gpt-5",
		err:   errors.New("upstream 502"),
	}
	svc := NewService(Config{
		Diff:     f.diffSvc,
		Provider: prov,
		LLMCalls: f.llmCalls,
		Audit:    f.audit,
	})

	_, err := svc.Generate(context.Background(), Request{
		TenantID: f.tenantID, ProjectID: f.projectID,
		FromSbomID: f.fromID, ToSbomID: f.toID,
	})
	if err == nil {
		t.Fatal("expected error on LLM failure")
	}
	if len(f.llmCalls.rows) != 1 {
		t.Fatalf("expected 1 llm_calls; got %d", len(f.llmCalls.rows))
	}
	if f.llmCalls.rows[0].ErrorMessage == "" {
		t.Errorf("expected ErrorMessage populated on failure")
	}
	if len(f.audit.rows) != 1 {
		t.Fatalf("expected 1 audit row on failure; got %d", len(f.audit.rows))
	}
	if f.audit.rows[0].Action != AuditActionAIFailed {
		t.Errorf("audit.Action on failure = %q, want %q", f.audit.rows[0].Action, AuditActionAIFailed)
	}
}

func TestGenerate_BadJSONResponse_RecordsParseFailure(t *testing.T) {
	f := newFixture(t)
	prov := &fakeProvider{
		name:  "openai",
		model: "gpt-5",
		resp: &llm.CompleteResponse{
			Content:     "this is not JSON at all",
			Model:       "gpt-5",
			RawResponse: []byte("not json"),
		},
	}
	svc := NewService(Config{
		Diff:     f.diffSvc,
		Provider: prov,
		LLMCalls: f.llmCalls,
		Audit:    f.audit,
	})
	_, err := svc.Generate(context.Background(), Request{
		TenantID: f.tenantID, ProjectID: f.projectID,
		FromSbomID: f.fromID, ToSbomID: f.toID,
	})
	if err == nil {
		t.Fatal("expected error on bad JSON")
	}
	if len(f.llmCalls.rows) != 1 {
		t.Fatalf("llm_calls rows: got %d, want 1", len(f.llmCalls.rows))
	}
	if !strings.Contains(f.llmCalls.rows[0].ErrorMessage, "parse") {
		t.Errorf("expected parse error recorded; got %q", f.llmCalls.rows[0].ErrorMessage)
	}
	if len(f.audit.rows) != 1 {
		t.Fatalf("audit rows: got %d, want 1", len(f.audit.rows))
	}
	if f.audit.rows[0].Action != AuditActionAIFailed {
		t.Errorf("audit.Action on parse fail = %q, want %q", f.audit.rows[0].Action, AuditActionAIFailed)
	}
}

func TestGenerate_ConfidenceClampedToOne(t *testing.T) {
	f := newFixture(t)
	prov := &fakeProvider{
		name: "openai", model: "gpt-5",
		resp: &llm.CompleteResponse{
			Content:     `{"summary":"x","highlights":[],"confidence":5.0}`,
			RawResponse: []byte(`{"confidence":5.0}`),
		},
	}
	svc := NewService(Config{Diff: f.diffSvc, Provider: prov, LLMCalls: f.llmCalls, Audit: f.audit})
	resp, err := svc.Generate(context.Background(), Request{TenantID: f.tenantID, ProjectID: f.projectID})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Confidence != 1.0 {
		t.Errorf("confidence not clamped; got %f", resp.Confidence)
	}
}

func TestGenerate_JapaneseLang_UsesJaPrompt(t *testing.T) {
	f := newFixture(t)
	prov := &fakeProvider{
		name: "openai", model: "gpt-5",
		resp: &llm.CompleteResponse{
			Content:     `{"summary":"日本語要約","highlights":[],"confidence":0.7}`,
			RawResponse: []byte("{}"),
		},
	}
	svc := NewService(Config{Diff: f.diffSvc, Provider: prov, LLMCalls: f.llmCalls, Audit: f.audit})
	resp, err := svc.Generate(context.Background(), Request{
		TenantID: f.tenantID, ProjectID: f.projectID, Lang: "ja",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Lang != "ja" {
		t.Errorf("expected lang=ja propagated; got %q", resp.Lang)
	}
	if !strings.Contains(prov.lastReq.System, "SBOMHub") || !strings.Contains(prov.lastReq.System, "JSON") {
		t.Errorf("system prompt expected to contain SBOMHub/JSON; got %q", prov.lastReq.System)
	}
}

func TestGenerate_RespectsTenantIsolation(t *testing.T) {
	f := newFixture(t)
	prov := &llm.DisabledProvider{}
	svc := NewService(Config{Diff: f.diffSvc, Provider: prov, LLMCalls: f.llmCalls, Audit: f.audit})

	other := uuid.New()
	_, err := svc.Generate(context.Background(), Request{
		TenantID: other, ProjectID: f.projectID,
	})
	if err == nil {
		t.Fatal("expected cross-tenant access to error")
	}
}
