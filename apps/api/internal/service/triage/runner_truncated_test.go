package triage

// M75 — a triage answer the provider reports as cut at its token limit
// (or stopped by a content filter) is not a draft: Run fails, no vex_draft
// is saved, and the llm_calls row keeps the partial answer, the provider's
// finish reason and an error message.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

func TestRunner_Run_ProviderStopReasonIsNotADraft(t *testing.T) {
	cases := []struct {
		reason string
		want   error
	}{
		{"length", llm.ErrTruncatedResponse},
		{"max_tokens", llm.ErrTruncatedResponse},
		{"MAX_TOKENS", llm.ErrTruncatedResponse},
		{"content_filter", llm.ErrFilteredResponse},
		{"SAFETY", llm.ErrFilteredResponse},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			componentID := uuid.New()
			// A complete-looking, valid JSON verdict: the cut must be
			// caught from the finish reason, not from a parse failure.
			content := canonicalLLMResponse()
			stub := &stubProvider{resp: &llm.CompleteResponse{
				Content: content, InputTokens: 10, OutputTokens: 20, FinishReason: c.reason,
			}}
			llmCalls := &fakeLLMCallWriter{}
			drafts := &fakeVexDraftStore{}
			r := NewRunner(RunnerConfig{
				Drafts: drafts, Advisories: &fakeAdvisoryReader{},
				Reachability: &fakeReachabilityReader{}, LLMCalls: llmCalls,
				Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
				ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
				VulnerabilityCVE:         okVulnCVE("CVE-2026-0075"),
			})
			res, err := r.Run(context.Background(), RunInput{
				TenantID: uuid.New(), ProjectID: uuid.New(),
				VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0075",
				ComponentID: &componentID,
			})
			if !errors.Is(err, c.want) || res != nil {
				t.Fatalf("Run = (%v, %v), want error %v", res, err, c.want)
			}
			if n := len(drafts.inserted); n != 0 {
				t.Fatalf("saved %d draft(s) from a %s answer", n, c.reason)
			}
			if n := len(llmCalls.records); n != 1 {
				t.Fatalf("llm_calls rows = %d, want 1", n)
			}
			row := llmCalls.records[0]
			if row.FinishReason != c.reason || row.ErrorMessage == "" || row.ResponseBody != content || row.OutputTokens != 20 {
				t.Errorf("row finish_reason=%q error=%q body recorded=%v tokens=%d",
					row.FinishReason, row.ErrorMessage, row.ResponseBody == content, row.OutputTokens)
			}
		})
	}
}

// Codex R4 Medium: an OpenAI / Azure refusal (content null, message.refusal
// set, finish_reason "stop") is rejected, and the llm_calls row keeps the
// refusal text as the response.
func TestRunner_Run_RefusalRecordedNotDrafted(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Refusal: "I can't help with that.", FinishReason: "stop", OutputTokens: 7}}
	llmCalls := &fakeLLMCallWriter{}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: &fakeAdvisoryReader{},
		Reachability: &fakeReachabilityReader{}, LLMCalls: llmCalls,
		Audit: &fakeAuditWriter{}, Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0076"),
	})
	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0076", ComponentID: &componentID,
	})
	if !errors.Is(err, llm.ErrFilteredResponse) || len(drafts.inserted) != 0 {
		t.Fatalf("err = %v drafts = %d, want ErrFilteredResponse and none", err, len(drafts.inserted))
	}
	if row := llmCalls.records[0]; row.ResponseBody != "I can't help with that." || row.ErrorMessage == "" {
		t.Errorf("row body=%q error=%q, want the refusal text recorded", row.ResponseBody, row.ErrorMessage)
	}
}
