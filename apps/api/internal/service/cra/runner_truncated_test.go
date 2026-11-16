package cra

// M75 — a CRA answer the provider reports as cut at its token limit (or
// stopped by a content filter) is not a draft: Run fails, no cra_report is
// saved, and the llm_calls row keeps the partial answer, the provider's
// finish reason and an error message. A cut CRA draft would otherwise be
// rendered with the template's placeholders for every missing field and
// read as a complete report.

import (
	"context"
	"errors"
	"testing"

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
		{"refusal", llm.ErrFilteredResponse},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			h := newTestHarness(t)
			content := canonicalLLMResponse(t)
			h.provider.resp = &llm.CompleteResponse{
				Content: content, InputTokens: 10, OutputTokens: 20, FinishReason: c.reason,
			}
			in := h.baseInput()
			in.ReportType = ReportTypeEarlyWarning
			in.Lang = LangEN
			res, err := h.runner.Run(context.Background(), in)
			if !errors.Is(err, c.want) || res != nil {
				t.Fatalf("Run = (%v, %v), want error %v", res, err, c.want)
			}
			if n := len(h.craReports.inserted); n != 0 {
				t.Fatalf("saved %d cra_report draft(s) from a %s answer", n, c.reason)
			}
			if n := len(h.llmCalls.records); n != 1 {
				t.Fatalf("llm_calls rows = %d, want 1", n)
			}
			row := h.llmCalls.records[0]
			if row.FinishReason != c.reason || row.ErrorMessage == "" || row.ResponseBody != content {
				t.Errorf("row finish_reason=%q error=%q body recorded=%v",
					row.FinishReason, row.ErrorMessage, row.ResponseBody == content)
			}
		})
	}
}
