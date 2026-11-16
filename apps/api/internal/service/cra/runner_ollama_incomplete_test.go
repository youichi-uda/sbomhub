package cra

// M74 — consumer side of the Ollama incomplete-answer contract: a CRA draft
// run against an Ollama answer that ended without done:true fails, saves no
// cra_report, and records the llm_calls row with finish_reason
// "incomplete" and the partial body (not "stop", not a successful row).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

func TestRunner_Run_OllamaIncompleteAnswerIsNotADraft(t *testing.T) {
	h := newTestHarness(t)

	content := canonicalLLMResponse(t) // a complete-looking JSON draft
	body, err := json.Marshal(map[string]any{
		"model":   "m",
		"message": map[string]string{"role": "assistant", "content": content},
		"done":    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	r := NewRunner(RunnerConfig{
		VEXDrafts:           h.drafts,
		AdvisoryExcerpts:    h.advisories,
		ReachabilityResults: h.reach,
		CRAReports:          h.craReports,
		LLMCalls:            h.llmCalls,
		VulnerabilityCVE:    h.vulnCVE,
		Audit:               h.audit,
		Provider:            llm.NewOllama(srv.URL, "m"),
		Clock:               fixedClock(h.clockTime),
		GeneratedBy:         "SBOMHub/test",
	})

	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangJA
	_, runErr := r.Run(context.Background(), in)
	if !errors.Is(runErr, llm.ErrIncompleteResponse) {
		t.Fatalf("Run err = %v, want ErrIncompleteResponse", runErr)
	}
	if n := len(h.craReports.inserted); n != 0 {
		t.Fatalf("truncated answer saved %d cra_report draft(s)", n)
	}
	if n := len(h.llmCalls.records); n != 1 {
		t.Fatalf("llm_calls rows = %d, want 1", n)
	}
	lc := h.llmCalls.records[0]
	if lc.FinishReason != llm.FinishReasonIncomplete {
		t.Errorf("finish_reason = %q, want %q", lc.FinishReason, llm.FinishReasonIncomplete)
	}
	if lc.ErrorMessage == "" {
		t.Error("llm_calls row has no error_message for the incomplete answer")
	}
	if lc.ResponseBody != content {
		t.Error("partial response body not recorded")
	}
}
