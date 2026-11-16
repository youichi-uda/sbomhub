package main

// M75 — the bench scores a provider the way production triage would treat
// it: an answer the provider reports as cut at its token limit (or
// filtered) is an error row, not a verdict, even when the cut text still
// parses. The row keeps the tokens and the finish reason.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestRunBench_ProviderStopReasonIsAnError(t *testing.T) {
	cases := []EvalCase{{
		CaseID: "c1", CVEID: "CVE-2024-0075",
		AdvisoryExcerpt: "x", ComponentName: "foo", Ecosystem: "go",
		CodeReachability: CodeReachability{Reachable: false, Evidence: []string{}},
		ExpectedState:    "not_affected",
	}}
	for _, reason := range []string{"length", "MAX_TOKENS", "content_filter"} {
		t.Run(reason, func(t *testing.T) {
			providers := []namedProvider{{name: "openai", model: "gpt-4o-mini",
				provider: &fakeProvider{name: "openai", model: "gpt-4o-mini",
					inputTokens: 100, outputTokens: 200, finishReason: reason,
					responses: map[string]string{
						"CVE-2024-0075": `{"state":"not_affected","confidence":0.9,"evidence":[{"kind":"llm_rationale","description":"ok","source":"llm"}]}`,
					}}}}
			var jsonl bytes.Buffer
			results, err := runBench(context.Background(),
				slog.New(slog.NewTextHandler(io.Discard, nil)), providers, cases,
				runOptions{Timeout: time.Second, MaxConcurrency: 1, JSONLWriter: &jsonl,
					Clock: func() time.Time { return time.Unix(0, 0) }})
			if err != nil {
				t.Fatalf("runBench: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("results = %d", len(results))
			}
			r := results[0]
			if r.Error == "" || r.GotState != "" {
				t.Fatalf("%s answer scored as a verdict: %+v", reason, r)
			}
			if r.FinishReason != reason || r.OutputTokens != 200 {
				t.Errorf("row finish_reason=%q output_tokens=%d, want %q / 200", r.FinishReason, r.OutputTokens, reason)
			}
			if !strings.Contains(jsonl.String(), `"finish_reason":"`+reason+`"`) {
				t.Errorf("JSONL row lacks finish_reason: %s", jsonl.String())
			}
			if s := aggregate(results); len(s) != 1 || s[0].Errors != 1 || s[0].TotalCostUSD != r.CostUSD || r.CostUSD == 0 {
				t.Errorf("summary = %+v (row cost %v), want 1 error and the row's cost counted", s, r.CostUSD)
			}
		})
	}
}
