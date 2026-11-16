package diff_summary

// M75 — a diff summary the provider reports as cut at its token limit (the
// call sets MaxTokens 1024) or stopped by a content filter is not shown:
// Generate fails, the llm_calls row keeps the partial answer, the
// provider's finish reason and an error message, and the audit row is
// ai_failed rather than ai_generated.

import (
	"context"
	"errors"
	"testing"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

func TestGenerate_ProviderStopReasonIsNotASummary(t *testing.T) {
	for _, reason := range []string{"length", "max_tokens", "MAX_TOKENS", "content_filter", "SAFETY"} {
		t.Run(reason, func(t *testing.T) {
			f := newFixture(t)
			prov := &fakeProvider{name: "openai", model: "m", resp: &llm.CompleteResponse{
				// Valid JSON: the cut must be caught from the finish
				// reason, not from a parse failure.
				Content:      `{"summary":"Two CVEs were resolved.","highlights":["a"],"confidence":0.9}`,
				InputTokens:  11,
				OutputTokens: 1024,
				FinishReason: reason,
				RawResponse:  []byte(`{"choices":[]}`),
			}}
			svc := NewService(Config{Diff: f.diffSvc, Provider: prov, LLMCalls: f.llmCalls, Audit: f.audit})

			resp, err := svc.Generate(context.Background(), Request{
				TenantID: f.tenantID, ProjectID: f.projectID,
				FromSbomID: f.fromID, ToSbomID: f.toID,
			})
			if err == nil || resp != nil {
				t.Fatalf("%s answer accepted: resp=%v err=%v", reason, resp, err)
			}
			if !errors.Is(err, llm.ErrTruncatedResponse) && !errors.Is(err, llm.ErrFilteredResponse) {
				t.Errorf("err = %v, want it to wrap ErrTruncatedResponse / ErrFilteredResponse", err)
			}
			if len(f.llmCalls.rows) != 1 {
				t.Fatalf("llm_calls rows = %d, want 1", len(f.llmCalls.rows))
			}
			row := f.llmCalls.rows[0]
			if row.FinishReason != reason || row.ErrorMessage == "" || row.ResponseHash == "" || row.OutputTokens != 1024 {
				t.Errorf("row = %+v, want finish_reason %q, error, partial response", row, reason)
			}
			if len(f.audit.rows) != 1 || f.audit.rows[0].Action != AuditActionAIFailed {
				t.Errorf("audit rows = %+v, want one %s", f.audit.rows, AuditActionAIFailed)
			}
		})
	}
}
