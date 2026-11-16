package diff_summary

// M74 (Codex R1 Medium): an LLM error that comes WITH a response (Ollama's
// ErrIncompleteResponse: the partial answer, FinishReason "incomplete")
// fails the summary like any other error, but the llm_calls row keeps the
// partial response, tokens and finish reason for diagnosis.

import (
	"context"
	"fmt"
	"testing"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

type partialErrProvider struct{ fakeProvider }

func (p *partialErrProvider) Complete(_ context.Context, _ llm.CompleteRequest) (*llm.CompleteResponse, error) {
	return &llm.CompleteResponse{
			Content: `{"summary":"half`, InputTokens: 11, OutputTokens: 7,
			FinishReason: llm.FinishReasonIncomplete, RawResponse: []byte(`{"done":false}`),
		},
		fmt.Errorf("ollama: %w: answer ended without done:true", llm.ErrIncompleteResponse)
}

func TestGenerate_IncompleteResponse_RecordedButNotUsed(t *testing.T) {
	f := newFixture(t)
	prov := &partialErrProvider{fakeProvider{name: "ollama", model: "m"}}
	svc := NewService(Config{Diff: f.diffSvc, Provider: prov, LLMCalls: f.llmCalls, Audit: f.audit})

	resp, err := svc.Generate(context.Background(), Request{
		TenantID: f.tenantID, ProjectID: f.projectID,
		FromSbomID: f.fromID, ToSbomID: f.toID,
	})
	if err == nil || resp != nil {
		t.Fatalf("incomplete answer accepted: resp=%v err=%v", resp, err)
	}
	if len(f.llmCalls.rows) != 1 {
		t.Fatalf("llm_calls rows = %d, want 1", len(f.llmCalls.rows))
	}
	row := f.llmCalls.rows[0]
	if row.FinishReason != llm.FinishReasonIncomplete || row.ErrorMessage == "" {
		t.Errorf("row finish_reason=%q error=%q, want incomplete + error", row.FinishReason, row.ErrorMessage)
	}
	if row.ResponsePreview == "" || row.ResponseHash == "" || row.OutputTokens != 7 {
		t.Errorf("partial response not recorded: %+v", row)
	}
	if len(f.audit.rows) != 1 || f.audit.rows[0].Action != AuditActionAIFailed {
		t.Errorf("audit rows = %+v, want one %s", f.audit.rows, AuditActionAIFailed)
	}
}
