package llm

// M75 — provider-reported truncation and filter stops. A provider that says
// the answer was cut (token limit) or stopped by a content filter returns a
// CompleteResponse with a nil error; CheckFinish / Complete turn that into an
// error so no consumer saves the cut answer as a normal draft.

import (
	"context"
	"errors"
	"testing"
)

func TestClassifyFinishReason(t *testing.T) {
	cases := []struct {
		reason string
		want   FinishKind
	}{
		// Normal ends, every provider's spelling.
		{"", FinishUnfinished}, // provider did not say (Gemini: not stopped): fail closed (Codex R2 High)
		{"stop", FinishNormal},
		{"STOP", FinishNormal},              // Gemini
		{"end_turn", FinishNormal},          // Anthropic
		{"stop_sequence", FinishNormal},     // Anthropic
		{"tool_calls", FinishUnfinished},    // tool stop: not a final answer (Codex R1 Low)
		{"tool_use", FinishUnfinished},      // tool stop: not a final answer (Codex R1 Low)
		{"function_call", FinishUnfinished}, // tool stop: not a final answer (Codex R1 Low)
		{" stop ", FinishNormal},
		// Token-limit truncation.
		{"length", FinishTruncated},                        // OpenAI / Azure / Ollama
		{"max_tokens", FinishTruncated},                    // Anthropic
		{"MAX_TOKENS", FinishTruncated},                    // Gemini
		{"model_context_window_exceeded", FinishTruncated}, // Anthropic
		{"pause_turn", FinishTruncated},                    // Anthropic
		// Filter / safety / refusal stops.
		{"content_filter", FinishFiltered}, // OpenAI / Azure
		{"refusal", FinishFiltered},        // Anthropic
		{"SAFETY", FinishFiltered},         // Gemini
		{"RECITATION", FinishFiltered},
		{"BLOCKLIST", FinishFiltered},
		{"PROHIBITED_CONTENT", FinishFiltered},
		{"SPII", FinishFiltered},
		{"IMAGE_SAFETY", FinishFiltered},
		{"LANGUAGE", FinishFiltered},   // Gemini (Codex R3 Medium)
		{"ESCALATION", FinishFiltered}, // Gemini
		// Anything else is not a normal end: fail closed.
		{FinishReasonIncomplete, FinishUnfinished},
		{FinishReasonUnrecognized, FinishUnfinished},
		{"OTHER", FinishUnfinished}, // Gemini
		{"FINISH_REASON_UNSPECIFIED", FinishUnfinished},
		{"MALFORMED_FUNCTION_CALL", FinishUnfinished},
		{"load", FinishUnfinished}, // Ollama load-only answer
		{"some_future_reason", FinishUnfinished},
	}
	for _, c := range cases {
		if got := ClassifyFinishReason(c.reason); got != c.want {
			t.Errorf("ClassifyFinishReason(%q) = %v, want %v", c.reason, got, c.want)
		}
	}
	if !IsTruncated("length") || !IsTruncated("MAX_TOKENS") || IsTruncated("stop") || IsTruncated("content_filter") {
		t.Error("IsTruncated disagrees with ClassifyFinishReason")
	}
}

func TestCheckFinish(t *testing.T) {
	if err := CheckFinish(nil); err != nil {
		t.Errorf("CheckFinish(nil) = %v", err)
	}
	if err := CheckFinish(&CompleteResponse{FinishReason: ""}); !errors.Is(err, ErrIncompleteResponse) {
		t.Errorf("empty finish reason: err = %v, want ErrIncompleteResponse", err)
	}
	if err := CheckFinish(&CompleteResponse{FinishReason: "stop"}); err != nil {
		t.Errorf("stop: %v", err)
	}
	err := CheckFinish(&CompleteResponse{FinishReason: "length"})
	if !errors.Is(err, ErrTruncatedResponse) || !errors.Is(err, ErrIncompleteResponse) {
		t.Errorf("length: err = %v, want ErrTruncatedResponse (an ErrIncompleteResponse)", err)
	}
	err = CheckFinish(&CompleteResponse{FinishReason: "SAFETY"})
	if !errors.Is(err, ErrFilteredResponse) || errors.Is(err, ErrTruncatedResponse) {
		t.Errorf("SAFETY: err = %v, want ErrFilteredResponse only", err)
	}
	err = CheckFinish(&CompleteResponse{FinishReason: "OTHER"})
	if !errors.Is(err, ErrIncompleteResponse) || errors.Is(err, ErrTruncatedResponse) || errors.Is(err, ErrFilteredResponse) {
		t.Errorf("OTHER: err = %v, want plain ErrIncompleteResponse", err)
	}
}

type finishStub struct {
	resp *CompleteResponse
	err  error
}

func (s finishStub) Name() string  { return "stub" }
func (s finishStub) Model() string { return "m" }
func (s finishStub) Complete(context.Context, CompleteRequest) (*CompleteResponse, error) {
	return s.resp, s.err
}
func (s finishStub) Embed(context.Context, EmbedRequest) (*EmbedResponse, error) {
	return nil, ErrNotImplemented
}
func (s finishStub) Capabilities() Capabilities { return Capabilities{} }

func TestComplete_ChecksFinishReason(t *testing.T) {
	cut := &CompleteResponse{Content: `{"a":`, FinishReason: "max_tokens"}
	resp, err := Complete(context.Background(), finishStub{resp: cut}, CompleteRequest{})
	if !errors.Is(err, ErrTruncatedResponse) {
		t.Fatalf("err = %v, want ErrTruncatedResponse", err)
	}
	if resp != cut {
		t.Error("response must still be returned so the caller can record it")
	}

	ok := &CompleteResponse{Content: "{}", FinishReason: "end_turn"}
	if resp, err := Complete(context.Background(), finishStub{resp: ok}, CompleteRequest{}); err != nil || resp != ok {
		t.Errorf("normal answer: resp=%v err=%v", resp, err)
	}

	// (nil, nil) from a faulty provider is an error, not a success the
	// caller would dereference (Codex R1 Low).
	if _, err := Complete(context.Background(), finishStub{}, CompleteRequest{}); err == nil {
		t.Error("nil response with nil error accepted")
	}

	// A provider error wins; it is returned unchanged.
	boom := errors.New("boom")
	if _, err := Complete(context.Background(), finishStub{resp: cut, err: boom}, CompleteRequest{}); err != boom {
		t.Errorf("provider error = %v, want boom", err)
	}
}
