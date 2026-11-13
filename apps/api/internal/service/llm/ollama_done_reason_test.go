package llm

import (
	"context"
	"strings"
	"testing"
)

// Ollama reports why generation ended in done_reason (api.ChatResponse
// DoneReason, `json:"done_reason,omitempty"`): "stop" for a natural end or a
// stop sequence, "length" when num_predict / the context ran out, and
// "load" / "unload" for the empty-messages model (un)load calls. The provider
// used to record "stop" for every done=true answer, so a draft cut off at
// num_predict was audited as a complete one. The value now passes through
// NormalizeFinishReason like every other provider's; "stop" is only the
// fallback for an Ollama too old to send the field.
func TestOllama_Complete_DoneReason(t *testing.T) {
	long := strings.Repeat("z", MaxFinishReasonLen+1)
	cases := []struct {
		name string
		body string
		want string
	}{
		{"length (num_predict hit)", `{"model":"m","message":{"role":"assistant","content":"trunc"},"done":true,"done_reason":"length"}`, "length"},
		{"stop", `{"model":"m","message":{"role":"assistant","content":"x"},"done":true,"done_reason":"stop"}`, "stop"},
		{"load", `{"model":"m","message":{"role":"assistant","content":""},"done":true,"done_reason":"load"}`, "load"},
		{"padded", `{"model":"m","message":{"role":"assistant","content":"x"},"done":true,"done_reason":" length "}`, "length"},
		{"absent, done (older Ollama)", `{"model":"m","message":{"role":"assistant","content":"x"},"done":true}`, "stop"},
		{"absent, not done", `{"model":"m","message":{"role":"assistant","content":"x"},"done":false}`, ""},
		{"null, done (treated as absent)", `{"model":"m","message":{"role":"assistant","content":"x"},"done":true,"done_reason":null}`, "stop"},
		// Present but empty is a reason the server chose not to give, not an
		// old server: it is not upgraded to "stop" (stored as NULL).
		{"present but empty", `{"model":"m","message":{"role":"assistant","content":"x"},"done":true,"done_reason":""}`, ""},
		{"over-long", `{"model":"m","message":{"role":"assistant","content":"x"},"done":true,"done_reason":"` + long + `"}`, FinishReasonUnrecognized},
		{"NUL", `{"model":"m","message":{"role":"assistant","content":"x"},"done":true,"done_reason":"stop\u0000"}`, FinishReasonUnrecognized},
		// done=false declares the answer incomplete; a done_reason beside it
		// is contradictory and is not recorded as a terminal reason
		// (Codex R1 Low).
		{"reason with done=false", `{"model":"m","message":{"role":"assistant","content":"x"},"done":false,"done_reason":"length"}`, ""},
		{"wrong type with done=false", `{"model":"m","message":{"role":"assistant","content":"x"},"done":false,"done_reason":3}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := m71RawServer(t, tc.body)
			out, err := NewOllama(srv.URL, "m").Complete(context.Background(), CompleteRequest{
				Messages: []Message{{Role: RoleUser, Content: "hi"}},
			})
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if out.FinishReason != tc.want {
				t.Fatalf("FinishReason = %q, want %q", out.FinishReason, tc.want)
			}
		})
	}
}

// A non-string done_reason does not fail a generation that otherwise
// succeeded, and is not recorded as "stop" either: it is an unrecognised
// termination code.
func TestOllama_Complete_DoneReasonWrongType(t *testing.T) {
	for _, raw := range []string{`3`, `true`, `{"x":1}`, `["stop"]`} {
		srv := m71RawServer(t, `{"model":"m","message":{"role":"assistant","content":"x"},"done":true,"done_reason":`+raw+`}`)
		out, err := NewOllama(srv.URL, "m").Complete(context.Background(), CompleteRequest{
			Messages: []Message{{Role: RoleUser, Content: "hi"}},
		})
		if err != nil {
			t.Fatalf("done_reason %s: Complete: %v", raw, err)
		}
		if out.FinishReason != FinishReasonUnrecognized {
			t.Fatalf("done_reason %s: FinishReason = %q, want %q", raw, out.FinishReason, FinishReasonUnrecognized)
		}
	}
}
