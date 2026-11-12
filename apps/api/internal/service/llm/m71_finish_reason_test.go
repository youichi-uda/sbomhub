package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// Every value a provider documents today passes through unchanged, in the
// provider's own spelling (existing rows store Gemini's "STOP", Anthropic's
// "end_turn"); the longest documented one fits llm_calls.finish_reason.
func TestM71NormalizeFinishReason_KeepsDocumentedValues(t *testing.T) {
	for _, v := range []string{
		// OpenAI / Azure OpenAI
		"stop", "length", "tool_calls", "content_filter", "function_call",
		// Anthropic
		"end_turn", "max_tokens", "stop_sequence", "tool_use", "pause_turn", "refusal",
		"model_context_window_exceeded",
		// Gemini
		"STOP", "MAX_TOKENS", "SAFETY", "RECITATION", "LANGUAGE", "OTHER", "BLOCKLIST",
		"PROHIBITED_CONTENT", "SPII", "MALFORMED_FUNCTION_CALL", "IMAGE_SAFETY",
		"UNEXPECTED_TOOL_CALL", "FINISH_REASON_UNSPECIFIED", "TOO_MANY_TOOL_CALLS",
	} {
		if got := NormalizeFinishReason(v); got != v {
			t.Errorf("NormalizeFinishReason(%q) = %q, want it unchanged", v, got)
		}
	}
	if got := NormalizeFinishReason(""); got != "" {
		t.Errorf("empty = %q, want empty (stored as NULL)", got)
	}
	if got := NormalizeFinishReason("  stop "); got != "stop" {
		t.Errorf("padded = %q, want stop", got)
	}
}

// Anything that is not a short plain token becomes one bounded marker: the
// column is VARCHAR(30) and PostgreSQL refuses NUL and invalid UTF-8, so the
// raw value would make the llm_calls INSERT — and with it the draft's write
// transaction — fail.
func TestM71NormalizeFinishReason_BoundsEverythingElse(t *testing.T) {
	for _, v := range []string{
		strings.Repeat("x", MaxFinishReasonLen+1),
		"MODEL_CONTEXT_WINDOW_EXCEEDED_BY_PROVIDER",
		"stop\x00",
		"st\xffop",
		"stop sequence",
		"停止",
		"st\nop",
		"<script>",
	} {
		got := NormalizeFinishReason(v)
		if got != FinishReasonUnrecognized {
			t.Errorf("NormalizeFinishReason(%q) = %q, want %q", v, got, FinishReasonUnrecognized)
		}
	}
	if n := utf8.RuneCountInString(FinishReasonUnrecognized); n > MaxFinishReasonLen {
		t.Fatalf("marker is %d characters, over the column's %d", n, MaxFinishReasonLen)
	}
}

// m71RawServer answers every request with one fixed JSON body.
func m71RawServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Each provider's Complete returns the normalised value, so every caller
// (triage, CRA, diff summary) persists a bounded one.
func TestM71Providers_NormalizeFinishReason(t *testing.T) {
	long := strings.Repeat("Z", 64)
	req := CompleteRequest{System: "s", Messages: []Message{{Role: RoleUser, Content: "hi"}}}
	cases := []struct {
		name string
		p    func(url string) Provider
		body string
	}{
		{"openai", func(u string) Provider { return NewOpenAIWithEndpoint("sk-test", "m", u) },
			`{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"` + long + `"}],"usage":{}}`},
		{"openai NUL", func(u string) Provider { return NewOpenAIWithEndpoint("sk-test", "m", u) },
			`{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop\u0000"}],"usage":{}}`},
		{"azure_openai", func(u string) Provider {
			return NewAzureOpenAIWithClient("k", u, "dep", "2024-10-21", "m", http.DefaultClient)
		}, `{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"` + long + `"}],"usage":{}}`},
		{"anthropic", func(u string) Provider { return NewAnthropicWithEndpoint("sk-ant", "m", u) },
			`{"id":"x","type":"message","role":"assistant","model":"m","stop_reason":"` + long + `","content":[{"type":"text","text":"x"}],"usage":{}}`},
		{"gemini", func(u string) Provider { return NewGeminiWithEndpoint("k", "m", u) },
			`{"candidates":[{"content":{"parts":[{"text":"x"}],"role":"model"},"finishReason":"` + long + `"}],"usageMetadata":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := m71RawServer(t, tc.body)
			out, err := tc.p(srv.URL).Complete(context.Background(), req)
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if out.FinishReason != FinishReasonUnrecognized {
				t.Fatalf("FinishReason = %q, want %q", out.FinishReason, FinishReasonUnrecognized)
			}
		})
	}
}
