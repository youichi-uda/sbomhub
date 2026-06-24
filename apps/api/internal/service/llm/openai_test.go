package llm

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeOpenAIServer mimics POST /v1/chat/completions.
// On a real run we'd hit api.openai.com; tests use httptest so CI is
// hermetic (no network).
func fakeOpenAIServer(t *testing.T, handler func(t *testing.T, body openaiChatRequest) (status int, resp openaiChatResponse)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %q, want /chat/completions", r.URL.Path)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("Authorization header = %q, want 'Bearer ...'", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req openaiChatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		status, resp := handler(t, req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestOpenAI_Complete_Success(t *testing.T) {
	srv := fakeOpenAIServer(t, func(t *testing.T, req openaiChatRequest) (int, openaiChatResponse) {
		if req.Model != "gpt-4o-mini" {
			t.Errorf("model = %q, want gpt-4o-mini", req.Model)
		}
		if len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[1].Role != "user" {
			t.Errorf("messages = %+v, want [system, user]", req.Messages)
		}
		resp := openaiChatResponse{Model: req.Model}
		resp.Choices = append(resp.Choices, struct {
			Index   int `json:"index"`
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		}{
			Index:        0,
			FinishReason: "stop",
		})
		resp.Choices[0].Message.Role = "assistant"
		resp.Choices[0].Message.Content = "hello world"
		resp.Usage.PromptTokens = 9
		resp.Usage.CompletionTokens = 2
		resp.Usage.TotalTokens = 11
		return http.StatusOK, resp
	})
	defer srv.Close()

	p := NewOpenAIWithEndpoint("sk-test", "gpt-4o-mini", srv.URL)
	out, err := p.Complete(context.Background(), CompleteRequest{
		System:   "you are a test",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.Content != "hello world" {
		t.Errorf("Content = %q", out.Content)
	}
	if out.InputTokens != 9 || out.OutputTokens != 2 {
		t.Errorf("tokens = (%d, %d), want (9, 2)", out.InputTokens, out.OutputTokens)
	}
	if out.FinishReason != "stop" {
		t.Errorf("FinishReason = %q", out.FinishReason)
	}
	if len(out.RawResponse) == 0 {
		t.Error("RawResponse is empty")
	}
}

func TestOpenAI_Complete_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limited","type":"rate_limit_error"}}`))
	}))
	defer srv.Close()

	p := NewOpenAIWithEndpoint("sk-test", "gpt-4o-mini", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("err = %v, want 'rate limited'", err)
	}
}

func TestOpenAI_Complete_EmptyAPIKey(t *testing.T) {
	p := NewOpenAI("", "gpt-4o-mini")
	_, err := p.Complete(context.Background(), CompleteRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if !IsDisabled(err) {
		t.Errorf("expected DisabledError, got %v", err)
	}
}

func TestOpenAI_Complete_JSONMode(t *testing.T) {
	srv := fakeOpenAIServer(t, func(t *testing.T, req openaiChatRequest) (int, openaiChatResponse) {
		if req.ResponseFormat == nil || req.ResponseFormat.Type != "json_object" {
			t.Errorf("expected JSON mode response_format, got %+v", req.ResponseFormat)
		}
		resp := openaiChatResponse{Model: req.Model}
		resp.Choices = append(resp.Choices, struct {
			Index   int `json:"index"`
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		}{Index: 0, FinishReason: "stop"})
		resp.Choices[0].Message.Content = "{}"
		return http.StatusOK, resp
	})
	defer srv.Close()

	p := NewOpenAIWithEndpoint("sk-test", "gpt-4o-mini", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
		JSONMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenAI_Embed_NotImplemented(t *testing.T) {
	p := NewOpenAI("sk-x", "gpt-4o-mini")
	_, err := p.Embed(context.Background(), EmbedRequest{})
	if err != ErrNotImplemented {
		t.Errorf("err = %v, want ErrNotImplemented", err)
	}
}

func TestOpenAI_Capabilities(t *testing.T) {
	cases := []struct {
		model       string
		wantVision  bool
		wantContext int
	}{
		{"gpt-4o", true, 128000},
		{"gpt-4o-mini", true, 128000},
		{"o1-preview", false, 200000},
		{"o3-mini", false, 200000},
		{"unknown-model", false, 16000},
	}
	for _, tc := range cases {
		p := NewOpenAI("k", tc.model)
		cap := p.Capabilities()
		if cap.SupportsVision != tc.wantVision {
			t.Errorf("%s: SupportsVision = %v, want %v", tc.model, cap.SupportsVision, tc.wantVision)
		}
		if cap.MaxContextTokens != tc.wantContext {
			t.Errorf("%s: MaxContextTokens = %d, want %d", tc.model, cap.MaxContextTokens, tc.wantContext)
		}
	}
}

func TestOpenAI_LogValueDoesNotLeakAPIKey(t *testing.T) {
	p := NewOpenAI("sk-supersecret-12345", "gpt-4o-mini")
	val := p.LogValue()
	// slog.Value.String() returns a structured printout of the group.
	repr := val.String()
	if strings.Contains(repr, "supersecret") {
		t.Errorf("LogValue leaked API key: %q", repr)
	}
	if !strings.Contains(repr, "openai") {
		t.Errorf("LogValue should mention provider name, got %q", repr)
	}
	// Also sanity check via slog with a buffer.
	var sb strings.Builder
	logger := slog.New(slog.NewTextHandler(&sb, nil))
	logger.Info("test", "provider", p)
	if strings.Contains(sb.String(), "supersecret") {
		t.Errorf("slog leaked API key: %q", sb.String())
	}
}
