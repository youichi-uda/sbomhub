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

func fakeAnthropicServer(t *testing.T, handler func(t *testing.T, body anthropicRequest) (int, anthropicResponse)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" {
			t.Errorf("path = %q, want /messages", r.URL.Path)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("x-api-key"); got == "" {
			t.Error("missing x-api-key header")
		}
		if got := r.Header.Get("anthropic-version"); got == "" {
			t.Error("missing anthropic-version header")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req anthropicRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		status, resp := handler(t, req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestAnthropic_Complete_Success(t *testing.T) {
	srv := fakeAnthropicServer(t, func(t *testing.T, req anthropicRequest) (int, anthropicResponse) {
		if req.System != "you are a test" {
			t.Errorf("system = %q", req.System)
		}
		if req.MaxTokens <= 0 {
			t.Errorf("max_tokens = %d, want > 0", req.MaxTokens)
		}
		resp := anthropicResponse{
			ID:         "msg_x",
			Type:       "message",
			Role:       "assistant",
			Model:      req.Model,
			StopReason: "end_turn",
		}
		resp.Content = append(resp.Content, struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{Type: "text", Text: "hi from claude"})
		resp.Usage.InputTokens = 10
		resp.Usage.OutputTokens = 5
		return http.StatusOK, resp
	})
	defer srv.Close()

	p := NewAnthropicWithEndpoint("sk-ant-test", "claude-sonnet-4-6", srv.URL)
	out, err := p.Complete(context.Background(), CompleteRequest{
		System:   "you are a test",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.Content != "hi from claude" {
		t.Errorf("Content = %q", out.Content)
	}
	if out.InputTokens != 10 || out.OutputTokens != 5 {
		t.Errorf("tokens = (%d, %d)", out.InputTokens, out.OutputTokens)
	}
	if out.FinishReason != "end_turn" {
		t.Errorf("FinishReason = %q", out.FinishReason)
	}
	if len(out.RawResponse) == 0 {
		t.Error("RawResponse empty")
	}
}

func TestAnthropic_Complete_DefaultMaxTokens(t *testing.T) {
	var seenMax int
	srv := fakeAnthropicServer(t, func(_ *testing.T, req anthropicRequest) (int, anthropicResponse) {
		seenMax = req.MaxTokens
		resp := anthropicResponse{Model: req.Model, StopReason: "end_turn"}
		resp.Content = append(resp.Content, struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{Type: "text", Text: "x"})
		return http.StatusOK, resp
	})
	defer srv.Close()

	p := NewAnthropicWithEndpoint("k", "claude-sonnet-4-6", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
		// MaxTokens deliberately 0
	})
	if err != nil {
		t.Fatal(err)
	}
	if seenMax <= 0 {
		t.Errorf("default max_tokens = %d, want > 0 (Anthropic requires it)", seenMax)
	}
}

func TestAnthropic_Complete_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","message":"bad model"}}`))
	}))
	defer srv.Close()

	p := NewAnthropicWithEndpoint("k", "claude-sonnet-4-6", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad model") {
		t.Errorf("err = %v", err)
	}
}

func TestAnthropic_Complete_EmptyAPIKey(t *testing.T) {
	p := NewAnthropic("", "claude-sonnet-4-6")
	_, err := p.Complete(context.Background(), CompleteRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if !IsDisabled(err) {
		t.Errorf("expected DisabledError, got %v", err)
	}
}

func TestAnthropic_Embed_NotImplemented(t *testing.T) {
	p := NewAnthropic("k", "claude-sonnet-4-6")
	_, err := p.Embed(context.Background(), EmbedRequest{})
	if err != ErrNotImplemented {
		t.Errorf("err = %v, want ErrNotImplemented", err)
	}
}

func TestAnthropic_Capabilities(t *testing.T) {
	p := NewAnthropic("k", "claude-sonnet-4-6")
	cap := p.Capabilities()
	if !cap.SupportsFunctionCall {
		t.Error("claude-sonnet-4 should support function calling")
	}
	if !cap.SupportsVision {
		t.Error("claude-sonnet-4 should support vision")
	}
	if cap.MaxContextTokens < 100000 {
		t.Errorf("MaxContextTokens = %d, want >= 100000", cap.MaxContextTokens)
	}
}

func TestAnthropic_LogValueDoesNotLeakAPIKey(t *testing.T) {
	p := NewAnthropic("sk-ant-supersecret-12345", "claude-sonnet-4-6")
	var sb strings.Builder
	logger := slog.New(slog.NewTextHandler(&sb, nil))
	logger.Info("test", "provider", p)
	if strings.Contains(sb.String(), "supersecret") {
		t.Errorf("LogValue leaked API key: %q", sb.String())
	}
}

func TestAnthropic_RoleNormalization(t *testing.T) {
	srv := fakeAnthropicServer(t, func(t *testing.T, req anthropicRequest) (int, anthropicResponse) {
		// "tool" role should be downgraded to "user" — Anthropic Messages
		// API rejects unknown roles.
		for _, m := range req.Messages {
			if m.Role != RoleUser && m.Role != RoleAssistant {
				t.Errorf("unexpected role %q in payload", m.Role)
			}
		}
		resp := anthropicResponse{Model: req.Model, StopReason: "end_turn"}
		resp.Content = append(resp.Content, struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{Type: "text", Text: "ok"})
		return http.StatusOK, resp
	})
	defer srv.Close()

	p := NewAnthropicWithEndpoint("k", "claude-sonnet-4-6", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{
			{Role: RoleTool, Content: "tool result"},
			{Role: RoleUser, Content: "hi"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}
