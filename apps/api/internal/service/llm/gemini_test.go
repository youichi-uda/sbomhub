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

func fakeGeminiServer(t *testing.T, handler func(t *testing.T, body geminiRequest) (int, geminiResponse)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The path looks like /models/<model>:generateContent
		if !strings.HasPrefix(r.URL.Path, "/models/") || !strings.HasSuffix(r.URL.Path, ":generateContent") {
			t.Errorf("path = %q, want /models/<model>:generateContent", r.URL.Path)
		}
		if r.URL.Query().Get("key") == "" {
			t.Error("missing ?key= auth parameter")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req geminiRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		status, resp := handler(t, req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestGemini_Complete_Success(t *testing.T) {
	srv := fakeGeminiServer(t, func(t *testing.T, req geminiRequest) (int, geminiResponse) {
		if req.SystemInstruction == nil || req.SystemInstruction.Parts[0].Text != "you are a test" {
			t.Errorf("system instruction = %+v", req.SystemInstruction)
		}
		if len(req.Contents) != 1 || req.Contents[0].Role != "user" {
			t.Errorf("contents = %+v, want [user]", req.Contents)
		}
		resp := geminiResponse{}
		resp.Candidates = append(resp.Candidates, struct {
			Content      geminiContent `json:"content"`
			FinishReason string        `json:"finishReason"`
		}{
			Content: geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: "hi from gemini"}},
			},
			FinishReason: "STOP",
		})
		resp.UsageMetadata.PromptTokenCount = 7
		resp.UsageMetadata.CandidatesTokenCount = 4
		resp.UsageMetadata.TotalTokenCount = 11
		return http.StatusOK, resp
	})
	defer srv.Close()

	p := NewGeminiWithEndpoint("gem-key", "gemini-2.5-flash", srv.URL)
	out, err := p.Complete(context.Background(), CompleteRequest{
		System:   "you are a test",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.Content != "hi from gemini" {
		t.Errorf("Content = %q", out.Content)
	}
	if out.InputTokens != 7 || out.OutputTokens != 4 {
		t.Errorf("tokens = (%d, %d)", out.InputTokens, out.OutputTokens)
	}
	if out.FinishReason != "STOP" {
		t.Errorf("FinishReason = %q", out.FinishReason)
	}
}

func TestGemini_Complete_AssistantRoleMapping(t *testing.T) {
	srv := fakeGeminiServer(t, func(t *testing.T, req geminiRequest) (int, geminiResponse) {
		// Generic "assistant" must be translated to Gemini's "model".
		if len(req.Contents) != 2 {
			t.Fatalf("contents len = %d, want 2", len(req.Contents))
		}
		if req.Contents[0].Role != "user" || req.Contents[1].Role != "model" {
			t.Errorf("roles = [%q, %q], want [user, model]", req.Contents[0].Role, req.Contents[1].Role)
		}
		resp := geminiResponse{}
		resp.Candidates = append(resp.Candidates, struct {
			Content      geminiContent `json:"content"`
			FinishReason string        `json:"finishReason"`
		}{
			Content:      geminiContent{Role: "model", Parts: []geminiPart{{Text: "ok"}}},
			FinishReason: "STOP",
		})
		return http.StatusOK, resp
	})
	defer srv.Close()

	p := NewGeminiWithEndpoint("k", "gemini-2.5-flash", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{
			{Role: RoleUser, Content: "Q"},
			{Role: RoleAssistant, Content: "A"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGemini_Complete_JSONMode(t *testing.T) {
	srv := fakeGeminiServer(t, func(t *testing.T, req geminiRequest) (int, geminiResponse) {
		if req.GenerationConfig == nil || req.GenerationConfig.ResponseMimeType != "application/json" {
			t.Errorf("expected application/json mime type, got %+v", req.GenerationConfig)
		}
		resp := geminiResponse{}
		resp.Candidates = append(resp.Candidates, struct {
			Content      geminiContent `json:"content"`
			FinishReason string        `json:"finishReason"`
		}{
			Content:      geminiContent{Role: "model", Parts: []geminiPart{{Text: "{}"}}},
			FinishReason: "STOP",
		})
		return http.StatusOK, resp
	})
	defer srv.Close()

	p := NewGeminiWithEndpoint("k", "gemini-2.5-flash", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
		JSONMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGemini_Complete_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":403,"message":"API_KEY_INVALID","status":"PERMISSION_DENIED"}}`))
	}))
	defer srv.Close()

	p := NewGeminiWithEndpoint("k", "gemini-2.5-flash", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "API_KEY_INVALID") {
		t.Errorf("err = %v", err)
	}
}

func TestGemini_Complete_EmptyAPIKey(t *testing.T) {
	p := NewGemini("", "gemini-2.5-flash")
	_, err := p.Complete(context.Background(), CompleteRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if !IsDisabled(err) {
		t.Errorf("expected DisabledError, got %v", err)
	}
}

func TestGemini_Embed_NotImplemented(t *testing.T) {
	p := NewGemini("k", "gemini-2.5-flash")
	_, err := p.Embed(context.Background(), EmbedRequest{})
	if err != ErrNotImplemented {
		t.Errorf("err = %v, want ErrNotImplemented", err)
	}
}

func TestGemini_Capabilities(t *testing.T) {
	cases := []struct {
		model            string
		wantJSONSchema   bool
		wantMinContext   int
	}{
		{"gemini-2.5-pro", true, 1000000},
		{"gemini-2.5-flash", true, 500000},
		{"gemini-1.0-pro", false, 16000},
	}
	for _, tc := range cases {
		p := NewGemini("k", tc.model)
		cap := p.Capabilities()
		if cap.SupportsJSONSchema != tc.wantJSONSchema {
			t.Errorf("%s: SupportsJSONSchema = %v, want %v", tc.model, cap.SupportsJSONSchema, tc.wantJSONSchema)
		}
		if cap.MaxContextTokens < tc.wantMinContext {
			t.Errorf("%s: MaxContextTokens = %d, want >= %d", tc.model, cap.MaxContextTokens, tc.wantMinContext)
		}
	}
}

func TestGemini_LogValueDoesNotLeakAPIKey(t *testing.T) {
	p := NewGemini("AIza-supersecret-12345", "gemini-2.5-flash")
	var sb strings.Builder
	logger := slog.New(slog.NewTextHandler(&sb, nil))
	logger.Info("test", "provider", p)
	if strings.Contains(sb.String(), "supersecret") {
		t.Errorf("LogValue leaked API key: %q", sb.String())
	}
}
