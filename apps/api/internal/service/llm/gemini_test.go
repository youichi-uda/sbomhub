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
		// M1 Codex review #F13: Gemini auth must travel via the
		// `x-goog-api-key` header, never as a `?key=` query parameter.
		// Reject both halves so a regression cannot reintroduce URL
		// auth (which would leak the BYOK key through *url.Error on
		// any transport failure — see TestGemini_Complete_NetworkError_DoesNotLeakAPIKey).
		if r.Header.Get("x-goog-api-key") == "" {
			t.Error("missing x-goog-api-key header (Gemini auth must use header, not query)")
		}
		if r.URL.Query().Get("key") != "" {
			t.Errorf("unexpected ?key= query param present: %q (Gemini auth must use header)", r.URL.Query().Get("key"))
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

// TestGemini_Complete_NetworkError_DoesNotLeakAPIKey regresses M1 Codex
// review #F13: a transport failure during a Gemini call used to surface
// the BYOK key verbatim. net/http returns the failure as `*url.Error`
// whose `Error()` method renders the full request URL — and Gemini's
// historical auth used a `?key=AIza...` query string, so the wrapped
// error would carry the secret into:
//
//   - the rewrapped error returned by GeminiProvider.Complete,
//   - llm_calls.error_message (persisted by the triage runner),
//   - the HTTP 500 JSON body returned to the caller.
//
// The fix is two-layered: (1) switch Gemini auth to the
// `x-goog-api-key` header so the URL itself no longer carries the key,
// (2) wrap the transport error through llm.RedactProviderError as
// defense in depth. This test exercises both layers — it forces a
// transport error by hijacking and slamming the connection at the
// server side, then asserts the API key is nowhere in the returned
// error string.
func TestGemini_Complete_NetworkError_DoesNotLeakAPIKey(t *testing.T) {
	const apiKey = "AIzaSyTEST_F13_SUPER_SECRET_KEY_12345"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Hijack and immediately close so the client sees EOF /
		// connection reset — net/http turns that into a *url.Error
		// whose .Error() includes the URL.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	p := NewGeminiWithEndpoint(apiKey, "gemini-2.5-flash", srv.URL)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected transport error from hijacked connection, got nil")
	}
	msg := err.Error()
	if strings.Contains(msg, apiKey) {
		t.Errorf("Gemini transport error leaked the API key:\nerror = %q", msg)
	}
	// Belt and braces: the older `?key=AIza...` URL shape must not appear
	// even in scrubbed form (the regex would have replaced the value but
	// not the param name; the auth migration removes the param entirely).
	if strings.Contains(msg, "key=AIza") {
		t.Errorf("Gemini transport error retained a key=AIza... fragment:\nerror = %q", msg)
	}
}

// TestGemini_Complete_SendsAPIKeyHeader pins the auth-migration
// contract from #F13: the BYOK key MUST be sent via `x-goog-api-key`
// header, NOT as a `?key=` query parameter. Both halves are asserted so
// a future refactor cannot silently fall back to URL auth and reopen
// the leak path.
func TestGemini_Complete_SendsAPIKeyHeader(t *testing.T) {
	const apiKey = "AIzaSyHEADER_AUTH_KEY"
	var sawHeader string
	var sawQueryKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("x-goog-api-key")
		sawQueryKey = r.URL.Query().Get("key")
		resp := geminiResponse{}
		resp.Candidates = append(resp.Candidates, struct {
			Content      geminiContent `json:"content"`
			FinishReason string        `json:"finishReason"`
		}{
			Content:      geminiContent{Role: "model", Parts: []geminiPart{{Text: "ok"}}},
			FinishReason: "STOP",
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewGeminiWithEndpoint(apiKey, "gemini-2.5-flash", srv.URL)
	if _, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if sawHeader != apiKey {
		t.Errorf("x-goog-api-key header = %q, want %q", sawHeader, apiKey)
	}
	if sawQueryKey != "" {
		t.Errorf("request still carried ?key= query parameter = %q (URL-auth must be removed)", sawQueryKey)
	}
}
