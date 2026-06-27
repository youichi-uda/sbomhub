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

// fakeOllamaServer wires up an httptest server whose POST /api/chat
// handler delegates to the supplied closure. The closure receives the
// decoded request body so individual tests can assert on the wire
// payload (stream flag, format=json, system prompt, etc.).
func fakeOllamaServer(t *testing.T, handler func(t *testing.T, body ollamaChatRequest) (int, ollamaChatResponse)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path = %q, want /api/chat", r.URL.Path)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req ollamaChatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		// Single-shot path: stream must be false.
		if req.Stream {
			t.Errorf("stream = true, want false (provider uses single-shot path)")
		}
		status, resp := handler(t, req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestOllama_Complete_Success(t *testing.T) {
	srv := fakeOllamaServer(t, func(t *testing.T, req ollamaChatRequest) (int, ollamaChatResponse) {
		if req.Model != "qwen2.5-coder:7b" {
			t.Errorf("model = %q", req.Model)
		}
		if len(req.Messages) != 2 {
			t.Fatalf("messages = %d, want 2 (system + user)", len(req.Messages))
		}
		if req.Messages[0].Role != RoleSystem || req.Messages[0].Content != "be terse" {
			t.Errorf("system message = %+v", req.Messages[0])
		}
		if req.Messages[1].Role != RoleUser || req.Messages[1].Content != "hi" {
			t.Errorf("user message = %+v", req.Messages[1])
		}
		if req.Options == nil || req.Options.NumPredict <= 0 {
			t.Errorf("options.num_predict = %+v, want > 0", req.Options)
		}
		if req.Format != "" {
			t.Errorf("format = %q, want empty (JSONMode not requested)", req.Format)
		}
		return http.StatusOK, ollamaChatResponse{
			Model:           req.Model,
			Message:         ollamaMessage{Role: RoleAssistant, Content: "hi from ollama"},
			Done:            true,
			PromptEvalCount: 12,
			EvalCount:       7,
		}
	})
	defer srv.Close()

	p := NewOllama(srv.URL, "qwen2.5-coder:7b")
	out, err := p.Complete(context.Background(), CompleteRequest{
		System:   "be terse",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.Content != "hi from ollama" {
		t.Errorf("Content = %q", out.Content)
	}
	if out.InputTokens != 12 || out.OutputTokens != 7 {
		t.Errorf("tokens = (%d, %d), want (12, 7)", out.InputTokens, out.OutputTokens)
	}
	if out.FinishReason != "stop" {
		t.Errorf("FinishReason = %q, want stop", out.FinishReason)
	}
	if out.Model != "qwen2.5-coder:7b" {
		t.Errorf("Model = %q", out.Model)
	}
	if out.CostUSD != 0 {
		t.Errorf("CostUSD = %v, want 0 (local LLM)", out.CostUSD)
	}
	if len(out.RawResponse) == 0 {
		t.Error("RawResponse empty")
	}
}

func TestOllama_Complete_JSONMode(t *testing.T) {
	srv := fakeOllamaServer(t, func(t *testing.T, req ollamaChatRequest) (int, ollamaChatResponse) {
		if req.Format != "json" {
			t.Errorf("format = %q, want json", req.Format)
		}
		return http.StatusOK, ollamaChatResponse{
			Model:   req.Model,
			Message: ollamaMessage{Role: RoleAssistant, Content: `{"ok":true}`},
			Done:    true,
		}
	})
	defer srv.Close()

	p := NewOllama(srv.URL, "qwen2.5-coder:7b")
	out, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "give me json"}},
		JSONMode: true,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.Content != `{"ok":true}` {
		t.Errorf("Content = %q", out.Content)
	}
}

func TestOllama_Complete_DefaultMaxTokens(t *testing.T) {
	var seenNumPredict int
	srv := fakeOllamaServer(t, func(_ *testing.T, req ollamaChatRequest) (int, ollamaChatResponse) {
		if req.Options != nil {
			seenNumPredict = req.Options.NumPredict
		}
		return http.StatusOK, ollamaChatResponse{
			Model:   req.Model,
			Message: ollamaMessage{Role: RoleAssistant, Content: "x"},
			Done:    true,
		}
	})
	defer srv.Close()

	p := NewOllama(srv.URL, "qwen2.5-coder:7b")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
		// MaxTokens deliberately 0.
	})
	if err != nil {
		t.Fatal(err)
	}
	if seenNumPredict <= 0 {
		t.Errorf("default num_predict = %d, want > 0", seenNumPredict)
	}
}

func TestOllama_Complete_NonSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"model 'nope:7b' not found"}`))
	}))
	defer srv.Close()

	p := NewOllama(srv.URL, "nope:7b")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "model 'nope:7b' not found") {
		t.Errorf("err = %v, want to include upstream error message", err)
	}
}

func TestOllama_Complete_NonSuccessNonJSONBodyTruncated(t *testing.T) {
	// Misrouted POST hits an HTML proxy page — we must surface a useful
	// snippet of the body but not flood the audit log.
	bigBody := strings.Repeat("X", ollamaResponseBodyCap*4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(bigBody))
	}))
	defer srv.Close()

	p := NewOllama(srv.URL, "qwen2.5-coder:7b")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	// We do not assert exact length here (the rendered error contains
	// the status prefix as well), but the rendered error MUST be
	// smaller than the original body — i.e. the cap fired.
	if len(err.Error()) >= len(bigBody) {
		t.Errorf("err length = %d, want < raw body %d (cap should truncate)", len(err.Error()), len(bigBody))
	}
}

func TestOllama_Complete_TransportErrorRedacted(t *testing.T) {
	// Point at an obviously-broken URL so the http.Client returns a
	// *url.Error. RedactProviderError should strip the query string —
	// here we plant a fake ?key= to prove the scrubber ran.
	p := NewOllamaWithClient(
		"http://127.0.0.1:1/?key=should-be-redacted",
		"qwen2.5-coder:7b",
		&http.Client{}, // no timeout — connection refused returns immediately
	)
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected transport error")
	}
	if strings.Contains(err.Error(), "should-be-redacted") {
		t.Errorf("transport error leaked auth-shaped query value: %v", err)
	}
}

func TestOllama_Complete_DoneFalseHasNoFinishReason(t *testing.T) {
	srv := fakeOllamaServer(t, func(_ *testing.T, req ollamaChatRequest) (int, ollamaChatResponse) {
		return http.StatusOK, ollamaChatResponse{
			Model:   req.Model,
			Message: ollamaMessage{Role: RoleAssistant, Content: "partial"},
			Done:    false,
		}
	})
	defer srv.Close()

	p := NewOllama(srv.URL, "qwen2.5-coder:7b")
	out, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.FinishReason != "" {
		t.Errorf("FinishReason = %q, want empty when done=false", out.FinishReason)
	}
}

func TestOllama_Complete_200WithErrorField(t *testing.T) {
	// A 200 OK envelope can still carry a non-empty error field if the
	// model load failed mid-stream; treat that as an error so audit log
	// rows are not persisted as successful drafts.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"model":"q","message":{"role":"assistant","content":""},"done":true,"error":"gpu oom"}`))
	}))
	defer srv.Close()

	p := NewOllama(srv.URL, "qwen2.5-coder:7b")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected error for 200-with-error-field")
	}
	if !strings.Contains(err.Error(), "gpu oom") {
		t.Errorf("err = %v, want to mention upstream error", err)
	}
}

func TestOllama_Complete_EmptyModel(t *testing.T) {
	// Constructed without a model — the caller should hit a clear error
	// rather than a silent wire failure.
	p := NewOllama("http://localhost:11434", "")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected error for empty model")
	}
	if !strings.Contains(err.Error(), "model") {
		t.Errorf("err = %v, want to mention model", err)
	}
}

func TestOllama_Complete_RoleNormalization(t *testing.T) {
	srv := fakeOllamaServer(t, func(t *testing.T, req ollamaChatRequest) (int, ollamaChatResponse) {
		// Unknown role should be downgraded to user.
		var sawUnknown bool
		for _, m := range req.Messages {
			switch m.Role {
			case RoleUser, RoleAssistant, RoleSystem, RoleTool:
				// ok
			default:
				sawUnknown = true
			}
		}
		if sawUnknown {
			t.Error("payload contained an unknown role (should have been normalised to user)")
		}
		return http.StatusOK, ollamaChatResponse{
			Model:   req.Model,
			Message: ollamaMessage{Role: RoleAssistant, Content: "ok"},
			Done:    true,
		}
	})
	defer srv.Close()

	p := NewOllama(srv.URL, "qwen2.5-coder:7b")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{
			{Role: "weird", Content: "garbage"},
			{Role: RoleUser, Content: "hi"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func fakeOllamaEmbeddingServer(
	t *testing.T,
	handler func(t *testing.T, body ollamaEmbedRequest) (status int, resp ollamaEmbedResponse, rawBody []byte),
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embed" {
			t.Errorf("path = %q, want /api/embed", r.URL.Path)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req ollamaEmbedRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		status, resp, rawBody := handler(t, req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if rawBody != nil {
			_, _ = w.Write(rawBody)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func makeOllamaEmbeddings(count int) [][]float32 {
	out := make([][]float32, count)
	for i := range out {
		out[i] = []float32{float32(i) + 0.1, float32(i) + 0.2}
	}
	return out
}

func TestOllama_Embed_SuccessAndChunking(t *testing.T) {
	total := ollamaEmbedMaxBatchSize + 1
	var calls int
	srv := fakeOllamaEmbeddingServer(t, func(t *testing.T, req ollamaEmbedRequest) (int, ollamaEmbedResponse, []byte) {
		calls++
		if req.Model != "mxbai-embed-large" {
			t.Errorf("model = %q", req.Model)
		}
		return http.StatusOK, ollamaEmbedResponse{
			Model:           req.Model,
			Embeddings:      makeOllamaEmbeddings(len(req.Input)),
			PromptEvalCount: len(req.Input),
		}, nil
	})
	defer srv.Close()
	p := NewOllamaWithEmbedding(srv.URL, "qwen2.5-coder:7b", "mxbai-embed-large")
	out, err := p.Embed(context.Background(), EmbedRequest{Texts: make([]string, total)})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if calls != 2 || len(out.Vectors) != total || out.InputTokens != total || out.Model != "mxbai-embed-large" {
		t.Fatalf("calls=%d out=%+v", calls, out)
	}
}

func TestOllama_Embed_ErrorsAndCaps(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError} {
		srv := fakeOllamaEmbeddingServer(t, func(_ *testing.T, _ ollamaEmbedRequest) (int, ollamaEmbedResponse, []byte) {
			return status, ollamaEmbedResponse{Error: "upstream error"}, nil
		})
		p := NewOllama(srv.URL, "qwen2.5-coder:7b")
		_, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"x"}})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "upstream error") {
			t.Fatalf("status %d err = %v", status, err)
		}
	}
	t.Run("partial failure discards", func(t *testing.T) {
		var calls int
		srv := fakeOllamaEmbeddingServer(t, func(_ *testing.T, req ollamaEmbedRequest) (int, ollamaEmbedResponse, []byte) {
			calls++
			if calls == 1 {
				return http.StatusOK, ollamaEmbedResponse{Model: req.Model, Embeddings: makeOllamaEmbeddings(len(req.Input))}, nil
			}
			return http.StatusInternalServerError, ollamaEmbedResponse{}, []byte("boom")
		})
		defer srv.Close()
		p := NewOllama(srv.URL, "qwen2.5-coder:7b")
		out, err := p.Embed(context.Background(), EmbedRequest{Texts: make([]string, ollamaEmbedMaxBatchSize+1)})
		if err == nil || out != nil {
			t.Fatalf("out=%+v err=%v, want whole-call failure", out, err)
		}
	})
	p := NewOllama("http://localhost:11434", "qwen2.5-coder:7b")
	_, err := p.Embed(context.Background(), EmbedRequest{Texts: make([]string, ollamaEmbedMaxTotalInputs+1)})
	if err == nil || !strings.Contains(err.Error(), "safety cap") {
		t.Fatalf("err = %v", err)
	}
	t.Run("context cancel", func(t *testing.T) {
		srv := fakeOllamaEmbeddingServer(t, func(_ *testing.T, req ollamaEmbedRequest) (int, ollamaEmbedResponse, []byte) {
			return http.StatusOK, ollamaEmbedResponse{Model: req.Model, Embeddings: makeOllamaEmbeddings(len(req.Input))}, nil
		})
		defer srv.Close()
		p := NewOllama(srv.URL, "qwen2.5-coder:7b")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := p.Embed(ctx, EmbedRequest{Texts: []string{"x"}})
		if err == nil {
			t.Fatal("expected context cancel error")
		}
	})
}

func TestOllama_Capabilities(t *testing.T) {
	cases := []struct {
		model      string
		wantCtxMin int
		wantCtxMax int
	}{
		// Bare names + tagged variants both collapse to the same row.
		{"qwen2.5-coder:7b", 32768, 32768},
		{"qwen2.5", 32768, 32768},
		{"llama3.1:8b", 131072, 131072},
		{"llama3.2:3b", 131072, 131072},
		{"llama3:8b", 8192, 8192},
		{"mistral-nemo:12b", 131072, 131072},
		{"mistral:7b", 32768, 32768},
		{"mixtral:8x7b", 32768, 32768},
		{"phi3:mini", 131072, 131072},
		{"gemma2:9b", 8192, 8192},
		{"deepseek-r1:7b", 163840, 163840},
		{"codellama:13b", 16384, 16384},
		{"some-future-model:1b", 8192, 8192}, // fallback
	}
	for _, tc := range cases {
		t.Run(tc.model, func(t *testing.T) {
			p := NewOllama("http://localhost:11434", tc.model)
			c := p.Capabilities()
			if c.MaxContextTokens < tc.wantCtxMin || c.MaxContextTokens > tc.wantCtxMax {
				t.Errorf("MaxContextTokens = %d, want in [%d, %d]", c.MaxContextTokens, tc.wantCtxMin, tc.wantCtxMax)
			}
			if !c.SupportsJSONMode {
				t.Error("SupportsJSONMode = false, want true (Ollama format=json)")
			}
			if c.SupportsJSONSchema {
				t.Error("SupportsJSONSchema = true, want false (Ollama enforces grammar, not schema)")
			}
			if c.SupportsFunctionCall {
				t.Error("SupportsFunctionCall = true, want false in M4")
			}
			if c.SupportsVision {
				t.Error("SupportsVision = true, want false (multimodal needs different request shape)")
			}
			if !c.SupportsEmbedding {
				t.Error("SupportsEmbedding = false, want true")
			}
			if c.EmbeddingDimensions != 768 {
				t.Errorf("EmbeddingDimensions = %d, want 768 for default nomic-embed-text", c.EmbeddingDimensions)
			}
		})
	}
}

func TestOllama_NameAndModel(t *testing.T) {
	p := NewOllama("http://localhost:11434", "qwen2.5-coder:7b")
	if p.Name() != "ollama" {
		t.Errorf("Name() = %q, want ollama", p.Name())
	}
	if p.Model() != "qwen2.5-coder:7b" {
		t.Errorf("Model() = %q", p.Model())
	}
}

func TestOllama_LogValueDoesNotLeakBaseURL(t *testing.T) {
	// For an enterprise self-host deployment the Ollama service URL
	// (e.g. http://ollama.internal:11434 or a hostname containing a
	// tenant slug) is internal-network topology that should not show
	// up in audit logs or HTTP 500 bodies.
	p := NewOllama("http://ollama.internal.acme-secret-tenant.svc:11434", "qwen2.5-coder:7b")
	var sb strings.Builder
	logger := slog.New(slog.NewTextHandler(&sb, nil))
	logger.Info("test", "provider", p)
	out := sb.String()
	if strings.Contains(out, "acme-secret-tenant") {
		t.Errorf("LogValue leaked base URL hostname: %q", out)
	}
	if strings.Contains(out, "11434") {
		t.Errorf("LogValue leaked base URL port: %q", out)
	}
	// Sanity: provider + model should still surface.
	if !strings.Contains(out, "ollama") {
		t.Errorf("LogValue did not emit provider name: %q", out)
	}
	if !strings.Contains(out, "qwen2.5-coder:7b") {
		t.Errorf("LogValue did not emit model: %q", out)
	}
}

func TestOllama_NewOllama_EmptyBaseURLDefaults(t *testing.T) {
	p := NewOllama("", "qwen2.5-coder:7b")
	if p.baseURL != defaultOllamaEndpoint {
		t.Errorf("baseURL = %q, want %q", p.baseURL, defaultOllamaEndpoint)
	}
}

func TestOllama_NewOllama_TrimsTrailingSlash(t *testing.T) {
	p := NewOllama("http://localhost:11434/", "qwen2.5-coder:7b")
	if p.baseURL != "http://localhost:11434" {
		t.Errorf("baseURL = %q, want trailing-slash trimmed", p.baseURL)
	}
}

func TestOllama_NewOllamaWithClient_NilClientFallsBackToDefault(t *testing.T) {
	p := NewOllamaWithClient("http://localhost:11434", "qwen2.5-coder:7b", nil)
	if p.client == nil {
		t.Error("client = nil, want non-nil fallback")
	}
}
