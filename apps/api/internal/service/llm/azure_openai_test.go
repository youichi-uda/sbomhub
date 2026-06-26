package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeAzureServer mimics POST {endpoint}/openai/deployments/{deployment}/chat/completions
// for unit testing. Tests assert the URL pattern (deployment in path +
// api-version query) and the `api-key` auth header (NOT
// Authorization: Bearer) and then hand the decoded request to a
// per-test handler that returns the desired status + response.
//
// This mirrors fakeOpenAIServer (openai_test.go) for parity — anyone
// reading openai_test.go should immediately recognise the shape.
func fakeAzureServer(
	t *testing.T,
	wantDeployment string,
	wantAPIVersion string,
	handler func(t *testing.T, body openaiChatRequest) (status int, resp openaiChatResponse, rawBody []byte),
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// URL: /openai/deployments/<deployment>/chat/completions
		wantPath := "/openai/deployments/" + wantDeployment + "/chat/completions"
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("api-version"); got != wantAPIVersion {
			t.Errorf("api-version = %q, want %q", got, wantAPIVersion)
		}
		// Azure uses api-key, NOT Authorization: Bearer.
		if got := r.Header.Get("api-key"); got == "" {
			t.Errorf("api-key header missing (got %v)", r.Header)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header should NOT be set for Azure (got %q)", got)
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req openaiChatRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		// Azure routes by deployment URL, so the body's `model` field
		// should be empty (we deliberately do not send it).
		if req.Model != "" {
			t.Errorf("body model = %q, want empty (Azure routes by deployment)", req.Model)
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

func makeOpenAIChoice(content, finishReason string) openaiChatResponse {
	resp := openaiChatResponse{}
	resp.Choices = append(resp.Choices, struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}{Index: 0, FinishReason: finishReason})
	resp.Choices[0].Message.Role = "assistant"
	resp.Choices[0].Message.Content = content
	return resp
}

func TestAzureOpenAI_Complete_Success(t *testing.T) {
	const (
		deployment = "legal-vex-triage"
		apiVersion = "2024-10-21"
	)
	srv := fakeAzureServer(t, deployment, apiVersion, func(t *testing.T, req openaiChatRequest) (int, openaiChatResponse, []byte) {
		if len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[1].Role != "user" {
			t.Errorf("messages = %+v, want [system, user]", req.Messages)
		}
		resp := makeOpenAIChoice("hello azure", "stop")
		// Azure returns the underlying model name in the response.
		resp.Model = "gpt-4o-2024-11-20"
		resp.Usage.PromptTokens = 11
		resp.Usage.CompletionTokens = 3
		resp.Usage.TotalTokens = 14
		return http.StatusOK, resp, nil
	})
	defer srv.Close()

	p := NewAzureOpenAI("az-test-key", srv.URL, deployment, apiVersion, "gpt-4o")

	out, err := p.Complete(context.Background(), CompleteRequest{
		System:   "you are a test",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.Content != "hello azure" {
		t.Errorf("Content = %q", out.Content)
	}
	if out.InputTokens != 11 || out.OutputTokens != 3 {
		t.Errorf("tokens = (%d, %d), want (11, 3)", out.InputTokens, out.OutputTokens)
	}
	if out.FinishReason != "stop" {
		t.Errorf("FinishReason = %q, want stop", out.FinishReason)
	}
	if out.Model != "gpt-4o-2024-11-20" {
		t.Errorf("Model = %q", out.Model)
	}
	if len(out.RawResponse) == 0 {
		t.Error("RawResponse is empty")
	}
}

func TestAzureOpenAI_Complete_DefaultAPIVersion(t *testing.T) {
	// When NewAzureOpenAI is given apiVersion=="" the provider falls
	// back to defaultAzureAPIVersion. Use the constant in the
	// expectation so a future bump only requires touching one place.
	const deployment = "legal-vex-triage"
	srv := fakeAzureServer(t, deployment, defaultAzureAPIVersion, func(t *testing.T, _ openaiChatRequest) (int, openaiChatResponse, []byte) {
		return http.StatusOK, makeOpenAIChoice("ok", "stop"), nil
	})
	defer srv.Close()

	p := NewAzureOpenAI("k", srv.URL, deployment, "", "gpt-4o")
	if _, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestAzureOpenAI_Complete_JSONMode(t *testing.T) {
	const (
		deployment = "vex-json"
		apiVersion = "2024-10-21"
	)
	srv := fakeAzureServer(t, deployment, apiVersion, func(t *testing.T, req openaiChatRequest) (int, openaiChatResponse, []byte) {
		if req.ResponseFormat == nil || req.ResponseFormat.Type != "json_object" {
			t.Errorf("response_format = %+v, want json_object", req.ResponseFormat)
		}
		resp := makeOpenAIChoice("{}", "stop")
		return http.StatusOK, resp, nil
	})
	defer srv.Close()

	p := NewAzureOpenAI("k", srv.URL, deployment, apiVersion, "gpt-4o")
	if _, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
		JSONMode: true,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

// TestAzureOpenAI_Complete_AuthError covers the 401 path. Azure returns
// the structured OpenAI-shape error with "Unauthorized" — the provider
// must surface that text without leaking the api-key header.
func TestAzureOpenAI_Complete_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Access denied due to invalid subscription key","code":"401"}}`))
	}))
	defer srv.Close()

	p := NewAzureOpenAI("bad-key", srv.URL, "dep", "2024-10-21", "gpt-4o")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected auth error")
	}
	if !strings.Contains(err.Error(), "Access denied") {
		t.Errorf("err = %v, want to mention 'Access denied'", err)
	}
	if strings.Contains(err.Error(), "bad-key") {
		t.Errorf("err leaked api-key value: %v", err)
	}
}

func TestAzureOpenAI_Complete_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"Rate limit exceeded"}}`))
	}))
	defer srv.Close()

	p := NewAzureOpenAI("k", srv.URL, "dep", "2024-10-21", "gpt-4o")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected rate-limit error")
	}
	if !strings.Contains(err.Error(), "Rate limit") {
		t.Errorf("err = %v, want to mention 'Rate limit'", err)
	}
}

func TestAzureOpenAI_Complete_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Non-JSON body to exercise the raw-body fallback path.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	p := NewAzureOpenAI("k", srv.URL, "dep", "2024-10-21", "gpt-4o")
	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected 500 error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want to mention status 500", err)
	}
}

func TestAzureOpenAI_Complete_EmptyAPIKey(t *testing.T) {
	p := NewAzureOpenAI("", "https://x.openai.azure.com", "dep", "2024-10-21", "gpt-4o")
	_, err := p.Complete(context.Background(), CompleteRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if !IsDisabled(err) {
		t.Errorf("expected DisabledError, got %v", err)
	}
}

// TestAzureOpenAI_Embed_DisabledWhenDeploymentMissing is the M5-3
// replacement for the M4-era ErrNotImplemented assertion. An Azure
// provider constructed without an embedding deployment (the M4 default
// constructor signature) must refuse Embed with *DisabledError so the
// HTTP layer surfaces 503 + "set SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT"
// rather than a sentinel-typed error that callers might silently
// swallow.
func TestAzureOpenAI_Embed_DisabledWhenDeploymentMissing(t *testing.T) {
	p := NewAzureOpenAI("k", "https://x.openai.azure.com", "dep", "2024-10-21", "gpt-4o")
	_, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"hi"}})
	if !IsDisabled(err) {
		t.Errorf("expected DisabledError, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT") {
		t.Errorf("Reason should name the env var, got %v", err)
	}
}

func TestAzureOpenAI_Capabilities(t *testing.T) {
	cases := []struct {
		model       string
		wantVision  bool
		wantContext int
		wantSchema  bool
	}{
		{"gpt-4o", true, 128000, true},
		{"gpt-4o-mini", true, 128000, true},
		{"gpt-5", true, 128000, true},
		{"o1-preview", false, 200000, true},
		{"o3-mini", false, 200000, true},
		{"unknown-deployment-name", false, 16000, false},
	}
	for _, tc := range cases {
		t.Run(tc.model, func(t *testing.T) {
			p := NewAzureOpenAI("k", "https://x.openai.azure.com", "dep", "2024-10-21", tc.model)
			cap := p.Capabilities()
			if cap.SupportsVision != tc.wantVision {
				t.Errorf("SupportsVision = %v, want %v", cap.SupportsVision, tc.wantVision)
			}
			if cap.MaxContextTokens != tc.wantContext {
				t.Errorf("MaxContextTokens = %d, want %d", cap.MaxContextTokens, tc.wantContext)
			}
			if cap.SupportsJSONSchema != tc.wantSchema {
				t.Errorf("SupportsJSONSchema = %v, want %v", cap.SupportsJSONSchema, tc.wantSchema)
			}
			if !cap.SupportsJSONMode {
				t.Error("SupportsJSONMode should be true for all Azure chat-completions deployments")
			}
		})
	}
}

func TestAzureOpenAI_NameAndModel(t *testing.T) {
	t.Run("explicit model", func(t *testing.T) {
		p := NewAzureOpenAI("k", "https://x.openai.azure.com", "biz-deploy", "2024-10-21", "gpt-4o")
		if p.Name() != "azure_openai" {
			t.Errorf("Name = %q, want azure_openai", p.Name())
		}
		if p.Model() != "gpt-4o" {
			t.Errorf("Model = %q, want gpt-4o", p.Model())
		}
	})
	t.Run("model falls back to deployment", func(t *testing.T) {
		p := NewAzureOpenAI("k", "https://x.openai.azure.com", "biz-deploy", "2024-10-21", "")
		if p.Model() != "biz-deploy" {
			t.Errorf("Model = %q, want fallback to deployment 'biz-deploy'", p.Model())
		}
	})
}

func TestAzureOpenAI_LogValueDoesNotLeakSecrets(t *testing.T) {
	const (
		apiKey   = "az-supersecret-12345"
		endpoint = "https://tenant-resource.openai.azure.com"
	)
	p := NewAzureOpenAI(apiKey, endpoint, "biz-deploy", "2024-10-21", "gpt-4o")

	// 1) Direct LogValue() inspection.
	repr := p.LogValue().String()
	if strings.Contains(repr, "supersecret") {
		t.Errorf("LogValue leaked API key: %q", repr)
	}
	// Endpoint URL is considered tenancy metadata (M4-2 §LogValue policy).
	// We do not require it to be absent in repr if a future revision adds
	// it intentionally — but for now it MUST NOT appear.
	if strings.Contains(repr, "tenant-resource") {
		t.Errorf("LogValue leaked endpoint URL: %q", repr)
	}
	if !strings.Contains(repr, "azure_openai") {
		t.Errorf("LogValue should mention provider name, got %q", repr)
	}
	if !strings.Contains(repr, "biz-deploy") {
		t.Errorf("LogValue should mention deployment, got %q", repr)
	}

	// 2) Round-trip through slog with a buffer handler.
	var sb strings.Builder
	logger := slog.New(slog.NewTextHandler(&sb, nil))
	logger.Info("test", "provider", p)
	logged := sb.String()
	if strings.Contains(logged, "supersecret") {
		t.Errorf("slog leaked API key: %q", logged)
	}
	if strings.Contains(logged, "tenant-resource") {
		t.Errorf("slog leaked endpoint URL: %q", logged)
	}
}

// TestAzureOpenAI_TransportErrorRedactsEndpoint is the F63 regression
// guard: on a DNS / connect / timeout failure, the Azure tenant resource
// subdomain, deployment name, and api-version MUST NOT survive in the
// returned error message (which is persisted into
// llm_calls.error_message and may be echoed back through a 500 JSON
// body). The default RedactProviderError only strips query / fragment;
// RedactAzureTransportError additionally replaces the host + path with
// `[REDACTED-AZURE-ENDPOINT]`.
//
// We use an unroutable-but-syntactically-valid endpoint so the *http.Client
// call returns a *url.Error from a connect failure (port 1 is reserved
// and the loopback refusal is portable; this avoids depending on real
// DNS being available).
func TestAzureOpenAI_TransportErrorRedactsEndpoint(t *testing.T) {
	const (
		tenantResource = "secret-tenant-resource"
		deployment     = "legal-vex-triage"
		apiVersion     = "2024-10-21"
	)
	// http://<tenant>.openai.azure.com:1 — port 1 will fail to connect
	// on any sane OS. The hostname is what we care about leaking; the
	// *http.Client DNS resolution may itself fail (test sandbox) or
	// proceed to a connect refusal, but either way the resulting
	// *url.Error.URL will contain the tenant resource subdomain.
	endpoint := fmt.Sprintf("http://%s.openai.azure.com:1", tenantResource)

	// Short timeout client so the test does not hang if the sandbox
	// allows the connect to drift into SYN-retry territory.
	client := &http.Client{Timeout: 2 * time.Second}
	p := NewAzureOpenAIWithClient("k", endpoint, deployment, apiVersion, "gpt-4o", client)

	_, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	})
	if err == nil {
		t.Fatal("expected transport error from unroutable endpoint")
	}

	msg := err.Error()

	// The tenant resource subdomain MUST be gone (F63 primary leak).
	if strings.Contains(msg, tenantResource) {
		t.Errorf("transport error leaked tenant resource %q: %q", tenantResource, msg)
	}
	// Substring "openai.azure.com" MUST be gone — it identifies the
	// service and combined with a partial fragment of the original URL
	// would let a reader reconstruct the tenancy URL.
	if strings.Contains(msg, "openai.azure.com") {
		t.Errorf("transport error leaked Azure host suffix: %q", msg)
	}
	// The deployment name MUST be gone (operators name deployments
	// after business units — e.g. "legal-vex-triage" — which is
	// PII-adjacent).
	if strings.Contains(msg, deployment) {
		t.Errorf("transport error leaked deployment name %q: %q", deployment, msg)
	}
	// The api-version query value MUST be gone.
	if strings.Contains(msg, apiVersion) {
		t.Errorf("transport error leaked api-version %q: %q", apiVersion, msg)
	}

	// The placeholder MUST appear so an operator reading the persisted
	// llm_calls.error_message knows the URL was scrubbed deliberately
	// (not corrupted by a parse failure).
	if !strings.Contains(msg, "[REDACTED-AZURE-ENDPOINT]") {
		t.Errorf("expected redaction placeholder in error message, got %q", msg)
	}

	// Defense in depth: the *url.Error in the chain should also have its
	// URL field scrubbed (so any downstream errors.As caller sees the
	// scrubbed value too, not just the rendered message).
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if strings.Contains(urlErr.URL, tenantResource) ||
			strings.Contains(urlErr.URL, "openai.azure.com") {
			t.Errorf("*url.Error.URL still leaks endpoint: %q", urlErr.URL)
		}
	}
}

// TestAzureOpenAI_NewWithClient_Customizable verifies the test seam
// (NewAzureOpenAIWithClient) installs a custom *http.Client correctly
// so callers can hook the transport for record/replay.
func TestAzureOpenAI_NewWithClient_Customizable(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(makeOpenAIChoice("ok", "stop"))
	}))
	defer srv.Close()

	customClient := &http.Client{}
	p := NewAzureOpenAIWithClient("k", srv.URL, "dep", "2024-10-21", "gpt-4o", customClient)
	if _, err := p.Complete(context.Background(), CompleteRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !called {
		t.Error("expected custom client to dispatch to the test server")
	}
}

// ---------------------------------------------------------------------------
// M5 Wave M5-3 (issue #51) — Azure embedding deployment.
// ---------------------------------------------------------------------------

// fakeAzureEmbeddingServer mirrors fakeAzureServer for the embeddings
// endpoint. Asserts the URL pattern (embedding deployment in path +
// api-version query) and the `api-key` auth header, then hands the
// decoded request body to a per-test handler that returns the desired
// status + response.
func fakeAzureEmbeddingServer(
	t *testing.T,
	wantDeployment string,
	wantAPIVersion string,
	handler func(t *testing.T, body azureEmbeddingRequest) (status int, resp azureEmbeddingResponse, rawBody []byte),
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/openai/deployments/" + wantDeployment + "/embeddings"
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("api-version"); got != wantAPIVersion {
			t.Errorf("api-version = %q, want %q", got, wantAPIVersion)
		}
		if got := r.Header.Get("api-key"); got == "" {
			t.Errorf("api-key header missing (got %v)", r.Header)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header should NOT be set for Azure (got %q)", got)
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req azureEmbeddingRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
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

// makeAzureEmbeddingResponse builds an azureEmbeddingResponse with a
// 1-dimension dummy vector per input index. Tests assert structure /
// ordering — the vector values themselves are arbitrary.
func makeAzureEmbeddingResponse(model string, count int, promptTokens int) azureEmbeddingResponse {
	data := make([]azureEmbeddingDatum, count)
	for i := 0; i < count; i++ {
		data[i] = azureEmbeddingDatum{
			Object:    "embedding",
			Index:     i,
			Embedding: []float32{float32(i) + 0.1, float32(i) + 0.2},
		}
	}
	resp := azureEmbeddingResponse{
		Object: "list",
		Data:   data,
		Model:  model,
	}
	resp.Usage.PromptTokens = promptTokens
	resp.Usage.TotalTokens = promptTokens
	return resp
}

func TestAzureOpenAI_Embed_Success_SingleInput(t *testing.T) {
	const (
		embedDeployment = "text-embedding-3-small-prod"
		apiVersion      = "2024-10-21"
	)
	srv := fakeAzureEmbeddingServer(t, embedDeployment, apiVersion, func(t *testing.T, req azureEmbeddingRequest) (int, azureEmbeddingResponse, []byte) {
		if len(req.Input) != 1 || req.Input[0] != "hello" {
			t.Errorf("Input = %+v, want [hello]", req.Input)
		}
		return http.StatusOK, makeAzureEmbeddingResponse("text-embedding-3-small", 1, 7), nil
	})
	defer srv.Close()

	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", apiVersion, "gpt-4o",
		embedDeployment, "", "text-embedding-3-small",
	)
	out, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"hello"}})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(out.Vectors) != 1 {
		t.Fatalf("Vectors len = %d, want 1", len(out.Vectors))
	}
	if len(out.Vectors[0]) != 2 {
		t.Errorf("vector[0] len = %d, want 2", len(out.Vectors[0]))
	}
	if out.InputTokens != 7 {
		t.Errorf("InputTokens = %d, want 7", out.InputTokens)
	}
	if out.Model != "text-embedding-3-small" {
		t.Errorf("Model = %q", out.Model)
	}
}

// TestAzureOpenAI_Embed_Success_Batch10 covers a batch under the
// chunking threshold: one HTTP call, ten input texts.
func TestAzureOpenAI_Embed_Success_Batch10(t *testing.T) {
	const (
		embedDeployment = "ada-002-prod"
		apiVersion      = "2024-10-21"
	)
	calls := 0
	srv := fakeAzureEmbeddingServer(t, embedDeployment, apiVersion, func(t *testing.T, req azureEmbeddingRequest) (int, azureEmbeddingResponse, []byte) {
		calls++
		if len(req.Input) != 10 {
			t.Errorf("Input len = %d, want 10", len(req.Input))
		}
		return http.StatusOK, makeAzureEmbeddingResponse("text-embedding-ada-002", 10, 80), nil
	})
	defer srv.Close()

	texts := make([]string, 10)
	for i := range texts {
		texts[i] = fmt.Sprintf("text-%d", i)
	}
	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", apiVersion, "gpt-4o",
		embedDeployment, "", "text-embedding-ada-002",
	)
	out, err := p.Embed(context.Background(), EmbedRequest{Texts: texts})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if calls != 1 {
		t.Errorf("HTTP calls = %d, want 1 (batch under chunking threshold)", calls)
	}
	if len(out.Vectors) != 10 {
		t.Errorf("Vectors len = %d, want 10", len(out.Vectors))
	}
	for i, v := range out.Vectors {
		if v == nil {
			t.Errorf("Vectors[%d] is nil", i)
		}
	}
}

// TestAzureOpenAI_Embed_Chunked covers the transparent chunking path:
// 3000 inputs require ceil(3000 / 2048) = 2 HTTP calls. Asserts that
// (1) two calls land at the embedding URL, (2) input ordering is
// preserved across chunk boundaries, (3) token usage is summed.
func TestAzureOpenAI_Embed_Chunked(t *testing.T) {
	const (
		embedDeployment = "text-embedding-3-large-prod"
		apiVersion      = "2024-10-21"
		totalInputs     = 3000
	)
	calls := 0
	srv := fakeAzureEmbeddingServer(t, embedDeployment, apiVersion, func(t *testing.T, req azureEmbeddingRequest) (int, azureEmbeddingResponse, []byte) {
		calls++
		switch calls {
		case 1:
			if len(req.Input) != azureEmbedMaxBatchSize {
				t.Errorf("chunk 1 Input len = %d, want %d", len(req.Input), azureEmbedMaxBatchSize)
			}
		case 2:
			wantLen := totalInputs - azureEmbedMaxBatchSize
			if len(req.Input) != wantLen {
				t.Errorf("chunk 2 Input len = %d, want %d", len(req.Input), wantLen)
			}
		default:
			t.Errorf("unexpected extra HTTP call (#%d)", calls)
		}
		return http.StatusOK, makeAzureEmbeddingResponse("text-embedding-3-large", len(req.Input), 5*len(req.Input)), nil
	})
	defer srv.Close()

	texts := make([]string, totalInputs)
	for i := range texts {
		texts[i] = fmt.Sprintf("input-%d", i)
	}
	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", apiVersion, "gpt-4o",
		embedDeployment, "", "text-embedding-3-large",
	)
	out, err := p.Embed(context.Background(), EmbedRequest{Texts: texts})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if calls != 2 {
		t.Errorf("HTTP calls = %d, want 2", calls)
	}
	if len(out.Vectors) != totalInputs {
		t.Errorf("Vectors len = %d, want %d", len(out.Vectors), totalInputs)
	}
	for i, v := range out.Vectors {
		if v == nil {
			t.Errorf("Vectors[%d] is nil (chunk boundary loss)", i)
		}
	}
	if out.InputTokens != totalInputs*5 {
		t.Errorf("InputTokens = %d, want %d", out.InputTokens, totalInputs*5)
	}
}

// TestAzureOpenAI_Embed_AuthError covers the 401 path through Embed.
// Azure returns the same structured error shape as chat; the provider
// must surface the message without leaking the api-key value.
func TestAzureOpenAI_Embed_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Access denied due to invalid subscription key","code":"401"}}`))
	}))
	defer srv.Close()

	p := NewAzureOpenAIWithEmbedding(
		"bad-key", srv.URL, "chat-dep", "2024-10-21", "gpt-4o",
		"embed-dep", "", "text-embedding-3-small",
	)
	_, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"hi"}})
	if err == nil {
		t.Fatal("expected auth error")
	}
	if !strings.Contains(err.Error(), "Access denied") {
		t.Errorf("err = %v, want to mention 'Access denied'", err)
	}
	if strings.Contains(err.Error(), "bad-key") {
		t.Errorf("err leaked api-key value: %v", err)
	}
}

func TestAzureOpenAI_Embed_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"Rate limit exceeded"}}`))
	}))
	defer srv.Close()

	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", "2024-10-21", "gpt-4o",
		"embed-dep", "", "text-embedding-3-small",
	)
	_, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"hi"}})
	if err == nil {
		t.Fatal("expected rate-limit error")
	}
	if !strings.Contains(err.Error(), "Rate limit") {
		t.Errorf("err = %v, want to mention 'Rate limit'", err)
	}
}

// TestAzureOpenAI_Embed_ServerError exercises the 500 path with a
// non-JSON body so the raw-body fallback branch runs (mirrors the
// existing TestAzureOpenAI_Complete_ServerError shape).
func TestAzureOpenAI_Embed_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", "2024-10-21", "gpt-4o",
		"embed-dep", "", "text-embedding-3-small",
	)
	_, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"hi"}})
	if err == nil {
		t.Fatal("expected 500 error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want to mention status 500", err)
	}
}

// TestAzureOpenAI_Embed_PartialFailureDiscardsChunks covers the
// documented partial-failure contract: a mid-batch chunk failure
// returns an error and discards the completed chunks (no silent
// partial Vectors with truncated len).
func TestAzureOpenAI_Embed_PartialFailureDiscardsChunks(t *testing.T) {
	const (
		embedDeployment = "embed-dep"
		apiVersion      = "2024-10-21"
		totalInputs     = 3000
	)
	calls := 0
	srv := fakeAzureEmbeddingServer(t, embedDeployment, apiVersion, func(t *testing.T, req azureEmbeddingRequest) (int, azureEmbeddingResponse, []byte) {
		calls++
		if calls == 1 {
			return http.StatusOK, makeAzureEmbeddingResponse("text-embedding-3-small", len(req.Input), 10), nil
		}
		// Second chunk fails — the entire Embed call must fail, not
		// return Vectors of len 2048 with the remaining indices zero.
		return http.StatusInternalServerError, azureEmbeddingResponse{}, []byte("transient upstream failure")
	})
	defer srv.Close()

	texts := make([]string, totalInputs)
	for i := range texts {
		texts[i] = fmt.Sprintf("input-%d", i)
	}
	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", apiVersion, "gpt-4o",
		embedDeployment, "", "text-embedding-3-small",
	)
	out, err := p.Embed(context.Background(), EmbedRequest{Texts: texts})
	if err == nil {
		t.Fatal("expected partial-failure error")
	}
	if out != nil {
		t.Errorf("out should be nil on partial failure, got %+v", out)
	}
	if calls != 2 {
		t.Errorf("HTTP calls = %d, want 2", calls)
	}
}

// TestAzureOpenAI_Embed_EmptyTextsNoHTTP covers the no-input shortcut:
// an EmbedRequest with zero texts must not dispatch any HTTP traffic
// (a 0-length input array fails server-side with HTTP 400).
func TestAzureOpenAI_Embed_EmptyTextsNoHTTP(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", "2024-10-21", "gpt-4o",
		"embed-dep", "", "text-embedding-3-small",
	)
	out, err := p.Embed(context.Background(), EmbedRequest{Texts: nil})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if calls != 0 {
		t.Errorf("HTTP calls = %d, want 0", calls)
	}
	if len(out.Vectors) != 0 {
		t.Errorf("Vectors len = %d, want 0", len(out.Vectors))
	}
}

// TestAzureOpenAI_Embed_SafetyCapExceeded is the F25 DoS guard: a
// caller cannot light up the upstream quota with a >16k batch in one
// request. The cap is enforced before any HTTP traffic is dispatched.
func TestAzureOpenAI_Embed_SafetyCapExceeded(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	texts := make([]string, azureEmbedMaxTotalInputs+1)
	for i := range texts {
		texts[i] = "x"
	}
	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", "2024-10-21", "gpt-4o",
		"embed-dep", "", "text-embedding-3-small",
	)
	_, err := p.Embed(context.Background(), EmbedRequest{Texts: texts})
	if err == nil {
		t.Fatal("expected safety-cap error")
	}
	if !strings.Contains(err.Error(), "exceed safety cap") {
		t.Errorf("err = %v, want to mention safety cap", err)
	}
	if calls != 0 {
		t.Errorf("HTTP calls = %d, want 0 (cap enforced before dispatch)", calls)
	}
}

// TestAzureOpenAI_Embed_APIVersionOverride locks in the fallback rule:
// when embeddingAPIVersion is unset, the chat apiVersion is used; when
// set, the override wins.
func TestAzureOpenAI_Embed_APIVersionOverride(t *testing.T) {
	t.Run("falls back to chat apiVersion", func(t *testing.T) {
		const (
			embedDeployment = "embed-dep"
			chatAPIVersion  = "2024-10-21"
		)
		srv := fakeAzureEmbeddingServer(t, embedDeployment, chatAPIVersion, func(_ *testing.T, _ azureEmbeddingRequest) (int, azureEmbeddingResponse, []byte) {
			return http.StatusOK, makeAzureEmbeddingResponse("text-embedding-3-small", 1, 1), nil
		})
		defer srv.Close()
		p := NewAzureOpenAIWithEmbedding(
			"k", srv.URL, "chat-dep", chatAPIVersion, "gpt-4o",
			embedDeployment, "", "text-embedding-3-small",
		)
		if _, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"hi"}}); err != nil {
			t.Fatalf("Embed: %v", err)
		}
	})
	t.Run("override wins", func(t *testing.T) {
		const (
			embedDeployment = "embed-dep"
			chatAPIVersion  = "2024-10-21"
			embedAPIVersion = "2024-08-01-preview"
		)
		srv := fakeAzureEmbeddingServer(t, embedDeployment, embedAPIVersion, func(_ *testing.T, _ azureEmbeddingRequest) (int, azureEmbeddingResponse, []byte) {
			return http.StatusOK, makeAzureEmbeddingResponse("text-embedding-3-small", 1, 1), nil
		})
		defer srv.Close()
		p := NewAzureOpenAIWithEmbedding(
			"k", srv.URL, "chat-dep", chatAPIVersion, "gpt-4o",
			embedDeployment, embedAPIVersion, "text-embedding-3-small",
		)
		if _, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"hi"}}); err != nil {
			t.Fatalf("Embed: %v", err)
		}
	})
}

// TestAzureOpenAI_Embed_TransportErrorRedactsEndpoint is the F63
// regression guard on the Embed path. Same contract as
// TestAzureOpenAI_TransportErrorRedactsEndpoint (the chat-path test)
// but for the embeddings URL — the tenant resource subdomain,
// embedding deployment name, and api-version must all be scrubbed
// before the error is propagated.
func TestAzureOpenAI_Embed_TransportErrorRedactsEndpoint(t *testing.T) {
	const (
		tenantResource  = "secret-embed-tenant"
		embedDeployment = "text-embedding-3-large-prod"
		apiVersion      = "2024-10-21"
	)
	endpoint := fmt.Sprintf("http://%s.openai.azure.com:1", tenantResource)
	client := &http.Client{Timeout: 2 * time.Second}
	p := NewAzureOpenAIWithEmbeddingAndClient(
		"k", endpoint, "chat-dep", apiVersion, "gpt-4o",
		embedDeployment, "", "text-embedding-3-large", client,
	)
	_, err := p.Embed(context.Background(), EmbedRequest{Texts: []string{"hi"}})
	if err == nil {
		t.Fatal("expected transport error from unroutable endpoint")
	}
	msg := err.Error()
	if strings.Contains(msg, tenantResource) {
		t.Errorf("transport error leaked tenant resource %q: %q", tenantResource, msg)
	}
	if strings.Contains(msg, "openai.azure.com") {
		t.Errorf("transport error leaked Azure host suffix: %q", msg)
	}
	if strings.Contains(msg, embedDeployment) {
		t.Errorf("transport error leaked embedding deployment %q: %q", embedDeployment, msg)
	}
	if strings.Contains(msg, apiVersion) {
		t.Errorf("transport error leaked api-version %q: %q", apiVersion, msg)
	}
	if !strings.Contains(msg, "[REDACTED-AZURE-ENDPOINT]") {
		t.Errorf("expected redaction placeholder in error message, got %q", msg)
	}
}

// TestAzureOpenAI_Embed_ContextCancel is the timeout / cancellation
// guard: cancelling the context before dispatch yields a context error
// (no HTTP traffic), cancelling between chunks aborts the loop.
func TestAzureOpenAI_Embed_ContextCancel(t *testing.T) {
	srv := fakeAzureEmbeddingServer(t, "embed-dep", "2024-10-21", func(_ *testing.T, req azureEmbeddingRequest) (int, azureEmbeddingResponse, []byte) {
		return http.StatusOK, makeAzureEmbeddingResponse("text-embedding-3-small", len(req.Input), 1), nil
	})
	defer srv.Close()

	p := NewAzureOpenAIWithEmbedding(
		"k", srv.URL, "chat-dep", "2024-10-21", "gpt-4o",
		"embed-dep", "", "text-embedding-3-small",
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	_, err := p.Embed(ctx, EmbedRequest{Texts: []string{"hi"}})
	if err == nil {
		t.Fatal("expected context-cancelled error")
	}
	// We accept either the raw context.Canceled or the rewrapped form
	// — the transport scrubber may have wrapped it via
	// RedactAzureTransportError. The point is that it must surface a
	// non-success.
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("err = %v, want context-cancelled signal", err)
	}
}

// TestAzureOpenAI_Capabilities_Embedding locks in the embedding
// dimension table and the "embedding configured → SupportsEmbedding
// true" rule.
func TestAzureOpenAI_Capabilities_Embedding(t *testing.T) {
	cases := []struct {
		name            string
		embedDeployment string
		embedModel      string
		wantSupports    bool
		wantDim         int
	}{
		{"no embedding configured", "", "", false, 0},
		{"3-small explicit", "embed-dep", "text-embedding-3-small", true, 1536},
		{"3-large explicit", "embed-dep", "text-embedding-3-large", true, 3072},
		{"ada-002 explicit", "embed-dep", "text-embedding-ada-002", true, 1536},
		{"deployment name sniff 3-small", "text-embedding-3-small-prod", "", true, 1536},
		{"deployment name sniff 3-large", "text-embedding-3-large-prod", "", true, 3072},
		{"deployment name sniff ada-002", "ada-002-prod", "", true, 1536},
		{"unknown deployment", "biz-vec-prod", "", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewAzureOpenAIWithEmbedding(
				"k", "https://x.openai.azure.com", "chat-dep", "2024-10-21", "gpt-4o",
				tc.embedDeployment, "", tc.embedModel,
			)
			cap := p.Capabilities()
			if cap.SupportsEmbedding != tc.wantSupports {
				t.Errorf("SupportsEmbedding = %v, want %v", cap.SupportsEmbedding, tc.wantSupports)
			}
			if cap.EmbeddingDimensions != tc.wantDim {
				t.Errorf("EmbeddingDimensions = %d, want %d", cap.EmbeddingDimensions, tc.wantDim)
			}
		})
	}
}

// TestAzureOpenAI_LogValueEmbeddingFields verifies that when an
// embedding deployment is configured, LogValue emits it (and the
// canonical embedding model name when set) without ever leaking the
// API key or endpoint URL. Mirrors TestAzureOpenAI_LogValueDoesNotLeakSecrets
// for the M5-3 fields.
func TestAzureOpenAI_LogValueEmbeddingFields(t *testing.T) {
	const (
		apiKey   = "az-supersecret-12345"
		endpoint = "https://tenant-resource.openai.azure.com"
	)
	p := NewAzureOpenAIWithEmbedding(
		apiKey, endpoint, "biz-deploy", "2024-10-21", "gpt-4o",
		"text-embedding-3-small-prod", "", "text-embedding-3-small",
	)
	var sb strings.Builder
	logger := slog.New(slog.NewTextHandler(&sb, nil))
	logger.Info("test", "provider", p)
	logged := sb.String()

	if strings.Contains(logged, "supersecret") {
		t.Errorf("slog leaked API key: %q", logged)
	}
	if strings.Contains(logged, "tenant-resource") {
		t.Errorf("slog leaked endpoint URL: %q", logged)
	}
	if !strings.Contains(logged, "text-embedding-3-small-prod") {
		t.Errorf("slog should mention embedding deployment, got %q", logged)
	}
	if !strings.Contains(logged, "text-embedding-3-small") {
		t.Errorf("slog should mention embedding model, got %q", logged)
	}
}
