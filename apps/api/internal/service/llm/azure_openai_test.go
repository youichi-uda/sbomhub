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

func TestAzureOpenAI_Embed_NotImplemented(t *testing.T) {
	p := NewAzureOpenAI("k", "https://x.openai.azure.com", "dep", "2024-10-21", "gpt-4o")
	_, err := p.Embed(context.Background(), EmbedRequest{})
	if err != ErrNotImplemented {
		t.Errorf("err = %v, want ErrNotImplemented", err)
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
