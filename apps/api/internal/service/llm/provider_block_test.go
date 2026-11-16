package llm

// M75 (Codex R1 Medium): prompt-level safety blocks keep the provider's
// reason. Gemini answers a blocked prompt with no candidates and
// promptFeedback.blockReason; Azure OpenAI answers HTTP 400 with
// error.code "content_filter". Both are ErrFilteredResponse.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeminiPromptBlockIsFiltered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"promptFeedback":{"blockReason":"SAFETY"},"usageMetadata":{"promptTokenCount":12}}`))
	}))
	t.Cleanup(srv.Close)
	p := NewGeminiWithEndpoint("k", "gemini-2.0-flash", srv.URL)
	resp, err := Complete(context.Background(), p, CompleteRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if !errors.Is(err, ErrFilteredResponse) {
		t.Fatalf("err = %v, want ErrFilteredResponse", err)
	}
	if resp == nil || resp.FinishReason != "SAFETY" || resp.InputTokens != 12 || len(resp.RawResponse) == 0 {
		t.Errorf("resp = %+v, want blockReason SAFETY recorded", resp)
	}

	// No candidates and no block reason stays the plain error it was.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"candidates":[]}`))
	}))
	t.Cleanup(srv2.Close)
	_, err = NewGeminiWithEndpoint("k", "m", srv2.URL).Complete(context.Background(), CompleteRequest{})
	if err == nil || errors.Is(err, ErrFilteredResponse) {
		t.Errorf("empty candidates: err = %v", err)
	}
}

func TestAzureContentFilter400IsFiltered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"The response was filtered","type":null,"param":"prompt","code":"content_filter","status":400}}`))
	}))
	t.Cleanup(srv.Close)
	p := NewAzureOpenAI("k", srv.URL, "dep", "2024-10-21", "gpt-4o")
	resp, err := Complete(context.Background(), p, CompleteRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if !errors.Is(err, ErrFilteredResponse) || !strings.Contains(err.Error(), "filtered") {
		t.Fatalf("err = %v, want ErrFilteredResponse", err)
	}
	// Codex R2 Medium: the llm_calls row records the filter as the
	// finish reason, with the provider's error body.
	if resp == nil || resp.FinishReason != "content_filter" || len(resp.RawResponse) == 0 {
		t.Errorf("resp = %+v, want FinishReason content_filter and the raw body", resp)
	}
}
