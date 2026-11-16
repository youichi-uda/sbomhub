package llm

// M75 — OpenAI / Azure OpenAI structured-output refusals arrive as
// message.refusal with finish_reason "stop" and no content. llm.Complete
// must treat them as a filtered answer, not a normal (empty) one.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const openAIRefusalBody = `{"id":"x","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":null,"refusal":"I can't help with that."},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":7}}`

func refusalServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(openAIRefusalBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOpenAIRefusalIsFiltered(t *testing.T) {
	srv := refusalServer(t)
	for name, p := range map[string]Provider{
		"openai": NewOpenAIWithEndpoint("sk-test", "gpt-4o-mini", srv.URL),
		"azure":  NewAzureOpenAI("k", srv.URL, "dep", "2024-10-21", "gpt-4o"),
	} {
		resp, err := Complete(context.Background(), p, CompleteRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
		if !errors.Is(err, ErrFilteredResponse) {
			t.Errorf("%s: err = %v, want ErrFilteredResponse", name, err)
			continue
		}
		if resp == nil || resp.Refusal != "I can't help with that." || resp.OutputTokens != 7 {
			t.Errorf("%s: resp = %+v, want the refusal recorded", name, resp)
		}
	}
}
