package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultGeminiEndpoint is the base URL for the Google Generative Language
// API. The model name is appended as a path segment, e.g.
// /v1beta/models/gemini-2.5-flash:generateContent
// ※要確認: as of 2026-06 v1beta is the actively maintained API; v1 lags on
// JSON schema features. Switch to v1 once the feature parity gap closes.
const defaultGeminiEndpoint = "https://generativelanguage.googleapis.com/v1beta"

// GeminiProvider implements Provider against Google's Generative Language
// REST API. We intentionally avoid the google/generative-ai-go SDK in M1 —
// it pulls a sizeable transitive dep tree (gax-go, grpc, protobuf) for what
// is fundamentally a JSON POST.
// ※要確認: revisit SDK adoption in M2 if we need streaming / function
// calling / file uploads.
type GeminiProvider struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
}

// Compile-time interface conformance.
var _ Provider = (*GeminiProvider)(nil)

// NewGemini constructs a GeminiProvider with the default endpoint.
// If model is empty, defaults to "gemini-2.5-flash" (cheap + multilingual,
// matches SaaS managed default — LLM_PROVIDER_DESIGN.md §5.1).
// ※要確認: default model. "gemini-2.5-flash" is current per workspace
// CLAUDE.md; revisit when Google releases the next tier.
func NewGemini(apiKey, model string) *GeminiProvider {
	if model == "" {
		model = "gemini-2.5-flash"
	}
	return &GeminiProvider{
		apiKey:   apiKey,
		model:    model,
		endpoint: defaultGeminiEndpoint,
		client:   &http.Client{Timeout: 60 * time.Second},
	}
}

// NewGeminiWithEndpoint is used by tests (httptest.Server).
func NewGeminiWithEndpoint(apiKey, model, endpoint string) *GeminiProvider {
	p := NewGemini(apiKey, model)
	p.endpoint = strings.TrimRight(endpoint, "/")
	return p
}

// Name implements Provider.
func (p *GeminiProvider) Name() string { return "gemini" }

// Model implements Provider.
func (p *GeminiProvider) Model() string { return p.model }

// LogValue implements slog.LogValuer — emits only {provider, model}.
func (p *GeminiProvider) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", p.Name()),
		slog.String("model", p.model),
	)
}

// Gemini's generateContent payload models. We only include the subset of
// fields we actually use.
type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"` // "user" or "model"
	Parts []geminiPart `json:"parts"`
}

type geminiGenerationConfig struct {
	Temperature      *float32               `json:"temperature,omitempty"`
	MaxOutputTokens  int                    `json:"maxOutputTokens,omitempty"`
	StopSequences    []string               `json:"stopSequences,omitempty"`
	ResponseMimeType string                 `json:"responseMimeType,omitempty"`
	ResponseSchema   map[string]interface{} `json:"responseSchema,omitempty"`
}

type geminiRequest struct {
	Contents          []geminiContent         `json:"contents"`
	SystemInstruction *geminiContent          `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content      geminiContent `json:"content"`
		FinishReason string        `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
	Error *geminiError `json:"error,omitempty"`
}

type geminiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// Complete implements Provider.
//
// Gemini's chat role for model output is "model" (not "assistant"); we
// translate at the boundary so the generic Message contract stays clean.
func (p *GeminiProvider) Complete(ctx context.Context, req CompleteRequest) (*CompleteResponse, error) {
	if p.apiKey == "" {
		return nil, &DisabledError{Reason: "Gemini API key is empty"}
	}

	contents := make([]geminiContent, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := "user"
		if m.Role == RoleAssistant {
			role = "model"
		}
		contents = append(contents, geminiContent{
			Role:  role,
			Parts: []geminiPart{{Text: m.Content}},
		})
	}

	body := geminiRequest{Contents: contents}
	if req.System != "" {
		body.SystemInstruction = &geminiContent{
			Parts: []geminiPart{{Text: req.System}},
		}
	}

	if req.Temperature > 0 || req.MaxTokens > 0 || len(req.Stop) > 0 || req.JSONMode || req.JSONSchema != nil {
		cfg := &geminiGenerationConfig{
			MaxOutputTokens: req.MaxTokens,
			StopSequences:   req.Stop,
		}
		if req.Temperature > 0 {
			t := req.Temperature
			cfg.Temperature = &t
		}
		// Structured output: prefer schema > json mode.
		if req.JSONSchema != nil {
			cfg.ResponseMimeType = "application/json"
			cfg.ResponseSchema = req.JSONSchema
		} else if req.JSONMode {
			cfg.ResponseMimeType = "application/json"
		}
		body.GenerationConfig = cfg
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal request: %w", err)
	}

	// Gemini auth is via ?key=... query string. We use url.Values to safely
	// escape the key (paranoia: keys are normally ASCII but never trust).
	u := fmt.Sprintf("%s/models/%s:generateContent?%s",
		p.endpoint,
		url.PathEscape(p.model),
		url.Values{"key": []string{p.apiKey}}.Encode(),
	)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("gemini: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: http call: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gemini: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp geminiResponse
		_ = json.Unmarshal(rawBody, &errResp)
		if errResp.Error != nil {
			return nil, fmt.Errorf("gemini: http %d: %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("gemini: http %d", resp.StatusCode)
	}

	var parsed geminiResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("gemini: parse response: %w", err)
	}
	if len(parsed.Candidates) == 0 {
		return nil, fmt.Errorf("gemini: empty candidates")
	}

	first := parsed.Candidates[0]
	var sb strings.Builder
	for _, part := range first.Content.Parts {
		sb.WriteString(part.Text)
	}

	return &CompleteResponse{
		Content:      sb.String(),
		InputTokens:  parsed.UsageMetadata.PromptTokenCount,
		OutputTokens: parsed.UsageMetadata.CandidatesTokenCount,
		Model:        p.model, // Gemini does not echo the model id in the response
		FinishReason: first.FinishReason,
		CostUSD:      0,
		RawResponse:  rawBody,
	}, nil
}

// Embed implements Provider. Google has a distinct :embedContent endpoint;
// M1 leaves it unwired.
func (p *GeminiProvider) Embed(_ context.Context, _ EmbedRequest) (*EmbedResponse, error) {
	return nil, ErrNotImplemented
}

// Capabilities implements Provider.
// ※要確認: Gemini's docs split capabilities across model variants
// (-pro / -flash / -flash-lite); revisit before M1 ships.
func (p *GeminiProvider) Capabilities() Capabilities {
	switch {
	case strings.HasPrefix(p.model, "gemini-2.5-pro"), strings.HasPrefix(p.model, "gemini-2.0-pro"):
		return Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			SupportsEmbedding:    false,
			MaxContextTokens:     2000000,
		}
	case strings.HasPrefix(p.model, "gemini-2.5-flash"), strings.HasPrefix(p.model, "gemini-2.0-flash"):
		return Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			SupportsEmbedding:    false,
			MaxContextTokens:     1000000,
		}
	default:
		return Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   false,
			SupportsFunctionCall: false,
			SupportsVision:       false,
			SupportsEmbedding:    false,
			MaxContextTokens:     32000,
		}
	}
}
