package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// defaultOpenAIEndpoint is the base URL for OpenAI Chat Completions.
// We hit the Chat Completions API directly (not the new Responses API) for
// simplicity and broad model coverage. M2 may switch.
// ※要確認: as of design (2026-06), Chat Completions remains GA; if OpenAI
// deprecates it before M1 ships, switch to /v1/responses.
const defaultOpenAIEndpoint = "https://api.openai.com/v1"

const (
	defaultOpenAIEmbeddingModel = "text-embedding-3-small"
	openAIEmbedMaxBatchSize     = 2048
	openAIEmbedMaxTotalInputs   = azureEmbedMaxTotalInputs
)

// OpenAIProvider implements Provider against the OpenAI REST API.
//
// We deliberately do NOT depend on the official Go SDK in M1 to keep the
// dependency surface small (security product policy: prefer std lib). If a
// future milestone needs streaming / function calling / file uploads, a
// switch to the official SDK is reasonable — see PRODUCT_REBOOT_PLAN §20.
type OpenAIProvider struct {
	apiKey         string
	model          string
	endpoint       string
	client         *http.Client
	embeddingModel string
}

// Compile-time interface conformance.
var _ Provider = (*OpenAIProvider)(nil)

// NewOpenAI constructs an OpenAIProvider with the default endpoint and a
// 60-second HTTP timeout. If model is empty, it defaults to "gpt-4o-mini"
// (cheap + fast — recommended baseline for VEX triage prototypes).
// ※要確認: default model. gpt-4o-mini is current GA; revisit if OpenAI
// renames the budget tier (e.g. gpt-5-mini) before M1 ships.
func NewOpenAI(apiKey, model string) *OpenAIProvider {
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &OpenAIProvider{
		apiKey:         apiKey,
		model:          model,
		endpoint:       defaultOpenAIEndpoint,
		client:         &http.Client{Timeout: 60 * time.Second},
		embeddingModel: defaultOpenAIEmbeddingModel,
	}
}

// NewOpenAIWithEmbedding constructs an OpenAI provider with an explicit
// embedding model. Empty embeddingModel falls back to text-embedding-3-small.
func NewOpenAIWithEmbedding(apiKey, model, embeddingModel string) *OpenAIProvider {
	p := NewOpenAI(apiKey, model)
	if strings.TrimSpace(embeddingModel) != "" {
		p.embeddingModel = strings.TrimSpace(embeddingModel)
	}
	return p
}

// NewOpenAIWithEndpoint is used by tests (httptest.Server) to redirect the
// HTTP traffic. Not intended for production callers.
func NewOpenAIWithEndpoint(apiKey, model, endpoint string) *OpenAIProvider {
	p := NewOpenAI(apiKey, model)
	p.endpoint = strings.TrimRight(endpoint, "/")
	return p
}

// NewOpenAIWithEmbeddingAndEndpoint is the httptest seam for embedding tests.
func NewOpenAIWithEmbeddingAndEndpoint(apiKey, model, embeddingModel, endpoint string) *OpenAIProvider {
	p := NewOpenAIWithEmbedding(apiKey, model, embeddingModel)
	p.endpoint = strings.TrimRight(endpoint, "/")
	return p
}

// Name implements Provider.
func (p *OpenAIProvider) Name() string { return "openai" }

// Model implements Provider.
func (p *OpenAIProvider) Model() string { return p.model }

// LogValue implements slog.LogValuer so logging *OpenAIProvider only emits
// {provider, model} — NEVER the API key. (§7.2 never-log policy)
func (p *OpenAIProvider) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", p.Name()),
		slog.String("model", p.model),
		slog.String("embedding_model", p.embeddingModel),
	)
}

// openaiChatRequest mirrors the subset of the OpenAI Chat Completions
// request body that we use.
type openaiChatRequest struct {
	Model          string          `json:"model"`
	Messages       []openaiMessage `json:"messages"`
	Temperature    *float32        `json:"temperature,omitempty"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	ResponseFormat *openaiRespFmt  `json:"response_format,omitempty"`
	Stop           []string        `json:"stop,omitempty"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiRespFmt struct {
	Type       string                 `json:"type"`
	JSONSchema map[string]interface{} `json:"json_schema,omitempty"`
}

type openaiChatResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *openaiError `json:"error,omitempty"`
}

type openaiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

type openaiEmbeddingRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type openaiEmbeddingResponse struct {
	Object string                 `json:"object"`
	Data   []openaiEmbeddingDatum `json:"data"`
	Model  string                 `json:"model"`
	Usage  openaiEmbeddingUsage   `json:"usage"`
	Error  *openaiError           `json:"error,omitempty"`
}

type openaiEmbeddingDatum struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float32 `json:"embedding"`
}

type openaiEmbeddingUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// Complete implements Provider.
func (p *OpenAIProvider) Complete(ctx context.Context, req CompleteRequest) (*CompleteResponse, error) {
	if p.apiKey == "" {
		return nil, &DisabledError{Reason: "OpenAI API key is empty"}
	}

	// Translate the generic request into OpenAI's wire format.
	msgs := make([]openaiMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, openaiMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, openaiMessage(m))
	}

	body := openaiChatRequest{
		Model:     p.model,
		Messages:  msgs,
		MaxTokens: req.MaxTokens,
		Stop:      req.Stop,
	}
	// Only emit temperature when it's a meaningful value; OpenAI defaults
	// to 1.0 when omitted, which is fine.
	if req.Temperature > 0 {
		t := req.Temperature
		body.Temperature = &t
	}
	if req.JSONSchema != nil {
		body.ResponseFormat = &openaiRespFmt{
			Type:       "json_schema",
			JSONSchema: req.JSONSchema,
		}
	} else if req.JSONMode {
		body.ResponseFormat = &openaiRespFmt{Type: "json_object"}
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("openai: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: http call: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openai: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to surface the OpenAI error message but never echo the request body.
		var errResp openaiChatResponse
		_ = json.Unmarshal(rawBody, &errResp)
		if errResp.Error != nil {
			return nil, fmt.Errorf("openai: http %d: %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("openai: http %d", resp.StatusCode)
	}

	var parsed openaiChatResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("openai: parse response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("openai: empty choices")
	}

	choice := parsed.Choices[0]
	return &CompleteResponse{
		Content:      choice.Message.Content,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
		Model:        parsed.Model,
		FinishReason: choice.FinishReason,
		// ※要確認: cost computation deferred to audit layer (it has the
		// per-model price table). We leave CostUSD = 0 here.
		CostUSD:     0,
		RawResponse: rawBody,
	}, nil
}

// Embed implements Provider against POST /v1/embeddings.
func (p *OpenAIProvider) Embed(ctx context.Context, req EmbedRequest) (*EmbedResponse, error) {
	if p.apiKey == "" {
		return nil, &DisabledError{Reason: "OpenAI API key is empty"}
	}
	if len(req.Texts) == 0 {
		return &EmbedResponse{Vectors: [][]float32{}, Model: p.embeddingModel}, nil
	}
	if len(req.Texts) > openAIEmbedMaxTotalInputs {
		return nil, fmt.Errorf("openai: embed inputs %d exceed safety cap %d (set fewer or split caller-side)",
			len(req.Texts), openAIEmbedMaxTotalInputs)
	}

	vectors := make([][]float32, len(req.Texts))
	totalPromptTokens := 0
	respModel := ""

	for start := 0; start < len(req.Texts); start += openAIEmbedMaxBatchSize {
		end := start + openAIEmbedMaxBatchSize
		if end > len(req.Texts) {
			end = len(req.Texts)
		}
		chunk := req.Texts[start:end]
		body := openaiEmbeddingRequest{Model: p.embeddingModel, Input: chunk}
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("openai: marshal embed request: %w", err)
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/embeddings", bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("openai: new embed request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

		resp, err := p.client.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("openai: embed http call (chunk start=%d): %w", start, RedactProviderError(err))
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			const errBodyCap = 4 << 10
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, errBodyCap))
			resp.Body.Close()
			var errResp openaiEmbeddingResponse
			_ = json.Unmarshal(errBody, &errResp)
			if errResp.Error != nil {
				return nil, fmt.Errorf("openai: embed %s: %s", resp.Status, errResp.Error.Message)
			}
			return nil, fmt.Errorf("openai: embed %s: %s", resp.Status, string(errBody))
		}

		rawBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("openai: read embed body: %w", readErr)
		}
		var parsed openaiEmbeddingResponse
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			return nil, fmt.Errorf("openai: parse embed response: %w", err)
		}
		seen := make([]bool, len(chunk))
		for _, d := range parsed.Data {
			if d.Index < 0 || d.Index >= len(chunk) {
				return nil, fmt.Errorf("openai: embed response index %d out of range [0, %d)", d.Index, len(chunk))
			}
			if seen[d.Index] {
				return nil, fmt.Errorf("openai: embed response duplicate index %d", d.Index)
			}
			seen[d.Index] = true
			vectors[start+d.Index] = d.Embedding
		}
		for i, ok := range seen {
			if !ok {
				return nil, fmt.Errorf("openai: embed response missing index %d", i)
			}
		}
		if len(parsed.Data) != len(chunk) {
			return nil, fmt.Errorf("openai: embed response data count %d != chunk size %d", len(parsed.Data), len(chunk))
		}
		totalPromptTokens += parsed.Usage.PromptTokens
		if parsed.Model != "" {
			respModel = parsed.Model
		}
	}
	if respModel == "" {
		respModel = p.embeddingModel
	}
	return &EmbedResponse{Vectors: vectors, InputTokens: totalPromptTokens, Model: respModel}, nil
}

func openAIEmbeddingDimensions(model string) int {
	switch {
	case strings.Contains(model, "text-embedding-3-large"):
		return 3072
	case strings.Contains(model, "text-embedding-3-small"),
		strings.Contains(model, "text-embedding-ada-002"):
		return 1536
	default:
		return 0
	}
}

// Capabilities implements Provider.
//
// The capability table is static; we look up by model prefix. Anything not
// matched falls back to a conservative default. ※要確認: keep this table in
// sync with OpenAI's docs (capabilities & context sizes change).
func (p *OpenAIProvider) Capabilities() Capabilities {
	switch {
	case strings.HasPrefix(p.model, "gpt-4o"), strings.HasPrefix(p.model, "gpt-4.1"), strings.HasPrefix(p.model, "gpt-5"):
		c := Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			MaxContextTokens:     128000,
		}
		c.SupportsEmbedding = p.embeddingModel != ""
		c.EmbeddingDimensions = openAIEmbeddingDimensions(p.embeddingModel)
		return c
	case strings.HasPrefix(p.model, "o1"), strings.HasPrefix(p.model, "o3"):
		c := Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       false,
			MaxContextTokens:     200000,
		}
		c.SupportsEmbedding = p.embeddingModel != ""
		c.EmbeddingDimensions = openAIEmbeddingDimensions(p.embeddingModel)
		return c
	default:
		c := Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   false,
			SupportsFunctionCall: true,
			SupportsVision:       false,
			MaxContextTokens:     16000,
		}
		c.SupportsEmbedding = p.embeddingModel != ""
		c.EmbeddingDimensions = openAIEmbeddingDimensions(p.embeddingModel)
		return c
	}
}
