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

// geminiAPIKeyHeader is the HTTP header Google's Generative Language REST
// API recognises for inline API-key authentication.
//
// M1 Codex review #F13: SBOMHub previously authenticated Gemini via the
// `?key=AIza...` query string, which net/http echoed back through
// *url.Error on any transport failure — leaking the BYOK key into the
// runner's llm_calls.error_message column and the handler's 500 response
// body. Migrating to the header form removes the key from the URL
// entirely, closing the leak at the source. RedactProviderError below is
// a defense-in-depth scrubber that catches the same shape if any future
// regression reintroduces URL auth.
//
// Web reference (2026-06): ai.google.dev/gemini-api/docs/api-key uses
// `x-goog-api-key: YOUR_API_KEY` in the canonical curl example, and the
// header form is what Google recommends going forward (Standard keys
// without explicit restrictions are scheduled for rejection in
// September 2026). ※要確認 in M2 if Google standardises on a different
// header (e.g. `Authorization: Bearer ...` with service-account auth).
const geminiAPIKeyHeader = "x-goog-api-key" //nolint:gosec // header name, not a credential

// defaultGeminiEndpoint is the base URL for the Google Generative Language
// API. The model name is appended as a path segment, e.g.
// /v1beta/models/gemini-2.5-flash:generateContent
// ※要確認: as of 2026-06 v1beta is the actively maintained API; v1 lags on
// JSON schema features. Switch to v1 once the feature parity gap closes.
const defaultGeminiEndpoint = "https://generativelanguage.googleapis.com/v1beta"

const (
	defaultGeminiEmbeddingModel = "gemini-embedding-2"
	geminiEmbedMaxBatchSize     = 100
	geminiEmbedMaxTotalInputs   = azureEmbedMaxTotalInputs
)

// GeminiProvider implements Provider against Google's Generative Language
// REST API. We intentionally avoid the google/generative-ai-go SDK in M1 —
// it pulls a sizeable transitive dep tree (gax-go, grpc, protobuf) for what
// is fundamentally a JSON POST.
// ※要確認: revisit SDK adoption in M2 if we need streaming / function
// calling / file uploads.
type GeminiProvider struct {
	apiKey         string
	model          string
	endpoint       string
	client         *http.Client
	embeddingModel string
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
		apiKey:         apiKey,
		model:          model,
		endpoint:       defaultGeminiEndpoint,
		client:         &http.Client{Timeout: 60 * time.Second},
		embeddingModel: defaultGeminiEmbeddingModel,
	}
}

// NewGeminiWithEmbedding constructs a Gemini provider with an explicit
// embedding model. Empty embeddingModel falls back to gemini-embedding-2.
func NewGeminiWithEmbedding(apiKey, model, embeddingModel string) *GeminiProvider {
	p := NewGemini(apiKey, model)
	if strings.TrimSpace(embeddingModel) != "" {
		p.embeddingModel = strings.TrimSpace(embeddingModel)
	}
	return p
}

// NewGeminiWithEndpoint is used by tests (httptest.Server).
func NewGeminiWithEndpoint(apiKey, model, endpoint string) *GeminiProvider {
	p := NewGemini(apiKey, model)
	p.endpoint = strings.TrimRight(endpoint, "/")
	return p
}

// NewGeminiWithEmbeddingAndEndpoint is the httptest seam for embedding tests.
func NewGeminiWithEmbeddingAndEndpoint(apiKey, model, embeddingModel, endpoint string) *GeminiProvider {
	p := NewGeminiWithEmbedding(apiKey, model, embeddingModel)
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
		slog.String("embedding_model", p.embeddingModel),
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

type geminiEmbedContentRequest struct {
	Model                string        `json:"model,omitempty"`
	Content              geminiContent `json:"content"`
	OutputDimensionality int           `json:"output_dimensionality,omitempty"`
}

type geminiBatchEmbedRequest struct {
	Requests []geminiEmbedContentRequest `json:"requests"`
}

type geminiEmbedding struct {
	Values []float32 `json:"values"`
}

type geminiEmbedResponse struct {
	Embedding  geminiEmbedding   `json:"embedding"`
	Embeddings []geminiEmbedding `json:"embeddings"`
	Error      *geminiError      `json:"error,omitempty"`
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

	// Gemini auth travels via the `x-goog-api-key` request header (M1
	// Codex review #F13). The URL deliberately carries NO `?key=` query
	// parameter — net/http would otherwise echo it through *url.Error on
	// any transport failure, leaking the BYOK key into the runner's
	// llm_calls.error_message column and the handler's 500 response body.
	//
	// url.PathEscape is still applied to the model id so a hypothetical
	// colon-bearing model name cannot break the path-vs-action split
	// (":generateContent" is the action segment).
	u := fmt.Sprintf("%s/models/%s:generateContent",
		p.endpoint,
		url.PathEscape(p.model),
	)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("gemini: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(geminiAPIKeyHeader, p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		// Defense-in-depth: even though the URL no longer carries the
		// key, run the transport error through RedactProviderError so a
		// future SDK / proxy that reintroduces ?key= auth cannot leak
		// silently. The helper is a no-op when no auth-shaped material
		// is present.
		return nil, fmt.Errorf("gemini: http call: %w", RedactProviderError(err))
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

// Embed implements Provider against Gemini's :embedContent /
// :batchEmbedContents endpoints.
func (p *GeminiProvider) Embed(ctx context.Context, req EmbedRequest) (*EmbedResponse, error) {
	if p.apiKey == "" {
		return nil, &DisabledError{Reason: "Gemini API key is empty"}
	}
	if len(req.Texts) == 0 {
		return &EmbedResponse{Vectors: [][]float32{}, Model: p.embeddingModel}, nil
	}
	if len(req.Texts) > geminiEmbedMaxTotalInputs {
		return nil, fmt.Errorf("gemini: embed inputs %d exceed safety cap %d (set fewer or split caller-side)",
			len(req.Texts), geminiEmbedMaxTotalInputs)
	}

	vectors := make([][]float32, len(req.Texts))
	for start := 0; start < len(req.Texts); start += geminiEmbedMaxBatchSize {
		end := start + geminiEmbedMaxBatchSize
		if end > len(req.Texts) {
			end = len(req.Texts)
		}
		chunk := req.Texts[start:end]
		parsed, err := p.embedGeminiChunk(ctx, chunk, start)
		if err != nil {
			return nil, err
		}
		if len(parsed.Embeddings) != len(chunk) {
			return nil, fmt.Errorf("gemini: embed response embeddings count %d != chunk size %d",
				len(parsed.Embeddings), len(chunk))
		}
		for i, e := range parsed.Embeddings {
			vectors[start+i] = e.Values
		}
	}
	return &EmbedResponse{Vectors: vectors, Model: p.embeddingModel}, nil
}

func (p *GeminiProvider) embedGeminiChunk(ctx context.Context, chunk []string, start int) (*geminiEmbedResponse, error) {
	modelPath := "models/" + p.embeddingModel
	var endpoint string
	var body any
	if len(chunk) == 1 {
		endpoint = fmt.Sprintf("%s/models/%s:embedContent", p.endpoint, url.PathEscape(p.embeddingModel))
		body = geminiEmbedContentRequest{
			Model:   modelPath,
			Content: geminiContent{Parts: []geminiPart{{Text: chunk[0]}}},
		}
	} else {
		endpoint = fmt.Sprintf("%s/models/%s:batchEmbedContents", p.endpoint, url.PathEscape(p.embeddingModel))
		requests := make([]geminiEmbedContentRequest, 0, len(chunk))
		for _, text := range chunk {
			requests = append(requests, geminiEmbedContentRequest{
				Model:   modelPath,
				Content: geminiContent{Parts: []geminiPart{{Text: text}}},
			})
		}
		body = geminiBatchEmbedRequest{Requests: requests}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal embed request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("gemini: new embed request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(geminiAPIKeyHeader, p.apiKey)
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: embed http call (chunk start=%d): %w", start, RedactProviderError(err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		const errBodyCap = 4 << 10
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, errBodyCap))
		resp.Body.Close()
		var errResp geminiEmbedResponse
		_ = json.Unmarshal(errBody, &errResp)
		if errResp.Error != nil {
			return nil, fmt.Errorf("gemini: embed %s: %s", resp.Status, errResp.Error.Message)
		}
		return nil, fmt.Errorf("gemini: embed %s: %s", resp.Status, string(errBody))
	}
	rawBody, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("gemini: read embed body: %w", readErr)
	}
	var parsed geminiEmbedResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("gemini: parse embed response: %w", err)
	}
	if len(chunk) == 1 && len(parsed.Embeddings) == 0 {
		parsed.Embeddings = []geminiEmbedding{parsed.Embedding}
	}
	return &parsed, nil
}

func geminiEmbeddingDimensions(model string) int {
	switch {
	case strings.Contains(model, "gemini-embedding-2"), strings.Contains(model, "gemini-embedding-001"):
		return 3072
	case strings.Contains(model, "text-embedding-004"):
		return 768
	default:
		return 0
	}
}

// Capabilities implements Provider.
// ※要確認: Gemini's docs split capabilities across model variants
// (-pro / -flash / -flash-lite); revisit before M1 ships.
func (p *GeminiProvider) Capabilities() Capabilities {
	switch {
	case strings.HasPrefix(p.model, "gemini-2.5-pro"), strings.HasPrefix(p.model, "gemini-2.0-pro"):
		c := Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			MaxContextTokens:     2000000,
		}
		c.SupportsEmbedding = p.embeddingModel != ""
		c.EmbeddingDimensions = geminiEmbeddingDimensions(p.embeddingModel)
		return c
	case strings.HasPrefix(p.model, "gemini-2.5-flash"), strings.HasPrefix(p.model, "gemini-2.0-flash"):
		c := Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			MaxContextTokens:     1000000,
		}
		c.SupportsEmbedding = p.embeddingModel != ""
		c.EmbeddingDimensions = geminiEmbeddingDimensions(p.embeddingModel)
		return c
	default:
		c := Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   false,
			SupportsFunctionCall: false,
			SupportsVision:       false,
			MaxContextTokens:     32000,
		}
		c.SupportsEmbedding = p.embeddingModel != ""
		c.EmbeddingDimensions = geminiEmbeddingDimensions(p.embeddingModel)
		return c
	}
}
