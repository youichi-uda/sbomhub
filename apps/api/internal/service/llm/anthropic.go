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

// defaultAnthropicEndpoint is the base URL for the Anthropic Messages API.
const defaultAnthropicEndpoint = "https://api.anthropic.com/v1"

// defaultAnthropicVersion is the value for the anthropic-version header.
// ※要確認: Anthropic publishes new versions periodically. As of 2026-06 the
// "2023-06-01" string is still the stable Messages API contract; we may need
// to bump for new tools / cache_control features in later milestones.
const defaultAnthropicVersion = "2023-06-01"

// AnthropicProvider implements Provider against the Anthropic Messages API.
// We hit /v1/messages directly via net/http for the same reason as OpenAI:
// keep the dependency surface small in M1.
type AnthropicProvider struct {
	apiKey        string
	model         string
	endpoint      string
	versionHeader string
	client        *http.Client
	// defaultMaxTokens is required by the Anthropic API (no implicit
	// default). We provide a sane fallback if the caller leaves
	// CompleteRequest.MaxTokens == 0.
	defaultMaxTokens int
}

// Compile-time interface conformance.
var _ Provider = (*AnthropicProvider)(nil)

// NewAnthropic constructs an AnthropicProvider with the default endpoint.
// If model is empty, defaults to "claude-sonnet-4-6" (balanced cost/quality
// for VEX triage; Sonnet 4.x stops at 4-6 — there is no claude-sonnet-4-7).
// ※要確認: revisit if Anthropic releases a newer balanced-tier Sonnet.
func NewAnthropic(apiKey, model string) *AnthropicProvider {
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	return &AnthropicProvider{
		apiKey:           apiKey,
		model:            model,
		endpoint:         defaultAnthropicEndpoint,
		versionHeader:    defaultAnthropicVersion,
		client:           &http.Client{Timeout: 60 * time.Second},
		defaultMaxTokens: 1024,
	}
}

// NewAnthropicWithEndpoint is used by tests (httptest.Server).
func NewAnthropicWithEndpoint(apiKey, model, endpoint string) *AnthropicProvider {
	p := NewAnthropic(apiKey, model)
	p.endpoint = strings.TrimRight(endpoint, "/")
	return p
}

// Name implements Provider.
func (p *AnthropicProvider) Name() string { return "anthropic" }

// Model implements Provider.
func (p *AnthropicProvider) Model() string { return p.model }

// LogValue implements slog.LogValuer — emits only {provider, model}, never
// the API key (§7.2).
func (p *AnthropicProvider) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", p.Name()),
		slog.String("model", p.model),
	)
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature *float32           `json:"temperature,omitempty"`
	StopSeq     []string           `json:"stop_sequences,omitempty"`
}

type anthropicResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	Model   string `json:"model"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *anthropicError `json:"error,omitempty"`
}

type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Complete implements Provider.
//
// The Anthropic Messages API requires only user/assistant roles in the
// `messages` array; system prompts go in a top-level `system` field. We map
// the generic CompleteRequest accordingly. Tool role messages are downgraded
// to user role in M1 (we don't ship tool-calling yet).
// ※要確認: tool-role handling for M2 when we wire function calling.
func (p *AnthropicProvider) Complete(ctx context.Context, req CompleteRequest) (*CompleteResponse, error) {
	if p.apiKey == "" {
		return nil, &DisabledError{Reason: "Anthropic API key is empty"}
	}

	msgs := make([]anthropicMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role != RoleUser && role != RoleAssistant {
			role = RoleUser
		}
		msgs = append(msgs, anthropicMessage{Role: role, Content: m.Content})
	}

	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = p.defaultMaxTokens
	}

	body := anthropicRequest{
		Model:     p.model,
		System:    req.System,
		Messages:  msgs,
		MaxTokens: maxTok,
		StopSeq:   req.Stop,
	}
	if req.Temperature > 0 {
		t := req.Temperature
		body.Temperature = &t
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/messages", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("anthropic: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Anthropic uses x-api-key (not Bearer).
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", p.versionHeader)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: http call: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp anthropicResponse
		_ = json.Unmarshal(rawBody, &errResp)
		if errResp.Error != nil {
			return nil, fmt.Errorf("anthropic: http %d: %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("anthropic: http %d", resp.StatusCode)
	}

	var parsed anthropicResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("anthropic: parse response: %w", err)
	}

	var sb strings.Builder
	for _, c := range parsed.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}

	return &CompleteResponse{
		Content:      sb.String(),
		InputTokens:  parsed.Usage.InputTokens,
		OutputTokens: parsed.Usage.OutputTokens,
		Model:        parsed.Model,
		FinishReason: parsed.StopReason,
		CostUSD:      0, // computed downstream in audit layer
		RawResponse:  rawBody,
	}, nil
}

// Embed implements Provider. Anthropic does not currently expose a first-
// party embeddings endpoint; M1 returns ErrNotImplemented.
func (p *AnthropicProvider) Embed(_ context.Context, _ EmbedRequest) (*EmbedResponse, error) {
	slog.Warn("llm: Anthropic embeddings are not first-party supported; use Voyage AI or another embedding provider",
		"provider", p.Name(),
		"model", p.model)
	return nil, ErrNotImplemented
}

// Capabilities implements Provider.
// ※要確認: keep in sync with Anthropic's docs (context windows, JSON-mode
// support change across model generations).
func (p *AnthropicProvider) Capabilities() Capabilities {
	switch {
	case strings.HasPrefix(p.model, "claude-opus-4"), strings.HasPrefix(p.model, "claude-sonnet-4"):
		return Capabilities{
			SupportsJSONMode:     false, // Anthropic uses tool-use / prefill for JSON
			SupportsJSONSchema:   false,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			SupportsEmbedding:    false,
			MaxContextTokens:     200000,
		}
	case strings.HasPrefix(p.model, "claude-3"):
		return Capabilities{
			SupportsJSONMode:     false,
			SupportsJSONSchema:   false,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			SupportsEmbedding:    false,
			MaxContextTokens:     200000,
		}
	default:
		return Capabilities{
			SupportsJSONMode:     false,
			SupportsJSONSchema:   false,
			SupportsFunctionCall: false,
			SupportsVision:       false,
			SupportsEmbedding:    false,
			MaxContextTokens:     100000,
		}
	}
}
