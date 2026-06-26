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

// defaultOllamaEndpoint is the default Ollama server base URL when
// SBOMHUB_LLM_OLLAMA_URL is unset. Ollama's default bind address is
// localhost:11434; manufacturers using Docker / k8s self-host typically
// expose it through a service URL (e.g. http://ollama:11434).
//
// PRODUCT_REBOOT_PLAN.md §13 M4 / LLM_PROVIDER_DESIGN.md §9: Local LLM is
// the value carrier for manufacturers who cannot send proprietary code to
// external APIs. This provider is therefore the only first-class path
// without a BYOK key requirement.
const defaultOllamaEndpoint = "http://localhost:11434"

// defaultOllamaMaxTokens is the per-response generation cap when the
// caller leaves CompleteRequest.MaxTokens == 0. Ollama treats it as
// num_predict (-1 means unlimited); we pick a conservative bound to
// match the Anthropic provider's 1024-token default so cross-provider
// behaviour is predictable.
// ※要確認: VEX triage drafts in M1 fit in ~1k tokens; revisit if CRA
// report drafting (M2) needs a larger ceiling.
const defaultOllamaMaxTokens = 1024

// ollamaResponseBodyCap caps how many bytes of a non-2xx response body
// we surface in the wrapped error. 4 KiB is enough for Ollama's
// error envelopes while keeping logs / persisted error_message rows
// from blowing up on accidental HTML pages from a misconfigured proxy.
const ollamaResponseBodyCap = 4 << 10 // 4 KiB

// OllamaProvider implements Provider against the Ollama HTTP API.
//
// We intentionally avoid the official ollama-go SDK in M4 and call the
// REST endpoints directly via net/http for the same reasons as the
// OpenAI / Anthropic / Gemini providers: keep the dependency surface
// small (security product policy: prefer std lib), and stay testable
// via httptest.Server.
//
// Wire reference: github.com/ollama/ollama/blob/main/docs/api.md (chat
// completion via POST /api/chat with {stream: false} returns a single
// JSON envelope rather than a stream of NDJSON lines). The streaming
// variant is intentionally NOT used here — VEX triage / CRA drafting
// flows in SBOMHub buffer the whole draft anyway, and a single-shot
// JSON read keeps error handling identical to the other providers.
// ※要確認: streaming (stream=true, NDJSON) may be wired in M4-3 if the
// llm-bench tool wants progress reporting; the wire shape is documented
// in api.md but currently outside scope.
type OllamaProvider struct {
	baseURL          string
	model            string
	client           *http.Client
	defaultMaxTokens int
}

// Compile-time interface conformance.
var _ Provider = (*OllamaProvider)(nil)

// NewOllama constructs an OllamaProvider for the given base URL and
// model. If baseURL is empty it falls back to defaultOllamaEndpoint
// (localhost:11434); callers that want to point at a remote Ollama
// node should pass the SBOMHUB_LLM_OLLAMA_URL value explicitly.
//
// Unlike the BYOK providers, Ollama has no API key — auth, if any, is
// the operator's responsibility (TLS termination + IP allowlist on the
// reverse proxy in front of the Ollama service).
func NewOllama(baseURL, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = defaultOllamaEndpoint
	}
	return &OllamaProvider{
		baseURL:          strings.TrimRight(baseURL, "/"),
		model:            model,
		client:           &http.Client{Timeout: 120 * time.Second},
		defaultMaxTokens: defaultOllamaMaxTokens,
	}
}

// NewOllamaWithClient is used by tests (httptest.Server) and by callers
// that want to inject a custom *http.Client (e.g. with a proxy or a
// stricter timeout). Not intended for production callers.
func NewOllamaWithClient(baseURL, model string, c *http.Client) *OllamaProvider {
	p := NewOllama(baseURL, model)
	if c != nil {
		p.client = c
	}
	return p
}

// Name implements Provider.
func (p *OllamaProvider) Name() string { return "ollama" }

// Model implements Provider.
func (p *OllamaProvider) Model() string { return p.model }

// LogValue implements slog.LogValuer.
//
// Ollama has no API key to leak, but we deliberately also keep the
// base URL out of the logged value — for an enterprise self-host
// deployment the Ollama service URL is internal-network topology that
// should not show up in audit logs or HTTP 500 bodies. (§7.2)
func (p *OllamaProvider) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", p.Name()),
		slog.String("model", p.model),
	)
}

// ollamaMessage is one chat turn in the /api/chat request / response.
type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ollamaOptions mirrors the subset of Ollama's generation options that
// SBOMHub uses. The full option set (top_p, top_k, repeat_penalty, ...)
// is intentionally omitted — VEX triage runs determinism-first
// (temperature near zero), and surfacing the rest would invite
// per-tenant drift that defeats audit comparability.
type ollamaOptions struct {
	Temperature *float32 `json:"temperature,omitempty"`
	NumPredict  int      `json:"num_predict,omitempty"`
}

// ollamaChatRequest is the POST /api/chat body.
type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Format   string          `json:"format,omitempty"`
	Options  *ollamaOptions  `json:"options,omitempty"`
}

// ollamaChatResponse is the non-streaming POST /api/chat response.
// The wire shape includes load_duration / prompt_eval_duration /
// eval_duration nanoseconds that we ignore — audit cost accounting
// for Ollama is zero by definition (no upstream API charges).
type ollamaChatResponse struct {
	Model           string        `json:"model"`
	Message         ollamaMessage `json:"message"`
	Done            bool          `json:"done"`
	PromptEvalCount int           `json:"prompt_eval_count"`
	EvalCount       int           `json:"eval_count"`
	// Error is non-empty when Ollama returns a structured error envelope
	// (e.g. {"error":"model 'foo' not found"} with HTTP 404). It is not
	// used for non-2xx generic transport errors.
	Error string `json:"error,omitempty"`
}

// Complete implements Provider.
//
// The Ollama chat API is closer to OpenAI's shape than Anthropic's:
// system prompts are passed as the first message with role=system
// rather than a dedicated top-level field. JSONMode is honoured via
// the "format":"json" request field, which Ollama enforces by adding
// a grammar constraint to the sampler — supported across the
// llama / qwen / mistral families.
func (p *OllamaProvider) Complete(ctx context.Context, req CompleteRequest) (*CompleteResponse, error) {
	if p.model == "" {
		// We don't return DisabledError here because the factory layer
		// already maps "no model configured" to DisabledProvider. If
		// someone constructs OllamaProvider directly without a model
		// we surface a clear error rather than silently picking one.
		return nil, fmt.Errorf("ollama: model is empty (set SBOMHUB_LLM_MODEL)")
	}

	msgs := make([]ollamaMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, ollamaMessage{Role: RoleSystem, Content: req.System})
	}
	for _, m := range req.Messages {
		role := m.Role
		// Ollama's /api/chat accepts user / assistant / system / tool
		// roles depending on the model template. Unknown roles fall
		// back to user (parity with anthropic.go).
		if role != RoleUser && role != RoleAssistant && role != RoleSystem && role != RoleTool {
			role = RoleUser
		}
		msgs = append(msgs, ollamaMessage{Role: role, Content: m.Content})
	}

	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = p.defaultMaxTokens
	}

	body := ollamaChatRequest{
		Model:    p.model,
		Messages: msgs,
		// We always use the single-shot envelope. The agent prompt and
		// docs note this is deliberate; if M4-3 needs streaming we will
		// add a separate code path rather than tee through bufio here.
		Stream: false,
		Options: &ollamaOptions{
			NumPredict: maxTok,
		},
	}
	if req.Temperature > 0 {
		t := req.Temperature
		body.Options.Temperature = &t
	}
	if req.JSONMode {
		// Ollama's documented value for JSON-constrained output. The
		// model must support the format constraint for this to take
		// effect; on models without grammar support Ollama silently
		// returns free-form text, which the caller will need to
		// re-prompt for. ※要確認: M4-3 bench harness should record
		// JSON-mode adherence rate per model.
		body.Format = "json"
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("ollama: marshal request: %w", err)
	}

	endpoint := p.baseURL + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("ollama: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		// Defense-in-depth: even though Ollama has no API key to leak,
		// the base URL may carry internal-network hostnames (e.g.
		// http://ollama.internal:11434) that operators don't want
		// surfaced in HTTP 500 bodies or audit logs. RedactProviderError
		// strips the URL query string + drops the URL to its scheme +
		// host form on *url.Error nodes; it is a no-op when the chain
		// contains no auth-shaped material, which is the common case
		// here. We wrap rather than replace to retain transport error
		// sentinels (context.DeadlineExceeded etc.) for callers using
		// errors.Is.
		return nil, fmt.Errorf("ollama: http call: %w", RedactProviderError(err))
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ollama: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Cap the body we echo so a misrouted request that hits an
		// HTML proxy page does not flood llm_calls.error_message.
		snippet := rawBody
		if len(snippet) > ollamaResponseBodyCap {
			snippet = snippet[:ollamaResponseBodyCap]
		}
		// Try the structured error first; fall back to the raw body
		// snippet if the response is not JSON.
		var errResp ollamaChatResponse
		if err := json.Unmarshal(rawBody, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("ollama: %s: %s", resp.Status, errResp.Error)
		}
		return nil, fmt.Errorf("ollama: %s: %s", resp.Status, string(snippet))
	}

	var parsed ollamaChatResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("ollama: parse response: %w", err)
	}

	// Even a 200 OK response can carry a non-empty Error field when the
	// model load failed mid-stream; treat that as an error so audit log
	// rows are not persisted as successful drafts.
	if parsed.Error != "" {
		return nil, fmt.Errorf("ollama: model error: %s", parsed.Error)
	}

	// FinishReason: Ollama does not have OpenAI's stop / length /
	// content_filter taxonomy. The chat API only signals "done" when
	// generation terminates normally. We normalise to "stop" so audit
	// downstream code can compare across providers.
	// ※要確認: M4-3 bench may want to distinguish num_predict-hit from
	// natural EOS; would require reading parsed.done_reason which
	// Ollama only exposes in newer (0.5+) versions.
	finish := ""
	if parsed.Done {
		finish = "stop"
	}

	return &CompleteResponse{
		Content:      parsed.Message.Content,
		InputTokens:  parsed.PromptEvalCount,
		OutputTokens: parsed.EvalCount,
		Model:        parsed.Model,
		FinishReason: finish,
		// Local LLM has zero per-call upstream cost. The audit layer
		// may still surface compute / GPU amortised cost, but that is
		// out of scope for the provider itself.
		CostUSD:     0,
		RawResponse: rawBody,
	}, nil
}

// Embed implements Provider.
//
// Ollama exposes a /api/embed endpoint, but SBOMHub does not consume
// embeddings yet (M2+ reachability / search may use them). Return
// ErrNotImplemented so the interface stays consistent with the other
// providers in M1/M4.
// ※要確認: wire /api/embed when M2 introduces vector search.
func (p *OllamaProvider) Embed(_ context.Context, _ EmbedRequest) (*EmbedResponse, error) {
	return nil, ErrNotImplemented
}

// Capabilities implements Provider.
//
// Context-window sizes come from the upstream model cards (Ollama
// itself reports them via /api/show, but we encode the common subset
// here so callers can size prompts without making an extra round trip).
// Anything not matched falls back to 8 KiB, the smallest context window
// among modern instruction-tuned models — safer to under-promise.
// ※要確認: keep this table in sync as new self-host-friendly models
// land (e.g. qwen3-coder, llama-4). M4-3 bench will surface drift.
func (p *OllamaProvider) Capabilities() Capabilities {
	maxCtx := ollamaContextWindow(p.model)
	return Capabilities{
		// format=json + grammar-constrained sampling — supported on the
		// llama / qwen / mistral families that Ollama ships templates
		// for. We advertise it on for all models and rely on the
		// per-call adherence-rate signal to flag misbehaving models.
		SupportsJSONMode: true,
		// Ollama does not enforce JSON schema (only the json grammar
		// constraint), so leave false.
		SupportsJSONSchema: false,
		// Function calling is model-dependent (llama-3.1 / qwen-2.5
		// support it via templates), but we have not wired tool_use
		// through the Provider interface yet. Leave false; revisit
		// when M2 wraps tool calls in the generic interface.
		SupportsFunctionCall: false,
		// Vision: llava / bakllava etc. support multimodal input via a
		// different request shape (images[] field). Out of scope.
		SupportsVision: false,
		// Embed not wired — see Embed().
		SupportsEmbedding: false,
		MaxContextTokens:  maxCtx,
	}
}

// ollamaContextWindow returns the published native context window for
// the given Ollama model tag. The match is prefix-based on the bare
// model name (everything before the first colon) so size suffixes
// (":7b" / ":13b") and quantisation tags (":q4_K_M") all collapse to
// the same row.
//
// Sources (workspace policy: web-confirmed, not internal model
// knowledge — checked 2026-06):
//
//   - qwen2.5 / qwen2.5-coder:  32k
//   - llama3.1 / llama3.2:     128k
//   - llama3:                    8k
//   - mistral / mistral-nemo:  128k (nemo) / 32k (7B)
//   - mixtral:                  32k
//   - phi3 / phi3.5:           128k (mini-instruct), 4k (mini)
//   - gemma2:                    8k
//   - deepseek-coder-v2:      164k
//   - codellama:               16k
//
// Anything else returns 8192 (smallest modern default — conservative).
func ollamaContextWindow(model string) int {
	bare := model
	if i := strings.Index(model, ":"); i >= 0 {
		bare = model[:i]
	}
	bare = strings.ToLower(bare)
	switch {
	case strings.HasPrefix(bare, "qwen2.5-coder"),
		strings.HasPrefix(bare, "qwen2.5"),
		strings.HasPrefix(bare, "qwen3-coder"),
		strings.HasPrefix(bare, "qwen3"):
		return 32768
	case strings.HasPrefix(bare, "llama3.1"),
		strings.HasPrefix(bare, "llama3.2"),
		strings.HasPrefix(bare, "llama3.3"):
		return 131072
	case strings.HasPrefix(bare, "llama3"):
		return 8192
	case strings.HasPrefix(bare, "mistral-nemo"):
		return 131072
	case strings.HasPrefix(bare, "mistral"):
		return 32768
	case strings.HasPrefix(bare, "mixtral"):
		return 32768
	case strings.HasPrefix(bare, "phi3.5"),
		strings.HasPrefix(bare, "phi3"):
		return 131072
	case strings.HasPrefix(bare, "gemma2"),
		strings.HasPrefix(bare, "gemma"):
		return 8192
	case strings.HasPrefix(bare, "deepseek-coder-v2"),
		strings.HasPrefix(bare, "deepseek-r1"):
		return 163840
	case strings.HasPrefix(bare, "codellama"):
		return 16384
	default:
		return 8192
	}
}
