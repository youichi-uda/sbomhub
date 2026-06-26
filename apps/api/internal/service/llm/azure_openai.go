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

// defaultAzureAPIVersion is the api-version query string parameter used when
// the operator has not pinned one via SBOMHUB_LLM_AZURE_API_VERSION.
//
// 2024-10-21 is the current "GA stable" api-version for Azure OpenAI Chat
// Completions as of 2026-06. Microsoft maintains the rolling list at
// https://learn.microsoft.com/azure/ai-services/openai/reference. We default
// to the GA channel (not the latest preview) because:
//
//   - GA is supported for ≥ 1 year after its successor ships, so operators
//     who set up the deployment once and forget are unlikely to hit a 410.
//   - Preview api-versions can break wire compat between minor revisions,
//     which is exactly the surface we DON'T want our defaults to absorb.
//
// ※要確認: revisit before each M-x release if Microsoft promotes a newer
// stable api-version (e.g. 2025-xx-xx); operators can always override via
// SBOMHUB_LLM_AZURE_API_VERSION without waiting for a sbomhub release.
const defaultAzureAPIVersion = "2024-10-21"

// AzureOpenAIProvider implements Provider against Azure OpenAI Service.
//
// Azure OpenAI is wire-compatible with the OpenAI Chat Completions API
// (same request / response schemas), so the bulk of the wire handling
// mirrors openai.go. The two differences this type encodes are:
//
//  1. The endpoint URL is per-deployment:
//     ${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=...
//     There is no `model` parameter in the request body — the deployment
//     name in the URL fully specifies which model is invoked.
//
//  2. Authentication uses an `api-key` header rather than
//     `Authorization: Bearer`.
//
// We keep `modelName` separate from `deployment` for display / Capabilities
// purposes: Azure operators commonly name their deployment after the
// business unit ("legal-vex-triage") rather than the underlying model
// ("gpt-4o"), and downstream consumers (Capabilities, audit) want the
// canonical model identifier.
type AzureOpenAIProvider struct {
	apiKey           string
	endpoint         string // base, e.g. https://my-resource.openai.azure.com
	deployment       string // Azure deployment name (URL path segment)
	apiVersion       string // api-version query string value
	modelName        string // display / Capabilities model identifier
	client           *http.Client
	defaultMaxTokens int
}

// Compile-time interface conformance.
var _ Provider = (*AzureOpenAIProvider)(nil)

// NewAzureOpenAI constructs an AzureOpenAIProvider for production callers.
//
// Defaults:
//   - apiVersion == "" → defaultAzureAPIVersion ("2024-10-21").
//   - modelName == ""  → falls back to deployment (so audit logs still get
//     a non-empty identifier even when the operator forgets to set
//     SBOMHUB_LLM_MODEL).
//
// The HTTP client timeout matches openai.go / anthropic.go (60s).
func NewAzureOpenAI(apiKey, endpoint, deployment, apiVersion, modelName string) *AzureOpenAIProvider {
	if apiVersion == "" {
		apiVersion = defaultAzureAPIVersion
	}
	if modelName == "" {
		modelName = deployment
	}
	return &AzureOpenAIProvider{
		apiKey:           apiKey,
		endpoint:         strings.TrimRight(endpoint, "/"),
		deployment:       deployment,
		apiVersion:       apiVersion,
		modelName:        modelName,
		client:           &http.Client{Timeout: 60 * time.Second},
		defaultMaxTokens: 0, // 0 == provider default (no explicit cap)
	}
}

// NewAzureOpenAIWithClient is the test seam used by azure_openai_test.go
// (httptest.NewServer) to redirect HTTP traffic. The signature lets a test
// supply its own *http.Client (so the test server's URL can be passed as
// endpoint and the client can be hooked / instrumented) without forcing
// production callers to construct one.
func NewAzureOpenAIWithClient(apiKey, endpoint, deployment, apiVersion, modelName string, client *http.Client) *AzureOpenAIProvider {
	p := NewAzureOpenAI(apiKey, endpoint, deployment, apiVersion, modelName)
	if client != nil {
		p.client = client
	}
	return p
}

// Name implements Provider.
func (p *AzureOpenAIProvider) Name() string { return "azure_openai" }

// Model implements Provider — returns the canonical model identifier
// (NOT the Azure deployment name) so audit / Capabilities lookups behave
// consistently with the other OpenAI-family providers.
func (p *AzureOpenAIProvider) Model() string { return p.modelName }

// LogValue implements slog.LogValuer so logging *AzureOpenAIProvider only
// emits {provider, deployment, model} and NEVER the API key or the
// resource endpoint URL (the latter is sometimes considered tenancy
// metadata by enterprise operators). (§7.2 never-log policy, M4-2 §1.K)
func (p *AzureOpenAIProvider) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", p.Name()),
		slog.String("deployment", p.deployment),
		slog.String("model", p.modelName),
	)
}

// Complete implements Provider.
//
// The request/response schemas are identical to OpenAI Chat Completions
// (we deliberately reuse openaiChatRequest / openaiChatResponse from
// openai.go); only URL construction and auth header differ.
func (p *AzureOpenAIProvider) Complete(ctx context.Context, req CompleteRequest) (*CompleteResponse, error) {
	if p.apiKey == "" {
		return nil, &DisabledError{Reason: "Azure OpenAI API key is empty"}
	}
	if p.endpoint == "" {
		return nil, &DisabledError{Reason: "Azure OpenAI endpoint is empty"}
	}
	if p.deployment == "" {
		return nil, &DisabledError{Reason: "Azure OpenAI deployment is empty"}
	}

	// Translate the generic request into the OpenAI wire format. We reuse
	// the openai* types from openai.go because the body schema is
	// byte-identical; the `model` field is left empty because the
	// deployment in the URL fully specifies the routing target.
	msgs := make([]openaiMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, openaiMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, openaiMessage{Role: m.Role, Content: m.Content})
	}

	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = p.defaultMaxTokens
	}

	body := openaiChatRequest{
		// Model: deliberately left empty — Azure routes by deployment URL.
		// ※要確認: some Azure deployments accept a `model` field for
		// observability, but it's ignored for routing. We omit it to keep
		// the request minimal.
		Messages:  msgs,
		MaxTokens: maxTok,
		Stop:      req.Stop,
	}
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
		return nil, fmt.Errorf("azure_openai: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		p.endpoint, p.deployment, p.apiVersion)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("azure_openai: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Azure uses `api-key`, NOT `Authorization: Bearer`.
	httpReq.Header.Set("api-key", p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		// F13: scrub any API-key-shaped query params from the transport
		// error before propagating. Azure auth is header-based so the URL
		// itself does not carry the key, but defense-in-depth catches
		// regressions and third-party wrappers that echo request URLs.
		return nil, RedactProviderError(fmt.Errorf("azure_openai: http call: %w", err))
	}
	defer resp.Body.Close()

	// Cap the body at 4 KiB on error so a misbehaving upstream cannot
	// blow up our error message / log line. Successful responses are read
	// in full because we need the usage block + content.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		const errBodyCap = 4 << 10
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, errBodyCap))
		// Try to surface the structured Azure error.message first; fall
		// back to the raw (capped) body when parsing fails.
		var errResp openaiChatResponse
		_ = json.Unmarshal(errBody, &errResp)
		if errResp.Error != nil {
			return nil, fmt.Errorf("azure_openai: %s: %s", resp.Status, errResp.Error.Message)
		}
		return nil, fmt.Errorf("azure_openai: %s: %s", resp.Status, string(errBody))
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("azure_openai: read body: %w", err)
	}

	var parsed openaiChatResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, fmt.Errorf("azure_openai: parse response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("azure_openai: empty choices")
	}

	choice := parsed.Choices[0]
	return &CompleteResponse{
		Content:      choice.Message.Content,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
		Model:        parsed.Model,
		FinishReason: choice.FinishReason,
		// ※要確認: Azure billing is per-deployment with a different price
		// schedule than OpenAI direct; we leave CostUSD = 0 here and let
		// the audit layer compute it once a per-deployment price table is
		// available. (Matches openai.go / anthropic.go.)
		CostUSD:     0,
		RawResponse: rawBody,
	}, nil
}

// Embed implements Provider. Azure OpenAI does expose embeddings via
// separate deployments (text-embedding-3-small etc.), but wiring that up
// requires its own deployment name + dimension config which is out of
// scope for the M4-2 Provider implementation. Return ErrNotImplemented
// so the contract matches openai.go / anthropic.go.
//
// ※要確認: M4-x may add an `embeddingDeployment` field + dedicated
// AzureOpenAIProvider.Embed implementation when reachability features
// land. Tracked under the same milestone as OpenAI embedding support.
func (p *AzureOpenAIProvider) Embed(_ context.Context, _ EmbedRequest) (*EmbedResponse, error) {
	return nil, ErrNotImplemented
}

// Capabilities implements Provider.
//
// Azure OpenAI exposes a curated subset of OpenAI's models — the
// deployment is configured by the operator, so we look up by modelName
// (NOT deployment) to stay consistent with the OpenAI provider's lookup.
//
// ※要確認: per-deployment quotas can clamp the effective context window
// below the model's nominal MaxContextTokens (e.g. older Azure regions
// cap gpt-4o at 32k). We return the model's nominal capability and let
// the operator pin a lower MaxTokens via CompleteRequest if their
// deployment is constrained.
func (p *AzureOpenAIProvider) Capabilities() Capabilities {
	switch {
	case strings.HasPrefix(p.modelName, "gpt-4o"), strings.HasPrefix(p.modelName, "gpt-4.1"), strings.HasPrefix(p.modelName, "gpt-5"):
		return Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			SupportsEmbedding:    false,
			MaxContextTokens:     128000,
		}
	case strings.HasPrefix(p.modelName, "o1"), strings.HasPrefix(p.modelName, "o3"):
		return Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       false,
			SupportsEmbedding:    false,
			MaxContextTokens:     200000,
		}
	default:
		// Conservative default for unknown / business-named deployments.
		// SupportsJSONMode stays true because every GA Azure OpenAI
		// chat-completions deployment supports response_format=json_object;
		// SupportsJSONSchema is the stricter feature and we only enable it
		// for known recent families.
		return Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   false,
			SupportsFunctionCall: true,
			SupportsVision:       false,
			SupportsEmbedding:    false,
			MaxContextTokens:     16000,
		}
	}
}
