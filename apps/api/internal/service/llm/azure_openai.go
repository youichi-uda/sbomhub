package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
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
	deployment       string // Azure chat deployment name (URL path segment)
	apiVersion       string // chat api-version query string value
	modelName        string // display / Capabilities chat model identifier
	client           *http.Client
	defaultMaxTokens int

	// Embedding deployment (M5-3, issue #51). Azure exposes embedding
	// models through their own deployment — a separate URL path segment
	// from the chat deployment — so we keep the configuration parallel
	// to the chat fields rather than overloading them. All three fields
	// are zero-valued when the operator has not configured an embedding
	// deployment; in that case Embed returns *DisabledError and
	// Capabilities.SupportsEmbedding stays false.
	embeddingDeployment string // Azure embedding deployment name
	embeddingAPIVersion string // optional override; falls back to apiVersion
	embeddingModelName  string // canonical embedding model identifier (text-embedding-3-small etc.)
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

// NewAzureOpenAIWithEmbedding constructs an AzureOpenAIProvider with both
// chat and embedding deployments configured (M5-3, issue #51).
//
// Azure exposes embedding models (text-embedding-3-small / text-embedding-
// 3-large / text-embedding-ada-002 / etc.) through their own deployments
// — the embedding deployment is a separate URL path segment from the chat
// deployment. Operators commonly configure one Azure resource with both
// (e.g. `gpt-4o-chat` for chat + `text-embedding-3-small` for vector
// reachability). This constructor accepts both sets in one call rather
// than forcing callers to mutate fields after construction.
//
// Defaults:
//   - embeddingAPIVersion == "" → falls back to the chat apiVersion at
//     request time (Embed() reads embeddingAPIVersion, then apiVersion).
//     This matches the operator mental model that one Azure resource
//     pins one api-version unless they explicitly diverge per deployment.
//   - embeddingModelName == "" → Capabilities.EmbeddingDimensions falls
//     back to deployment-name sniffing (e.g. a deployment named
//     `text-embedding-3-small-prod` resolves to 1536). When sniffing also
//     fails, dimensions is left at 0 and the operator should set
//     SBOMHUB_LLM_AZURE_EMBEDDING_MODEL to a known family name.
//
// embeddingDeployment == "" is the explicit "embedding not configured"
// signal — Embed() returns *DisabledError and Capabilities.SupportsEmbedding
// stays false in that case.
func NewAzureOpenAIWithEmbedding(
	apiKey, endpoint, deployment, apiVersion, modelName,
	embeddingDeployment, embeddingAPIVersion, embeddingModelName string,
) *AzureOpenAIProvider {
	p := NewAzureOpenAI(apiKey, endpoint, deployment, apiVersion, modelName)
	p.embeddingDeployment = strings.TrimSpace(embeddingDeployment)
	p.embeddingAPIVersion = strings.TrimSpace(embeddingAPIVersion)
	p.embeddingModelName = strings.TrimSpace(embeddingModelName)
	return p
}

// NewAzureOpenAIWithEmbeddingAndClient is the test seam that combines
// NewAzureOpenAIWithEmbedding + a custom *http.Client. Used by
// azure_openai_test.go for the embedding test matrix; not intended for
// production callers.
func NewAzureOpenAIWithEmbeddingAndClient(
	apiKey, endpoint, deployment, apiVersion, modelName,
	embeddingDeployment, embeddingAPIVersion, embeddingModelName string,
	client *http.Client,
) *AzureOpenAIProvider {
	p := NewAzureOpenAIWithEmbedding(apiKey, endpoint, deployment, apiVersion, modelName,
		embeddingDeployment, embeddingAPIVersion, embeddingModelName)
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
// emits {provider, deployment, model[, embedding_deployment,
// embedding_model]} and NEVER the API key or the resource endpoint URL
// (the latter is sometimes considered tenancy metadata by enterprise
// operators). (§7.2 never-log policy, M4-2 §1.K)
//
// Embedding fields are surfaced only when configured (M5-3): an operator
// who has not deployed an embedding model should see the same log shape
// as M4-2 — adding empty attrs would be operator-confusing churn.
func (p *AzureOpenAIProvider) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("provider", p.Name()),
		slog.String("deployment", p.deployment),
		slog.String("model", p.modelName),
	}
	if p.embeddingDeployment != "" {
		attrs = append(attrs, slog.String("embedding_deployment", p.embeddingDeployment))
		if p.embeddingModelName != "" {
			attrs = append(attrs, slog.String("embedding_model", p.embeddingModelName))
		}
	}
	return slog.GroupValue(attrs...)
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
		// F63: Azure-specific scrub. The default RedactProviderError only
		// strips ?query / #fragment from `*url.Error.URL`; on a DNS,
		// connect, or timeout failure the host + path themselves still
		// contain the tenant resource name and deployment name (e.g.
		// `https://<tenant-resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions`).
		// Persisting that into llm_calls.error_message — or echoing it
		// back through a 500 JSON body — leaks tenancy metadata that the
		// LogValue policy (see LogValue above) deliberately keeps out of
		// structured logs. RedactAzureTransportError replaces the whole
		// URL with a static placeholder before falling through to the
		// generic api-key-query scrubber for defense-in-depth.
		return nil, RedactAzureTransportError(fmt.Errorf("azure_openai: http call: %w", err))
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

// azureEmbedMaxBatchSize is the documented Azure OpenAI /embeddings
// input-array hard cap (Microsoft Learn / Azure OpenAI embeddings doc,
// confirmed 2026-06: "the maximum array size is 2,048"). Requests with a
// longer `input` array fail server-side with HTTP 400, so Embed chunks
// the caller's []string transparently. ※要確認: Microsoft also documents
// an aggregate hard cap of 300,000 tokens summed across all inputs in
// one request (HTTP 400) and a per-input cap of 8,192 tokens — we do
// NOT enforce those client-side because we have no cheap tokeniser, and
// surfacing the upstream 400 lets the operator see the exact failure
// path. See azureEmbedMaxTotalInputs for the DoS safety cap.
const azureEmbedMaxBatchSize = 2048

// azureEmbedMaxTotalInputs is the per-call defense-in-depth cap on the
// total number of input texts (F25 batch DoS protection). 16,384 is 8
// chunks of azureEmbedMaxBatchSize — large enough for any sensible
// reachability batch we expect M2+ to drive (one SBOM component set is
// orders of magnitude smaller), and small enough that a single buggy
// caller cannot pin the worker on a runaway embedding loop.
//
// ※要確認: revisit if M2 reachability needs >16k component embeddings
// per call. The trivial mitigation is to surface this as
// SBOMHUB_LLM_AZURE_EMBEDDING_MAX_INPUTS env so the operator can opt
// out of the cap when running on a large-quota deployment.
const azureEmbedMaxTotalInputs = 16384

// azureEmbeddingRequest mirrors the Azure OpenAI Embeddings REST
// request body. The wire format is identical to OpenAI's
// /v1/embeddings (Azure routes by deployment URL, not by `model`),
// so we deliberately omit the `model` field for the same reason
// openaiChatRequest does in azure_openai.go Complete.
type azureEmbeddingRequest struct {
	Input []string `json:"input"`
}

// azureEmbeddingResponse mirrors the relevant fields of the Azure
// OpenAI Embeddings response. `data` is sorted by index in practice but
// we re-index defensively (Embed below) because the spec does not
// guarantee order.
type azureEmbeddingResponse struct {
	Object string                `json:"object"`
	Data   []azureEmbeddingDatum `json:"data"`
	Model  string                `json:"model"`
	Usage  struct {
		PromptTokens int `json:"prompt_tokens"`
		TotalTokens  int `json:"total_tokens"`
	} `json:"usage"`
	Error *openaiError `json:"error,omitempty"`
}

// azureEmbeddingDatum is one input's embedding vector.
type azureEmbeddingDatum struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float32 `json:"embedding"`
}

// Embed implements Provider against the Azure OpenAI Embeddings REST
// API (M5-3, issue #51).
//
// Wire format (confirmed against Microsoft Learn, 2026-06):
//
//	POST {endpoint}/openai/deployments/{embeddingDeployment}/embeddings?api-version={apiVersion}
//	api-key: {apiKey}
//	Content-Type: application/json
//	{"input": ["text", ...]}
//
// Behaviour:
//
//   - Empty req.Texts is a no-op (zero-length Vectors, no HTTP call).
//   - len(req.Texts) > azureEmbedMaxBatchSize is chunked transparently;
//     each chunk is a separate HTTP request. Chunks run sequentially
//     because we want predictable ordering and to keep TPM well below
//     the per-deployment quota (Azure's default Gen-3 embeddings quota
//     is 350K TPM per region — bursting in parallel would risk 429s).
//   - len(req.Texts) > azureEmbedMaxTotalInputs returns an error
//     without dispatching any HTTP request (F25 batch DoS cap).
//   - A failure mid-chunk discards completed chunks per the task spec.
//     This is intentional: partial Vectors with len < len(req.Texts)
//     would silently corrupt the caller's index mapping; failing hard
//     lets the caller decide whether to retry the whole batch.
//   - Transport errors are scrubbed via RedactAzureTransportError so
//     the tenant resource + deployment name never reach
//     llm_calls.error_message.
//
// ※要確認: per-chunk timeout management is delegated to the shared
// p.client.Timeout (60s). For very large batches the *http.Client*
// timeout is enforced per HTTP call, NOT per Embed call — a 10-chunk
// batch can therefore run up to 10 × 60s = 10 minutes wall time. The
// caller controls overall deadline via ctx, which is honoured per
// chunk (http.NewRequestWithContext).
func (p *AzureOpenAIProvider) Embed(ctx context.Context, req EmbedRequest) (*EmbedResponse, error) {
	if p.apiKey == "" {
		return nil, &DisabledError{Reason: "Azure OpenAI API key is empty"}
	}
	if p.endpoint == "" {
		return nil, &DisabledError{Reason: "Azure OpenAI endpoint is empty"}
	}
	if p.embeddingDeployment == "" {
		return nil, &DisabledError{
			Reason: "Azure OpenAI embedding deployment is empty " +
				"(set SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT or AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME)",
		}
	}
	if len(req.Texts) == 0 {
		return &EmbedResponse{
			Vectors: [][]float32{},
			Model:   p.embeddingResponseModelName(),
		}, nil
	}
	if len(req.Texts) > azureEmbedMaxTotalInputs {
		// F25: refuse before issuing any HTTP traffic so a buggy
		// caller cannot light up the upstream quota with a single
		// request. We do NOT include the input text in the error
		// message (no risk of leaking PII / source code).
		return nil, fmt.Errorf("azure_openai: embed inputs %d exceed safety cap %d (set fewer or split caller-side)",
			len(req.Texts), azureEmbedMaxTotalInputs)
	}

	// embeddingAPIVersion override falls back to the chat apiVersion.
	// Operators commonly pin one Azure resource to one api-version; the
	// override exists only for the rare case where chat and embedding
	// deployments diverge (e.g. one is on a preview channel).
	apiVersion := p.embeddingAPIVersion
	if apiVersion == "" {
		apiVersion = p.apiVersion
	}

	vectors := make([][]float32, len(req.Texts))
	totalPromptTokens := 0
	respModel := ""

	for start := 0; start < len(req.Texts); start += azureEmbedMaxBatchSize {
		end := start + azureEmbedMaxBatchSize
		if end > len(req.Texts) {
			end = len(req.Texts)
		}
		chunk := req.Texts[start:end]

		body := azureEmbeddingRequest{Input: chunk}
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("azure_openai: marshal embed request: %w", err)
		}

		url := fmt.Sprintf("%s/openai/deployments/%s/embeddings?api-version=%s",
			p.endpoint, p.embeddingDeployment, apiVersion)

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("azure_openai: new embed request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		// Azure uses `api-key`, NOT `Authorization: Bearer`.
		httpReq.Header.Set("api-key", p.apiKey)

		resp, err := p.client.Do(httpReq)
		if err != nil {
			// F63: scrub Azure-specific tenant resource + deployment
			// name from the transport error before propagating.
			// Partial Vectors collected so far are discarded by
			// returning here (chunked partial state cannot be merged
			// safely — see Embed doc comment).
			return nil, RedactAzureTransportError(
				fmt.Errorf("azure_openai: embed http call (chunk start=%d): %w", start, err))
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			const errBodyCap = 4 << 10
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, errBodyCap))
			resp.Body.Close()
			var errResp azureEmbeddingResponse
			_ = json.Unmarshal(errBody, &errResp)
			if errResp.Error != nil {
				return nil, fmt.Errorf("azure_openai: embed %s: %s", resp.Status, errResp.Error.Message)
			}
			return nil, fmt.Errorf("azure_openai: embed %s: %s", resp.Status, string(errBody))
		}

		rawBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("azure_openai: read embed body: %w", readErr)
		}

		var parsed azureEmbeddingResponse
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			return nil, fmt.Errorf("azure_openai: parse embed response: %w", err)
		}
		seen := make([]bool, len(chunk))
		for _, d := range parsed.Data {
			if d.Index < 0 || d.Index >= len(chunk) {
				return nil, fmt.Errorf("azure_openai: embed response index %d out of range [0, %d)",
					d.Index, len(chunk))
			}
			if seen[d.Index] {
				return nil, fmt.Errorf("azure_openai: embed response duplicate index %d", d.Index)
			}
			seen[d.Index] = true
			vectors[start+d.Index] = d.Embedding
		}
		for i, ok := range seen {
			if !ok {
				return nil, fmt.Errorf("azure_openai: embed response missing index %d", i)
			}
		}
		if len(parsed.Data) != len(chunk) {
			return nil, fmt.Errorf("azure_openai: embed response data count %d != chunk size %d",
				len(parsed.Data), len(chunk))
		}
		totalPromptTokens += parsed.Usage.PromptTokens
		// Azure returns the underlying model name on the embedding
		// response (e.g. "text-embedding-3-small"); we keep the last
		// chunk's reading on the assumption that all chunks land on the
		// same deployment (which they do — same URL).
		if parsed.Model != "" {
			respModel = parsed.Model
		}
	}

	if respModel == "" {
		respModel = p.embeddingResponseModelName()
	}
	return &EmbedResponse{
		Vectors:     vectors,
		InputTokens: totalPromptTokens,
		Model:       respModel,
		// ※要確認: Azure embedding pricing is per-deployment and
		// distinct from OpenAI direct; CostUSD is computed in the
		// audit layer once a per-deployment price table is available
		// (matches Complete + openai.go convention).
		CostUSD: 0,
	}, nil
}

// embeddingResponseModelName returns the best-effort canonical embedding
// model identifier for the EmbedResponse.Model field when the upstream
// response has not populated one (or when the caller asks for the model
// without dispatching a request — e.g. empty inputs).
func (p *AzureOpenAIProvider) embeddingResponseModelName() string {
	if p.embeddingModelName != "" {
		return p.embeddingModelName
	}
	return p.embeddingDeployment
}

// azureEmbeddingDimensions returns the embedding vector size for the
// known Azure OpenAI embedding model families. The lookup walks
// embeddingModelName first, then falls back to sniffing the deployment
// name (operators commonly name a deployment after the underlying model
// — e.g. `text-embedding-3-small-prod`).
//
// Returns 0 for unknown / business-named deployments; downstream vector
// storage callers should treat 0 as "operator should set
// SBOMHUB_LLM_AZURE_EMBEDDING_MODEL".
//
// ※要確認: text-embedding-3-{small,large} support a `dimensions`
// request parameter that lets callers truncate the vector to a smaller
// size (1536→256 etc.). sbomhub does not expose that today; if a
// future milestone wires it through, this lookup must consult the
// requested dimensions rather than the model default.
func (p *AzureOpenAIProvider) azureEmbeddingDimensions() int {
	if p.embeddingDeployment == "" {
		return 0
	}
	name := strings.ToLower(p.embeddingModelName)
	if name == "" {
		name = strings.ToLower(p.embeddingDeployment)
	}
	switch {
	case strings.Contains(name, "text-embedding-3-large"):
		return 3072
	case strings.Contains(name, "text-embedding-3-small"):
		return 1536
	case strings.Contains(name, "text-embedding-ada-002"), strings.Contains(name, "ada-002"):
		return 1536
	default:
		return 0
	}
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
	var c Capabilities
	switch {
	case strings.HasPrefix(p.modelName, "gpt-4o"), strings.HasPrefix(p.modelName, "gpt-4.1"), strings.HasPrefix(p.modelName, "gpt-5"):
		c = Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       true,
			MaxContextTokens:     128000,
		}
	case strings.HasPrefix(p.modelName, "o1"), strings.HasPrefix(p.modelName, "o3"):
		c = Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   true,
			SupportsFunctionCall: true,
			SupportsVision:       false,
			MaxContextTokens:     200000,
		}
	default:
		// Conservative default for unknown / business-named deployments.
		// SupportsJSONMode stays true because every GA Azure OpenAI
		// chat-completions deployment supports response_format=json_object;
		// SupportsJSONSchema is the stricter feature and we only enable it
		// for known recent families.
		c = Capabilities{
			SupportsJSONMode:     true,
			SupportsJSONSchema:   false,
			SupportsFunctionCall: true,
			SupportsVision:       false,
			MaxContextTokens:     16000,
		}
	}
	// Embedding flags are independent of the chat model — Azure exposes
	// embedding through its own deployment and an operator can ship one
	// without the other. SupportsEmbedding flips true the moment the
	// embedding deployment env is set; dimensions is a best-effort
	// lookup from the canonical embedding model name (env-supplied) or
	// the deployment name (sniffed) — see azureEmbeddingDimensions.
	c.SupportsEmbedding = p.embeddingDeployment != ""
	c.EmbeddingDimensions = p.azureEmbeddingDimensions()
	return c
}

// azureEndpointURLPlaceholder is the static replacement string used in
// transport-error redaction. Operators reading a triage / CRA / meti
// `llm_calls.error_message` should see this token and know the original
// URL was scrubbed deliberately — not corrupted by a parse failure.
const azureEndpointURLPlaceholder = "[REDACTED-AZURE-ENDPOINT]"

// azureEndpointHostPattern matches Azure OpenAI request URLs *and* bare
// `<tenant-resource>.openai.azure.com` hostnames that may appear in
// rendered error strings even after the `*url.Error.URL` field has been
// scrubbed. Two leak surfaces we have to cover:
//
//  1. A wrapper that printed the full URL into its own error message
//     before we got to the error.
//  2. The underlying transport error itself — e.g.
//     `dial tcp: lookup <tenant-resource>.openai.azure.com: no such host`
//     — which embeds just the bare hostname inside the OS-level error
//     and survives layer-1 URL scrubbing.
//
// Pattern: an optional `https?://` scheme followed by
// `<resource>.openai.azure.com` followed by any optional trailing
// `:port`, path, query, or fragment up to the next whitespace, quote,
// or apostrophe. The trailing greedy match deliberately absorbs the
// `:1/openai/deployments/<deployment>/chat/completions?api-version=...`
// suffix that would otherwise leak the deployment name and api-version.
// False-positive risk is low because `*.openai.azure.com` is unambiguous.
//
// Note: when the substring appears in the DNS error fragment
// `lookup <host>.openai.azure.com:`, the trailing `:` is itself absorbed
// before the following space terminates the match. That's a tolerable
// cosmetic side effect — the redacted message reads
// `lookup [REDACTED-AZURE-ENDPOINT] no such host`.
var azureEndpointHostPattern = regexp.MustCompile(
	`(?:https?://)?[A-Za-z0-9._-]+\.openai\.azure\.com[^\s"']*`,
)

// RedactAzureTransportError scrubs Azure tenant resource + deployment
// metadata from a transport error chain before the error is propagated,
// persisted, or echoed back to a client.
//
// The generic RedactProviderError (error_redact.go) only removes the
// query string and fragment from `*url.Error.URL`. That is correct for
// providers where the URL host/path are opaque (e.g. api.openai.com),
// but for Azure OpenAI the URL itself carries:
//
//   - the tenant resource subdomain (`<resource>.openai.azure.com`),
//   - the deployment name (URL path segment), and
//   - the api-version (query parameter).
//
// All three are considered tenancy metadata by the LogValue policy
// established for *AzureOpenAIProvider (see LogValue above). Leaking
// them through a DNS, connect, or timeout error chain is the same
// security regression we already guarded against for structured logs —
// just on a different surface.
//
// Behavior:
//
//  1. If the chain contains a `*url.Error`, its `URL` field is replaced
//     with the static placeholder `[REDACTED-AZURE-ENDPOINT]`. The
//     `*url.Error` value is mutated in place for the same reason
//     RedactProviderError mutates it — every downstream `errors.As`
//     caller sees the scrubbed URL too.
//
//  2. The rendered error string is then scrubbed for any residual
//     `*.openai.azure.com` URL substrings that survived layer 1 (e.g.
//     wrappers that printed the URL into their own message before we
//     got to the error).
//
//  3. The result is finally passed through RedactProviderError so the
//     generic api-key query-param scrubber still runs as defense in
//     depth (catches `?api-key=...` regressions, third-party libraries
//     that build URLs with auth-shaped params, etc.).
//
// nil input returns nil so callers can use the helper unconditionally.
//
// ※要確認: this helper is currently Azure-specific because Azure is the
// only provider where the URL host/path carry tenancy metadata. If a
// future provider (e.g. a self-hosted Ollama exposed on a tenant-named
// hostname) gains the same property, lift this to error_redact.go with
// a per-provider pattern map rather than copy-pasting.
func RedactAzureTransportError(err error) error {
	if err == nil {
		return nil
	}

	// Layer 1: scrub *url.Error.URL in place with the static placeholder.
	// Note: this is stricter than redactURLString — we drop host + path
	// + query + fragment all at once, not just query + fragment.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		urlErr.URL = azureEndpointURLPlaceholder
	}

	// Layer 2: scrub the rendered text for any residual
	// *.openai.azure.com URL substrings. After layer 1 mutated the
	// *url.Error.URL field, calling err.Error() again should produce a
	// URL-free message in the common case — but a wrapper that captured
	// the URL into its own string earlier in the chain will still leak,
	// and that's the case this pattern catches.
	rendered := err.Error()
	scrubbed := azureEndpointHostPattern.ReplaceAllString(rendered, azureEndpointURLPlaceholder)
	if scrubbed != rendered {
		err = &redactedError{msg: scrubbed, cause: err}
	}

	// Layer 3: defense in depth for api-key-shaped query params (matches
	// the generic provider error pathway used by openai / anthropic /
	// gemini / ollama). Returns the same error unchanged if no further
	// scrub is needed.
	return RedactProviderError(err)
}
