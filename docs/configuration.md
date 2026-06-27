# Configuration

SBOMHub can be configured through environment variables.

> SBOMHub is an **AI compliance evidence layer** for the EU Cyber Resilience Act (CRA) reporting deadline of **2026-09-11**, and only self-host (Docker Compose) is supported.
> The SaaS instance at `sbomhub.app` was sunset in 2026-06; Clerk / Lemon Squeezy and other SaaS integrations are not used in the OSS distribution.

## Environment Variables

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | API server port |
| `DATABASE_URL` | `postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable` | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `BASE_URL` | `http://localhost:3000` | Base URL for the web application |
| `APP_ENV` | `development` | Environment: `development`, `staging`, `production`. The legacy name `ENVIRONMENT` is still read as a fallback when `APP_ENV` is unset (M0 Trust Rescue, codex-r18). |

### NVD Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | (empty) | NVD API key for higher rate limits. Get one at https://nvd.nist.gov/developers/request-an-api-key |

### LLM Provider (AI Features, BYOK)

AI features (AI VEX triage, CRA report drafting, METI self-assessment prefill, etc.) are **BYOK (Bring Your Own Key) only**. SBOMHub OSS ships zero bundled LLM keys. Configure exactly one provider below to enable AI features. If unset, AI features are gracefully disabled and the rest of the product (SBOM management, manual VEX, manual CRA reports, manual METI self-assessment) continues to work.

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOMHUB_LLM_PROVIDER` | (empty) | `openai` / `anthropic` / `gemini` / `azure_openai` / `ollama` |
| `SBOMHUB_LLM_MODEL` | (empty) | e.g. `gpt-5`, `claude-opus-4-7`, `gemini-3.5-flash`, `qwen2.5-coder:7b`. For `azure_openai`, the canonical model name (used in audit logs); the routing is by deployment, not by this value. |
| `SBOMHUB_LLM_API_KEY` | (empty) | Canonical provider API key. Provider-native aliases below are checked as fall-back. |
| `OPENAI_API_KEY` | (empty) | Used if `provider=openai` and the canonical key is unset. |
| `ANTHROPIC_API_KEY` | (empty) | Used if `provider=anthropic` and the canonical key is unset. |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | (empty) | Used if `provider=gemini` and the canonical key is unset. |
| `AZURE_OPENAI_API_KEY` | (empty) | Used if `provider=azure_openai` and the canonical key is unset. NOT aliased to `OPENAI_API_KEY` (mixing them would silently send Azure traffic with an OpenAI.com key, or vice versa). |
| `OLLAMA_HOST` | (empty) | Required if `provider=ollama` (e.g. `http://localhost:11434`). |
| `SBOMHUB_LLM_OPENAI_EMBEDDING_MODEL` | `text-embedding-3-small` | OpenAI embedding model for `Embed` / future reachability search. Known dimensions: `text-embedding-3-small` / `text-embedding-ada-002` = 1536, `text-embedding-3-large` = 3072. |
| `SBOMHUB_LLM_GEMINI_EMBEDDING_MODEL` | `gemini-embedding-2` | Gemini embedding model. `gemini-embedding-2` is the stable 2026 model; `gemini-embedding-001` and legacy `text-embedding-004` can be selected explicitly. Default dimensions = 3072 for `gemini-embedding-*`. |
| `SBOMHUB_LLM_OLLAMA_EMBEDDING_MODEL` | `nomic-embed-text` | Ollama embedding model used with `/api/embed`. Common dimensions: `nomic-embed-text` = 768, `mxbai-embed-large` / `bge-m3` = 1024. |

> For manufacturing self-host setups that cannot send code or SBOMs to external APIs, Ollama (or any OpenAI-compatible local endpoint) is the recommended choice. Azure OpenAI is the recommended choice for operators who already have a Microsoft procurement contract.

#### Azure OpenAI configuration

Selecting `SBOMHUB_LLM_PROVIDER=azure_openai` additionally requires the deployment-specific settings below. Each row lists the canonical SBOMHub env name plus any provider-native aliases that are checked as fall-back, in precedence order (canonical first; the first non-empty value wins).

| Variable (canonical → aliases) | Default | Description |
|-------------------------------|---------|-------------|
| `SBOMHUB_LLM_AZURE_ENDPOINT` → `AZURE_OPENAI_ENDPOINT` | (empty) | Azure resource endpoint URL, e.g. `https://my-resource.openai.azure.com`. |
| `SBOMHUB_LLM_AZURE_DEPLOYMENT` → `AZURE_OPENAI_DEPLOYMENT` → `AZURE_OPENAI_DEPLOYMENT_NAME` → `AZURE_OPENAI_CHAT_DEPLOYMENT_NAME` | (empty) | Chat deployment name as registered in Azure (URL path segment). Four canonical / alias forms are accepted because Microsoft documentation is not internally consistent — pick whichever your existing automation already exports. |
| `SBOMHUB_LLM_AZURE_API_VERSION` → `AZURE_OPENAI_API_VERSION` | `2024-10-21` | Azure OpenAI `api-version` query parameter. Defaults to the current GA stable channel; override only if your deployment is pinned to a specific contract version. |

If any of `provider=azure_openai`, endpoint, deployment, or API key is missing, the provider is gracefully disabled (the rest of the product continues to work, AI features turn off).

##### Azure OpenAI embedding deployment (M5-3)

Azure routes embedding requests (`text-embedding-3-small` / `text-embedding-3-large` / `text-embedding-ada-002` / etc.) through their own deployment — a separate URL path segment from the chat deployment. The embedding deployment is **optional**: when unset, chat (Complete) still works and embedding (Embed) returns a "disabled" error per call.

| Variable (canonical → aliases) | Default | Description |
|-------------------------------|---------|-------------|
| `SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT` → `AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME` | (empty) | Embedding deployment name. When set, `Capabilities.SupportsEmbedding` flips to true; when unset, `Embed` returns `DisabledError`. |
| `SBOMHUB_LLM_AZURE_EMBEDDING_API_VERSION` | (chat `api-version`) | Optional override for the embedding `api-version` query parameter. Defaults to the chat `api-version` so a single Azure resource pinned to one api-version works without further env. |
| `SBOMHUB_LLM_AZURE_EMBEDDING_MODEL` | (sniffed from deployment) | Optional canonical embedding model name, used to populate `Capabilities.EmbeddingDimensions` (1536 for `text-embedding-3-small` / `text-embedding-ada-002`, 3072 for `text-embedding-3-large`). When unset, the deployment name is sniffed for a known family prefix; falls back to dimensions = 0 for business-named deployments. |

Request batching: a single `Embed` call accepts up to 2,048 inputs per HTTP request (the Azure documented hard cap); larger batches are chunked transparently into multiple sequential requests. A defense-in-depth safety cap rejects calls with more than 16,384 total inputs before any HTTP traffic is dispatched. Partial-failure semantics: if a mid-batch chunk fails, the entire `Embed` call returns an error and the completed chunks' vectors are discarded (the caller decides whether to retry the whole batch).

#### Non-Azure embedding providers (M5-7)

OpenAI, Gemini, and Ollama also implement `Embed`. Anthropic remains unsupported because Anthropic's official Claude Platform documentation still routes embeddings users to Voyage AI rather than a first-party Claude embeddings endpoint.

| Provider | Endpoint | Default embedding model | Dimensions | Batch behavior |
|----------|----------|-------------------------|------------|----------------|
| OpenAI | `POST https://api.openai.com/v1/embeddings` | `text-embedding-3-small` | 1536 | 2,048 inputs/request; 16,384 inputs/call safety cap; partial chunk failure discards all vectors. |
| Gemini | `POST .../models/{model}:embedContent` for one input, `:batchEmbedContents` for batches | `gemini-embedding-2` | 3072 | 100 inputs/request sbomhub cap; 16,384 inputs/call safety cap; partial chunk failure discards all vectors. |
| Ollama | `POST {OLLAMA_HOST}/api/embed` | `nomic-embed-text` | 768 | 2,048 inputs/request sbomhub cap; 16,384 inputs/call safety cap; partial chunk failure discards all vectors. |
| Anthropic | N/A | N/A | N/A | `Embed` returns `ErrNotImplemented`; use Voyage AI or another embedding provider separately. |

### Frontend Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | API URL for frontend |

## Configuration Files

### docker-compose.yml

Override settings using environment variables or a `.env` file:

```yaml
services:
  api:
    environment:
      - DATABASE_URL=postgres://user:pass@postgres:5432/sbomhub
      - REDIS_URL=redis://redis:6379
      - NVD_API_KEY=${NVD_API_KEY}
```

### .env File

Create a `.env` file in the project root:

```bash
# Core
DATABASE_URL=postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable
REDIS_URL=redis://localhost:6379
APP_ENV=production

# NVD
NVD_API_KEY=your-nvd-api-key

# AI features (BYOK). If unset, AI features are disabled.
# Configure exactly one of the providers below.
SBOMHUB_LLM_PROVIDER=openai          # openai | anthropic | gemini | azure_openai | ollama
SBOMHUB_LLM_MODEL=gpt-5
OPENAI_API_KEY=sk-...
SBOMHUB_LLM_OPENAI_EMBEDDING_MODEL=text-embedding-3-small       # optional; default

# Azure OpenAI example (managed via Microsoft procurement)
# SBOMHUB_LLM_PROVIDER=azure_openai
# SBOMHUB_LLM_MODEL=gpt-4o                                      # canonical model name (audit/Capabilities)
# SBOMHUB_LLM_AZURE_ENDPOINT=https://my-resource.openai.azure.com
# SBOMHUB_LLM_AZURE_DEPLOYMENT=my-chat-deployment
# SBOMHUB_LLM_AZURE_API_VERSION=2024-10-21                      # optional; defaults to the GA stable channel
# AZURE_OPENAI_API_KEY=...                                       # or SBOMHUB_LLM_API_KEY
# Optional: embedding deployment for reachability / vector search (M5-3)
# SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT=text-embedding-3-small-prod
# SBOMHUB_LLM_AZURE_EMBEDDING_MODEL=text-embedding-3-small      # optional canonical model name (Capabilities.EmbeddingDimensions)
# SBOMHUB_LLM_AZURE_EMBEDDING_API_VERSION=                      # optional; falls back to chat api-version

# Local LLM example (no code/SBOM leaves your network)
# SBOMHUB_LLM_PROVIDER=ollama
# SBOMHUB_LLM_MODEL=qwen2.5-coder:7b
# SBOMHUB_LLM_OLLAMA_EMBEDDING_MODEL=nomic-embed-text
# OLLAMA_HOST=http://localhost:11434
```

## Deployment Mode

Only self-host (Docker Compose) is supported. The SaaS instance at `sbomhub.app` was sunset in 2026-06.

- User authentication is handled by API keys (and a simple in-product account flow planned)
- Multi-tenancy is enforced via PostgreSQL Row-Level Security
- AI features are enabled / disabled gracefully via BYOK env vars

```bash
# Minimal configuration for self-host
export DATABASE_URL="postgres://..."
export REDIS_URL="redis://..."
docker compose up -d
```

## Database Configuration

### PostgreSQL

Recommended settings for production:

```sql
-- Connection pooling
max_connections = 100
shared_buffers = 256MB

-- Performance
effective_cache_size = 1GB
maintenance_work_mem = 128MB
```

### Redis

Recommended settings:

```
maxmemory 256mb
maxmemory-policy allkeys-lru
```

## Security Recommendations

### Production Checklist

- [ ] Use strong database passwords
- [ ] Enable SSL for database connections (`sslmode=require`)
- [ ] Configure HTTPS with valid certificates
- [ ] Set `APP_ENV=production`
- [ ] Restrict database access to application servers
- [ ] Regular backup of PostgreSQL data
- [ ] Monitor logs for security issues

### Secrets Management

For production deployments, consider using:

- Docker Secrets
- Kubernetes Secrets
- HashiCorp Vault
- AWS Secrets Manager
- Environment-specific CI/CD variables
