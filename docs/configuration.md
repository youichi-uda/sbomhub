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
| `APP_ENV` | (none — required) | Environment: `development`, `staging`, `production`. **No default.** The server refuses to start when it is unset or is not one of those three values (M48). Every startup guard downgrades itself to a warning only under `development`, so an unset value used to select the weakest posture silently. The legacy name `ENVIRONMENT` is still read as a fallback when `APP_ENV` is unset (M0 Trust Rescue, codex-r18); the value it yields is validated the same way. |
| `ENCRYPTION_KEY` | (none — required unless `APP_ENV=development`) | AES-256 key for secrets stored in the database (BYOK LLM API keys, issue-tracker tokens, diff-webhook signing secrets). Must be at least 32 bytes and must not be a known placeholder value; the server refuses to start otherwise, and downgrades that refusal to a warning only under `APP_ENV=development`. Generate with `openssl rand -base64 32`. Rotation runbook: [`encryption-key-rotation.md`](./encryption-key-rotation.md). |

### Authentication and Startup Guards

`SBOMHUB_AUTH_MODE` is a required declaration of which authentication mode this deployment intends; `SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS` is an opt-in that weakens webhook signature verification in development. Declaring `anonymous` is an acknowledgement, not a mitigation: it records that the operator meant to run without user authentication, it does not make the deployment safer.

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOMHUB_AUTH_MODE` | (none — required) | `clerk` or `anonymous`. Declares the deployment's authentication mode; there is no default, and nothing is inferred from whether `CLERK_SECRET_KEY` arrived. `clerk`: users authenticate through Clerk. `anonymous`: the self-host posture, in which the Clerk-fronted API route groups serve requests as Owner of the default tenant with no credential of any kind (see the Deployment Mode section below). The server refuses to start when the declaration is unset (in every environment, `development` included), is not one of the two values, says `clerk` while `CLERK_SECRET_KEY` is empty, says `anonymous` while `CLERK_SECRET_KEY` is set, or says `anonymous` while a SaaS-only variable (`CLERK_WEBHOOK_SECRET`, any `LEMONSQUEEZY_*`) is set — the half-configured case where the Clerk key specifically is the piece that went missing. `docker compose` also fails at variable substitution when it is unset, before the container starts. |
| `SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS` | `false` | Pre-existing (M47). Lets the Clerk / Lemon Squeezy webhook *receivers* accept deliveries that carry no signature when no signing secret is configured. Honoured only when `APP_ENV=development`; set under any other value it is ignored, and in SaaS mode with `APP_ENV=production` the server refuses to start. |

Why a required declaration rather than an inferred mode: a Clerk deployment whose secret store injects nothing at all is byte-for-byte identical to a self-hosted one — no Clerk key, no webhook secret, no billing key — so there is nothing left to contradict, and any durable "anonymous is fine" artefact from an earlier phase would authorise serving with no authentication. Refusing such an artefact only when a Clerk key is present does not close that, because it says nothing about a first boot, a crash-loop, or a rollout where the key never arrived. A declaration lives in the deployment manifest rather than the secret store, so it survives the injection failure and turns it into a refusal to boot. Staleness then fails in the safe direction: a stale `clerk` is a boot failure, and no state a Clerk deployment can carry permits anonymous mode. Keep the declaration outside the secret store for that reason. The boolean `SBOMHUB_ALLOW_ANONYMOUS_AUTH` used by intermediate drafts of this guard was removed rather than kept as an alias; setting it is itself refused at startup, with a message pointing at `SBOMHUB_AUTH_MODE=anonymous`.

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

### Outbound Egress Policy (Tenant-Configured Destinations)

Four settings screens let a tenant administrator name a URL the server then
connects to: the issue tracker base URL, the Slack / Discord notification
webhooks, the SBOM diff webhook, and the per-tenant Azure OpenAI endpoint. Those
URLs are untrusted input, so internal destinations are refused by default.

Destinations **you** configure — the `SBOMHUB_*_URL` feed mirrors, the Ollama
base URL (`SBOMHUB_LLM_OLLAMA_URL` / `OLLAMA_HOST`, default
`http://localhost:11434`), the billing provider API — are not affected.

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOMHUB_EGRESS_ALLOW_PRIVATE` | `false` | Permit RFC1918 / loopback / CGNAT / IPv6 unique-local destinations for the four purposes above. |
| `SBOMHUB_EGRESS_ALLOWED_INTERNAL` | (empty) | Narrow alternative: comma- or space-separated hostnames, IP addresses and CIDRs whose internal destinations are permitted. A hostname also matches its subdomains. A malformed entry refuses startup. |
| `SBOMHUB_EGRESS_ALLOW_PROXY` | `false` | Honour `HTTP_PROXY` / `HTTPS_PROXY` for the four purposes above. Off by default: with a proxy in the path only the proxy's address is inspected, and the proxy chooses the real destination. Turning it on delegates the destination policy to the proxy. |
| `SBOMHUB_EGRESS_NAT64_PREFIXES` | (empty) | RFC 6052 NAT64 translation prefixes this network uses, when not the well-known `64:ff9b::/96`. Addresses reached through a declared prefix are judged by the IPv4 address they embed. A bad value refuses startup. |

Cloud instance metadata (`169.254.169.254` and the rest of link-local, Azure's
`168.63.129.16`, and the IPv6 tunnel forms that embed them) is refused even when
these are set. See [docs/security/egress.md](./security/egress.md) for the full
policy and its documented limits, and [UPGRADE.md §2c](./UPGRADE.md) for the
migration path if your tenants point at internal services.

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

# Required unless APP_ENV=development. Generate with: openssl rand -base64 32
ENCRYPTION_KEY=

# Declares this deployment's authentication mode: anonymous (self-host, which
# has no user authentication — see "Deployment Mode") or clerk. Required in
# every environment, development included; the server refuses to start without
# it, and docker compose fails before the container starts.
SBOMHUB_AUTH_MODE=anonymous

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

**Self-host has no user authentication.** Self-hosted mode is selected by `CLERK_SECRET_KEY` being empty, which is the only configuration the OSS distribution uses. In that mode `handleSelfHostedAuth` in `internal/middleware/auth.go` reads no header and checks no credential: it sets the request role to Owner on the default tenant. That is the behaviour of the Clerk-fronted route groups — everything behind the `Auth` / `MultiAuth` middleware, which is where projects, SBOMs, VEX, settings and API-key issuance live. `/api/v1/cli/*` and `/api/v1/mcp/*` authenticate by API key and still require one; `/api/v1/health` and `/api/v1/public/:token` are anonymous by design in both modes. Measured against a real database on 2026-07-29, with no `Authorization` header at all, `POST /api/v1/projects` returned 201, `GET /api/v1/me` returned `role=owner plan=enterprise`, and `POST /api/v1/apikeys` — an admin-gated route — returned 201 with a live API key in the response body. That minted key kept working against `/api/v1/cli/*` and `/api/v1/mcp/*` after `CLERK_SECRET_KEY` was later set and the server restarted in SaaS mode (verified: HTTP 200 on both), so supplying the variable afterwards does not revoke what was issued while it was absent.

The control is therefore network reachability, and nothing else: anyone who can reach the API port can take Owner access to all data in the deployment through those route groups. Put the API behind a VPN, a private subnet, or an authenticating reverse proxy before it holds real data — see [`security/self-host-deployment.md`](./security/self-host-deployment.md) §7 (firewall / network segmentation).

API keys (`POST /api/v1/apikeys`, used by the CLI, GitHub Actions and the MCP server) are an *additional* way for machine clients to authenticate. They are not an access boundary for a self-hosted deployment, because minting one requires no credential in the first place.

- Authentication: none on the Clerk-fronted route groups in self-hosted mode, as above. `SBOMHUB_AUTH_MODE=anonymous` is required to declare that this is intended, in every environment including `development`; the server refuses to start without it.
- Multi-tenancy is enforced via PostgreSQL Row-Level Security, provided `DATABASE_URL` names a `NOSUPERUSER NOBYPASSRLS` role. It separates tenants from each other; it does not authenticate the caller.
- AI features are enabled / disabled gracefully via BYOK env vars

```bash
# Minimal configuration for self-host.
# The first three are startup requirements, in every environment: the server
# refuses to boot without APP_ENV, ENCRYPTION_KEY or SBOMHUB_AUTH_MODE.
export APP_ENV=production
export ENCRYPTION_KEY="$(openssl rand -base64 32)"   # store this; it decrypts existing rows
export SBOMHUB_AUTH_MODE=anonymous                   # declares: no user authentication (see above)
export DATABASE_URL="postgres://..."                 # use a NOSUPERUSER NOBYPASSRLS role
export REDIS_URL="redis://..."
docker compose up -d
```

`./install.sh` generates a `.env` containing these values (random `ENCRYPTION_KEY`, database roles) if you would rather not assemble them by hand.

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
- [ ] Set `APP_ENV=production` (the server refuses to start when it is unset or misspelled)
- [ ] Set a real `ENCRYPTION_KEY` (`openssl rand -base64 32`), kept outside the repository
- [ ] Point `DATABASE_URL` at a `NOSUPERUSER NOBYPASSRLS` role, so Row-Level Security is enforced against the application connection
- [ ] Self-host: declare `SBOMHUB_AUTH_MODE=anonymous` (required in every environment, not only production), and put a network boundary (VPN, private subnet, or authenticating reverse proxy) in front of the API — the declaration records that the Clerk-fronted routes have no authentication, it does not add any
- [ ] SaaS / Clerk: declare `SBOMHUB_AUTH_MODE=clerk`, and keep that line in the deployment manifest rather than the secret store, so a total failure of secret injection is refused at boot instead of starting unauthenticated
- [ ] Leave `SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS` unset
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
