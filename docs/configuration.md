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
| `SBOMHUB_LLM_PROVIDER` | (empty) | `openai` / `anthropic` / `gemini` / `ollama` |
| `SBOMHUB_LLM_MODEL` | (empty) | e.g. `gpt-5`, `claude-opus-4-7`, `gemini-3.5-flash`, `qwen2.5-coder:7b` |
| `OPENAI_API_KEY` | (empty) | Required if `provider=openai` |
| `ANTHROPIC_API_KEY` | (empty) | Required if `provider=anthropic` |
| `GOOGLE_API_KEY` | (empty) | Required if `provider=gemini` |
| `OLLAMA_HOST` | (empty) | Required if `provider=ollama` (e.g. `http://localhost:11434`) |

> For manufacturing self-host setups that cannot send code or SBOMs to external APIs, Ollama (or any OpenAI-compatible local endpoint) is the recommended choice.

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
SBOMHUB_LLM_PROVIDER=openai          # openai | anthropic | gemini | ollama
SBOMHUB_LLM_MODEL=gpt-5
OPENAI_API_KEY=sk-...

# Local LLM example (no code/SBOM leaves your network)
# SBOMHUB_LLM_PROVIDER=ollama
# SBOMHUB_LLM_MODEL=qwen2.5-coder:7b
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
