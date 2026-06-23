# CLAUDE.md - SBOMHub Development Guidelines

## Project Overview

SBOMHub is an open-source (AGPL-3.0) **AI compliance evidence layer** built on top of Dependency-Track / Syft / Trivy.

The product has pivoted away from positioning itself as "a Japanese Dependency-Track / general-purpose SBOM management dashboard." Its new wedge is the **EU Cyber Resilience Act (CRA) vulnerability reporting deadline of 11 September 2026**, with a primary ICP of Japanese SMB manufacturers shipping IoT / embedded / digital products to the EU.

Reframed in one line:

> Dependency-Track finds CVEs. SBOMHub turns them into submittable VEX statements, CRA reports, and audit trails — AI drafts them, humans approve them.

Strategy doc: `sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md` (internal).

### Core principles

- AI drafts only. Humans approve. No auto-confirmed `not_affected`, no auto-submitted CRA reports.
- Self-host first. SaaS is sunset (see below). The CLI + Docker Compose is the supported path.
- AGPL-3.0 OSS feel preserved. We do not gate core compliance features behind a paid tier.
- Existing shipped features (SBOM import, NVD/JVN correlation, EPSS, SSVC, KEV, manual VEX, license policies, METI self-assessment, audit log, MCP read access, multi-tenant) are kept and built on, not removed.

## Tech Stack

- Backend: Go 1.22+ (Echo v4)
- Frontend: Next.js 16 (App Router) + React 19 + TypeScript 5.7
- UI: shadcn/ui + Tailwind CSS 3.4
- Database: PostgreSQL 15+ (with Row-Level Security)
- Cache/Queue: Redis 7+
- LLM (optional, BYOK): OpenAI / Anthropic / Google Gemini / Ollama
- License: AGPL-3.0

## Repository Structure (Monorepo)

```
sbomhub/
├── apps/
│   ├── web/          # Next.js frontend
│   └── api/          # Go backend
├── packages/
│   ├── db/           # DB schema and migrations
│   ├── mcp-server/   # MCP Server (Claude/Cursor read access)
│   └── types/        # Shared TypeScript types
├── docker/
│   └── docker-compose.yml
├── docs/
└── .github/workflows/
```

## Development Guidelines

### Go Backend

- Use standard library where possible
- Error handling: wrap errors with context
- Logging: use slog (structured logging)
- API: RESTful, JSON responses
- SBOM parsing: use CycloneDX/SPDX Go libraries
- LLM access goes through the provider-agnostic interface (see "LLM Provider Policy")

### Frontend

- Use App Router (not Pages Router)
- Server Components by default
- Client Components only when needed
- Internationalization: next-intl (ja/en)
- Form handling: react-hook-form + zod
- AI-drafted artefacts (VEX, CRA reports, METI prefill) always render confidence + evidence + "Approve / Edit / Reject" controls

### Database

- Migrations: golang-migrate or goose
- Naming: snake_case for tables/columns
- Always use transactions for multi-table ops
- All tenant-scoped tables must carry `tenant_id` and use `SET LOCAL app.current_tenant_id` per request
- App runtime role must be a non-superuser so RLS is actually enforced

### Code Style

- Go: gofmt, golangci-lint
- TypeScript: ESLint, Prettier
- Commits: Conventional Commits format

## MVP Scope

### Phase 1 (shipped)

- CycloneDX / SPDX JSON import
- Project CRUD
- Component list view
- NVD + JVN vulnerability matching
- Vulnerability list (Critical / High / Medium / Low)
- EPSS scoring
- SSVC decision framework
- KEV catalog sync
- VEX (manual authoring + CycloneDX export)
- License policies
- METI guideline self-assessment (manual)
- GitHub Actions / API key auth
- CLI (`sbomhub scan`, `sbomhub check`)
- MCP Server (read-only)
- Multi-tenancy with PostgreSQL RLS
- Audit log
- Japanese UI

### Phase 7 (active — strategy pivot)

Must have, by milestone (see `PRODUCT_REBOOT_PLAN.md` §13 for detail):

- **M0 — Trust Rescue + positioning lock-in**
  - RLS / tenant isolation fully enforced under non-superuser DB role
  - Default encryption key removed; first-boot key generation + production startup refusal without one
  - CLI / GitHub Actions / API contracts unified to a single source of truth, doc curls exercised in CI
  - `sbomhub doctor` for self-host health checks
  - README / LP / docs reflect new positioning (this is being done in M0)
- **M1 — AI VEX triage MVP**
  - `sbomhub triage` CLI
  - Advisory parsing → ecosystem reachability (Go and npm first) → LLM judgement → CycloneDX VEX draft
  - Confidence threshold; below threshold → `under_investigation`
  - Evidence (referenced code, advisory excerpt) persisted alongside every draft
  - Approve / Edit / Reject / Re-analyse UI
  - Audit log of AI drafts and human decisions
- **M2 — CRA report drafting**
  - 24h early warning / 72h detailed notification / final report templates
  - Japanese and English drafts
  - Bundled into the Compliance Evidence Pack alongside VEX
  - No auto-submission. 24h / 72h clock start is a human decision.
- **M3 — METI self-assessment prefill**
  - Auto-fill self-assessment items from CI configs, SBOM scan history, matching history
  - Per-item evidence + remediation suggestion
- **M4 — Local LLM / enterprise self-host polish**
  - LLM provider abstraction stabilised
  - Quality benchmark: managed vs local
  - Self-host security guide for manufacturers

Explicitly **not** in scope:

- New SBOM format support purely for parity with DT
- AI features beyond drafting (e.g. autonomous remediation)
- Auto-submission of CRA reports
- Generic dashboard cosmetics
- Product Hunt / HN launch prep
- Large-enterprise PSIRT-grade RBAC

## Common Commands

```bash
# Development
cd apps/web && pnpm dev
cd apps/api && go run ./cmd/server

# Database
docker compose up -d postgres redis
cd apps/api && go run ./cmd/migrate up

# Testing
cd apps/api && go test ./...
cd apps/web && pnpm test

# Linting
cd apps/api && golangci-lint run
cd apps/web && pnpm lint

# Build
docker compose build
```

## API Endpoints (current)

```
POST   /api/v1/projects
GET    /api/v1/projects
GET    /api/v1/projects/:id
DELETE /api/v1/projects/:id

POST   /api/v1/projects/:id/sbom     # Upload SBOM
GET    /api/v1/projects/:id/sbom     # Get latest SBOM

GET    /api/v1/projects/:id/components
GET    /api/v1/projects/:id/vulnerabilities
GET    /api/v1/projects/:id/vex
```

Phase 7 will add `/triage`, `/cra/drafts`, `/meti/assessment` endpoints; see `PRODUCT_REBOOT_PLAN.md`.

## SaaS Architecture

SaaS sunset (2026-06-23~) — see `SAAS_SUNSET.md`.

The hosted instance at https://sbomhub.app is closed to new signups during the pivot. Self-host (Docker Compose) + CLI is the only supported path. Reopening under the new positioning is a separate decision and will be announced through the repository.

When SaaS reopens, it will follow the LLM Provider Policy below: managed Gemini will be the default for paid tiers, BYOK remains available; OSS / self-host is BYOK only.

## LLM Provider Policy

This product has two distribution channels with different LLM policies.

### OSS / self-host — BYOK only

- **No bundled LLM keys.** SBOMHub OSS ships zero credentials.
- Operator configures one of: `openai`, `anthropic`, `gemini`, `ollama`.
- If no provider is configured, AI features are disabled and the rest of the product continues to work.
- Ollama (or any OpenAI-compatible local endpoint) is the recommended path for manufacturers who cannot send code to external APIs.

Env contract:

```
SBOMHUB_LLM_PROVIDER   # openai | anthropic | gemini | ollama
SBOMHUB_LLM_MODEL      # e.g. gpt-5, claude-opus-4-7, gemini-3.5-flash, qwen2.5-coder:7b
OPENAI_API_KEY         # required if provider=openai
ANTHROPIC_API_KEY      # required if provider=anthropic
GOOGLE_API_KEY         # required if provider=gemini
OLLAMA_HOST            # required if provider=ollama
```

### SaaS — managed Gemini default + BYOK option (when reopened)

- Default managed model: Gemini family (cost-optimised, multilingual including Japanese).
- BYOK accepted for teams already on OpenAI / Anthropic procurement.
- Spec lives in `sbomhub-internal/planning/LLM_PROVIDER_DESIGN.md` (internal).

### Implementation notes

- All LLM calls go through a single `internal/llm` package with a provider-agnostic interface (`Generate`, `Embed`, capability descriptor).
- Provider implementations are isolated under `internal/llm/openai`, `internal/llm/anthropic`, `internal/llm/gemini`, `internal/llm/ollama`. No business logic outside `internal/llm` may import a provider SDK directly.
- For library version selection follow the workspace rule: check the web for the latest stable version before pinning, do not rely on internal model knowledge.
- Per-draft persistence captures: provider, model, prompt hash, response hash, confidence, evidence pointers. This is required for the audit log.
- Output without evidence pointers must not be saved as a draft.
