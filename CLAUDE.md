# CLAUDE.md - SBOMHub Development Guidelines

## Project Overview

SBOMHub is an open-source SBOM management dashboard for the Japanese market.

- SBOM management (not generation)
- Import from Syft, cdxgen, Trivy
- Vulnerability correlation with NVD/JVN
- Japanese UI + METI guidelines compliance

## Tech Stack

- Backend: Go 1.22+ (Echo v4)
- Frontend: Next.js 16 (App Router) + React 19 + TypeScript 5.7
- UI: shadcn/ui + Tailwind CSS 3.4
- Database: PostgreSQL 15+
- Cache/Queue: Redis 7+
- License: AGPL-3.0

## Repository Structure (Monorepo)

```
sbomhub/
├── apps/
│   ├── web/          # Next.js frontend
│   └── api/          # Go backend
├── packages/
│   ├── db/           # DB schema and migrations
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

### Frontend

- Use App Router (not Pages Router)
- Server Components by default
- Client Components only when needed
- Internationalization: next-intl (ja/en)
- Form handling: react-hook-form + zod

### Database

- Migrations: golang-migrate or goose
- Naming: snake_case for tables/columns
- Always use transactions for multi-table ops

### Code Style

- Go: gofmt, golangci-lint
- TypeScript: ESLint, Prettier
- Commits: Conventional Commits format
## MVP Scope (Phase 1)

Must have:
- CycloneDX JSON import
- SPDX JSON import
- Project CRUD
- Component list view
- NVD vulnerability matching (daily batch)
- Vulnerability list (Critical/High/Medium/Low)
- Japanese UI
- Docker Compose deployment

Not in MVP:
- JVN integration
- VEX support
- License policies
- GitHub Actions integration
- LDAP/OIDC auth
- Multi-tenancy

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

## API Endpoints (MVP)

```
POST   /api/v1/projects
GET    /api/v1/projects
GET    /api/v1/projects/:id
DELETE /api/v1/projects/:id

POST   /api/v1/projects/:id/sbom     # Upload SBOM
GET    /api/v1/projects/:id/sbom     # Get latest SBOM

GET    /api/v1/projects/:id/components
GET    /api/v1/projects/:id/vulnerabilities
```

## SaaS Architecture

Infrastructure:
- Hosting: Railway (auto-deploy, auto-scale)
- Database: Railway PostgreSQL (managed)
- Cache: Railway Redis (managed)

Multi-tenancy:
- Row-Level with tenant_id column
- PostgreSQL RLS for DB-level protection

Authentication:
- Clerk (Next.js integration)
- Free tier: 10,000 MAU

Billing:
- Lemon Squeezy (Merchant of Record)
- Handles tax/VAT automatically

Pricing Tiers:
- Self-hosted: Free (OSS)
- Cloud Starter: ¥2,500/mo (5 projects, 3 users)
- Cloud Pro: ¥8,000/mo (unlimited projects, 10 users)
- Enterprise: Custom pricing
