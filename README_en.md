# SBOMHub

[![日本語](https://img.shields.io/badge/lang-日本語-red.svg)](./README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](./README_en.md)

![License](https://img.shields.io/badge/license-AGPL--3.0-blue)
![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8)
![Next.js](https://img.shields.io/badge/Next.js-16-black)
![Docker Pulls](https://img.shields.io/docker/pulls/y1uda/sbomhub-api)
![GitHub Stars](https://img.shields.io/github/stars/youichi-uda/sbomhub)

<p align="center">
  <img src="docs/images/dashboard.png" alt="SBOMHub Dashboard" width="800">
</p>

## What is SBOMHub?

SBOMHub is an open-source SBOM (Software Bill of Materials) management dashboard designed for the Japanese market. It helps you:

- **Import** SBOMs from Syft, cdxgen, Trivy, and more (CycloneDX/SPDX)
- **Track** vulnerabilities with NVD and JVN (Japan) integration
- **Prioritize** with EPSS exploit prediction scores
- **Manage** VEX statements for vulnerability triage
- **Support** METI guidelines (Japan) and EU CRA response
- **Enforce** license policies across your projects
- **Alert** your team via Slack/Discord/Email

## Features

| Feature | Description |
|---------|-------------|
| Multi-format SBOM | Import CycloneDX and SPDX JSON |
| Vulnerability Tracking | NVD + JVN integration for comprehensive coverage |
| EPSS Scoring | Prioritize by exploit probability |
| VEX Support | Document vulnerability applicability |
| License Policies | Enforce allowed/denied licenses |
| Compliance Support | METI guideline self-assessment |
| CI/CD Integration | GitHub Actions support with API keys |
| Japanese UI | Full Japanese language support |

## Quick Start

### SaaS Version (Recommended)

Try SBOMHub instantly without installation: **https://sbomhub.app**

- No setup required
- Free tier available
- Managed infrastructure with automatic updates

### Docker Compose (Self-hosted)

```bash
# Download and start (no clone needed)
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker-compose.yml -o docker-compose.yml
docker compose up -d
```

Or clone and run:

```bash
git clone https://github.com/youichi-uda/sbomhub.git
cd sbomhub
docker compose up -d
```

Open http://localhost:3000

### From Source

**Prerequisites:**
- Go 1.22+
- Node.js 20+ / pnpm
- PostgreSQL 15+
- Redis 7+

```bash
# Start database
docker compose -f docker/docker-compose.yml up -d postgres redis

# Backend
cd apps/api
go run ./cmd/server

# Frontend (new terminal)
cd apps/web
pnpm install
pnpm dev
```

## Screenshots

<details>
<summary>Dashboard</summary>
<img src="docs/images/dashboard.png" width="600">
</details>

<details>
<summary>Vulnerability List</summary>
<img src="docs/images/vulnerabilities.png" width="600">
</details>

<details>
<summary>Compliance Score</summary>
<img src="docs/images/compliance.png" width="600">
</details>

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   Next.js Web   │────▶│    Go API       │
│   (Port 3000)   │     │   (Port 8080)   │
└─────────────────┘     └────────┬────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
             ┌───────────┐ ┌───────────┐ ┌───────────┐
             │ PostgreSQL│ │   Redis   │ │ NVD / JVN │
             │  (Data)   │ │  (Cache)  │ │  (APIs)   │
             └───────────┘ └───────────┘ └───────────┘
```

## API Reference

See [API Documentation](./docs/api.md)

### Core Endpoints

```
POST   /api/v1/projects              # Create project
GET    /api/v1/projects              # List projects
GET    /api/v1/projects/:id          # Get project
DELETE /api/v1/projects/:id          # Delete project

POST   /api/v1/projects/:id/sbom     # Upload SBOM
GET    /api/v1/projects/:id/components
GET    /api/v1/projects/:id/vulnerabilities
GET    /api/v1/projects/:id/vex      # VEX statements
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Upload SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        run: syft . -o cyclonedx-json > sbom.json

      - name: Upload to SBOMHub
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            ${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.PROJECT_ID }}/sbom
```

## Documentation

- [Installation Guide](./docs/installation.md)
- [Configuration](./docs/configuration.md)
- [API Reference](./docs/api.md)
- [GitHub Actions Integration](./docs/github-actions.md)

## Roadmap

- [x] SBOM Import (CycloneDX/SPDX)
- [x] NVD/JVN Vulnerability Matching
- [x] EPSS Scoring
- [x] VEX Support
- [x] License Policies
- [x] Compliance Support (METI Guideline Self-Assessment)
- [x] CI/CD Integration (GitHub Actions)
- [x] Notifications (Slack/Discord)
- [x] Multi-tenancy (Row-Level Security)
- [x] Clerk Authentication Integration
- [x] Lemon Squeezy Billing Integration
- [x] SBOMHub Cloud (Managed SaaS)
- [ ] LDAP/OIDC Authentication (Self-hosted)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the [AGPL-3.0 License](./LICENSE).

| Use Case | Allowed | Notes |
|----------|---------|-------|
| Self-hosted (internal use) | ✅ | No source disclosure required |
| Self-hosted (with modifications) | ✅ | Modified source must be disclosed |
| Providing as SaaS to third parties | ⚠️ | Full source code must be disclosed under AGPL |
| Official SBOMHub Cloud | ✅ | Provided by the maintainers |

> **Note**: If you want to offer SBOMHub as a commercial SaaS without AGPL obligations, please contact us for a commercial license.

## Tech Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Backend | Go (Echo v4) | 1.22+ |
| Frontend | Next.js (App Router) | 16 |
| UI Framework | React | 19 |
| Language | TypeScript | 5.7 |
| UI Components | shadcn/ui | Latest |
| Styling | Tailwind CSS | 3.4 |
| Database | PostgreSQL | 15+ |
| Cache | Redis | 7+ |
| i18n | next-intl | Latest |
| Form Validation | react-hook-form + zod | Latest |

## Development

### Prerequisites

- Go 1.22+
- Node.js 20+ with pnpm
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (optional)

### Project Structure

```
sbomhub/
├── apps/
│   ├── web/          # Next.js frontend
│   └── api/          # Go backend
├── packages/
│   ├── db/           # DB schema and migrations
│   └── types/        # Shared TypeScript types
├── docker/           # Docker configurations
├── docs/             # Documentation
└── .github/workflows/  # CI/CD pipelines
```

### Common Commands

```bash
# Start development servers
cd apps/web && pnpm dev      # Frontend (http://localhost:3000)
cd apps/api && go run ./cmd/server  # Backend (http://localhost:8080)

# Database
docker compose up -d postgres redis  # Start DB
cd apps/api && go run ./cmd/migrate up  # Run migrations

# Testing
cd apps/api && go test ./...   # Backend tests
cd apps/web && pnpm test       # Frontend tests

# Linting
cd apps/api && golangci-lint run   # Go linting
cd apps/web && pnpm lint           # TypeScript linting

# Build
docker compose build           # Build all containers
```

### Code Style

- **Go**: gofmt, golangci-lint
- **TypeScript**: ESLint, Prettier
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/)

## Claude Code Integration

This project includes [Claude Code](https://claude.ai/code) skills for AI-assisted development.

### Installed Skills

| Category | Source | Description |
|----------|--------|-------------|
| Security | [Trail of Bits](https://github.com/trailofbits/skills) | Security audits, vulnerability detection, static analysis |
| Go Development | [Gopher AI](https://github.com/gopherguides/gopher-ai) | Go best practices, testing patterns |
| React/Next.js | [Vercel Agent Skills](https://github.com/vercel-labs/agent-skills) | Performance optimization (57+ rules) |
| Workflows | [Claude Code SDK](https://github.com/hgeldenhuys/claude-code-sdk) | CI/CD, testing, code review patterns |

### Key Skills for This Project

- **differential-review** - Security-focused PR review
- **go-best-practices** - Idiomatic Go patterns
- **react-best-practices** - React/Next.js optimization
- **ci-cd-integration** - Pipeline automation
- **monorepo-patterns** - Monorepo workflows

Skills are located in `.claude/skills/` and are automatically detected by Claude Code.

## Security

### Reporting Vulnerabilities

If you discover a security vulnerability, please report it via:

1. **GitHub Security Advisories**: [Report a vulnerability](https://github.com/youichi-uda/sbomhub/security/advisories/new)
2. **Email**: security@sbomhub.app (for sensitive issues)

Please do NOT report security vulnerabilities through public GitHub issues.

### Security Features

- Row-Level Security (RLS) for multi-tenancy
- API key authentication for CI/CD integration
- HTTPS enforcement in production
- Input validation with zod schemas
- SQL injection prevention with parameterized queries

## Acknowledgements

- [CycloneDX](https://cyclonedx.org/) - SBOM specification
- [SPDX](https://spdx.dev/) - SBOM specification
- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [JVN](https://jvn.jp/) - Japan Vulnerability Notes
- [FIRST EPSS](https://www.first.org/epss/) - Exploit Prediction Scoring System
- [Trail of Bits](https://github.com/trailofbits/skills) - Security skills for Claude Code
- [Vercel](https://github.com/vercel-labs/agent-skills) - React best practices
