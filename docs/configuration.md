# Configuration

SBOMHub can be configured through environment variables.

## Environment Variables

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | API server port |
| `DATABASE_URL` | `postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable` | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `BASE_URL` | `http://localhost:3000` | Base URL for the web application |
| `ENVIRONMENT` | `development` | Environment: `development`, `staging`, `production` |

### NVD Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | (empty) | NVD API key for higher rate limits. Get one at https://nvd.nist.gov/developers/request-an-api-key |

### Authentication (SaaS Mode)

| Variable | Default | Description |
|----------|---------|-------------|
| `CLERK_SECRET_KEY` | (empty) | Clerk secret key for authentication |
| `CLERK_WEBHOOK_SECRET` | (empty) | Clerk webhook signing secret |

> When `CLERK_SECRET_KEY` is set, SBOMHub operates in SaaS mode with user authentication.

### Billing (SaaS Mode)

| Variable | Default | Description |
|----------|---------|-------------|
| `LEMONSQUEEZY_API_KEY` | (empty) | Lemon Squeezy API key |
| `LEMONSQUEEZY_WEBHOOK_SECRET` | (empty) | Lemon Squeezy webhook signing secret |
| `LEMONSQUEEZY_STORE_ID` | (empty) | Lemon Squeezy store ID |
| `LEMONSQUEEZY_STARTER_VARIANT_ID` | (empty) | Product variant ID for Starter plan |
| `LEMONSQUEEZY_PRO_VARIANT_ID` | (empty) | Product variant ID for Pro plan |
| `LEMONSQUEEZY_TEAM_VARIANT_ID` | (empty) | Product variant ID for Team plan |

### Frontend Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | API URL for frontend |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | (empty) | Clerk publishable key |

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
ENVIRONMENT=production

# NVD
NVD_API_KEY=your-nvd-api-key

# Clerk (SaaS mode only)
CLERK_SECRET_KEY=sk_live_xxxxx
CLERK_WEBHOOK_SECRET=whsec_xxxxx
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_xxxxx

# Lemon Squeezy (SaaS mode only)
LEMONSQUEEZY_API_KEY=xxxxx
LEMONSQUEEZY_WEBHOOK_SECRET=xxxxx
LEMONSQUEEZY_STORE_ID=xxxxx
```

## Deployment Modes

### Self-Hosted Mode

Default mode when no authentication is configured:

- No user authentication required
- Single-tenant operation
- All features available without subscription

```bash
# Minimal configuration for self-hosted
export DATABASE_URL="postgres://..."
export REDIS_URL="redis://..."
docker compose up -d
```

### SaaS Mode

Enabled when `CLERK_SECRET_KEY` is set:

- User authentication via Clerk
- Multi-tenant with row-level security
- Subscription-based feature access
- Billing via Lemon Squeezy

```bash
# SaaS mode configuration
export CLERK_SECRET_KEY="sk_live_xxxxx"
export LEMONSQUEEZY_API_KEY="xxxxx"
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
- [ ] Set `ENVIRONMENT=production`
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
