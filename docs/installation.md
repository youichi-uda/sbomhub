# Installation Guide

This guide covers different ways to install and run SBOMHub.

## Quick Start with Docker Compose

The fastest way to get started:

```bash
# Download docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker-compose.yml -o docker-compose.yml

# Start all services
docker compose up -d
```

Open http://localhost:3000 in your browser.

## Docker Compose (Full Installation)

### Prerequisites

- Docker 20.10+
- Docker Compose v2

### Steps

1. Clone the repository:

```bash
git clone https://github.com/youichi-uda/sbomhub.git
cd sbomhub
```

2. (Optional) Create `.env` file for configuration:

```bash
cp .env.example .env
# Edit .env with your settings
```

3. Start the services:

```bash
docker compose up -d
```

4. Access the application at http://localhost:3000

### Docker Services

| Service | Port | Description |
|---------|------|-------------|
| web | 3000 | Next.js frontend |
| api | 8080 | Go backend API |
| postgres | 5432 | PostgreSQL database |
| redis | 6379 | Redis cache |

## From Source

### Prerequisites

- Go 1.22+
- Node.js 20+
- pnpm 8+
- PostgreSQL 15+
- Redis 7+

### Database Setup

1. Start PostgreSQL and Redis (using Docker):

```bash
docker compose -f docker/docker-compose.yml up -d postgres redis
```

Or install natively and configure connection strings.

2. Create database:

```sql
CREATE DATABASE sbomhub;
CREATE USER sbomhub WITH PASSWORD 'sbomhub';
GRANT ALL PRIVILEGES ON DATABASE sbomhub TO sbomhub;
```

### Backend Setup

```bash
cd apps/api

# Install dependencies
go mod download

# Run database migrations
go run ./cmd/migrate up

# Start the server
go run ./cmd/server
```

The API will be available at http://localhost:8080

### Frontend Setup

```bash
cd apps/web

# Install dependencies
pnpm install

# Start development server
pnpm dev
```

The web interface will be available at http://localhost:3000

## Production Deployment

### Using Docker

Build production images:

```bash
# Build images
docker compose build

# Start with production settings
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Manual Deployment

#### Backend

```bash
cd apps/api

# Build binary
go build -o sbomhub-api ./cmd/server

# Run with production settings
export DATABASE_URL="postgres://user:pass@localhost:5432/sbomhub?sslmode=require"
export REDIS_URL="redis://localhost:6379"
export ENVIRONMENT="production"

./sbomhub-api
```

#### Frontend

```bash
cd apps/web

# Build production bundle
pnpm build

# Start production server
pnpm start
```

### Reverse Proxy (Nginx)

Example Nginx configuration:

```nginx
upstream sbomhub-web {
    server 127.0.0.1:3000;
}

upstream sbomhub-api {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name sbomhub.example.com;

    ssl_certificate /etc/ssl/certs/sbomhub.crt;
    ssl_certificate_key /etc/ssl/private/sbomhub.key;

    location / {
        proxy_pass http://sbomhub-web;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location /api/ {
        proxy_pass http://sbomhub-api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Kubernetes

See [DEPLOYMENT.md](./DEPLOYMENT.md) for Kubernetes deployment instructions.

## Updating

### Docker Compose

```bash
# Pull latest images
docker compose pull

# Restart with new images
docker compose up -d

# Run migrations if needed
docker compose exec api /app/sbomhub-api migrate up
```

### From Source

```bash
git pull origin main

# Backend
cd apps/api
go mod download
go run ./cmd/migrate up
# Restart the server

# Frontend
cd apps/web
pnpm install
pnpm build
# Restart the server
```

## Troubleshooting

### Database Connection Issues

Check PostgreSQL is running:

```bash
docker compose ps postgres
```

Verify connection string:

```bash
psql $DATABASE_URL -c "SELECT 1"
```

### Port Already in Use

Change ports in docker-compose.yml or .env:

```yaml
services:
  web:
    ports:
      - "3001:3000"  # Change to 3001
```

### Logs

View logs for troubleshooting:

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f api
```
