# Snippet: `install.sh` bootstrap

<!-- check-snippets:signature: curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/install.sh | sh -->

> **Canonical source.** This file is the single source of truth for the
> SBOMHub one-line bootstrap. Other docs (README, `docs/installation*.md`)
> link here instead of duplicating the command.

## One-line install (planned)

```bash
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/install.sh | sh
```

The `install.sh` script will:

1. Download `docker-compose.yml` to the current directory.
2. Generate an `ENCRYPTION_KEY` and write a minimal `.env` (if one does not exist).
3. Run `docker compose up -d` and print the dashboard URL.

> `install.sh` ships in a follow-up milestone (#6). Until then, use the manual
> equivalent below — both end at the same state.

## Manual equivalent

```bash
# 1. Download docker-compose.yml (no git clone required).
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker-compose.yml \
  -o docker-compose.yml

# 2. Generate an encryption key and write .env.
#    The Go server reads ENCRYPTION_KEY (no SBOMHUB_ prefix). docker compose
#    refuses to start if it is missing or set to the placeholder value.
cat > .env <<EOF
ENCRYPTION_KEY=$(openssl rand -base64 32)
EOF

# 3. Start the stack.
docker compose up -d

# 4. Open the dashboard.
#    open http://localhost:3000   # macOS
#    xdg-open http://localhost:3000   # Linux
```

## Verifying the install

```bash
# API health (expects 200 OK)
curl -fsS http://localhost:8080/healthz

# Or, once the CLI is installed:
sbomhub doctor
```

See [`docs/snippets/cli-quickstart.md`](./cli-quickstart.md) for the next step
(creating an API key and uploading your first SBOM).
