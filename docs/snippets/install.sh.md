# Snippet: `install.sh` bootstrap

<!-- check-snippets:signature: curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/install.sh | sh -->

> **Canonical source.** This file is the single source of truth for the
> SBOMHub one-line bootstrap. Other docs (README, `docs/installation*.md`)
> link here instead of duplicating the command.

## One-line install (planned)

```bash
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/install.sh | sh
```

The `install.sh` script will, when invoked with `--start`:

1. Download `docker-compose.yml` and `.env.example` to the current directory
   if they are not already present.
2. Generate `ENCRYPTION_KEY`, `MIGRATOR_PASSWORD`, `APP_PASSWORD` and write a
   secure `.env` (if one does not exist).
3. `docker compose up -d --wait postgres` so postgres reaches a healthy
   state before the rest of the stack tries to connect.
4. Create the `sbomhub_app` / `sbomhub_migrator` roles inside the running
   postgres container via `docker compose exec ... psql` (idempotent;
   re-runs are safe).
5. `docker compose up -d` to start `api` / `web` / `redis`, then print the
   dashboard URL.

> The pipe-to-`sh` one-liner above lands in a follow-up milestone (#6).
> Until then, the closest equivalent is the two-command manual flow below.

## Manual equivalent (curl-only, no `git clone`)

```bash
# 1. Download install.sh and docker-compose.yml (no git clone required).
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/install.sh \
  -o install.sh && chmod +x install.sh
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker-compose.yml \
  -o docker-compose.yml

# 2. Run the one-shot installer. This:
#    - generates a .env with a random ENCRYPTION_KEY / MIGRATOR_PASSWORD / APP_PASSWORD,
#    - starts postgres and waits for healthy,
#    - creates the sbomhub_app / sbomhub_migrator roles (codex-r8: previously
#      bind-mounted into postgres, now applied via `docker compose exec ... psql`
#      so the curl-only path no longer needs the apps/api/cmd/migrate/init.sh
#      host file),
#    - brings up api / web / redis.
./install.sh --start

# 3. Open the dashboard.
#    open http://localhost:3000        # macOS
#    xdg-open http://localhost:3000    # Linux
```

If you prefer to drive the stack manually instead of letting `install.sh` run
`docker compose`, split it into:

```bash
./install.sh                              # just generate .env
docker compose up -d --wait postgres      # start postgres first
./install.sh --bootstrap-roles            # create sbomhub_app / sbomhub_migrator
docker compose up -d                      # start api / web / redis
```

## Verifying the install

```bash
# API health (expects 200 OK)
curl -fsS http://localhost:8080/api/v1/health

# Or, once the CLI is installed:
sbomhub doctor
```

See [`docs/snippets/cli-quickstart.md`](./cli-quickstart.md) for the next step
(creating an API key and uploading your first SBOM).
