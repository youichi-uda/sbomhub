# Upgrade guide — M0 Trust Rescue

> Japanese readers: this guide is currently English-only. The Trust Rescue
> changes that motivate it are not localised in the migration code paths;
> commands are identical regardless of UI language. A `.ja.md` translation
> can follow once the self-host upgrade flow stabilises.

This guide covers upgrading a self-hosted SBOMHub deployment **from any v0.x
release shipped before M0 Trust Rescue to the current `main` / first M0 tag**.
M0 introduces several intentional breaking changes that require operator action
beyond `docker compose pull && docker compose up -d`.

If you are installing SBOMHub for the first time, follow the
[Quick start](../README.md#クイックスタート) (Japanese) /
[Quick start](../README_en.md#quick-start) (English) sections in the README
instead — they already incorporate every M0 change.

---

## 1. Who needs this guide

Read this guide if **all** of the following apply to you:

- You were running SBOMHub under `docker compose` (or an equivalent compose
  stack) before M0 — i.e. you have a populated `postgres_data` Docker
  volume on disk.
- Your existing `.env` does not yet contain `MIGRATOR_PASSWORD` /
  `APP_PASSWORD` / `ENCRYPTION_KEY`, or it relies on the bundled `changeme`
  default key.
- You intend to keep the existing database (sboms, projects, audit logs,
  API keys) rather than start over from a fresh volume.

If you do not have a pre-M0 volume, skip this guide and just follow the
README quick start.

---

## 2. Breaking changes summary

| Area | Pre-M0 behaviour | M0 behaviour | Notes |
|---|---|---|---|
| **DB roles** | App + migrations both ran as the `sbomhub` superuser of the DB. | Two distinct roles: `sbomhub_migrator` (DDL, CREATEDB + CREATEROLE, **NOBYPASSRLS**) and `sbomhub_app` (DML only, NOBYPASSRLS). | `docker-compose.yml` now wires the api container to the `_app` role and migrations to the `_migrator` role. Roles are created by `./install.sh --bootstrap-roles` (or by `./install.sh --start` on a fresh curl-only install), which runs the bootstrap SQL inside the running postgres container via `docker compose exec ... psql`. Both fresh installs and existing volumes use the same code path (codex-r8). |
| **`ENCRYPTION_KEY`** | Defaulted to `changeme` / `default` placeholder if unset. | No bundled default. The api refuses to boot unless `ENCRYPTION_KEY` is set, at least 32 bytes, and not one of the known placeholders (`changeme`, `default`, `test`, …). | `docker compose up` itself now errors out at variable-substitution time, before the api container is even started. |
| **SBOM upload API** | `POST /cli/upload` (multipart). | `POST /api/v1/projects/:id/sbom` with `Authorization: Bearer sbh_…` and raw JSON body. The legacy `/cli/upload` is deprecated and scheduled for removal on 2026-09-24. | Update any custom integrations against [docs/api.md](./api.md) / [docs/snippets/curl-upload.md](./snippets/curl-upload.md). |
| **`tenant_id` NOT NULL** | `sboms.tenant_id` / `components.tenant_id` were nullable (legacy rows from before migration 023 may have had NULL). | Migration **027** backfills any NULL `tenant_id` from the parent project / sbom and then promotes the column to `NOT NULL`. Truly orphaned rows abort the migration loudly. | See section 5 for remediation if 027 aborts on your DB. |
| **`api_keys` / `audit_logs` RLS** | Row-Level Security policies attempted to enforce tenant isolation directly in PostgreSQL. | Migrations **028** / **029** remove RLS from these two tables. Tenant isolation is enforced exclusively by the application layer (`internal/middleware/tenant.go`). | This is *not* a downgrade in safety — audit insert paths run before any tenant context is available, so RLS on those tables produced false negatives. The application path is now the single source of truth. |

---

## 3. Before you start

1. **Pin a maintenance window of ~15 minutes** of api downtime. Postgres
   keeps serving the existing data throughout; only the api / web
   containers cycle.
2. **Back up the database.** `pg_dump` from inside the running container is
   the lowest-risk option:
   ```bash
   docker compose exec -T postgres \
       pg_dump -U sbomhub -d sbomhub --format=custom \
       > sbomhub-preupgrade-$(date +%Y%m%d).dump
   ```
   Verify the file size is non-zero before continuing.
3. **Note your current `ENCRYPTION_KEY`** if any. Stored API tokens for
   issue-tracker integrations (Jira / GitHub) are encrypted with this key.
   If you regenerate it without rotating ciphertext you will lose those
   tokens (re-entry from the UI required). See
   [`docs/encryption-key-rotation.md`](./encryption-key-rotation.md) for the
   full re-encryption procedure if you need to rotate the key as part of
   this upgrade.

---

## 4. Upgrade procedure

### 4.1 Pull the new release

```bash
git pull --ff-only origin main
# or, if you only consume the published compose file:
#   curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker-compose.yml -o docker-compose.yml
```

Do **not** run `docker compose up -d` yet. The api will exit immediately if
the new `_app` / `_migrator` DB roles do not exist on your existing volume.

### 4.2 Bootstrap the new DB roles into the existing volume

The two new roles (`sbomhub_app`, `sbomhub_migrator`) live outside the
default `POSTGRES_USER` and must be created against the live database
explicitly. (Prior to codex-r8 a host-side bind mount of
`apps/api/cmd/migrate/init.sh` ran inside postgres on fresh volume init,
but that bind mount broke curl-only installs — the host file was simply
missing — so role creation now runs via `docker compose exec ... psql`
in every install path.)

`install.sh --bootstrap-roles` does this in one command. It reads
`MIGRATOR_PASSWORD` / `APP_PASSWORD` out of the **existing** `.env` (run
plain `./install.sh` first if those keys are absent), then pipes an
idempotent bootstrap SQL into `psql` inside the running postgres
container.

```bash
# 1. If your .env does not yet contain MIGRATOR_PASSWORD / APP_PASSWORD /
#    ENCRYPTION_KEY, generate them now without disturbing other settings:
./install.sh                # idempotent, only writes missing keys

# 2. Apply the new roles to the live postgres container:
./install.sh --bootstrap-roles
```

`--bootstrap-roles` requires the postgres service to already be running
(it uses `docker compose exec`). If it is not, start it on its own:

```bash
docker compose up -d postgres
./install.sh --bootstrap-roles
```

The script is idempotent. Re-running it after a successful bootstrap is a
safe no-op that re-asserts the password and the `NOBYPASSRLS` flag.

In addition to creating the roles, `--bootstrap-roles` walks the
`public` schema of the live database and re-owns every legacy
application object (tables, sequences, views, materialized views)
that is still held by the pre-M0 `sbomhub` role over to
`sbomhub_migrator`. This lets migrations 027 / 028 / 029 run
`ALTER TABLE ... SET NOT NULL` without tripping PostgreSQL's
owner-only check. On a fresh volume there are no matching objects so
the loop is a no-op. The script intentionally scopes the re-ownership
to `public` and never touches the database owner or `pg_catalog`
objects — using a blanket `REASSIGN OWNED BY sbomhub` would abort on
fresh `docker compose up` installs with "cannot reassign ownership of
objects owned by role sbomhub because they are required by the
database system".

### 4.3 Decide on `ENCRYPTION_KEY`

You have two choices:

- **Keep the existing key** — recommended unless you suspect compromise.
  Make sure `ENCRYPTION_KEY=<old value>` is present in `.env` exactly as it
  was. The `install.sh` invocations above will not overwrite an existing
  non-empty `ENCRYPTION_KEY`.
- **Rotate** — follow
  [`docs/encryption-key-rotation.md`](./encryption-key-rotation.md) *first*,
  then come back to step 4.4. Skipping the rotation runbook and just
  changing the value in `.env` will leave any encrypted issue-tracker
  tokens undecryptable.

If you ran `./install.sh --force` and want to preserve the old key, copy
it out of the `.env.bak.YYYYMMDD` file that `--force` wrote before
overwriting `.env`:

```bash
grep '^ENCRYPTION_KEY=' .env.bak.$(date +%Y%m%d) >> /tmp/keep.env
# then merge /tmp/keep.env back into the new .env by hand.
```

### 4.4 Bring the stack up

```bash
docker compose pull           # pull the new api / web / postgres images
docker compose up -d
```

The api container runs migrations 027 / 028 / 029 on startup, then begins
serving traffic. Watch for fatal startup messages:

```bash
docker compose logs -f --tail=200 api
```

A successful boot logs something like
`migrations applied; current version=029` followed by the usual
`echo` listener line. Any `tenant_id is still NULL` error from 027 means
you have orphan rows; see section 5.

### 4.5 Verify

```bash
# api health
curl -fsS http://localhost:8080/api/v1/health
#   {"status":"ok","mode":"production"}

# CLI doctor (run against the same host from a workstation; sbomhub-cli is
# a separate binary, not bundled in the api image)
sbomhub login --api-key <existing key> --url http://localhost:8080
sbomhub doctor
```

Then open the web UI at <http://localhost:3000>:

- Project list renders the existing projects.
- Each project shows its SBOMs and component / vulnerability counts.
- API keys page still lists the keys you had before.

If any of these are empty for a project that previously had data, **stop
and roll back** (section 6). The most likely cause is a partial bootstrap
that left rows with the wrong owner / GUC.

---

## 5. Known issues during the upgrade

### 5.1 Migration 027 aborts with `tenant_id is still NULL`

`027_sbom_tenant_id_not_null.up.sql` backfills `tenant_id` on `sboms` and
`components` from the parent project / sbom and then refuses to install the
`NOT NULL` constraint if any rows remain unmapped. This is intentional — a
silent `SET NOT NULL` failure mid-migration would leave the DB in an
ambiguous state.

Find the orphans:

```sql
-- sboms with no resolvable tenant
SELECT id, project_id, created_at
FROM sboms
WHERE tenant_id IS NULL
ORDER BY created_at DESC
LIMIT 50;

-- components with no resolvable tenant
SELECT id, sbom_id
FROM components
WHERE tenant_id IS NULL
LIMIT 50;
```

For each orphan, either:

- assign it to the correct tenant manually
  (`UPDATE sboms SET tenant_id = '...' WHERE id = '...';`), or
- delete it if it is genuinely stale
  (`DELETE FROM components WHERE sbom_id = '...';` then the parent
  `DELETE FROM sboms WHERE id = '...';`).

After remediation, re-run `docker compose up -d` and the migration retries
from a clean state.

### 5.2 `password authentication failed` on api start

You skipped section 4.2. The api is trying to connect as `sbomhub_app` but
that role does not exist on the volume yet. Run:

```bash
./install.sh --bootstrap-roles
docker compose up -d api
```

### 5.3 `ENCRYPTION_KEY` mismatch — old tokens fail to decrypt

If you regenerated `ENCRYPTION_KEY` without first running the rotation
runbook, any saved issue-tracker tokens (Jira, GitHub) will surface as
"decryption failed" in the integration page. Re-enter the tokens through
the UI to re-encrypt them under the new key, or restore the old key from
`.env.bak.YYYYMMDD` and follow
[`docs/encryption-key-rotation.md`](./encryption-key-rotation.md) instead.

---

## 6. Rollback

If verification (section 4.5) fails and you cannot diagnose within your
maintenance window:

```bash
docker compose down

# Restore the pre-upgrade DB dump.
docker volume rm sbomhub_postgres_data
docker compose up -d postgres
docker compose exec -T postgres \
    pg_restore -U sbomhub -d sbomhub --clean --if-exists \
    < sbomhub-preupgrade-$(date +%Y%m%d).dump

# Restore the previous .env if you ran install.sh --force.
cp .env.bak.$(date +%Y%m%d) .env

# Roll the code back to the previous release tag.
git checkout <previous-tag>
docker compose pull
docker compose up -d
```

Then file an issue with the api logs (`docker compose logs api > api.log`)
attached so we can address the regression in the next M0 patch.
