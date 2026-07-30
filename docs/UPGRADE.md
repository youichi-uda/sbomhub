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

## 2b. Breaking changes — M48 (fail-open sweep)

These require operator action on top of `docker compose pull && docker compose up -d`.
Several will stop an existing deployment from starting until the `.env` is
updated; that is deliberate, and each refusal names the variable to set.

> **Do this before you pull.** `install.sh` preserves an existing `.env`, so
> updating the template does not update yours. `SBOMHUB_AUTH_MODE` is the line
> that is universally new — `docker compose` fails at variable-substitution
> time, before any container starts, without it. A pre-M48 `.env` generated
> from the old template does carry `APP_ENV=development`; leaving that in place
> keeps every startup guard at warning level, which is the other half of this
> release, so set it deliberately rather than by omission. Add or correct both:
>
> ```bash
> # Self-host (the OSS default: no user authentication — read the row below)
> printf 'APP_ENV=production\nSBOMHUB_AUTH_MODE=anonymous\n' >> .env
> ```
>
> Use `SBOMHUB_AUTH_MODE=clerk` instead if you run Clerk, and `APP_ENV=development`
> only on a machine where you want the startup guards relaxed. Nothing is
> inferred and there is no default — see the `SBOMHUB_AUTH_MODE` row for why.

| Area | Pre-M48 behaviour | M48 behaviour | What you must do |
|---|---|---|---|
| **`APP_ENV`** | Optional. Unset resolved to `development`, which is the setting under which *every* startup guard downgrades itself to a warning — a missing `ENCRYPTION_KEY`, and a database role that **bypasses Row-Level Security** (i.e. tenant isolation not enforced), both became warnings rather than refusals. Note the supported install path was affected in practice: `install.sh` copies `.env.example` verbatim and `.env.example` shipped `APP_ENV=development`, so production self-host deployments ran with the guards disarmed. | **Required, no default.** Must be exactly one of `development`, `staging`, `production`. The api refuses to start on an unset or misspelled value, and `docker compose` now fails at variable-substitution time before the container starts. `.env.example` ships `APP_ENV=production`. | Add `APP_ENV=production` to your `.env` (or `development` on a machine where you want the guards relaxed). If you were relying on the old default, expect the `ENCRYPTION_KEY` and DB-role guards to become **refusals** — that is the point; see sections 3 and 5 if either now fails. |
| **`SBOMHUB_AUTH_MODE`** | Did not exist. The authentication mode was inferred entirely from whether `CLERK_SECRET_KEY` happened to arrive, so self-hosted mode (which serves the Clerk-fronted route groups as Owner with no credential) was reached by the *absence* of a variable, announced by one `WARN` line naming only the cause. | **Required. `clerk` or `anonymous`, no default, nothing inferred.** The api refuses to start when it is unset, misspelled, or disagrees with whether `CLERK_SECRET_KEY` actually arrived — in every environment, `development` included. `docker compose` fails at variable-substitution time before the container starts. The posture itself is unchanged; the startup log now states the consequence rather than the cause. | Add `SBOMHUB_AUTH_MODE=anonymous` for a self-host deployment, or `SBOMHUB_AUTH_MODE=clerk` if you run Clerk. Then read `docs/security/self-host-deployment.md` §2.1.1 and put a network boundary in front of the api if you have not. **Why a required declaration rather than an opt-in flag:** as long as the mode was inferred from a secret, a Clerk deployment whose secret store failed to inject *anything at all* was byte-for-byte identical to a self-hosted one and started with authentication off. A declaration lives in the deployment manifest, not the secret store, so it survives that failure and turns it into a refusal to boot. There is no development exemption: the pre-M48 `.env.example` shipped `APP_ENV=development` and `install.sh` preserves an existing `.env`, so an exemption would have let every already-installed deployment upgrade without being asked anything. |
| **Contradictory Clerk config** | A deployment with `CLERK_WEBHOOK_SECRET` or any `LEMONSQUEEZY_*` set but `CLERK_SECRET_KEY` missing started silently in anonymous-Owner mode. | **Refused in every environment** when the declaration says `anonymous`. That combination means the Clerk key was meant to be present and did not arrive. | If you hit this: either supply `CLERK_SECRET_KEY` (you meant SaaS) or remove the leftover SaaS variables (you meant self-host). Note that any API key minted while the deployment was accidentally anonymous **keeps working** — audit `/api/v1/apikeys` and revoke anything you do not recognise. |
| **Diff webhook signing** | A per-tenant SBOM diff webhook with no shared secret was delivered **unsigned** — the `X-SBOMHub-Signature` header was simply omitted. | A `format=json` webhook now requires a secret: `PUT /api/v1/tenant/settings/diff-webhook` rejects enabling one without it (400), and deliveries for existing secret-less rows are refused and recorded as `diff_webhook_failed` in the audit log instead of being sent. `format=slack` is exempt — a Slack incoming-webhook URL is itself the credential and Slack does not read our signature header. | **Functional reduction.** If you have a `json`-format diff webhook with no secret it stops firing. Set a shared secret in the diff-webhook settings screen and configure your receiver to verify `X-SBOMHub-Signature`. Switching the format to `slack` only avoids the requirement when the destination really is `https://hooks.slack.com/...` — a Slack-*compatible* relay on another host still needs a secret. Check the audit log for `diff_webhook_failed` with `missing signing secret`. |

One further M48 change needs no operator action: the anonymous public share
links (`GET /api/v1/public/:token`) now have a brute-force budget — 10 failed
attempts per token and 60 per source IP, per hour, counting **failures only**,
so normal viewing is not throttled by its own volume. A separate cap on
admissions holding a live lease (16 per token, 64 per IP, leases expiring after
two minutes) bounds parallel bursts, and it can reject a *successful* request
once that many hold live leases for one link. It bounds admissions, not
executing handlers: one that outlives its lease keeps running while the next
wave is admitted. Both are backed by Redis, and the endpoint denies (503) when
Redis is unreachable. See `docs/security/self-host-deployment.md` §10.2.

---

## 2c. Breaking change — M50 (outbound egress policy)

**This one can silently stop a webhook or an issue tracker from working after
the upgrade, without any startup refusal.** Read it if any tenant in your
deployment points a settings screen at an address inside your network.

### What changed

Four settings screens let a tenant administrator type a URL that the server then
connects to:

| Setting | Column |
|---|---|
| Issue tracker base URL | `issue_tracker_connections.base_url` |
| Slack / Discord notification webhook | `notification_settings.slack_webhook_url` / `.discord_webhook_url` |
| SBOM diff webhook | `tenant_diff_webhook_settings.webhook_url` |
| Per-tenant Azure OpenAI endpoint | `tenant_llm_config.azure_endpoint` |

Before M50 these had inconsistent, and in places absent, destination checks. The
notification webhooks had none at all; the diff webhook checked only that the
string parsed as `http(s)://host`; the issue tracker resolved the hostname once,
at creation time, and allowed anything it could not resolve.

From M50 all four go through one policy (`internal/egress`), enforced when the
connection is opened rather than when the row is written:

- **Internal addresses are refused by default** — RFC1918, loopback, carrier-grade
  NAT (`100.64.0.0/10`), IPv6 unique-local. This is the change that can break an
  existing deployment.
- **Cloud instance metadata is refused always** — `169.254.0.0/16` (which carries
  `169.254.169.254`), Azure's `168.63.129.16`, IPv6 link-local, and the NAT64 /
  6to4 / IPv4-compatible forms that embed those addresses. No setting re-enables
  this.
- Redirects are re-checked hop by hop instead of followed blindly.
- **`HTTP_PROXY` / `HTTPS_PROXY` are ignored for these four purposes** unless
  `SBOMHUB_EGRESS_ALLOW_PROXY=true`. A proxy defeats the mechanism — the server
  would only ever inspect the proxy's address while the proxy chose the real
  destination — so honouring one is an explicit delegation. **If your only route
  out is a proxy, these four integrations stop working until you set that flag.**

### What is NOT affected

Destinations **you** configure as the operator are untouched:

- `SBOMHUB_NVD_URL` / `_JVN_URL` / `_EPSS_URL` / `_KEV_URL` / `_EOL_URL` /
  `_OSV_URL` air-gapped mirrors.
- The Ollama base URL from `SBOMHUB_LLM_OLLAMA_URL` / `OLLAMA_HOST`, **including
  its default `http://localhost:11434`**. The recommended local-LLM deployment
  for manufacturers needs no change.
- The billing provider API.

`tenant_llm_config.ollama_url` is persisted by the settings screen but is not
read by the provider factory (the base URL comes from the env vars above), so it
is not a destination and is not subject to the policy.

### Do I need to act?

Check whether any tenant has stored an internal address. Run this against your
database **before** upgrading:

```sql
SELECT 'issue_tracker' AS setting, base_url AS value
  FROM issue_tracker_connections
 WHERE base_url ~* '(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.)'
UNION ALL
SELECT 'slack_webhook', slack_webhook_url FROM notification_settings
 WHERE slack_webhook_url ~* '(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)'
UNION ALL
SELECT 'discord_webhook', discord_webhook_url FROM notification_settings
 WHERE discord_webhook_url ~* '(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)'
UNION ALL
SELECT 'diff_webhook', webhook_url FROM tenant_diff_webhook_settings
 WHERE webhook_url ~* '(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)'
UNION ALL
SELECT 'azure_endpoint', azure_endpoint FROM tenant_llm_config
 WHERE azure_endpoint ~* '(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)';
```

Note what this query does **not** catch: a value like
`https://jira.corp.example` whose *hostname* resolves to an internal address.
That is the more common shape in a self-hosted deployment, and the query cannot
see it. If your tenants reach internal services by name, assume you are
affected and read the next section.

### How to restore internal destinations

Prefer the narrow form. List only the hosts and networks you actually need:

```bash
SBOMHUB_EGRESS_ALLOWED_INTERNAL=jira.corp.example,hooks.corp.example,10.20.0.0/24
```

Entries may be hostnames, bare IP addresses, or CIDRs. A hostname entry also
matches its subdomains (`corp.example` matches `jira.corp.example`). A malformed
entry is a startup refusal rather than a silently dropped one — an exemption you
believe is in place but is not is worse than a loud failure.

The blunt form opens every internal address for all four purposes:

```bash
SBOMHUB_EGRESS_ALLOW_PRIVATE=true
```

Use it only if you accept that any tenant administrator can then direct the
server at any internal HTTP service it can route to. Neither setting re-enables
the cloud metadata endpoint.

### If you run an outbound HTTP proxy

```bash
SBOMHUB_EGRESS_ALLOW_PROXY=true
```

Without it, these four integrations bypass the proxy and will fail in a network
that has no direct route out. With it, the destination policy has to be enforced
on the proxy — SBOMHub can no longer see the final destination. The startup log
carries a WARN when it is set.

### How a refusal looks

There is no startup error — the deployment boots normally and the refusal
appears at delivery time:

```
egress (diff_webhook): destination hooks.corp.example -> 10.20.0.5 is not permitted:
RFC 1918 private range — internal destinations are disabled
(set SBOMHUB_EGRESS_ALLOW_PRIVATE=true, or list this host in
SBOMHUB_EGRESS_ALLOWED_INTERNAL, to permit it)
```

The same message is surfaced on the settings screen when an administrator saves
a URL that is refusable on its face (a literal internal address, `localhost`, a
non-http scheme). A hostname that only *resolves* internally saves successfully
and fails at delivery, because the address behind a name is not knowable at save
time — that is why the enforcement point is the connection, not the form.

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
   issue-tracker integrations (Jira / Backlog / GitHub) are encrypted with
   this key.
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

If the api logs `parse "postgres://...": ...` or `pq: SSL is not enabled on
the server` style errors instead — or it tries to dial a host that looks like
part of your password — your `APP_PASSWORD` / `MIGRATOR_PASSWORD` contains a
character that the URL parser treats as a delimiter (`@ : / # ? & % +`). The
docker-compose fallback substitutes the raw password into the connect string,
so any of those characters break parsing. Either rotate to a URL-safe
password (alphanumerics, `-`, `.`, `_`, `~`) or set `DATABASE_URL` /
`MIGRATE_DATABASE_URL` in `.env` to the full URL with the password
URL-encoded (`@` → `%40`, `/` → `%2F`, `#` → `%23`, etc.). The values you
put there are forwarded verbatim via the `${DATABASE_URL:-...}` fallback in
`docker-compose.yml`.

### 5.3 `ENCRYPTION_KEY` mismatch — old tokens fail to decrypt

If you regenerated `ENCRYPTION_KEY` without first running the rotation
runbook, any saved issue-tracker tokens (Jira, Backlog, GitHub) will
surface as
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

# Wipe the post-upgrade DB volume so the pre-upgrade dump can be loaded
# into a clean cluster (the upgrade may have applied new migrations whose
# DDL would conflict with the older dump otherwise).
docker volume rm sbomhub_postgres_data
docker compose up -d postgres
```

**DB と secrets の復元には canonical `restore.sh` を使用すること**
(F70 fix 後)。 以前は `pg_restore -U sbomhub -d sbomhub --clean --if-exists`
を `--single-transaction` なし + sanity check なしでこの場で直接実行する
手順を載せていたが、 partial restore でも `cp .env.bak.* .env` と service
startup に進んでしまい DB と secrets の不整合を生む production blocker と
なっていた。 §9.3 manual restore (F65/F67/F69 fix) と rollback runbook で
別々の `pg_restore` を持つと regression が再発するため、 両者とも
`docker/scripts/restore.sh` の fail-safe (`--single-transaction` +
`schema_migrations` / `tenants` sanity check + sanity 通過後に secrets 復元)
を single source of truth とする。

ただし backup の **format / 配置** に応じて 2 通りある:

- **upgrade 前に `backup.sh` で取った tar (`sbomhub-backup-*.tar.gz`)
  がある場合**: `restore.sh` をそのまま使う (推奨)。 詳細手順と
  `AGE_IDENTITY` / `FORCE=yes` の指定方法は
  [`../docker/README.enterprise.md`](../docker/README.enterprise.md) §5.3
  および [`./security/self-host-deployment.md`](./security/self-host-deployment.md)
  §9.3 を参照。 fail-safe 動作 (sanity FAIL 時に secrets を戻さず exit 1)
  は §5.3 「fail-safe 動作 (F65 fix 後)」 節に記載。

  ```bash
  # 例: 平文 tar
  ./docker/scripts/restore.sh /path/to/sbomhub-backup-YYYYMMDD-HHMMSS.tar.gz

  # 例: age 暗号化 tar
  export AGE_IDENTITY=/path/to/your-age-key.txt
  ./docker/scripts/restore.sh /path/to/sbomhub-backup-YYYYMMDD-HHMMSS.tar.gz.age
  ```

- **section 3 で `pg_dump` 単体 (`sbomhub-preupgrade-*.dump`) しか
  取っていない場合**: `restore.sh` の tar 形式 (`<timestamp>/db.dump` +
  `<timestamp>/secrets/`) に揃える wrapping が必要なので、 後続の
  M0 patch までは `restore.sh` の §「DB restore」 と同じ command を
  手動でなぞること — すなわち以下の **全ステップ** を順守する
  (途中で抜けない):

  ```bash
  # 1) pg_restore は --single-transaction + --no-owner --no-privileges 必須
  #    (partial apply による DB と secrets の不整合を排除する fail-safe)。
  docker compose exec -T postgres \
      pg_restore -U sbomhub -d sbomhub \
      --clean --if-exists --single-transaction --no-owner --no-privileges \
      < sbomhub-preupgrade-$(date +%Y%m%d).dump

  # 2) Sanity check 1: schema_migrations 最新 version が取れること
  #    (空 / error なら restore 不完全、 .env を戻さず調査)
  docker compose exec -T postgres \
      psql -U sbomhub -d sbomhub -tA -v ON_ERROR_STOP=1 -c \
      "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;"

  # 3) Sanity check 2: tenants table が query 可能なこと
  #    (失敗なら schema 自体が壊れている、 .env を戻さず調査)
  docker compose exec -T postgres \
      psql -U sbomhub -d sbomhub -tA -v ON_ERROR_STOP=1 -c \
      "SELECT count(*) FROM tenants;"

  # 4) 上記 1-3 が全て通った場合のみ .env を復元 (install.sh --force を
  #    実行していた場合)。 sanity FAIL 時は本 step に進まず、 旧 .env を
  #    untouched にしたまま原因調査する。
  cp .env.bak.$(date +%Y%m%d) .env

  # 5) **enterprise compose (role-separated) を使っている場合のみ**:
  #    pg_restore --no-owner --no-privileges で落ちた sbomhub_app / sbomhub_migrator
  #    用 GRANT / OWNER を db-bootstrap 再実行で再付与する (F79 fix と同等)。
  #    省略すると sbomhub-api が `permission denied for table ...` で起動失敗する。
  docker compose -f docker/docker-compose.enterprise.yml run --rm db-bootstrap
  ```

`.env` 復元と service startup は **必ず sanity check 両方 PASS の後**。
これは §9.3 / `restore.sh` (F65/F67/F69/F79 fix) と同じ fail-safe contract で、
DRY のため将来 backup format を tar 化したら本節の inline pg_restore も
削除して `restore.sh` 1 本に寄せる予定。

```bash
# Roll the code back to the previous release tag.
git checkout <previous-tag>
docker compose pull
docker compose up -d
```

Then file an issue with the api logs (`docker compose logs api > api.log`)
attached so we can address the regression in the next M0 patch.
