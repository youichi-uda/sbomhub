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

## 2d. Breaking change — M50 W2 (project-scoped API keys are enforced)

**This one can stop a CI pipeline that uses a key created from a project's "API
Keys" tab.** It needs no `.env` change and there is no startup refusal: the
change is that a credential which previously carried more authority than its
label now carries exactly what the label says.

### What changed

`api_keys` has always had a `project_id` column, and
`POST /api/v1/projects/:id/apikeys` (a project's **API Keys** tab) has always
filled it in. Nothing read it. Every authentication path derived the request's
authority from `api_keys.tenant_id` alone, so a key the UI described as
"Project-scoped" could act on **every project of the tenant** — upload SBOMs into
them, read their vulnerabilities, approve their VEX drafts, build their evidence
packs — and could create new projects.

Keys created from **Settings → API Keys** (`POST /api/v1/apikeys`, `project_id`
NULL) were, and remain, tenant-wide. They are unaffected by this change.

The consequence was not that a key holder gained more than the administrator who
issued it — issuing requires Owner/Admin. It was that the administrator could not
give away *less*. Handing a "project-scoped" key to a contractor, an auditor, or
a per-repository CI job handed over the tenant.

### New behaviour

A key with `project_id` set is now answered **`403 {"error":"forbidden"}`** unless
the request names that project — or is one of the two project **lists**, which
answer with that one project instead of the tenant's, or `POST /api/v1/cli/check`,
which names no project and touches none. Specifically:

| Request | Before | Now |
|---|---|---|
| Any `/api/v1/projects/<the key's project>/…` endpoint that accepts an API key | works | **works, unchanged** |
| The same endpoint with any other project id | works | **403** |
| `POST /api/v1/cli/upload` / `POST /api/v1/cli/projects` naming the key's own project by name | works | **works**, idempotently — `/cli/projects` answers 200 with `"created":false` (never 201), `/cli/upload` answers 200 with `"project_created":false` |
| The same two naming any other project, or a name that does not exist | works — **and created the project when the name was unknown** | **403**, and nothing is created |
| `GET /api/v1/cli/projects`, `GET /api/v1/mcp/projects` (project lists) | works, lists every project of the tenant | **200, narrowed** to the key's own project — a one-element list |
| `GET /api/v1/mcp/dashboard/summary`, `/mcp/search/cve`, `/mcp/search/component` | works | **403** |
| `POST /api/v1/mcp/sbom/diff` | works | **403** — see residual below |
| `POST /api/v1/cli/check` (stateless OSV lookup, touches no project) | works | **works** |
| Any future endpoint mounted behind API-key auth | — | **403 until it is explicitly classified** (default-deny) |
| A mistyped URL under `/api/v1/cli` or `/api/v1/mcp` | 404 | **403** — unmatched paths are unclassified, so a typo reads as a scope refusal (see residuals) |

A project-scoped key can reach 34 of the 38. Twenty-nine of them name the project
in the path, and require that `:id` to be the key's own project — in full:

```
POST   /api/v1/projects/:id/sbom
GET    /api/v1/projects/:id/sbom
POST   /api/v1/projects/:id/scan
GET    /api/v1/projects/:id/vulnerabilities
GET    /api/v1/projects/:id/sboms/:sbom_id/scan-status
POST   /api/v1/projects/:id/reachability
GET    /api/v1/projects/:id/reachability/targets
POST   /api/v1/projects/:id/triage/run
GET    /api/v1/projects/:id/vex-drafts
GET    /api/v1/projects/:id/vex-drafts/:draft_id
PUT    /api/v1/projects/:id/vex-drafts/:draft_id/decision
POST   /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse
POST   /api/v1/projects/:id/cra-reports/run
GET    /api/v1/projects/:id/cra-reports
GET    /api/v1/projects/:id/cra-reports/:report_id
PUT    /api/v1/projects/:id/cra-reports/:report_id/decision
PATCH  /api/v1/projects/:id/cra-reports/:report_id/awareness
POST   /api/v1/projects/:id/cra-reports/:report_id/submissions
GET    /api/v1/projects/:id/cra-reports/:report_id/submissions
POST   /api/v1/projects/:id/cra-reports/:report_id/reanalyse
GET    /api/v1/projects/:id/meti/assessment
POST   /api/v1/projects/:id/meti/assessment/refresh
PUT    /api/v1/projects/:id/meti/assessment/:criterion_id/override
DELETE /api/v1/projects/:id/meti/assessment/:criterion_id/override
GET    /api/v1/projects/:id/meti/improvement-actions
POST   /api/v1/projects/:id/evidence-pack/build
GET    /api/v1/cli/projects/:id
GET    /api/v1/mcp/projects/:id/vulnerabilities
GET    /api/v1/mcp/projects/:id/compliance
GET    /api/v1/mcp/projects/:id/sboms
```

The other five name no project in the path:

- `GET /api/v1/cli/projects` and `GET /api/v1/mcp/projects` — the project lists,
  **narrowed** to the key's own project rather than refused (see below);
- `POST /api/v1/cli/upload` and `POST /api/v1/cli/projects` — allowed only when
  the body names the key's own project;
- `POST /api/v1/cli/check` — no project at all.

The four that remain are the tenant-wide ones refused in the table above —
29 + 5 + 4 = the 38 endpoints that accept an API key.

> **M53 W1 (2026-08-05) — the counts above are one higher.** `POST
> /api/v1/projects/:id/scan` was added to the fenced list. It had been
> registered Clerk-only since M47 W1, so **no API key could reach it at all**:
> measured on a throwaway stack with one tenant-level `sbh_` key, upload
> answered 201, read-back 200, and `POST …/scan?sbom_id=…` answered **404** in
> `SBOMHUB_AUTH_MODE=anonymous` (the Bearer header was ignored and the request
> resolved as the *default* tenant, which does not own the SBOM — the identical
> 404 the route gives with no credential at all) and **401** under Clerk. That
> is the third step of the workflow this repository ships
> (`.github/workflows/sbom-upload.yml`), which never turned a run red — not only
> because it carried `continue-on-error: true`, but because its `curl` had no
> `--fail` flag and its last command was an unconditional `echo`, so the step
> could not fail in the first place. Both were removed and the two calls now
> compare their status exactly (200 / 202). The route now sits on the same MultiAuth →
> RequireWrite → RateLimitByAPIKey(standard, 60/min) → TenantTx → audit chain as
> `POST /api/v1/projects/:id/sbom`, and is classified `scopeProjectPathParam`,
> so a project-scoped key may scan **its own project only** and is answered the
> same 403 as everywhere else for any other project id. Read the two sentences
> before this note as **35 of the 39** and **thirty of them name the project in
> the path**, i.e. 30 + 5 + 4 = 39.
>
> **What was NOT broken.** An earlier draft of this note said SBOMs "were
> uploaded and never scanned". That is false. `POST /api/v1/projects/:id/sbom`
> starts its own **tracked** NVD/JVN scan on ingest and always has — measured on
> the same stack, an upload with no `/scan` call afterwards left a
> `component_vulnerabilities` row and `GET /sboms/<id>/scan-status` reporting
> `{"status":"completed", … "critical":1}`. What never worked is the explicit
> **re-scan** trigger. Because of that, the workflow's `scan` input now defaults
> to **false**: with the route reachable, running it on a freshly uploaded SBOM
> sweeps it a second time (measured: NVD served from its Redis cache,
> `cache_hits=1 api_calls=0`; JVN issuing a fresh outbound request; no change to
> the row count, and no movement in `scan-status`, because this route has no
> ScanTracker).
>
> **Operator action.** None for the API keys themselves: no existing key loses
> anything, and a tenant-level key is unaffected by the scope table entirely.
> One caveat if you use the shipped workflow — take the workflow and the server
> in the same upgrade, or leave `scan` off. The upload step is irreversible and
> the scan step no longer swallows its errors, so a NEW workflow pointed at an
> OLD server stores (and scans) the SBOM and then goes red on the trigger, and
> re-dispatching uploads it again. The same shape applies to the shared 60/min
> rate limit: upload, read-back and trigger all draw on one budget per key, so a
> key near its ceiling can red the job after the upload has already succeeded.

**Why the project lists are narrowed and the other tenant-wide endpoints are
not.** Narrowing an answer is safe exactly when the response *is* the set being
narrowed. A project list is: you receive the projects one by one, every one of
them is a project the key can address, and nothing else in the body is computed
over a wider set. The dashboard summary and the two searches are not: their
counters, risk scores and "this CVE is not present" verdicts are derived from a
population the response does not name, so a narrowed answer would be shaped
exactly like a tenant-wide one and would be read — by an operator or by an LLM
through the MCP server — as a statement about the whole tenant. `/mcp/search/cve`
would report a CVE as absent while it is present in a sibling project. Those stay
refused. (`/mcp/dashboard/summary` and both searches do carry project ids in their
bodies; that is not the same thing as being a project list, and it is why they are
not narrowed.)

The narrowed lists disclose nothing the key could not already read: the same
project is readable through `GET /api/v1/cli/projects/:id`, and the narrowed row
is produced by the same query as the tenant-wide one, so it carries the same
fields.
This list is checked against the code on every test run:
`TestM50W2UpgradeDocEndpointListMatchesTheRouteTable` parses the block above and
compares it to the enforcement table, and
`TestM50W2APIKeyReachableRoutesAreAllClassified` re-derives that table from the
route registrations. A route added or removed without updating this list fails
the build.

Two properties worth knowing:

- **The refusal carries no information.** It is a comparison of two UUIDs the
  request already holds, made before any database access, so a project that
  exists, a project of another tenant, and a UUID that was never allocated all
  produce the identical response. The same is true of the two by-name CLI routes:
  an unknown project name and a sibling project's name are indistinguishable.
- **403, not 404.** The repository's convention for "resource you cannot address"
  is a 404 sentinel, deliberately indistinguishable from "does not exist". This
  refusal is about the *credential*, not the resource — the key is valid and the
  project may well exist — so it answers 403 like the existing role guards
  (`RequireWrite` / `RequireAdmin`) do. A 404 here would make a mis-scoped CI job
  indistinguishable from a deleted project. The failure is visible either way — a
  404 is not a silent success — but an operator debugging a CI job that stopped
  uploading would be looking for a deleted project instead of a mis-scoped key.

### What you must do

1. **Find out whether you have any project-scoped keys.** They are the only rows
   affected:
   ```bash
   docker compose exec -T postgres psql -U sbomhub -d sbomhub -c \
     "SELECT k.id, k.key_prefix, k.name, p.name AS project
        FROM api_keys k JOIN projects p ON p.id = k.project_id
       WHERE k.project_id IS NOT NULL;"
   ```
   An empty result means nothing changes for your deployment. (For reference: the
   development database this change was built against had 96 keys, **0** of them
   project-scoped — measured 2026-07-30.)
2. **For each row, decide which authority you actually meant.** If the consumer
   only ever touches that one project, nothing to do — it now does exactly that.
   If it needs more (it lists projects, reads the dashboard summary, or uploads to
   several projects), replace it with a tenant-level key from
   **Settings → API Keys** and revoke the old one.
3. **Watch for the refusal in your logs.** Every denial is recorded as
   `apikey: project scope violation` at WARN with `path`, `method`, `api_key_id`,
   `tenant_id` and `key_project_id`. There is no `audit_logs` row — the refusal
   happens before the audit middleware is entered, the same residual the role
   guards have.

### Residuals

- **`sbomhub doctor` and `sbomhub projects list` work with a project-scoped key —
  no CLI upgrade required.** The first cut of this change refused both project
  lists, which made `doctor` report `[FAIL] 認証失敗 (403)` and exit 1 (it probes
  `GET /api/v1/cli/projects` as its authentication check) and made
  `sbomhub projects list` fail outright. Narrowing the lists instead of refusing
  them fixed both without touching the CLI: `doctor` reports `[OK] 認証 OK` and
  `projects list` prints the one project the key can address. Any released
  `sbomhub` binary behaves this way — the change is entirely server-side.
  A project-scoped key can therefore now discover its own project id, which every
  `/api/v1/projects/:id/…` endpoint requires it to supply.
- **`sbomhub scan` needs an explicit `--project` with a project-scoped key.**
  Without the flag the CLI falls back to the working-directory basename, which is
  refused unless the directory happens to be named exactly like the project.
  Both forms of the flag work, by different routes: `--project <exact project
  name>` goes through `POST /api/v1/cli/projects` (name resolved and compared),
  and `--project <project uuid>` is short-circuited by the CLI straight to
  `POST /api/v1/projects/<uuid>/sbom` (path parameter compared). The name must
  match exactly — there is no fuzzy or case-insensitive matching.
- **`POST /api/v1/mcp/sbom/diff` is refused for project-scoped keys, including
  for their own SBOMs.** The route selects two SBOMs by UUID in the body, so the
  project is only known after both rows are loaded, and no comparison against the
  key's project exists there yet. Refusing was chosen over half-checking. Use a
  tenant-level key, or the web UI's project diff view.
- **A key whose `project_id` points at another tenant's project can no longer
  reach any project data.** Such rows were possible before M47 W1 added an
  ownership check to the mint route (`api_keys` has no RLS, and its foreign key is
  on `projects(id)` alone, not on `(tenant_id, id)`). The key still authenticates
  as its own tenant, so the one project id it will accept in a path resolves to
  nothing under that tenant's RLS: every project-scoped route answers 403 (wrong
  project) or 404 (its own project id, invisible under its own tenant), the two
  project lists answer **`200` with an empty list**, and the remaining tenant-wide
  routes answer 403. The one exception is `POST /api/v1/cli/check`, which reads no
  tenant data at all and still works. Revoke and reissue if you find one; the
  query in step 1 joins on `projects`, so a cross-tenant row does not appear in
  its output.

  This is the only way a project-scoped key sees an empty project list. Deleting
  the project does **not** produce one: `api_keys.project_id` is
  `REFERENCES projects(id) ON DELETE CASCADE`, so deleting a project deletes its
  project-scoped keys, and the key is then answered `401 {"error":"invalid API
  key"}` — which `sbomhub doctor` correctly reports as
  `認証失敗 (401) — api_key が無効・失効しています`.
- **A mistyped URL under `/api/v1/cli` or `/api/v1/mcp` answers 403 rather than
  404** for a project-scoped key, because Echo runs the group middleware for
  unmatched paths and an unmatched path is (correctly) unclassified.
- **Self-hosted mode is unchanged in what it is.** With
  `SBOMHUB_AUTH_MODE=anonymous` the Clerk-fronted route groups grant Owner on the
  default tenant to a request with **no** credential at all (see §2b and
  `docs/configuration.md`). A caller who can reach the API can therefore ignore
  API keys entirely. Project scope narrows what a *key* can do; it is not a
  network boundary and does not make one unnecessary.

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

---

## 7. `X-API-Key` on the canonical routes, and the MCP scan-state probe

Added 2026-08-04. Two changes an operator can observe, plus five limitations in
§7.2 that are recorded rather than closed.

### 7.1 `X-API-Key` now authenticates on `/api/v1/projects/...`

`APIKeyAuth` (the `/api/v1/cli/*` and `/api/v1/mcp/*` groups) has always accepted
the key in either `X-API-Key` or `Authorization: Bearer`. `MultiAuth`, which
fronts the canonical per-project routes, read only `Authorization`.

A request that carried only `X-API-Key` was therefore **not refused** — with
`Authorization` empty it fell through to the Clerk/self-hosted handler, and in
`SBOMHUB_AUTH_MODE=anonymous` that handler provisions the default tenant's
Owner. The key was discarded and, with it, `api_keys.project_id`: a
**project-scoped key reached any project of the deployment**. Measured on a
throwaway stack (2026-08-04, anonymous mode) before the fix:

| header | route | before | after |
|---|---|---|---|
| `X-API-Key: <project-scoped>` | `GET /api/v1/projects/<OWN>/sbom` | 200 (key ignored) | 200 (key honoured) |
| `X-API-Key: <project-scoped>` | `GET /api/v1/projects/<SIBLING>/sbom` | **200** | **403** |
| `X-API-Key: <invalid>` | `GET /api/v1/projects/<OWN>/sbom` | **200** | **401** |
| *(no header)* | `GET /api/v1/projects/<OWN>/sbom` | 200 | 200 |

**What this is not.** In `anonymous` mode this was not a privilege escalation:
a caller sending no header at all already reaches those routes as the default
tenant's Owner, which is that mode's acknowledged posture. What was broken is
the promise the web UI's "Project-scoped" label makes about a key someone was
handed. Under `SBOMHUB_AUTH_MODE=clerk` the same requests were answered 401
before the fix and are answered 401 or 403 after it.

**What operators may need to change.** Nothing, if requests already used
`Authorization: Bearer` (the CLI, GitHub Actions via `sbomhub scan`, and
`docs/api.md`'s examples all do). Two behaviours are new:

- a request carrying an `X-API-Key` value that does not validate is now **401**
  where an anonymous-mode deployment previously served it as the default Owner.
  A CI job pointing a stale or revoked key at `POST /api/v1/projects/:id/sbom`
  will start failing loudly instead of silently uploading;
- a request carrying **two different** values under one credential header
  (`X-API-Key` or `Authorization`) is **401**. Picking one would be a guess.
  Repeats of the same value are unaffected.

The self-host promise is unchanged: a request with **no** credential still
reaches the default tenant in `anonymous` mode. "No credential" and "a
credential I cannot use" are deliberately different cases.

### 7.2 The MCP server now reports whether a scan had finished

`packages/mcp-server` reads `GET /api/v1/projects/:id/sboms/:sbom_id/scan-status`
around its vulnerability walk and reports `scan_state` / `counts_final` /
`scanned_sbom_id`. Before this it could not see the asynchronous scan's state,
so a project whose scan was still running answered `0 vulnerabilities` in exactly
the shape a scanned-and-clean project does.

**Extra requests per tool call.** The walk is bracketed by two probes of two
requests each. The second probe is only issued when the first said `completed`,
so a project whose scan is running — or whose tracker entry has aged out, which
is the steady state after an hour or an API restart — costs **two** extra
requests; one that can be certified costs **four**.

**Rate-limit consequence (not closed).** `RateLimitByAPIKey` keys its Redis
counter on the API key alone (`mcp:ratelimit:<key id>:<window>`) with no route in
the key, so every limiter an API key passes through shares one counter and the
smallest limit wins. The probe's requests are charged to the same bucket as the
`/mcp` group's 60/min. A one-page `sbomhub_get_vulnerabilities` call now costs 3
or 5 against that bucket instead of 1, so a key doing nothing else exhausts it
after roughly 12-20 tool calls per minute rather than 60. Raising the `/mcp`
limit, or giving the limiter a per-route counter, is a separate change.

**What `counts_final: true` asserts.** That the scan apps/api *tracks* for that
SBOM reported `completed` both before and after the read, that its count did not
move in between, and that the walk covered the whole project (a walk cut short by
the 5000-row cap is reported `scan_truncated: true` and never final). It is the
strongest statement the API supports — not a guarantee that no write is in
flight.

**What is still not proven — recorded, not closed.**

1. **A manual rescan is invisible in `scan_state`.**
   `POST /api/v1/projects/:id/scan` never marks the shared `ScanTracker`, and
   entries live an hour, so an SBOM being rescanned still reads `completed`
   throughout. Detection rests entirely on the summary comparison. That comparison
   is stronger than it first appears here, because `VulnerabilityHandler.runScan`
   commits NVD and JVN in ONE transaction (`database.WithTxFunc`, and the link
   writes go through the transaction-bearing context), so a reader sees the whole
   rescan or none of it: a commit before both readings or after both leaves the
   walk consistent with them, and a commit in between changes the summary and is
   reported as `changed`. What is left is the case where the new summary happens
   to equal the old — i.e. limitation 2 below. Marking the tracker on that handler
   would let `scan_state` say so directly; it is a backend change and was left out
   of the change that found this.

   (An earlier revision of this note claimed the rescan writes in phases and can
   expose a partial summary between NVD and JVN. It does not — the two run inside
   one transaction.)
2. **A replacement that keeps the whole summary the same.** The per-page
   `X-Total-Count` guard fires only when the count moves and the row-identity
   guard only when a row comes back twice, so an interleaving that swaps one row
   for another passes both: read rows 0-499, have row 0 replaced by a row that
   sorts last, and page two returns 501-599 plus the replacement — 600 distinct
   rows, none repeated, the count unchanged, and row 500 never read. Closing this
   needs a snapshot to walk against, which the API does not offer. (An earlier
   revision of this note claimed the multi-page guards caught it; they do not.)
3. **`GET /api/v1/projects/:id/sbom` answers 404** for a project with no SBOM,
   for a project that does not exist, and for a repository error alike, so the
   client reports `unavailable` for all three rather than naming one.
4. **A failing `sbomhub_get_project_dashboard` keeps its other legs running.**
   `Promise.all` rejects on the first failure but does not cancel the siblings,
   so a capped project can keep issuing page requests — against the rate-limit
   bucket above — after the tool has already answered with an error. An
   `AbortController` fixes it and was written, then reverted: with it, the number
   of requests a failing dashboard makes depends on when the abort lands relative
   to the in-flight fetches, and every case in the MCP contract suite asserts the
   EXACT request list. That exactness is what lets the suite catch a tool talking
   to a route it should not, and it is worth more than a bounded amount of wasted
   quota on an error path.

---

## 8. Per-API-key rate limits are now separated (M51)

Added 2026-08-05. One change with an operator-visible effect on the first minute
after the deploy, and one that is permanent.

### 8.1 What was wrong

`RateLimitByAPIKey` was configured 28 times in `cmd/server/main.go` with two
different ceilings — 60 requests/minute for uploads and one-shot reads, 300 for
the polling and list surfaces — but the Redis key every one of them incremented
was

```
mcp:ratelimit:<api key uuid>:<yyyymmddhhmm>
```

which names the key and the minute and nothing else. All 28 therefore advanced
**one** integer, and a route's own ceiling only decided the threshold that shared
integer was compared against. Measured on a throwaway stack (2026-08-04, one
tenant-level `sbh_` key, inside a single minute):

| # | request | configured ceiling | before | after |
|---|---|---|---|---|
| 1-61 | `GET /api/v1/projects/:id/sboms/:sbom_id/scan-status` | 300/min | 200 | 200 |
| 62 | `GET /api/v1/projects/:id/sbom` — **its first call** | 60/min | **429** | **200** (`X-RateLimit-Remaining: 59`) |
| 63 | `GET /api/v1/projects/:id/vulnerabilities` — **its first call** | 60/min | **429** | **200** |

and in the other direction:

| # | request | configured ceiling | before | after |
|---|---|---|---|---|
| 1-60 | `GET /api/v1/projects/:id/sbom` | 60/min | 200 | 200 |
| 61 | `GET /api/v1/projects/:id/sbom` | 60/min | 429 | 429 |
| 62 | `GET .../scan-status` | 300/min | 200, `X-RateLimit-Remaining: 238` | 200, `X-RateLimit-Remaining: 299` |

The direction that costs a legitimate client is the first one: `sbomhub scan
--fail-on <severity>` polls `scan-status` about once a second, which is exactly
what its 300/min ceiling exists for, and 60 of those polls used to lock the same
key out of the SBOM upload it had just made.

### 8.2 What changed

The counter is now named by a **budget** — a (name, ceiling, window) triple — so
every request charged to a counter has the same ceiling as every other request
charged to it. The ceiling is part of the budget rather than an argument at the
call site, which is what makes "one counter, two ceilings" impossible to spell.

Four budgets, all per API key, all per minute:

| budget | ceiling | routes |
|---|---|---|
| `standard` | 60 | canonical `/api/v1/projects/...` mutations, plus `GET .../sbom` and `GET .../vulnerabilities` |
| `poll` | 300 | `scan-status`, `reachability/targets`, and the `vex-drafts` / `cra-reports` / `submissions` / METI list+get surfaces |
| `mcp` | 60 | the `/api/v1/mcp/*` group |
| `cli` | 60 | the legacy `/api/v1/cli/*` group |

**The aggregate one key may spend goes up**, and that is deliberate rather than
incidental: previously a key was capped at whatever ceiling the route it was
calling had (about 300/minute in practice), and it is now the sum of the four
budgets, **480 requests/minute**. Splitting per ROUTE instead — the obvious
one-line repair — would have made it roughly 4,300/minute for one key, since the
budget would then multiply by the size of the route table; that is why the split
is by budget.

If your deployment sizes anything on "one API key cannot exceed ~300 req/min",
that assumption is now 480.

### 8.3 The deploy itself: counters reset once

The Redis key changed shape and prefix:

```
before:  mcp:ratelimit:<api key uuid>:<window>
after:   ratelimit:apikey:v2:<api key uuid>:<budget>:<window>
```

**Every counter that is live at the moment the new binary starts serving is
abandoned.** A key that had already spent its budget starts the new buckets at
zero, so within that one minute it can spend a full budget again. The exposure is
bounded by the window: less than 60 seconds, and at most one extra budget per
bucket.

**During a rolling deploy the two binaries do not share a counter.** Old and new
pods increment different keys, so for the duration of the rollout a key can spend
up to one full budget on each fleet — up to twice the intended rate. Two options,
neither of them required:

- accept it. The overshoot is bounded by the rollout window and by 2x, and it
  affects only API-key traffic (the limiter is a no-op for Clerk sessions and for
  the self-hosted default identity);
- if a deployment cannot accept even that, stop the old pods before starting the
  new ones rather than rolling.

**No cleanup is needed.** The old `mcp:ratelimit:*` keys carry a TTL of
window + 1s and expire on their own within a minute of the last request that
touched them. Deleting them by hand is harmless but pointless:

```bash
docker compose exec redis redis-cli --scan --pattern 'mcp:ratelimit:*' | \
  xargs -r docker compose exec -T redis redis-cli DEL
```

### 8.4 `Authorization: bearer <token>` is now accepted everywhere it should be

Separately, `Auth()` (the Clerk window) parsed the `Authorization` header with a
case-sensitive `strings.TrimPrefix(v, "Bearer ")` over `Header.Get`, while
`MultiAuth` and `APIKeyAuth` used the RFC 9110 rule — case-insensitive scheme,
one or more delimiting spaces, and a refusal when a repeated header carries two
different credentials. All three now share one parser. Four measurable
differences disappear, of which three **tighten** the Clerk window:

| request shape | before, `Auth()` routes | after |
|---|---|---|
| `Authorization: bearer <token>` | 401 `invalid authorization header format` | parsed and verified normally |
| `Authorization: Bearer ` (no token) | passed on to Clerk as an empty token → 401 `invalid token` | **401** `invalid authorization header format` |
| two different `Authorization` values | first one silently used | **401** — picking one is a guess |
| empty `Authorization` followed by a real one | 401 `missing authorization header` | the real one is used |

Nothing an existing client sends changes: `Bearer <token>` with a single space is
unaffected. If a client of yours relies on a repeated `Authorization` header, or
on sending `Authorization: Bearer` with nothing after it, it will now receive 401.

### 8.5 Not fixed here

- The window is still **fixed**, not sliding. A caller can spend a bucket at the
  end of one minute and another at the start of the next, so the observable
  short-term peak is twice the ceiling. Unchanged from before M51.
- Nothing bounds the aggregate **across** budgets, or a **tenant** holding
  several API keys.
- A Redis error still answers **500** on these routes (fail-closed), so a Redis
  outage takes the API-key surface down rather than un-throttling it. Unchanged.
- `POST /api/v1/projects/:id/scan` is still registered on the Clerk-only route
  group, so an API key cannot trigger a scan. `.github/workflows/sbom-upload.yml`
  attempts it under `continue-on-error: true` and has therefore always failed
  silently; the workflow now says so in a comment.
- **RESOLVED 2026-08-05 (M53 W1) — the bullet directly above is no longer true.**
  `POST /api/v1/projects/:id/scan` moved onto the MultiAuth chain
  (`MultiAuth → RequireWrite → RateLimitByAPIKey(standard, 60/min) → TenantTx →
  audit`) and is classified `scopeProjectPathParam` in
  `middleware/project_scope.go`, so an API key does trigger a scan: 202 for a
  tenant-level key, and for a project-scoped key naming its own project.
  `continue-on-error: true` was removed from the workflow step, which now fails
  the run when the trigger is refused, and the step's `scan` input now defaults
  to **false** because the upload already scans (see §2d's M53 W1 note). Being a
  trigger, the step still cannot observe whether the background sweep finished —
  poll `/sboms/:sbom_id/scan-status`, or use `sbomhub scan --fail-on`, for that.
  The route is rate-limited but not capacity-managed: the limiter caps
  ADMISSIONS (60 per window per key) and nothing else. An admission is not a
  sweep — a request admitted by the limiter still has to pass the handler's
  synchronous `SbomInProject` check, and a refused one starts nothing. What is
  uncapped is the layer past that check: up to 60 ACCEPTED requests per window
  each spawn a background goroutine, nothing limits how many run at once, and
  the fixed window admits 120 across a boundary.
- One correction to §8.3's "no cleanup is needed": the TTL on a counter is set
  by a separate `EXPIRE` issued only after the **first** `INCR` of a window
  (unchanged from before M51). If that one `EXPIRE` fails — a Redis error in
  exactly that instant — the key never receives a TTL and persists. The
  `redis-cli --scan ... | xargs ... DEL` above is what removes such a key; for
  the normal case it remains unnecessary.

### 8.6 The `sbh_` prefix test is now case-insensitive too

Found by review after §8.4 landed, and the reason §8.4 is not the whole story.

Whether a Bearer value is an API-key attempt or a Clerk session token is decided
by a `sbh_` prefix test, and that test was case-sensitive in both windows. The
consequence was not a 401 with a different body. Measured on a throwaway stack
(2026-08-04, `SBOMHUB_AUTH_MODE=anonymous`) with a **project-scoped** key,
against a project belonging to another tenant:

| header | before | after |
|---|---|---|
| `Authorization: Bearer sbh_<scoped key>` | 403 `forbidden` | 403 `forbidden` |
| `Authorization: Bearer SBH_<the same key>` | **200 + the project's SBOM** | **401** `invalid API key` |
| `Authorization: Bearer sBh_<the same key>` | **200** | **401** |
| `X-API-Key: SBH_<the same key>` | 401 | 401 |

Uppercasing four characters made `MultiAuth` stop recognising the value as a
credential, so the request fell through to the self-hosted handler and ran as the
**default tenant's Owner with `api_keys.project_id` discarded** — §7.1's finding,
reachable again through a different spelling, while `X-API-Key` answered 401 to
the same string.

Both windows now apply one case-insensitive rule. This does **not** make an
uppercased key work: the service hashes the raw string, so `SBH_x` still does not
match the stored hash of `sbh_x`. It makes the request a refusal instead of a
default identity.

**What operators may need to change.** Nothing. No client mints or sends a
key with a different casing — `APIKeyService.generateAPIKey` always emits
lowercase `sbh_`. A request that was silently served as the default tenant
because of this will now return 401, which is the intended outcome.

**Still open, recorded not closed.** A Bearer value that is neither
`sbh_`-shaped nor a valid Clerk token (`Authorization: Bearer some-random-string`)
still reaches the default identity in `anonymous` mode, because
`handleSelfHostedAuth` does not read the header at all. Closing that means
deciding whether a self-hosted deployment should refuse a request carrying an
Authorization header it cannot use — which would also refuse
`Authorization: Bearer sbh_<valid key>` on the Clerk-only route group, where it
is currently served as the default Owner and where `scripts/project-scope-e2e.sh`
and real CI jobs rely on it. That is a posture decision for the anonymous mode as
a whole, not a bug in this change.

### 8.7 Correction to §8.2's per-route figure

§8.2 said splitting the counter per ROUTE would come to "roughly 4,300/minute".
Counted rather than estimated, from `cmd/server/main.go`: 38 rate-limited route
paths — 25 registered individually (16 on `standard`, 9 on `poll`) plus 8 on the
`/mcp` group and 5 on the two `/cli` groups — i.e. 9x300 + 29x60 =
**4,440 req/min** for a single API key. The conclusion is unchanged; the number
is now measured.

### 8.8 A malformed Bearer credential is now refused, not ignored

Found by review after §8.6, and the same fall-through reached through the
DELIMITER rather than the prefix.

`bearerAny` reported "no credential" for anything after the scheme that was not
`<space>...`, and it stripped only SPACE when skipping the delimiter. A tab
therefore made a perfectly recognisable key look like the absence of one — and
absence, on a MultiAuth route in `SBOMHUB_AUTH_MODE=anonymous`, means the default
tenant's Owner. Measured on a throwaway stack (2026-08-04) with a
**project-scoped** key against a project in another tenant:

| header | before | after |
|---|---|---|
| `Authorization: Bearer<SP>sbh_<scoped key>` | 403 `forbidden` | 403 `forbidden` |
| `Authorization: Bearer<SP><HTAB>sbh_<same>` | **200 + that project's SBOM** | **401** `invalid API key` |
| `Authorization: Bearer<HTAB>sbh_<same>` | **200 + that project's SBOM** | **401** `invalid API key` |
| `Authorization: Bearer` (bare scheme) | served as the default identity | **401** `invalid API key` |

The rule is now in two parts, matching RFC 9110. Whether a request ANNOUNCED
Bearer is decided by the scheme name alone — an auth-scheme is an HTTP `token`,
so it ends at the first non-`tchar`, which makes `Bearer<HTAB>x` an announcement
with a bad delimiter while `BearerX x` remains a different scheme. Whether the
announcement carries a usable credential is then decided by `1*SP token68`. An
announcement that fails the second test is **presented but unusable**, which every
window turns into 401 instead of a default identity.

**What operators may need to change.** Nothing for a well-formed client:
`Bearer <token>` with one or more spaces and a `token68` credential is unaffected,
and both credential kinds this product accepts are `token68` by construction (an
`sbh_` key is `sbh_` + hex; a Clerk JWT is base64url segments joined by `.`).
Requests that will newly receive 401 rather than being served as the default
tenant: a tab anywhere in or before the credential, a bare `Bearer`, whitespace
or control characters inside the token.

One further tightening falls out of it: `Authorization: Bearer` followed by a
second `Authorization: Bearer <token>` is now **ambiguous** (a credential
announced twice with different content) and answers 401, where the bare value
used to be invisible.

### 8.9 Correction to §8.4 on repeated `Authorization` headers

§8.4 said "If a client of yours relies on a repeated `Authorization` header […]
it will now receive 401." That is wider than what the code does and would send an
operator looking for a client that does not exist.

What is refused is a repeated header whose values are **different**. Identical
repeats are one credential sent twice, which says nothing conflicting, and they
authenticate exactly as a single header does — `pickSingleCredential` returns
early only when a second DISTINCT value appears. The §8.4 table row should be
read as "two **different** `Authorization` values".

(§8.8 adds one shape to the "different" set that was previously invisible: a bare
`Authorization: Bearer` alongside a real one now counts as two different values.)

### 8.10 Two more corrections, both to §8.8/§8.9's wording

Neither changes behaviour; both are places where the guide claimed more than the
code does. Measured against the shipped build on a throwaway stack (2026-08-05).

**§8.9 said "different `Authorization` values" are refused. It is narrower than
that: two distinct BEARER candidates are.** A value that is not a Bearer
credential at all — a different scheme, or an empty value — is not a candidate,
so it cannot conflict with anything:

| headers | result |
|---|---|
| `Authorization: Basic anVuaw==` + `Authorization: Bearer <valid key>` | **200** — one Bearer candidate |
| `Authorization:` (empty) + `Authorization: Bearer <valid key>` | **200** — one Bearer candidate |
| `Authorization: Bearer <key A>` + `Authorization: Bearer <key B>` | **401** — two distinct candidates |

**§8.8 said a tab "anywhere in or before the credential" newly returns 401.
Only *before* it is new.** A tab AFTER the recognised `sbh_` prefix —
`Bearer sbh_ab<HTAB>cd` — already matched the prefix before this change, went
down the API-key path, failed validation and answered 401. What changed is the
values that previously escaped API-key classification altogether and were served
as the default identity: a bad delimiter, a bare scheme, or a credential whose
first four characters are not `sbh_` in some casing.
