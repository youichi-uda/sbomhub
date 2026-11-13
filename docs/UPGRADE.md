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
> (`.github/workflows/sbom-upload.yml`), which never turned a run red for two
> independent reasons: it carried `continue-on-error: true`, and its `curl` had
> no `--fail` flag, so an HTTP refusal exited 0 and the `echo` after it ran
> anyway. (The step could still have failed on a transport error, so neither
> reason was redundant.) Both were removed and the two calls now compare their
> status exactly (200 / 202). The route now sits on the same MultiAuth →
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
> **Operator action.** A tenant-level key is unaffected by the scope table
> entirely, and no key loses access to any route it could already use *as a
> key*. But in `SBOMHUB_AUTH_MODE=anonymous` this route is now STRICTER than it
> was, because the header it used to ignore is now read (Codex round 5 caught an
> earlier version of this note claiming otherwise). Measured on a throwaway
> stack 2026-08-05 against a default-tenant SBOM, pre-fix binary → post-fix
> binary:
>
> | credential on the scan call | before | after |
> |---|---|---|
> | read-scoped (Viewer) `sbh_` key | 202 | **403** |
> | unknown / stale `sbh_` value | 202 | **401** |
> | no `Authorization` header | 202 | 202 |
>
> The old behaviour was that `Auth()` ignored the header and served the request
> as the default tenant's Owner, so the key was never consulted. If a
> self-hosted CI job passes a read-scoped or stale key to this route, it was
> succeeding by accident and will now fail — give it a write-scoped key.
> One further caveat if you use the shipped workflow — take the workflow and the server
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

---

## 9. Vulnerability scanning now looks at far more of NVD and JVN (M55)

Three independent truncations were removed. Every one of them was silent: the
scan reported `completed` while having examined a small fraction of what the
upstream catalogue held. **Expect the number of findings to rise, in some cases
by two orders of magnitude, with no change to your SBOM.**

Nothing here is a schema change except migration 066 (§9.4).

### 9.1 NVD: the first 20 matches were the only matches

`searchByKeyword` asked NVD for `resultsPerPage=20`, read the first page, and
returned. `totalResults` and `startIndex` were both present in the response and
both ignored, so anything past the twentieth match was discarded with no log
line and no error.

Measured against live NVD on 2026-08-11:

| keyword | matches | seen before | seen now |
|---|---|---|---|
| `jackson-databind 2.9.10` | 44 | 20 | 44 |
| `libxml2 2.9.10` | 4 | 4 | 4 |
| `openssl 1.1.1k` | 2 | 2 | 2 |

The scanner sends `name` **and** `version`, and NVD treats the words as an AND,
so a versioned component matches tens of records, not thousands. Raising the
page size to 200 therefore returns every match for a realistic component **in
the same single request** — the rate limit is charged per request, not per
record, so a 500-component SBOM still costs 500 requests and takes the same
time it did before.

Components with no version are the exception (`openssl` alone matches 563,
`linux` matches 21,670). Those are capped at 5 pages / 996 records and reported
as truncated rather than fetched — see §9.3.

### 9.2 JVN: only the last seven days, ten at a time

Three defects compounded:

- **No date range was sent.** MyJVN defaults `rangeDatePublic`,
  `rangeDatePublished` and `rangeDateFirstPublished` to `w` — the current day
  plus six. Anything older was invisible.
- **`maxCountItem=10`, `startItem` never sent.** The response's `totalRes` was
  ignored.
- **The page was never identified.** MyJVN returns `firstRes` (where this page
  starts) and `totalResRet` (how many entries it holds); neither was checked, so
  a response that was short of its own declared length was accepted as complete.

Measured coverage before the fix, against corpora sized from live `totalRes`:

| keyword | catalogue | retrieved before | retrieved now |
|---|---|---|---|
| `openssl` | 459 | 1 (0.2%) | 459 |
| `glibc` | 158 | ~3 | 158 |
| `linux` | 17,622 | 2 (0.011%) | 500, reported truncated |

The request now sends `rangeDate*=n` (no range) and `maxCountItem=50` (the API
maximum), and pages up to 10 pages per component with an additional sweep-wide
pool of 500 pages shared across components. Page identity is verified on every
response.

**Note that MyJVN ORs the keyword words rather than ANDing them** — measured:
`glibc` = 158, `2.31` = 40, `glibc 2.31` = 198. Adding the version therefore
widens the result set. The scanner deliberately sends the component name only.

### 9.3 What "completed" means now, and a CLI exit-code change

When a component's matches exceed the budget, the scan no longer pretends to be
complete. The truncation propagates through `ScanComponents` to
`ScanTracker.MarkFailed`, so `GET /projects/:id/sboms/:sbom_id/scan-status`
reports `failed` and the MCP server reports `counts_final: false`.

**This changes `sbomhub scan --fail-on <severity>`.** A truncated sweep is
reported as a failed scan, so the CLI exits **2** (scan did not complete) rather
than **1** (threshold exceeded), even when the records it did retrieve contain a
finding above your threshold. Both are non-zero, so a plain `set -e` CI step
still fails; a pipeline that branches on the specific code needs updating.

The trade was made deliberately: a partial answer must not be readable as a
clean one.

### 9.4 CVE metadata is now refreshed (migration 066)

`cve_sync` already updated `description`, `severity` and `cvss_score` on rows it
matched, but three classes of row were frozen forever:

- CVEs whose NVD record carries no CPE (the keyword set came out empty),
- rows whose `source` was `JVN`,
- **any row, when an older record arrived after a newer one** — there was no
  staleness comparison at all, so a replayed old record silently downgraded a
  CRITICAL back to LOW.

Migration 066 adds `vulnerabilities.source_modified_at`, holding upstream's
`lastModified`. A write is now accepted only when the incoming record is
strictly newer than what is stored, or when nothing is stored.

**Existing rows are not frozen by this.** `source_modified_at` is NULL for every
row that predates the migration, and NULL is treated as "unknown, therefore
writable" — the first sync after upgrading refreshes those rows and stamps them.
Verified with 25 legacy rows: all 25 refreshed and stamped in one tick, and a
replay of the older record afterwards downgraded none of them.

What is still not reached: a CVE that NVD has not modified since the sync
watermark. The delta feed never mentions it, so its stored metadata stands. Rows
in that state are identifiable with `WHERE source_modified_at IS NULL`; a bounded
reconciliation pass over them is future work.

The scanner remains a **pure linker** — it creates a row if the CVE is unknown
and links it to the component, and never rewrites metadata. Ownership of the
global catalogue row sits with `cve_sync` alone, which is what keeps a
per-tenant scan from writing global rows inside its tenant transaction.

`down` is safe: it drops only the new column, leaves all sixteen others intact,
and a new binary run against the rolled-back schema fails loudly on its first
catalogue write rather than silently writing unarbitrated metadata.

### 9.5 The NVD response cache is cold for one TTL after upgrade

`cache.NVDCachePrefix` changed from `nvd:vuln:` to `nvdv2:`. Entries written by
an older build are orphaned — nothing reads them and nothing deletes them — and
expire on their own 24-hour TTL. The first scan after upgrading refetches from
NVD instead of serving cache.

The reason is that both builds compose keys as `<prefix> + <component name>`,
and component names are arbitrary strings from an uploaded SBOM. Sharing a
prefix therefore means sharing a key space regardless of how either build
encodes the rest, which let a component named after a precomputed digest poison
the entry a newer build reads for an unrelated component. `nvdv2:` shares no
prefix with `nvd:vuln:`, so the two spaces are disjoint. (A bump to
`nvd:vuln:v2:` would *not* have achieved this — it is reachable from the old
scheme by naming a component `v2:...`.)

### 9.6 What this release does not fix

- **Matching precision is unchanged.** Both scanners match on keywords, not
  CPEs. Retrieving 459 JVN advisories for `openssl` instead of 1 surfaces the
  true positives that were being missed *and* the false positives that were
  always going to be there. CPE-based matching is the real fix and is not in
  this release.
- **Partial fetch failures are still reported as success.** Only a total failure
  escalates. The counts are now carried on `NVDScanReport` / `JVNScanReport`, but
  no threshold policy consumes them yet.
- **A single refused statement still discards a whole sweep.** The scanner writes
  inside the tenant transaction; one rejected row rolls back everything the sweep
  had written.
- **Components above the budget stay truncated** — `linux` and similar retrieve
  996 (NVD) / 500 (JVN) records and say so.

## 10. Client IP behind a reverse proxy: set `SBOMHUB_TRUSTED_PROXIES` (echo v4.16.3)

**Who must act:** anyone running the API behind nginx, Traefik, a load
balancer, or a PaaS router (Railway, Render, Fly, …). A directly exposed API
needs no change.

### 10.1 What changed

echo v4.16.3 fixes GHSA-246p-cpwv-v3jq / GHSA-99jh-6h7p-pp36. Before it, when no
IP extractor was configured, `c.RealIP()` took the client IP from
`X-Forwarded-For` / `X-Real-IP` **from any caller** — so any client could pick
the IP recorded in the audit log and pick its own per-IP rate-limit bucket.
From this release the client IP is the TCP peer address unless you name the
proxies you trust.

### 10.2 What you see if you do nothing

Behind a proxy, every request appears to come from the proxy:

- all clients share **one** per-IP rate-limit bucket (one noisy client can
  throttle everybody);
- every audit-log row, MCP audit row and CRA submission record carries the
  proxy's IP.

At startup the API logs which mode it is in, and in the direct mode it says to
set `SBOMHUB_TRUSTED_PROXIES` if you are behind a proxy.

### 10.3 What to do

Add your proxy's address to `.env`:

```bash
# nginx on the same host
SBOMHUB_TRUSTED_PROXIES=127.0.0.1,::1
# a reverse-proxy container with a fixed address
SBOMHUB_TRUSTED_PROXIES=172.18.0.10
```

- Prefer exact addresses. Every host inside a listed CIDR can make the API
  believe any client IP. Use a range only for a network from which nothing but
  the proxy can reach the API.
- Loopback, link-local and private networks are **not** trusted implicitly —
  only what you list.
- `X-Real-IP` is never used; configure the proxy to send `X-Forwarded-For`, and
  have the outermost proxy overwrite (not append to) any client-supplied value.
- A malformed entry refuses startup rather than silently trusting nothing.
- Each `X-Forwarded-For` entry must be a bare IP address (what nginx's
  `$proxy_add_x_forwarded_for` and most load balancers send). An entry with a
  port (`203.0.113.7:53123`) or an IPv6 zone is not parsed, and the request is
  attributed to the proxy's address instead.

`docker compose` passes the variable through from `.env` (`env_file`); no
compose edit is needed. See [configuration.md](./configuration.md#client-ip-and-reverse-proxies).

### 10.4 Other operator-visible dependency changes in the same release

- **CycloneDX 1.7 uploads now parse.** The previous `cyclonedx-go` rejected
  `specVersion: "1.7"` although format detection accepted it, so such uploads
  failed.
- **`lib/pq` 1.12 supports and tests PostgreSQL 14+ only.** Older servers may
  still work but are unsupported. The bundled compose uses 15; check an external
  database if you bring your own.
- **Go toolchain go1.26.10** for the API image and the CLI (17–19 reachable
  standard-library advisories fixed). Building from source needs go1.26.10, or
  an older Go 1.26+ with automatic toolchain download allowed (the default
  `GOTOOLCHAIN=auto`); with `GOTOOLCHAIN=local` on an older patch the build
  either fails or ships the unfixed standard library.
- **Next.js 16.4.5 / `@clerk/nextjs` 6.39.8** in the web image (unauthenticated
  RCE in the image-optimisation API and a Clerk middleware route-protection
  bypass were fixed upstream). Pull the new images.

## 11. CVE metadata refresh actually runs now, and the catalogue leaves the scan transaction (M57)

**Who must act:** nobody has to change configuration. Read §11.1 if you size
PostgreSQL `max_connections` tightly, and §11.2 because severities you see may
change after the first sync.

### 11.1 One more small connection pool per API process

The CVE catalogue insert a scan makes when it meets an unknown CVE
(`vulnerabilities`) no longer runs inside that scan's tenant transaction. Inside
it, the row was invisible to the daily CVE sync for the whole scan, was
discarded when the scan rolled back, and — when PostgreSQL refused it — aborted
the scan and discarded every finding the scan had already recorded. The
findings themselves (component ↔ CVE links) still commit all-or-nothing with the
scan, exactly as before.

The insert uses a separate pool of at most **4** connections (same
`DATABASE_URL`, same role), so a scan that holds a connection for its
transaction never waits on the pool it is holding. Each API process can
therefore open up to **29** PostgreSQL connections instead of 25.

Because a refused catalogue insert no longer discards the rest of a scheduled
scan, the scheduled scan's log now records `failed` whenever any project's scan
reported an error (it used to say `completed` and skip that project's count),
and the findings that did commit are counted in `new_vulnerabilities` and
passed to the notification step (which, as before, lists at most 20 recent
findings per project). Before, a project whose NVD lookups all failed was also logged
`completed`; it is now `failed` too.

### 11.2 Correction to §9.4: the refresh did not run on real NVD data

§9.4 says the first sync after migration 066 refreshes and stamps every legacy
row. That was verified only against test records whose timestamps carried a
`Z`. The NVD API sends them **without** an offset
(`"lastModified": "2026-08-11T19:33:44.513"`), and the sync parsed them with a
parser that required one. Every record it fetched was therefore treated as
undateable: **no existing row was refreshed**, the log carried one
`NVD record carries no believable lastModified; not written` warning per CVE
per tick, and every row the sync inserted got `published_at` and
`source_modified_at` NULL.

From this release the sync uses the scanner's parser, which reads NVD's
zoneless timestamps as UTC. It also now prefers NVD's own ("Primary") CVSS
assessment over a CNA's ("Secondary") one within each CVSS version, as the
scanner has since M54; before, whichever assessment NVD happened to list first
was taken, which could turn a Primary 9.8 CRITICAL into a Secondary 6.3 MEDIUM.
(The two still differ on which CVSS *version* wins when a CVE has both v4.0 and
v3.x: the sync prefers v4.0, the scanner v3.x.) The first sync after upgrading refreshes rows whose
CVE NVD modified inside its window; severities can change on that tick
(LOW → CRITICAL and vice versa) wherever NVD re-scored a CVE.

### 11.3 Each sync re-reads the last ~25 hours before its watermark

A scan can create a catalogue row from an NVD answer cached up to 24 hours
earlier. If the daily sync had already passed a newer record for that CVE while
the row did not exist yet, nothing offered it again. Each tick now starts its
window `NVD cache TTL + 1h` (25h) before the stored watermark (less only when
that would exceed NVD's maximum request span of ~110 days, in which case the
window is cut at the limit). Cost, measured 2026-11-08: NVD modified 1,156 CVEs
in the preceding 24h and 3,706 in the preceding 49h, so a daily tick goes from
one 2000-record page to two (11.4 MB / 2.8 s for a full page). A record seen
twice is refused the second time by the freshness guard, so the replay changes
nothing it has already applied.

What this does not cover:

- a race bounded to one sync interval: if NVD re-scores a CVE while a sync is
  still writing an older copy it fetched minutes earlier, and a scan creates the
  row from the newer copy in between, the sync's older copy is written; the
  next sync's window contains the newer record and repairs it;
- a scan that stalls for more than a day between looking a component up and
  writing its findings creates the row from data older than the overlap
  covers. Scans have no deadline of their own today.

### 11.4 Still not reached

Rows whose CVE NVD has not modified since well before the watermark — rows from
before migration 066 (including, because of §11.2, every row that existed when
you upgraded to M55), and rows the JVN scanner created with JVN's metadata —
keep their stored metadata until NVD next modifies the CVE. They are
identifiable with `WHERE source_modified_at IS NULL`. Fetching them by id is a
rate-limit budget decision and is not in this release.

## 12. Monthly full re-read of NVD's catalogue, and stricter page checks (M58)

**Who must act:** nobody. Read §12.2 if you point `SBOMHUB_NVD_URL` at a
mirror, and §12.1 if you meter outbound traffic.

### 12.1 What runs, and what it costs

§11.4 left one class of row unreached: CVEs NVD has not modified since well
before the daily sync's watermark keep whatever metadata they were stored
with. Measured 2026-11-08 against live NVD, that class is most of the
catalogue for anyone upgrading from M55/M56: 315,761 of NVD's 421,074 CVEs were
last modified between 2026-04-21 and 2026-08-09, while the sync's refresh was
not writing (§11.2).

The CVE sync now re-reads NVD's whole modification history in 110-day windows,
by default every 30 days, and refreshes every CVE already in your catalogue
through the same freshness guard as the daily sync (an older record never
overwrites a newer one). It never adds CVEs.

| | with `NVD_API_KEY` | without |
|---|---|---|
| requests per pass | ~300 (211 data pages + ~93 mostly empty windows) | same |
| transfer per pass | ~2.4 GB (2000-record page = 11.4 MB) | same |
| duration | ~20 min | a little over 1 h |

The first pass starts right after the first daily sync following the upgrade.

- Configure with `SBOMHUB_NVD_RECONCILE_INTERVAL` (`30d` default, `off` to
  disable; see [configuration.md](./configuration.md)). An unusable value
  stops the API at startup.
- It runs after the daily sync, never alongside it, at half its request rate,
  with a 6-hour deadline per run (each run follows a daily sync or a process
  start); a window cut off by the deadline is re-read whole by the next run.
- Progress and the last result live in the `system_settings` row
  `cve_catalogue_reconcile`. A restart resumes at the window it was in. A pass
  in which the database refused some rows finishes as
  `completed_with_write_failures` and names up to 20 of them; a window NVD
  could not serve leaves the pass in progress (logged at ERROR), and the next
  day retries from that window.

### 12.2 The daily sync now refuses a page that is not the page it asked for

Every page of NVD's modification feed must now carry `startIndex` and
`totalResults`, `startIndex` must be the one requested, and a page may not be
empty while `totalResults` says records remain. Before, a mirror that answered
every request with its first page made the sync stop early and skip the rest
of the window without any error. A mirror that omits `startIndex` now makes
the sync fail loudly (it is retried each day) instead of silently reading part
of the feed — fix the mirror rather than the check.

### 12.3 Not covered

- CVEs that exist only in JVN (JVNDB ids) — NVD has no record to re-read.
- Two API processes sharing one database each run the re-read (as they each
  already run the daily sync); they share the progress row, so they converge,
  but the NVD traffic doubles.
- Records that move between pages while a large window is being read are
  reached by the daily sync (if NVD changed them) or by the next pass.


## 13. NVD matching by CPE, and every finding says how it was matched (M60)

Until this release both scanners matched components to CVEs by **text search**:
NVD `keywordSearch` on `"<name> <version>"`, MyJVN `keyword` on the name. The
NVD scanner now matches by **CPE** when the SBOM gives the component one, and
checks every candidate CVE against NVD's own affected-configuration data. Every
component→vulnerability link now records **how** it was made.

Migration **067** adds `components.cpes` and `component_vulnerabilities.match_method`.

### 13.1 What "a match" means now

For each component with CPE names in the SBOM (Syft emits them; CycloneDX
`cpe` + `syft:cpe23` properties, SPDX 2 `cpe23Type`/`cpe22Type` externalRefs,
SPDX 3 `cpe23`/`cpe22` identifiers):

1. up to 3 distinct `part:vendor:product` candidates are tried, in SBOM order;
2. for a plain dotted-numeric version, NVD is asked
   `cpeName=<candidate at the component's version>`;
3. each returned CVE is **verified** against its `configurations`: it must have a
   `vulnerable: true` criterion for the same product whose version (or
   `versionStart*`/`versionEnd*` range) contains the component's version;
4. if that answer is empty — or the version is not plain dotted numbers
   (`1.1.1k`, `2.0-beta9`), whose encoding in NVD is ambiguous — NVD is asked
   for the whole product (`virtualMatchString=<part:vendor:product>`, same CPE
   page budget, see 13.5) and every record is verified the same way. No records → NVD does not
   know the product → the next candidate; no candidate known → the old keyword
   search. "No CVE at this version" therefore always comes from checking NVD's
   own configurations, never from an empty `cpeName` answer.

Step 3 matters: NVD's `cpeName` also returns CVEs in which the product is only
the **platform** something else runs on. Measured 2026-11-08: openssl 1.1.1k →
5 of 47 (Mutt, Apache httpd); Linux 5.10.46 → 504 of the first 997 (Flash
Player "on Linux" and similar). Those are now dropped.

Step 4 matters too: NVD answers `cpeName` with an ordinary empty result, no
error, both for a product it has never heard of and for a version written
differently from NVD's encoding of the release (NVD stores log4j 2.0-beta9 as
version `2.0` + update `beta9`). Syft's first CPE guess is often such a
product (`apache:log4j-core`; NVD's product is `apache:log4j`, Syft's third
guess), so trusting the first candidate would have turned a wrong guess into a
silent "no vulnerabilities".

Versions are normalised before matching: a leading `v` is dropped (Go modules;
`v0.7.0` matches nothing in NVD, `0.7.0` does), and for **distro packages**
(purl type `deb`, `rpm`, `apk`, `alpm`) the epoch and distro revision are
dropped (`1.1.1k-1+deb11u2` → `1.1.1k`).

A version comparison may **exclude** a CVE only when the component version, as
the SBOM states it, and every version the NVD criterion involves are **plain
dotted-numeric** (`2.14.1`, `v0.7.0`; no letters, no `-`, `+`, `~`, `!`, `^`,
`_`, and no pinned CPE update other than ANY/NA). In every other case — OpenSSL
letter releases (`1.1.1k`), pre-releases (`2.0-beta9`), distro versions
(`1.1.1k-1`), `+build` metadata, criteria that pin an update (`log4j:2.0:beta9`)
— the CVE NVD returned is **kept** and labelled `nvd_cpe_unverified` (low
confidence), and that answer is not cached. A gap in version comparison
therefore never drops a CVE; it only lowers a label. Records that name the
product only as a `vulnerable: false` platform are still dropped (no version
comparison is involved). Non-plain versions skip the exact `cpeName` query and
walk the whole product, because NVD's own `cpeName` answer for such versions can
be incomplete (measured: for log4j `2.0-beta9` it omitted Log4Shell).

### 13.2 `match_method` / `match_confidence`

| `match_method` | `match_confidence` | meaning |
|---|---|---|
| `nvd_cpe` | high | CPE match verified against NVD configurations |
| `nvd_cpe_distro` | medium | same, for a distro package, on the **upstream** version — a fix the distro backported without changing the upstream version is NOT seen, so these can be false positives |
| `nvd_cpe_unverified` | low | NVD returned the CVE for the component's CPE, but no plain version comparison could confirm or exclude it (non-plain component version or bound, pinned update, or absent configurations). Kept rather than dropped; 315 in the measurement below |
| `nvd_keyword` | low | NVD text search (no usable CPE) |
| `jvn_keyword` | low | MyJVN text search on the component name |
| `cve_sync_keyword` | low | the daily CVE-sync linker (product names vs component names) |
| *(absent)* | unknown | link made before this release |

`GET /api/v1/projects/:id/vulnerabilities` returns both fields per CVE (the
strongest method among the SBOM's links to it). A link is relabelled only
upward: a later CPE match upgrades a keyword or pre-067 link, a keyword match
never downgrades a CPE one.

**Low-confidence findings are still findings.** Nothing previously linked is
dropped, and keyword links are still counted by `--fail-on` and in reports.
They are labelled so they can be triaged as candidates.

### 13.3 Expect NVD finding counts to go UP, not down

The keyword search was mostly *missing* things, not over-matching: NVD ANDs the
words, and the version string rarely appears in a CVE description. Measured on
2026-11-08 against live NVD (fixture: real Syft 1.46.0 output for a Debian 11
tree + Maven/npm/Go manifests, plus a kernel and glibc component; ground truth
OSV for Maven/npm/Go, openssl.org's 1.1.1 advisory list for OpenSSL):

| component | ground truth | NVD links before | NVD links after (true) | labels after |
|---|---|---|---|---|
| log4j-core 2.14.1 | 8 | **0** (Log4Shell missed) | 10 (8) | 10 nvd_cpe |
| tomcat-embed-core 9.0.30 | 51 | 0 | 77 (50) | 76 nvd_cpe + 1 unverified |
| lodash 4.17.20 | 4 | 1 (0) | 5 (4) | 5 nvd_cpe |
| golang.org/x/net v0.7.0 | 24 | 0 | 2 (2) | 2 nvd_cpe |
| gin v1.7.0 | 3 | 0 | 2 (2) | 1 nvd_cpe + 1 unverified |
| openssl 1.1.1k-1 (deb) | 49 | 0 | 313 (44) | 313 nvd_cpe_unverified³ |
| glibc 2.31 | 26¹ | 3 (0) | 26 (26) | 26 nvd_cpe |
| libc6 2.31-13 (deb) | 26¹ | 0 | 0 | keyword fallback |
| linux kernel 5.10.46 | 7,059² | 0 | 6,552, complete | 6,550 nvd_cpe + 2 unverified |

¹ NVD's own configurations — not an independent source. ² NVD's count; not
verified independently. ³ `1.1.1k-1` is not a plain version, so no version
comparison may exclude anything (13.1): every openssl CVE NVD configures is kept
except the 8 that name openssl only as a platform. 44 of the 313 affect 1.1.1k
per openssl.org — two more than the exact `cpeName` answer contained.

Across the components with ground truth: **before 4 links, 0 true; after 435
links, 136 true (precision 31%, recall 71%)**. Counting only verified
(high/medium-confidence) links: **120 links, 91 true (precision 76%, recall
48%)**. The 315 `nvd_cpe_unverified` links hold 45 true findings and 270 false
ones, almost all from the Debian openssl package; they are candidates to triage,
not confirmed findings. Verified false positives are mostly NVD's product
granularity (NVD's `apache:tomcat` covers server-only issues that do not affect
the embedded jar); the remaining misses are CVEs NVD has not configured
(golang.org/x/net: NVD's CPE data covers 2 of 24) and packages whose CPE Syft
could not guess (Debian `libc6`).

JVN matching is **unchanged** (see 13.6), so the JVN half of the counts does not
move; it is now labelled `jvn_keyword`.

### 13.4 Existing SBOMs keep matching by keyword until re-uploaded

CPE names are read at import time. SBOMs uploaded before this release have no
stored CPEs, so scheduled re-scans of them keep using the keyword search
(`nvd_keyword`), and their existing links show `unknown` until a scan
reproduces them. **Re-upload an SBOM to get CPE matching** — this release
does not backfill CPEs into existing SBOMs. Re-scans add links;
they never remove one, so a stale keyword link stays until the SBOM is
replaced.

### 13.5 Cost, truncation and the kernel

- **Requests.** Per CPE candidate: a plain dotted-numeric version asks
  `cpeName` first (1 request per page of answers); if that is empty, or the
  version has letters/qualifiers (`1.1.1k`, `2.0-beta9`), the whole product is
  walked (1 request per ~200 of the product's CVEs, up to the 60-page CPE
  budget below). An
  unknown product therefore costs 2 requests with a plain version and 1
  otherwise, and a known product whose exact version has no CVE costs 1 plus
  its product walk. Maven packages where Syft guesses `apache:log4j-core` first
  cost up to 5.
  The fixture above (measured 2026-11-08, no API key) took **68 NVD requests and
  14 min 24 s** for 13 components on a cold cache — the kernel's 36 pages
  dominate, and NVD itself took 15-36 s to answer each deep kernel page — and
  **40 requests / 4 min 54 s** on the next scan. The 24-hour cache holds
  verified answers and "unknown product" answers, but not truncated answers or
  answers holding an `nvd_cpe_unverified` CVE; here that is the kernel (36
  pages, 2 unverified CVEs) and openssl (2 pages), re-fetched on every scan.
  Before M60 the same SBOM cost 14 requests (one keyword walk each, two pages
  for one of them). Without an NVD API key the limiter allows one request per
  6 s.
- **Truncation and the CPE page budget.** The keyword path keeps its budget of
  5 pages / 996 records. The CPE path has its own, larger budget of **60 pages
  / 11,941 records**, sized for a full Linux kernel: NVD lists 7,059 CVEs for
  kernel 5.10.46 (measured 2026-11-08), which is 36 pages, plus headroom
  because kernel CVE counts grow quickly. A kernel component is therefore no
  longer reported truncated; an answer larger than 11,941 records still is, and
  the scan is then reported **failed / truncated** as before.
- **Scan time for a kernel.** Every page is one NVD request and goes through
  the same rate limiter as every other request, so NVD's published rate limit
  is respected however many pages a component needs. A full kernel costs ~36
  requests: **about 3.6 minutes without an NVD API key** (6 s per request) or
  ~25 s with one, plus NVD's own response time: deep kernel pages took 15-36 s
  each in the measurement above. The worst case, a 60-page answer, is 6 minutes
  / 42 s of pacing plus NVD's time. The per-request client timeout was raised
  from 30 s to **60 s** because one kernel page took 35.8 s at NVD; if a page
  still fails partway through a CPE walk, the pages already verified are kept
  and the component is reported truncated (the scan reports failed) rather
  than losing every finding. There is no overall scan deadline (this
  predates M60), and the scan's database transaction stays open for the whole
  sweep, so a kernel lengthens it by that much. A complete answer is cached for
  24 h unless it holds an `nvd_cpe_unverified` CVE; truncated answers never are.
- **SPDX 2 purls.** The SPDX 2 importer never stored a package's purl (it read
  the `externalRefs` array as if it were a string). Purls are now stored, which
  also changes VEX purl matching and the reachability ecosystem for SPDX 2
  uploads.

### 13.6 JVN: why it was not changed

MyJVN's API (and all of JVN iPedia except the RSS data feeds) has been **out of
service since 2026-10-22**: JPCERT/CC's notice of that date
(https://jvn.jp/nav/info2026102281.html) says the resumption date is
undetermined. (An earlier edition of this section said the notice expected
service to resume in November; it does not.) See §26 for how the outage is
reported. While it is down, every JVN lookup
fails and every online scan that looks up at least one component in JVN
(not with `SBOMHUB_OFFLINE=true`) is reported `failed` ("jvn: scan
failed"); NVD's links are still committed. Nothing in this release changes that.

MyJVN's `cpeName` parameter therefore could not be measured, and per this
project's rule it is not used. Measured offline against the JVNDBRSS feeds
instead: the JVN overview carries product-level CPEs with **no version ranges**,
so filtering JVN results by product would raise openssl's precision only from
9% (48 true of 508) to 16%, and it would have dropped both true x/net
advisories. JVN results stay keyword matches, labelled low confidence.

### 13.7 Rollback

`067_component_cpes_and_match_method.down.sql` drops both columns. The stored
CPE names come back on re-upload; the link methods do not (all return to
`unknown`). Roll the binary back with the schema: this release writes both
columns.

## 14. Web UI dependency majors and Node.js 22 image

The web image (`apps/web/Dockerfile`) now runs on `node:22-alpine`; it previously
used `node:20-alpine`, which is end-of-life. Root `package.json` `engines.node`
is now `>=22.18.0`. If you build or run the web app outside Docker, upgrade
Node.js to 22.18 or newer first.

The web UI moved to Tailwind CSS 4, lucide-react 1, TypeScript 6 and
Clerk 7 (`@clerk/nextjs` 7 / `@clerk/localizations` 4). What changes for operators:

- **Appearance.** The UI looks the same as before, apart from two things. The
  landing hero is slightly taller: v4 now honours its `leading-tight`, which
  v3 silently overrode. Icon shapes also follow upstream lucide redesigns. No
  icon was removed.
- **Browser support.** Tailwind CSS 4 needs Safari 16.4+, Chrome 111+ or
  Firefox 128+. Older browsers render the UI incorrectly.
- **Touch devices.** Hover styles now only apply on devices that support
  hover, so they no longer stick after a tap.
- **Clerk mode.** No environment variables changed. The web server logs a
  Clerk "`createRouteMatcher` is deprecated" warning. It is expected and
  harmless: the matcher behaves the same, and CI pins the public/protected
  route classification (`apps/web/src/proxy.public-routes.test.mjs`).
  `CLERK_ENCRYPTION_KEY` is not needed, because SBOMHub does not pass
  `secretKey` to `clerkMiddleware`.
- **Open Graph images** now render on the Node.js runtime instead of the
  deprecated Edge runtime. Output is the same: PNG, 1200×630.

Not upgraded:

- **ESLint 10.** It waits for `eslint-plugin-react`, `eslint-plugin-import` and
  `eslint-plugin-jsx-a11y` to support it.
- **TypeScript 7.** It waits for `typescript-eslint` and Next's build
  typecheck to support it.

## 15. Scans no longer hold a database transaction, have a deadline, and report partial failure (M62)

**Who must act:** nobody has to change configuration. Read §15.2 if you run
without `NVD_API_KEY` and scan large SBOMs, and §15.3 if a CI step branches on
`sbomhub scan` exit codes or on the scheduled scan log.

### 15.1 No transaction is open while a scan waits on NVD or JVN

Until this release every vulnerability scan — after an upload, from
`POST /api/v1/projects/:id/scan`, and the scheduled scan (which wrapped *every
project of a tenant* in one) — ran inside one tenant transaction for its whole
duration, including every NVD/JVN request. For a cold scan without an API key of
an SBOM holding a Linux kernel that was about 14 minutes (§13.5). Measured on
PostgreSQL 15 with the pre-release code, while a scan waited on NVD the API held:

- one connection of its 25-connection pool `idle in transaction`, with a
  transaction id assigned (it holds back VACUUM's cleanup horizon);
- 32 locks: `AccessShareLock` / `RowShareLock` on `components`,
  `vulnerabilities` and their indexes (any migration or `ALTER TABLE` on them
  queued behind the scan, and every query queued behind that), a
  `RowExclusiveLock` on `component_vulnerabilities`, the row locks of the links
  already written and the foreign-key share locks on the rows they reference;
- no advisory lock.

Scans now read the SBOM's components in a short transaction, talk to NVD/JVN
with **no transaction open**, and write their findings in one short transaction
per scanner at the end. Measured with the same probe after the change: no
app-role backend in a transaction and no locks held while NVD was blocked; the
write transaction for 2,437 links took 0.2-0.4 s.

Consequences you can observe:

- `GET .../scan-status` counts change twice per scan (after NVD, after JVN)
  instead of once at the end. As before, trust them only once `status` is
  `completed`.
- A single refused database write now costs only the component it belongs to,
  not the whole scan (each component's links are written under their own
  savepoint). The scan is still reported failed (`write_refused`). This closes
  the §9.6 item "a single refused statement still discards a whole sweep".
- Two scans of the same SBOM (an upload scan and a manual one, or two replicas)
  now take a per-SBOM advisory lock for their write phase, so they cannot
  deadlock on each other's links, and the scheduled scan's
  `new_vulnerabilities` cannot count another scan's findings. (Measured with the
  lock removed: in 3 runs of two simultaneous scans, one aborted with a refused
  write and two counted every new finding twice; with the lock, 0 of 6.)
- Webhook/e-mail notifications from the scheduled scan are sent one finding per
  short transaction instead of inside the tenant-wide one.

### 15.2 Overall scan deadline: `SBOMHUB_SCAN_DEADLINE` (default `30m`)

A scan (NVD then JVN, for one SBOM; per project for the scheduled scan) now has
a deadline. Default 30 minutes, accepted `1m`-`24h`; anything else, including
`off`, stops the API at startup.

Why 30 minutes: the slowest scan measured — cold, no API key, SBOM with a
Linux kernel — took 68 NVD requests and 14 min 24 s against live NVD
(2026-11-08). A replay of the same fixture against this release (recorded NVD
answers, plus a synthetic 7,059-CVE kernel answer served as 36 pages at 17 s of
latency each; no key) took 71 requests and 13 min 49 s (2026-11-09), during
which the longest app-role transaction observed was 2.0 s (the final write of
7,496 links took 0.64 s).
Without a key NVD requests are paced at 6 s, so 30 minutes holds fewer than
300 requests; a component costs one request on the keyword path and typically
1-5 on the CPE path, so **an SBOM beyond roughly 100-250 distinct components
needs `NVD_API_KEY` (0.7 s per request) or a longer deadline.**

When the deadline fires:

- findings obtained before it are committed; a CPE page walk it interrupts keeps
  the pages already validated and is reported truncated;
- nothing partial is cached as a complete answer (truncated and interrupted
  answers are never cached);
- the scan is reported failed: `scan-status` returns `"status": "failed"`,
  `"error": "nvd: scan failed (deadline_exceeded, ...)"` and
  `"reasons": ["deadline_exceeded", ...]`; JVN is not started if NVD used up the
  deadline; the scheduled scan's log reads `scan failed (deadline_exceeded)`;
- the API logs `WARN scan: overall scan deadline exceeded` with the deadline and
  elapsed time.

The in-memory scan-status tracker keeps a running scan's entry for at least the
deadline plus 15 minutes (it was a fixed hour), so a long deadline does not turn
into `unknown` while the scan is still running.

### 15.3 Partial lookup failures fail the scan; the manual route reports status

**Behaviour change.** Until now a scan in which *some* component lookups failed
(NVD/JVN 5xx, timeouts) was reported `completed` — only a total failure was
escalated (§9.6). It is now reported `failed` with reason `fetch_failed`, on
NVD and JVN alike; the findings of the components that did answer are still
committed. As with truncation (§9.3), `sbomhub scan --fail-on <severity>` exits
**2** instead of 1 or 0 for such a scan, and the scheduled scan log records
`failed`. A scan interrupted before it looked every component up (deadline,
shutdown) was also reported `completed` before; it is now `failed`
(`deadline_exceeded` / `cancelled`).

While MyJVN is out of service (§13.6) every scan that includes JVN keeps
reporting `failed` (`jvn: scan failed (fetch_failed)`), as before.

`POST /api/v1/projects/:id/scan` now records its outcome where the upload scan
does: poll `GET /api/v1/projects/:id/sboms/:sbom_id/scan-status` after the 202.
It reads `running` immediately, then `completed` or `failed` with `reasons`. The
202 body gained `status_url` (the path to poll). Before this release the route's
outcome reached the server log only.

API response changes are additive only: `scan-status` gained `reasons`
(present only when `status` is `failed`), the scan route's 202 gained
`status_url`; no field was renamed or removed. The `error` string now carries
the reason codes in parentheses (`nvd: scan failed (fetch_failed)`); it still
starts with `<scanner>: scan failed`.

Reason codes: `deadline_exceeded`, `cancelled`, `fetch_failed`, `truncated`,
`write_refused`, `scan_error`.

### 15.4 Not covered

- A scheduled scan of a tenant with many projects is bounded per project, not
  per tenant run.
- Two concurrent scans of one SBOM still both fetch from NVD (only their writes
  are serialised). `scan-status` stays `running` until both have finished and
  is then `failed` if either failed.
- A notification's webhook / mail delivery still runs inside that one
  notification's short transaction (the notification log row is written in it).
- The scan-status tracker is still in-memory per API process, so a manual scan
  on one replica and a poll on another still read `unknown`.
- The deadline bounds fetching. A scan that fetched everything in time but
  whose final write finished after the deadline (it waits at most 5 minutes)
  has complete results and is reported `completed`.

## 16. Go 1.27 toolchain and access-log format

**Who must act:** operators who build the API from source, and anyone who parses the API's access log.

- **Go toolchain go1.27.3** for the API image (`golang:1.27.3-alpine`) and the
  release `llm-bench` binaries. Building from source needs go1.27.3, or any
  Go 1.26.1+ with automatic toolchain download allowed (the default
  `GOTOOLCHAIN=auto`). With `GOTOOLCHAIN=local` on an older Go the build still
  works (the `go` floor is unchanged at 1.26.1) but does not use the pinned
  1.27.3 standard library.
- **The access log is now a slog JSON line** on stdout, alongside the rest of
  the server log (`"msg":"http request"`), replacing echo's own JSON line:
  - `uri` is the path only. The query string is no longer logged, and
    public-link tokens are redacted (`/api/v1/public/[REDACTED]`). The matched
    route template is in the new `route` field.
  - `id` is renamed `request_id` and only appears when the request carries
    `X-Request-ID`.
  - `error` no longer contains the error text: it is `http_error code=<status>`
    for HTTP errors, otherwise the Go error type chain (for example
    `*fmt.wrapError > *url.Error > *net.OpError`). 5xx details are still logged
    separately as `"http 5xx error"`.
  - 5xx requests are logged at ERROR, everything else at INFO. `method`,
    `status`, `latency` (ns), `latency_human`, `remote_ip`, `host`,
    `user_agent`, `bytes_in`, `bytes_out` keep their names and types.

## 17. Safer 5xx log, SBOM version checks, Redis timeouts, migration lock (M64)

**Who must act:** anyone who parses the `"http 5xx error"` log line; anyone who uploads CycloneDX without `specVersion` or SPDX with a non-standard `spdxVersion`; operators running more than one API replica (no action, but read §17.4).

### 17.1 The `"http 5xx error"` log line carries no error text

The server's 5xx record used to include `detail` (the HTTP error message) and `internal` (the wrapped error) verbatim. Error text can carry credentials: a DSN with its password, an outbound URL with a token, and `*url.Error`, which repeats the whole URL. The line now mirrors the access log (§16):

- `error` is a classification: `http_error code=<status>` plus the internal error's Go type chain (`internal=*fmt.wrapError > *url.Error > *net.OpError`), or the type chain alone for a plain error.
- `message_error` (only when the HTTP error's message is itself an error) is that error's type chain.
- `method`, `route` (the route template, replacing `path`, which already held the template), `status`, `request_id` (when the request carried `X-Request-ID`).
- `detail` and `internal` are gone. The level is now ERROR (was WARN).
- A plain (non-HTTP) handler error, which echo answers with 500, is now logged too. It wasn't logged here before.

To debug a 5xx, match `request_id` / `route` with the access log. Handlers that need the error text must log it themselves, scrubbed.

### 17.2 Unsupported SBOM spec versions are refused with 400

The SBOM spec version is now checked when the format is detected, before anything is stored:

- CycloneDX: `bomFormat` must be exactly `"CycloneDX"`. `specVersion` must be a version that the bundled cyclonedx-go supports and that has a JSON format, currently 1.2–1.7. If it is missing, not a string, unknown (e.g. `"1.8"`) or one of the XML-only versions 1.0 / 1.1, the upload gets a 400.
- SPDX 2: `spdxVersion` must be `SPDX-2.0` … `SPDX-2.3`. A bare `"2.3"` and `"SPDX-3.0"` are now refused. Before, `"SPDX-3.0"` was sent to the SPDX 3 parser and silently produced zero components. `packages`, when present, must be an array of objects. `null`, a number or a non-object entry used to be stored as an SBOM with zero components.
- SPDX 3: `@context` must start with `https://spdx.org/rdf/3` (or `http://`), and its release segment must be `3.0` or `3.0.1`. Before, `3.0.2` was labelled `3.0`.
- CycloneDX `components`, when present, must be an array of objects, and every top-level component must have a `name`, as the schema requires. `null`, `[null]` and nameless components used to be stored as empty components. Nested component trees are still not read.
- Components are now parsed before the SBOM row is written. An upload that fails parsing therefore leaves nothing stored. Before, the row could be inserted ahead of the 400.

The 400 message names the field, the value sent and the accepted versions, e.g. `failed to parse SBOM: unsupported SBOM spec version: CycloneDX specVersion "1.8" (supported: 1.2, 1.3, 1.4, 1.5, 1.6, 1.7)`. The CLI upload path returns the same text after `failed to detect SBOM format:`. Syft, Trivy and cdxgen output is unaffected.

### 17.3 Redis client timeouts

The API now sets explicit go-redis timeouts unless `REDIS_URL` sets them: `dial_timeout=3s`, `read_timeout=2s`, `write_timeout=2s`, `pool_timeout=3s`. These were go-redis's implicit 5s / 5s / 5s / 6s. A query parameter in `REDIS_URL` still wins. Automatic command retries are now off: go-redis's default of 3 retries could replay an `INCR` or rate-limit script whose reply was lost, charging one request several times. `max_retries` in the URL overrides this. Call sites now also bound every operation: rate-limit bookkeeping 3s, NVD cache 1s per round trip, startup ping 5s. Before, the API-key limiter used the request context, which has no deadline, and the public-link limiter's 3s deadline was ignored for socket I/O.

When Redis is down or hung:

- API-key rate limiting answers 500.
- Public-link rate limiting answers 503.
- The NVD cache counts as a miss.
- Startup fails within ~5s.

The API-key rate limiter now charges its per-window bucket and sets the bucket's TTL in one Lua script. Before, these were two calls, and a lost `EXPIRE` left the counter without a TTL.

### 17.4 Migrations take an advisory lock

The startup auto-migration and `cmd/migrate up|down|status` now hold a session-level PostgreSQL advisory lock for the whole run. Replicas that boot together against one database therefore migrate one after another. Before, two replicas on an empty database failed with `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`.

A waiting migrator logs `waiting for migration lock held by another migrator` every 10s with the holder's pid / application / client address. The whole acquisition is bounded by that wait: getting a database connection, each poll, and a grant that arrives after the deadline is handed back. After 10 minutes it gives up with `migration lock: another migrator (...) still held it after 10m0s`. The process then exits and the orchestrator restarts it. The migrator role needs no new privileges: advisory locks need none.

### 17.5 Web: react-query data loading (Clerk mode only)

Web pages now load their data through react-query. Self-hosted deployments
see no difference. In Clerk mode, switching organisation now shows a brief
"Loading..." screen and reloads the dashboard. Before, the previous
organisation's data could stay on screen until the next fetch.

## 18. Input validation, CRA 72h reports, NVD search status codes (M66)

**Who must act:** clients that send project names with control characters or
descriptions over 1000 characters; anyone who branches on the status of
`GET /api/v1/search/cve`; operators rolling back past migration 068.

### 18.1 72h CRA reports work (migration 068)

`cra_reports.report_type` was VARCHAR(20), but its CHECK allows
`detailed_notification`, which is 21 characters, so every 72h report failed
with 500. Migration 068 widens the column to VARCHAR(32).

- **Upgrading** does not rewrite the table. One scan re-checks the CHECK: 25 ms
  for 300k rows on PostgreSQL 15. The migration bounds its lock wait (5s) and
  its run time (60s).
- **Rolling 068 back** rewrites the table and is refused while any 72h report
  exists. Export and remove those reports first, or stay on 068.

### 18.2 Text in JSON request bodies

A JSON request body now gets 400 `invalid request body: <reason> at offset N`
when it:

- is not valid UTF-8,
- contains U+0000 (raw or `\u0000`), or
- contains an unpaired UTF-16 surrogate escape (`\ud800`).

Before, U+0000 and lone surrogates failed in PostgreSQL with 500, and invalid
UTF-8 was silently stored as U+FFFD. SBOM uploads (`POST /projects/:id/sbom`,
`POST /cli/upload`) get the same check whatever the Content-Type, and answer
400 `failed to parse SBOM: ...`. On a 10,000-component SBOM the check costs
about 1-2% of parse time.

### 18.3 Project name and description

These rules apply to `POST /api/v1/projects`, `POST /api/v1/cli/projects` and
the create path of `POST /api/v1/cli/upload`:

- `name` must not be blank. It may be at most 255 characters, the column's
  limit; longer names used to fail with 500. It may not contain control or
  line-break characters (C0, DEL, C1, U+2028/U+2029).
- `description` may be at most 1000 characters. The API always declared this
  limit but never enforced it. It may not contain U+0000.

A violation returns 400 with a message naming the field.

The CLI routes still find an existing project whose name predates these rules;
only creating such a name is refused. An empty name, which used to be stored,
is now refused.

### 18.4 Other status changes

- **`DELETE /api/v1/projects/:id` for a project that does not exist:** now 404.
  It was 500.
- **`GET /api/v1/search/cve` and `/mcp/search/cve`:** this applies when the CVE
  is not stored locally and the NVD lookup fails. Both used to return 500.
  - If NVD answered 403, 429 or 503, the response is **503** with `Retry-After`
    in seconds and `{"code":"nvd_unavailable","retry_after_seconds":N}`.
    `Retry-After` is NVD's own value clamped to 1s-1h, or 30 when NVD sends
    none.
  - Any other upstream failure returns **502** with
    `{"code":"nvd_upstream_error"}`.
- **METI override and clear-override notes:** the 4096 limit now counts
  characters, not bytes. Japanese notes over about 1,366 characters used to be
  refused. The audit fields `override_note_len` and `clear_note_len` are now in
  characters too.
- **Reanalyse with a refused body:** `POST .../cra-reports/:id/reanalyse` and
  `.../vex-drafts/:id/reanalyse` now answer 400 or 413 when the body is refused
  for its text or size. They used to run with the defaults instead.

## 19. Web: security headers, error states, required METI override reason (M66)

### 19.1 Security headers on every page

The web app now sends:

- Content-Security-Policy
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY, with CSP `frame-ancestors 'none'`
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy

It no longer sends X-Powered-By. Pages can no longer be embedded in iframes.

The policy's origins are computed at build time (since §23 the header itself is built per request, with a nonce):

- `connect-src` allows the origin of `NEXT_PUBLIC_API_URL`, and of
  `NEXT_PUBLIC_WAITLIST_FORM_URL` when that is set.
- Clerk builds also allow the Frontend API host decoded from the publishable
  key, plus Clerk's documented hosts.

If your deployment loads something the policy does not allow, rebuild with
`SBOMHUB_CSP_REPORT_ONLY=true`. The CSP is then sent as Report-Only; framing
stays denied.

The app does not set HSTS. Set it on your TLS-terminating proxy.

### 19.2 Failed loads are shown as errors

When one of these lists fails to load, the page now shows an error with a
Retry button instead of an empty list:

- projects
- API keys
- integrations
- CRA reports
- a project's API keys
- a project's license check

### 19.3 METI manual override requires a reason

The override form now requires a reason that is not blank. The API already
rejected a blank reason with 400.

### 19.4 SSO settings page on self-host

Self-hosted instances now see that they have no user authentication or SSO (see
Deployment Mode). Before, the page asked them to upgrade to Enterprise.

### 19.5 Dialog buttons

The "Add integration", "Create API key" and vulnerability "Create ticket"
buttons now open their dialogs. A shared Dialog component bug dropped the
trigger while the dialog was closed.

## 20. One CVSS version rule for every path, and the version is recorded (M67)

**Who must act:** operators running more than one API process against one
database (§20.3). Everybody else: nothing to configure, but read §20.2 —
stored severities change for some CVEs.

### 20.1 What changed

When NVD publishes several CVSS assessments for a CVE, SBOMHub now stores the
same one whichever path writes the row:

1. **CVSS v3.1, then v3.0, then v4.0, then v2.** v3.x is preferred over v4.0
   deliberately: it is what NVD itself displays, what JVN iPedia and
   Dependency-Track use, and most v4.0 assessments NVD carries today are a
   CNA's Secondary beside NVD's own v3.1 Primary.
2. Within one version, NVD's own (`Primary`) assessment over a CNA's
   (`Secondary`) one, as since M54 / M57.
3. Among assessments of the same version and type, the more severe one, then
   the higher score. Before, the first one listed was used; NVD's order is not
   significant, so the stored value could depend on it.

The severity stored is the band of the chosen score on its version's scale
(v2: three bands, 0.0–3.9 is LOW), or the rating the assessment states when that
is harsher. A score that is not a CVSS base score (outside 0–10) is dropped
and the stated rating kept. An assessment whose score is absent or `null`
on the wire is no longer read as 0.0 ("None"). Before, an empty v3.1 entry
could be stored as 0.0 / NONE beside a valid v4.0 9.8 CRITICAL.

Before this release the daily CVE sync (and the monthly catalogue re-read,
§12) preferred v4.0, while the scanner and the CVE search preferred v3.x. A
CVE carrying both was stored at whichever score the last writer chose.
Measured on the NVD responses recorded on 2026-11-08: CVE-2026-34478 / -34479 /
-34480 / -34481 (Apache Log4j) are v3.1 Primary **7.5 HIGH** beside a v4.0
Secondary **6.9 / 6.3 MEDIUM**, and their stored severity flipped between
HIGH and MEDIUM.

The JVN scanner follows the same rule. It used to keep the most severe
assessment across versions; it now prefers the newer v3.x version first, so
an advisory carrying v3.0 MEDIUM beside v2 HIGH is stored MEDIUM.

Migration **069** adds `vulnerabilities.cvss_version` (`'3.1'`, `'3.0'`,
`'4.0'`, `'2.0'`; NULL when there is no usable assessment, when JVN states an
unrecognised version, or for rows written before 069). It can be set while
`cvss_score` is NULL, for an assessment that states a rating without a usable
score. It is recorded on every write and is not yet returned by the API. The migration adds a nullable column and a `NOT VALID`
CHECK under `lock_timeout = '5s'`. It rewrites and scans nothing.

### 20.2 How existing rows converge, and how long it takes

No one-shot backfill runs. Rows written before 069 carry no version, and
they are re-derived once from NVD's record when it is next offered:

- by the **daily CVE sync**, for CVEs NVD modified in its window (the last
  ~25 hours) — on the first tick after the upgrade;
- by the **monthly catalogue re-read** (§12), for every other CVE in your
  catalogue — on the next pass that is due. That is at most
  `SBOMHUB_NVD_RECONCILE_INTERVAL` (default 30 days) after the previous pass
  finished, plus the pass itself (~20 min with `NVD_API_KEY`, a little over an
  hour without). If no pass has completed yet, it starts right after the first
  daily sync.

This needed a change to the freshness guard (§9.4 / §11). It refuses a record
whose `lastModified` is not newer than the stored one, and the re-read offers
exactly the `lastModified` the old sync stored. A dated row with no
`cvss_version` is now writable **once** at an equal `lastModified`, by a record
that carries a CVSS assessment and was answered by NVD itself: the configured
URL is NVD's, the request did not go through a proxy, and no redirect led
away from NVD. After that the strict rule applies again.

Expect severities to change on those ticks, in both directions. Most changes
are MEDIUM → HIGH for CVEs where the old sync stored a CNA's v4.0 score over
NVD's v3.1. CVEs that NVD rates only with CVSS v2 also change: the previous
build missed the rating NVD puts on the v2 metric and could store them
UNKNOWN. Rows created by the scanner were already stored by the v3.x rule.

Not covered:

- JVN-only rows (JVNDB ids): NVD has no record to re-read. They keep the
  value the JVN scanner stored. The JVN rule change applies to advisories
  scanned from now on.
- `SBOMHUB_NVD_RECONCILE_INTERVAL=off`: rows NVD does not modify keep the old
  rule.
- **`SBOMHUB_NVD_URL` set to a mirror, or the API's NVD traffic going through
  an HTTP(S) proxy (`HTTPS_PROXY`) or being redirected:** the
  equal-`lastModified` re-derivation is off. A mirror or caching proxy can
  serve a stale or partial copy under an unchanged timestamp, and the
  re-derivation would let that copy replace the stored record once. Rows keep the old rule until NVD modifies each CVE. To converge
  them anyway, once the mirror is known to be complete and current, run once:

  ```sql
  UPDATE vulnerabilities SET source_modified_at = NULL
  WHERE cvss_version IS NULL AND source = 'NVD'
    AND source_modified_at IS NOT NULL;
  ```

  Each such row then accepts the next dated record from whatever source the
  sync reads.
- NVD answers cached in Redis by the previous build are not served. They
  are re-fetched from NVD, so scans may make more NVD requests than usual for
  up to 24 hours after upgrading.

### 20.3 More than one API process: stop the old ones first

A pre-069 binary still running against the 069 schema writes scores by the
old rule and leaves `cvss_version` unchanged. A row a new process has already
stamped then holds a version that does not describe its score, and the
freshness guard defends it until NVD next modifies the CVE.

Stop every pre-069 API process before, or while, migration 069 is applied.
The docker compose upgrade (§4) already does this. If an old process kept
running alongside a new one, run one of these once, after the last old process
has stopped.

If the sync reads NVD itself:

```sql
UPDATE vulnerabilities SET cvss_version = NULL
WHERE cvss_version IS NOT NULL AND source = 'NVD';
```

If the sync reads a mirror, or goes through a proxy (§20.2), run this instead,
once the mirror is known to be complete and current:

```sql
UPDATE vulnerabilities SET cvss_version = NULL, source_modified_at = NULL
WHERE source = 'NVD'
  AND (cvss_version IS NOT NULL OR source_modified_at IS NOT NULL);
```

Either statement returns every NVD-sourced row to a re-derivable state. The
next daily sync and re-read re-derive each one. JVN-only rows are left alone:
NVD has no record for them to re-derive from.

### 20.4 Rollback

`069_vulnerabilities_cvss_version.down.sql` drops the column (metadata-only,
`lock_timeout = '5s'`). Scores and severities stay as M67 derived them. Roll
the binary back first, because the M67 binary names the column in every
catalogue write. Upgrading again later re-adds the column empty, and §20.2
then re-derives each row once, as on the first upgrade.

## 21. Distribution-aware matching for Debian, Ubuntu, AlmaLinux and Rocky Linux packages (M70)

**Who must act:** operators who restrict egress (allow `api.osv.dev`, or set
`SBOMHUB_OSV_URL`); anyone who reads `match_method` from the API or the
database; operators rolling back past migration 070.

### 21.1 What changed

NVD describes upstream versions, so a Debian or RHEL-family package that
carries a backported fix (`openssl 1.1.1n-0+deb11u5`) used to be matched
against the upstream range and could only be labelled
`nvd_cpe_unverified` (§13). After the NVD/JVN steps, every scan (upload,
manual and scheduled) now relabels the existing links of packages from
Debian ≥ 7, Ubuntu LTS, AlmaLinux and Rocky Linux, using the distribution's
own fixed-version data from OSV. Versions are compared with dpkg / rpm
semantics.

The step **never adds or removes a link**. It only changes the label:

| `match_method` | Meaning | Confidence |
|---|---|---|
| `distro_affected` | The distribution's data says the installed version is affected | high |
| `distro_unfixed` | Affected, with no fixed version published | high |
| `distro_fixed` | The installed version is at or past the distribution's fix | `distro_fixed` (the link stays; dashboards still count it — review it) |

`distro_fixed` is not `not_affected`: no VEX statement is drafted or
confirmed from it. Each label carries the evidence it rests on in the new
`component_vulnerabilities.match_evidence` column (OSV record ids, release,
fixed version, and `basis`). For an end-of-life Debian release (≤ 11) the
verdict may be inferred from later releases (`basis = later_releases`).

A label whose OSV records were later withdrawn is cleared on a later scan,
back to the method it replaced.

Measured on the M60 fixture (openssl, Debian 11; local PostgreSQL 15.18 +
Redis, recorded NVD/OSV responses, 2026-11-10): of 313 links that were all
`nvd_cpe_unverified`, 21 became `distro_affected` (all 21 true), 181
`distro_fixed`, and 111 stayed unchanged. No true CVE was labelled
`distro_fixed`. Scan time was unchanged; a rescan is served from the Redis
cache with no OSV request.

### 21.2 New settings and scan outcomes

- `SBOMHUB_OSV_URL` (default `https://api.osv.dev/v1`; a path prefix and a
  query are kept) and `SBOMHUB_OSV_SOURCE_ID` (a stable name for the dataset,
  kept across credential rotation). See `docs/configuration.md`.
- `SBOMHUB_OFFLINE=true` makes no OSV request; links keep their NVD labels.
- New scan failure reason **`distro_data_failed`**: OSV returned malformed or
  incomplete data, or a record lookup failed. The scan is marked `failed`
  and no label is changed.
- Links held by another transaction are left for the next scan and counted as
  `write_refused` in the scan report.

### 21.3 Not covered

RHEL, Alpine, kernel images (`linux-signed` is not mapped to `linux`),
Ubuntu Pro / FIPS / ESM builds, Debian ELTS, RPM entries qualified by
architecture / epoch / version, `repository_url`-scoped packages, and
multi-CVE multi-binary ALSA errata get no verdict and keep their NVD label.
New Debian / Ubuntu releases need their codenames added in a release of
SBOMHub before their packages get a verdict.

### 21.4 Rollback

`070_component_vulnerabilities_distro_match.down.sql` takes an ACCESS
EXCLUSIVE lock on `component_vulnerabilities`, restores each distro label to
the method it replaced (its evidence `prior_method`, else NULL), restores the
previous `match_method` CHECK, and drops `match_evidence`. Roll the binary
back first.

## 22. Web: distro labels and their evidence (M70)

**Who must act:** nobody. The API is unchanged.

The project vulnerability list now shows the M70 labels (§21):

- `distro_affected` / `distro_unfixed` appear as high-confidence badges. When the evidence names a fix, the badge adds "upgrade to <fixed>".
- `distro_fixed` appears as "Review required — distribution reports fixed, still open". It is still counted and is never shown as resolved. A reviewer records any VEX statement by hand.

"Show evidence" lists the OSV records (linked to osv.dev), the release, the basis, the package and the versions. It warns when a `later_releases` verdict was inferred for an end-of-life Debian release, and when the data came from a mirror or from an endpoint that was not recorded. Evidence that does not match its label is shown as "no evidence recorded". NVD/JVN match labels are still not shown in the web UI.

## 23. Web: per-request CSP nonce, accessible distro badges, IPA settings errors (M71)

**Who must act:** only deployments that inject their own scripts into the web pages.

- Content-Security-Policy `script-src` is now `'self' 'nonce-…' 'strict-dynamic'`; `'unsafe-inline'` is gone. The proxy (`src/proxy.ts`) sets the CSP on every page request, so no page is prerendered. `/api`, `/_next` and `/_vercel` bypass the proxy and get a fallback CSP that allows no scripts; files under `/_next/static/` get it only when loaded as a document or frame, or by a client that sends no `Sec-Fetch-Dest`; ordinary browser script / style / image loads of them carry no CSP. `style-src` keeps `'unsafe-inline'`: React `style` attributes and Clerk's runtime styles cannot carry a nonce.
- `SBOMHUB_CSP_REPORT_ONLY=true` still applies at build time.
- A script you inject must now carry the nonce. The proxy passes it to the app in the `x-nonce` request header.
- The vulnerability list's distro badges (§22) can be reached by keyboard and touch. Evidence timestamps follow the viewer's locale and time zone.
- The IPA settings page shows a failed load as an error with Retry, not as a form of default values.

## 24. API: text checks on URLs and forms, LLM finish reasons, `cvss_version` (M71)

**Who must act:** clients that send U+0000 or invalid UTF-8 in a query string,
path or form; clients that want the CVSS version of a score.

### 24.1 Query strings, path parameters and form values

Every request now gets 400 `{"error": "<what> must not contain a NUL character"}`
(or `... is not valid UTF-8`) when a path parameter, a query parameter name or
value, or an urlencoded / multipart form value contains U+0000 or is not valid
UTF-8 (`%00`, `%FF`, a UTF-16 surrogate such as `%ED%A0%80`). The message names
the parameter, never the value. Before, these reached PostgreSQL and answered
500. Any audited GET did too, even for a parameter the route ignores
(`?x=%00`), because the audit log records the query string.

- The check runs before authentication, inside CORS, and reads only the URL.
  Form values are checked when the handler reads the form. SBOM file parts are
  binary and are never inspected.
- A form body that does not parse is now 400 on every route that reads the
  form (through request binding or the form check, including the legacy CLI
  upload). Routes that ignore the body still ignore it.
- The share-link password (`?password=` on `GET /api/v1/public/:token` and
  `.../download`) is exempt: it is only compared with its bcrypt hash, and a
  link created before M66 may have one containing U+0000.
- Above net/url's 10,000-parameter limit nothing is decoded for the handler,
  and nothing is refused.

### 24.2 LLM finish reasons

`llm_calls.finish_reason` stores the provider's value, with surrounding
whitespace trimmed, when it is 1-30 ASCII letters, digits, `_ . : -` (every
value OpenAI, Anthropic and Gemini document today; Ollama calls are recorded
as `stop`, as before). An empty value is
stored as NULL, as before. Anything else is stored as `unrecognized`. Before,
a longer value, or one with U+0000 or invalid UTF-8, failed the insert, and
with it the triage / CRA run. No migration.

### 24.3 `cvss_version` in responses

`cvss_version` (`"3.1"`, `"3.0"`, `"4.0"`, `"2.0"`; recorded since migration
069, §20) is now returned beside `cvss_score` by:
`GET /projects/:id/vulnerabilities` (and `/mcp/...`), `GET /search/cve`,
`GET /search/component`, `GET /projects/:id/kev`,
`GET /vulnerabilities/:cve_id/impact` and `GET /vulnerabilities/:cve_id/paths`.

It is omitted when unknown: no usable assessment, an unrecognised feed version,
or a row not re-derived since 069 (§20.2 says when that happens). It can be
present without `cvss_score`. Dashboard top-risks and SSVC responses do not
carry it yet.

## 25. Redis circuit breaker, per-tenant scan limit, shared scan status (M72)

**Who must act:** operators of more than one API replica (read §25.3); anyone whose CI relies on many simultaneous scans of one tenant (§25.2).

### 25.1 Redis circuit breaker
Every Redis data call now goes through a circuit breaker (the only exception is the scan-status store's `CONFIG GET` of the eviction settings, §25.3: at most one every 30s per process, each bounded by its own timeout). After `SBOMHUB_REDIS_BREAKER_THRESHOLD` (default 5, 1–1000) consecutive failures — a dial/read error, the call's own timeout, or an answer that took 1s or more — Redis calls fail at once for `SBOMHUB_REDIS_BREAKER_COOLDOWN` (default 5s, 1s–30s), then one probe call decides. The caches, the rate limiters and the scan-status store have separate breakers. Transitions are logged (`redis circuit breaker opened` / `half-open` / `closed`).
For the caches and rate limiters, what happens when Redis is down is unchanged, only faster: the NVD and distro caches count a miss, API-key rate limiting answers 500, public-link rate limiting answers 503 — now immediately instead of after 1–3s per call. Measured against a frozen Redis (docker pause): 20 cache lookups 20.0s → 5.0s, 10 rate-limited calls 20.0s → 10.0s. Recovery after Redis returns takes up to one cool-down. Starting a scan (an upload, for example) now waits up to 250ms for the shared scan-status write (§25.3) before going on without it.

### 25.2 Per-tenant scan concurrency: `SBOMHUB_SCAN_TENANT_CONCURRENCY` (default 2)
At most this many upload, manual (`POST .../scan`) and forced (`POST /settings/scan/force`) scans of one tenant run at once per API process (`off` disables it, 1–64 otherwise). The periodic scheduler takes no slot, so its one scan at a time may run in addition. A scan that finds the slots taken waits, first come first served, within its own `SBOMHUB_SCAN_DEADLINE`: if the deadline fires while it waits it is reported failed (`deadline_exceeded`) without running. At most 32 scans per slot may wait; one beyond that fails at once with the new reason `queue_full`.

### 25.3 scan-status is shared through Redis
`GET /api/v1/projects/:id/sboms/:sbom_id/scan-status` now reads a status kept in Redis, so a scan started on one replica is visible from every replica and survives restarts.
- A scan whose API process stopped (crash, restart, kill) reads `failed` with the new reason `interrupted` once its 90s lease has run out and no other scan of the same SBOM is still running (until then it reads `running`), instead of `running` until retention or `unknown`.
- If Redis cannot be read, or holds no entry, a scan that completed in the answering process reads `unknown` (another replica may be scanning). When Redis was read but held no entry while that process still has status writes to Redis pending, it reads `running` instead; `running` and `failed` are answered from the process itself.
- When Redis can evict keys (`maxmemory` set and a policy other than `noeviction`), or does not answer `CONFIG GET` (some managed Redis services), a status entry younger than 75s does not read `completed`; such a scan reads `running` until then, so that runs of an evicted entry can rejoin it. Each API process reads these settings at startup and again, while scans are being tracked, at most every 30s. When a later read finds that Redis can no longer evict, the hold stays in effect for another 75s. The read at startup applies at once, and a setting changed after a read is seen at the next read: if keys were evicted shortly before an API process starts, or before its next read, a fast scan on it can read `completed` while another replica's evicted scan of the same SBOM has not yet rejoined, as after a `FLUSHDB` below. The bundled docker compose Redis cannot evict, so a scan there reads `completed` as soon as it ends. After a Redis restart that lost data, or a `FLUSHDB`, a fast scan can read `completed` while another replica's scan of the same SBOM has not yet rejoined; that run rejoins on its next successful heartbeat (normally within 30s).
- The response shape is unchanged; the new reason codes are `interrupted` and `queue_full`. The status is only read after the SBOM was found in the caller's project.

New environment variables: `SBOMHUB_REDIS_BREAKER_THRESHOLD`, `SBOMHUB_REDIS_BREAKER_COOLDOWN`, `SBOMHUB_SCAN_TENANT_CONCURRENCY`. An invalid value stops the API at startup.


## 26. JVN outage: `source_unavailable`, early stop, and `SBOMHUB_JVN=off`

JPCERT/CC suspended JVN iPedia and MyJVN for system maintenance on 2026-10-22
with no resumption date (https://jvn.jp/nav/info2026102281.html). Every MyJVN
API URL answers HTTP 404. With JVN on (the default), every online scan that
looks up at least one component in JVN (not with SBOMHUB_OFFLINE=true) is
reported `failed`.

### 26.1 The outage is named, and the sweep stops asking

- A JVN lookup that gets no HTTP 200 at all (404, 410, 403, 408, 429, 5xx, or a
  network error / client timeout) is distinguished from one whose answer failed
  validation. When MyJVN is unavailable, scan-status `reasons` gain
  `source_unavailable` in addition to `fetch_failed`, and the `error` contains
  the marker `jvn: scan failed (fetch_failed, source_unavailable)` (other
  sources' failures can add their own reasons and markers). The verdict is
  unchanged: the scan is `failed`, `sbomhub scan --fail-on` exits 2, NVD
  findings are still committed.
- After 3 consecutive unavailable lookups the JVN sweep stops querying MyJVN;
  the remaining components are reported as not checked.

### 26.2 `SBOMHUB_JVN=off`: scan without JVN until MyJVN returns

New setting `SBOMHUB_JVN`: `on` (default, also when unset) or `off`,
case-insensitive. Any other value (including `false`, `0`, `disabled`) refuses
startup, before migrations run. With `off` the API logs a WARN at startup.

With `off`:

- The scan after an upload and `POST /api/v1/projects/:id/scan` send no request
  to MyJVN. A scan whose other sources succeeded reads `completed`; one whose
  other sources failed reads `failed` with their reasons.
- `GET .../sboms/:sbom_id/scan-status` adds `"skipped_sources": ["jvn"]` to a
  `completed` or `failed` scan that skipped JVN (absent when nothing was
  skipped). It is stored in the shared scan status (Redis), so every replica
  reports it. The MCP tools report it as `skipped_sources` next to
  `counts_final`.
- `POST /api/v1/projects/:id/scan?sources=jvn` (or `nvd,jvn`) still answers
  `202`; JVN is skipped and reported in `skipped_sources`.
- The scheduled scan (periodic and forced) runs NVD and the distro step only,
  with JVN on or off; this setting does not change it.
- Findings earlier scans made with JVN stay linked: `off` adds and removes no
  JVN finding, so a scan with `skipped_sources: ["jvn"]` may still list older
  JVN findings, which are not re-checked.

Undo: unset `SBOMHUB_JVN` (or set `on`) and restart; the next scan queries JVN
again.

Several replicas: set `off` only once every replica sharing the Redis runs this
version. An older replica cannot report `skipped_sources`, so a scan polled
through it reads a bare `completed`. The `sbomhub` CLI shows
`skipped_sources` (a warning, and the field in `--json`) from sbomhub-cli
commit `2354439` on; exit codes and `--fail-on` are unchanged. Older CLI builds
print a bare `completed`; read scan-status directly to see the field.

API changes are additive only: reason code `source_unavailable`, scan-status
field `skipped_sources`, MCP payload field `skipped_sources`.


## 27. `cvss_version` on the dashboard and SSVC, Ollama finish reasons, project lookup errors

- `cvss_version` (see §20 for the selection rule) is now also returned in the `top_risks` rows of `GET /api/v1/dashboard/summary` (and MCP `GET /api/v1/mcp/dashboard/summary`) and in each row of `GET /api/v1/dashboard/top-risks`. In the SSVC assessment lists (`GET /api/v1/projects/:id/ssvc/assessments`, `GET /api/v1/ssvc/immediate`) it is called `vulnerability_cvss_version`, next to `vulnerability_cvss_score`. The rules are the same as §24.3: it is left out when unknown, and it can appear without a score. This only adds fields, so existing clients are unaffected.
- MCP server: the five tools that return `cvss_score` (`sbomhub_get_dashboard`, `sbomhub_get_project_dashboard`, `sbomhub_get_vulnerabilities`, `sbomhub_search_cve`, `sbomhub_search_component`) now explain `cvss_version` in their descriptions. Clients that pin `tools/list` descriptions will see those five strings change. Input schemas are unchanged.
- Ollama: `llm_calls.finish_reason` now records what Ollama reports in `done_reason` (`stop`, `length`, …) instead of always `stop`. A draft that ran into `num_predict` now shows up as `length`. Ollama versions that do not send `done_reason` still record `stop` for finished responses. Rows written before this change are not rewritten, so `stop` on older Ollama rows does not rule out truncation.
- `GET /api/v1/projects/:id` and `GET /api/v1/cli/projects/:id` now answer **500** `{"error":"failed to get project"}` when the database itself fails (connection, timeout, …). Before, this was reported as 404. A project that does not exist or belongs to another tenant still answers 404 `{"error":"project not found"}`. Clients that treated every 404 here as "deleted" will now see 500 during database outages, and should retry rather than drop the project.

## 28. Web: match confidence on the vulnerability list, popover/card colours

**Who must act:** nobody. The API is unchanged.

- Every finding that is not a distro label (§22) now shows how it was matched (§13.2) and its confidence. Only `nvd_cpe` (CPE match, version verified) appears without a review flag. `nvd_cpe_distro` (medium), `nvd_cpe_unverified`, `nvd_keyword`, `jvn_keyword`, `cve_sync_keyword` (low), links made before §13 ("match method not recorded", confidence unknown) and match methods the page does not recognise lead with "Needs review" / 「要確認」. If `match_method` and `match_confidence` disagree, or `match_confidence` is missing, the lower or unknown value is shown. Nothing is hidden or removed from counts; the explanation (keyboard, touch, screen reader, ja/en) says the finding stays listed until a person reviews it.
- Tooltips (KEV, EOL, SSVC badges) and Select dropdowns were transparent: `bg-popover` / `bg-card` were never defined in the theme. They now render on an opaque background, and tooltips stay inside the viewport on narrow screens. `bg-card` panels (analytics, audit, reports, settings) now have the card colour (white in light mode).
- The tooltip's entry animation never existed (tailwindcss-animate was not installed) and its classes were removed; legal/privacy/terms lost the inert `prose` classes. Neither changes what is rendered.

## 29. Web: consistent light theme, keyboard tooltips, 320px reflow, project load errors

**Who must act:** nobody.

- **Dark mode:** the `dark:` variant is now tied to the `.dark` class (`@custom-variant dark`), the same condition as the theme tokens. Nothing sets `.dark`, so the UI renders light regardless of the OS colour scheme. Before, OS dark mode produced a mixed page, for example grey-on-white audit action labels. `color-scheme: light` keeps native controls light. A future theme toggle only has to set `.dark` on `<html>`.
- **Tooltips:** the KEV, EOL, SSVC and ticket badges and the truncated METI titles are now keyboard focus stops. They open on focus, hover or tap and close with Escape; the badges also toggle with Enter/Space (the METI titles, which are headings, do not). Screen readers announce the explanation as the badge's description.
- **Narrow screens:** below 768px the dashboard sidebar becomes a menu button in the header. No main page scrolls sideways at 320px; wide tables and tab rows scroll inside their own box.
- **Project page errors:** "Project not found" now appears only when the API answers 404 (or 400 for a malformed id). A server error (500, §27) or a network failure shows "Failed to load the project…" with a Retry button, instead of implying the project was deleted.
- New UI strings: `Navigation.openMenu` / `closeMenu` / `mainMenu`, `Common.projectLoadFailed`.
