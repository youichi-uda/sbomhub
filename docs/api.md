# API Reference

This document describes the SBOMHub REST API.

> SBOMHub is an **AI compliance evidence layer** for the EU Cyber Resilience Act (CRA) reporting deadline of **2026-09-11**.
> The SaaS instance at `sbomhub.app` / `api.sbomhub.app` was sunset in 2026-06; self-host (Docker Compose) is the only supported path. Examples in this document use the self-host default URL `http://localhost:8080`.

## Base URL

- Self-host (recommended): `http://localhost:8080`
- Self-host behind a reverse proxy: `https://sbomhub.example.com`

## Authentication

### API Key Authentication

For CI/CD integration, use API keys. Send them as `Authorization: Bearer <key>`
(the `X-API-Key` header is accepted on `/api/v1/cli/*` and `/api/v1/mcp/*`):

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8080/api/v1/cli/projects
```

Two kinds of key exist, and the difference is enforced on every request:

| Kind | Created by | Authority |
|---|---|---|
| **Tenant-level** | `POST /api/v1/apikeys` (Settings → API Keys) | Every project of the tenant, plus the tenant-wide endpoints (project list, dashboard summary, cross-project search) |
| **Project-scoped** | `POST /api/v1/projects/:id/apikeys` (a project's API Keys tab) | That one project only |

Both mint routes — and the four list/revoke routes — require an **Owner or Admin web-UI
session**. An API key cannot mint, list, or revoke another API key, of either kind.

A project-scoped key is answered **`403 {"error":"forbidden"}`** when the request
names any other project, when the endpoint is tenant-wide, and when it would
create a project. The refusal is identical for a project that exists, a project
of another tenant, and a UUID that was never allocated, so it cannot be used to
discover what exists. The two project-list endpoints are the exception: they are
**narrowed rather than refused**, returning the key's own project as a one-element
list, because there the response *is* the set being narrowed and no field of it
changes meaning. `docs/UPGRADE.md` §2d enumerates all 34 endpoints a
project-scoped key can use — the 29 that name the project in the path, plus the
five that do not — and the four it cannot.

**Not every endpoint accepts an API key.** Most of the API is reachable only with a
web-UI session (Clerk JWT). In self-hosted mode (`SBOMHUB_AUTH_MODE=anonymous`, the
OSS default) those same route groups grant **Owner on the default tenant to a request
carrying no credential at all** — so on a self-hosted deployment API-key scoping is a
limit on what a key can do, not a network boundary. See `docs/configuration.md`. The endpoints that accept `Bearer sbh_...` are `/api/v1/cli/*`,
`/api/v1/mcp/*`, and the per-project SBOM / vulnerability / triage / CRA / METI /
evidence-pack routes documented below. `GET /api/v1/projects` is **not** one of
them; a machine client uses `GET /api/v1/cli/projects` instead — a tenant-level key
gets the whole tenant there, a project-scoped key gets its own project.

## Endpoints

### Projects

#### Create Project

```
POST /api/v1/projects
```

**Request Body:**
```json
{
  "name": "my-project",
  "description": "Project description"
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "my-project",
  "description": "Project description",
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### List Projects

```
GET /api/v1/projects
```

**Query Parameters:**
- `page` (int): Page number (default: 1)
- `limit` (int): Items per page (default: 20)

#### Get Project

```
GET /api/v1/projects/:id
```

#### Delete Project

```
DELETE /api/v1/projects/:id
```

---

### SBOM

#### Upload SBOM (canonical)

```
POST /api/v1/projects/:id/sbom
```

This is the single canonical SBOM upload endpoint (Trust Rescue 9.3.1 / #9).
The web UI (Clerk session) and the CLI / GitHub Actions (`Authorization: Bearer sbh_...`)
both target this route through the `MultiAuth` middleware.

**Request:**
- `Authorization: Bearer <CLERK_JWT|sbh_API_KEY>`
- Content-Type: `application/json` (raw CycloneDX or SPDX JSON body — format is auto-detected server-side)

**Example (API key):**

The verbatim `curl` command, including a smoke-test follow-up and
matching CI variants, is the single source of truth in
[`snippets/curl-upload.md`](./snippets/curl-upload.md). For embedding in
GitHub Actions / GitLab CI, see
[`snippets/github-actions.yml.md`](./snippets/github-actions.yml.md) and
[`snippets/gitlab-ci.yml.md`](./snippets/gitlab-ci.yml.md). All three
target the same canonical contract:

- `POST /api/v1/projects/:id/sbom`
- `Authorization: Bearer sbh_...`
- `Content-Type: application/json` with the raw CycloneDX / SPDX JSON body
  (`--data-binary @sbom.json`, **not** `-F sbom=@sbom.json`).

#### Upload SBOM via CLI (deprecated)

```
POST /api/v1/cli/upload   # DEPRECATED, Sunset: 2026-09-24
```

The multipart `/cli/upload` endpoint is kept alive for a 3-month overlap so
existing CI pipelines continue to work, but every response carries:

- `Deprecation: true`
- `Sunset: Thu, 24 Sep 2026 00:00:00 GMT`
- `Link: </api/v1/projects/{id}/sbom>; rel="successor-version"`

Migrate to the canonical endpoint above.

#### Get Components

```
GET /api/v1/projects/:id/components
```

**Query Parameters:**
- `page` (int): Page number
- `limit` (int): Items per page
- `search` (string): Search by name

---

### Vulnerabilities

#### List Vulnerabilities

```
GET /api/v1/projects/:id/vulnerabilities
```

**Query Parameters:**
- `page` (int): Page number
- `limit` (int): Items per page
- `severity` (string): Filter by severity (critical, high, medium, low)
- `status` (string): Filter by VEX status

**Response:**
```json
{
  "items": [
    {
      "id": "CVE-2024-1234",
      "severity": "high",
      "cvss_score": 8.5,
      "epss_score": 0.15,
      "component": "lodash",
      "version": "4.17.20",
      "vex_status": "affected"
    }
  ],
  "total": 100,
  "page": 1,
  "limit": 20
}
```

---

### Reachability

The CLI reachability flow: the CLI fetches the project's (cve_id, component_id)
worklist from `GET .../reachability/targets`, runs the static reachability
analyzer locally against the project source, and POSTs one verdict per pair
back to `POST .../reachability`.

#### List Reachability Targets

```
GET /api/v1/projects/:id/reachability/targets
```

**Query Parameters:**
- `ecosystem` (string, optional): only return targets whose purl-derived ecosystem matches (e.g. `go`, `npm`)

**Response:**
```json
{
  "targets": [
    {
      "cve_id": "CVE-2024-0001",
      "component_id": "uuid",
      "purl": "pkg:golang/example.com/foo@v1.2.3",
      "component_name": "foo",
      "component_version": "v1.2.3",
      "ecosystem": "go",
      "vuln_funcs": ["xml.Unmarshal", "Pkg.Type.Method"]
    }
  ]
}
```

- `ecosystem` is derived from the purl server-side; it may be `""` when the component carries no package URL.
- `vuln_funcs` (string array, optional): the advisory-declared vulnerable symbols
  for the row, unioned across advisory sources (NVD / GHSA / JVN / OSV —
  the OSV entries come from the structured advisory symbol lists) and
  normalized server-side under the row's purl-derived ecosystem (trimmed,
  trailing `()` stripped, malformed entries dropped, de-duplicated, capped at
  200 symbols per CVE):
  - `go` rows keep only `Pkg.Func` / `Pkg.Type.Method` selectors (2–3
    dot-separated Go-identifier-shaped parts; bare names are dropped);
  - `npm` rows keep bare export names (`defaultsDeep`) and dotted
    `recv.method` selectors with 1–3 JS-identifier-shaped parts (`$` and `_`
    allowed); path/URL-shaped strings, bare version strings, and entries over
    256 bytes are dropped;
  - every other ecosystem conservatively uses the Go rules.

  Structured advisory symbols are **scoped to the component**: only the
  symbols declared for the row's own purl-derived module — the Go module path
  for `go` rows, the npm package name (including `@scope/name`) for `npm`
  rows — are delivered on that row (they lead the list), so a CVE spanning
  several modules/packages does not leak one component's symbols into a
  sibling component's row; symbols from prose sources (NVD etc.) carry no
  module attribution and are delivered on every row of the CVE (each row
  normalizing them under its own ecosystem rules), after the scoped ones. The
  field is **omitted entirely** when no well-formed symbol is known for the
  row — the CLI then falls back to import-only analysis for that pair.

#### Upload Reachability Results

```
POST /api/v1/projects/:id/reachability
```

**Request Body:**
```json
{
  "results": [
    {
      "component_id": "uuid",
      "cve_id": "CVE-2024-0001",
      "ecosystem": "go",
      "status": "reachable",
      "confidence": 0.87,
      "analyzer_version": "v1.2.3",
      "analyzed_at": "2026-07-05T10:00:00Z",
      "evidence": { "callgraph_nodes": ["main.main"] }
    }
  ]
}
```

- `component_id`, `cve_id`, and `status` are required; the other fields are optional.
- `status` must be one of `not_present` | `import_only` | `reachable` | `unknown`.
- `confidence`, when present, must be within `[0, 1]`.
- Every `(component_id, cve_id)` pair must be a genuine vulnerability target of
  the project — the same set `GET .../reachability/targets` returns. One
  non-target pair rejects the whole batch with `400` and nothing persisted.
- The batch is all-or-nothing: any invalid row or persistence failure rolls the
  entire upload back, so the CLI can safely retry the whole batch.

**Response (201):**
```json
{
  "upserted": 1
}
```

---

### VEX Statements

#### Create VEX Statement

```
POST /api/v1/projects/:id/vex
```

**Request Body:**
```json
{
  "vulnerability_id": "CVE-2024-1234",
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "statement": "This vulnerability does not affect our usage"
}
```

**VEX Status Values:**
- `affected`
- `not_affected`
- `fixed`
- `under_investigation`

#### List VEX Statements

```
GET /api/v1/projects/:id/vex
```

---

### API Keys

All six routes below require an **Owner or Admin** web-UI session
(`appmw.RequireAdmin`); an API key cannot mint or revoke another API key.

#### Create a tenant-level API key

Valid for every project of the tenant.

```
POST /api/v1/apikeys
```

**Request Body:**
```json
{
  "name": "GitHub Actions",
  "permissions": "write",
  "expires_in_days": 365
}
```

`permissions` must be one of `read`, `write`, `admin` (omitted defaults to
`write`). Anything else is rejected with `400`. The same validation and the same
default apply to the project-scoped mint route below — permissions and project
scope are independent, so a project-scoped key still needs `write` to drive a
write endpoint.

#### List / revoke tenant-level API keys

```
GET    /api/v1/apikeys
DELETE /api/v1/apikeys/:key_id
```

#### Create a project-scoped API key

Valid for **this project only** — see the scope table under
[Authentication](#api-key-authentication).

```
POST /api/v1/projects/:id/apikeys
```

**Request Body:**
```json
{
  "name": "CI/CD Key",
  "permissions": "write",
  "expires_in_days": 365
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "CI/CD Key",
  "key": "sbh_xxxxxxxxxxxx",
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-01-01T00:00:00Z"
}
```

> **Note:** The `key` is only returned once at creation time. Store it securely.

#### List project-scoped API keys

```
GET /api/v1/projects/:id/apikeys
```

#### Revoke a project-scoped API key

`:id` must be the project the key was created under; a key of a sibling project
answers `404`.

```
DELETE /api/v1/projects/:id/apikeys/:key_id
```

---

### Compliance

#### Get Compliance Score

```
GET /api/v1/projects/:id/compliance
```

**Response:**
```json
{
  "score": 85,
  "checks": [
    {
      "name": "sbom_exists",
      "passed": true,
      "description": "SBOM is present"
    },
    {
      "name": "vulnerabilities_triaged",
      "passed": false,
      "description": "All critical vulnerabilities should have VEX statements"
    }
  ]
}
```

---

### License Policies

#### Create License Policy

```
POST /api/v1/license-policies
```

**Request Body:**
```json
{
  "name": "Default Policy",
  "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "denied": ["GPL-3.0", "AGPL-3.0"]
}
```

#### Check License Violations

```
GET /api/v1/projects/:id/license-violations
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "error_code",
  "message": "Human readable message"
}
```

**Common HTTP Status Codes:**
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

---

## Rate Limiting

Self-host **does** have built-in rate limiting, but only for requests that
authenticate with an API key. It needs Redis, which the bundled Docker Compose
stack already runs.

### What is limited, and what is not

The limiter (`RateLimitByAPIKey` in `cmd/server/main.go`, on every route in the
budget table below) counts per **`api_keys` row**. It is a **no-op** when no
API key is on the request context — a Clerk session and the self-hosted default
identity both pass through it untouched, which is why the web UI is not
throttled. Requests that never reach an authenticated identity at all (a 401,
say) are not counted either.

So: if you need to bound anonymous or browser traffic, that is still a reverse
proxy's job (Nginx, Caddy, …). What is covered here is a leaked or misbehaving
`sbh_…` key.

### The four budgets

A counter is named by a **budget** — a (name, ceiling, window) triple — not by
the route. Every request charged to a counter has the same ceiling as every
other request charged to it. All four are per API key, per minute:

| budget | ceiling | routes |
|---|---|---|
| `standard` | 60/min | canonical `/api/v1/projects/…` mutations, plus `GET …/sbom` and `GET …/vulnerabilities` |
| `poll` | 300/min | `scan-status`, `reachability/targets`, and the `vex-drafts` / `cra-reports` / `submissions` / METI list+get surfaces |
| `mcp` | 60/min | the `/api/v1/mcp/*` group |
| `cli` | 60/min | the legacy `/api/v1/cli/*` group |

One key may spend all four concurrently, so the aggregate ceiling is
**480 req/min**, not 60. The window is fixed rather than sliding, so the
observable short-term peak is twice the ceiling (spend a bucket at the end of
one minute and the next at the start of the following one). Nothing here bounds
a *tenant*: two keys for one tenant get two of everything.

`docs/UPGRADE.md` §8 has the migration notes, including the one-off counter
reset at the deploy that introduced budgets.

### Headers

Every non-throttled API-key response carries:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
```

A throttled one answers `429` with `Retry-After` in **seconds**:

```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
Retry-After: 60

{"error": "rate limit exceeded", "retry_after": "60s"}
```

There is **no `X-RateLimit-Reset` header** — an earlier draft of this page
advertised one, and nothing emits it. Use `Retry-After`.

A Redis failure answers `500`, not `200`: the limiter is fail-closed, so a Redis
outage takes the API-key surface down rather than un-throttling it.

### Public share links are limited separately

`GET /api/v1/public/:token` and `…/download` are anonymous, so they are bounded
by their own limiter (`RateLimitPublicLink`) rather than by a budget. It counts
**failed** attempts — 10 per token and 60 per IP per hour — so a link that is
merely popular is not throttled by its own success, and it separately caps
concurrent admissions (16 per token, 64 per IP) so a parallel burst cannot turn
connection count into bcrypt work. Both rejections answer the same `429` body,
deliberately, so a caller cannot tell which limit it hit:

```json
{"error": "too many requests for this share link", "retry_after": "3600s"}
```

These routes carry no `X-RateLimit-*` headers. When the counters cannot be
consulted at all the answer is `503 {"error": "temporarily unavailable"}` —
fail-closed, but a different status from the API-key limiter's `500`.
