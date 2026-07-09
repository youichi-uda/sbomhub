# API Reference

This document describes the SBOMHub REST API.

> SBOMHub is an **AI compliance evidence layer** for the EU Cyber Resilience Act (CRA) reporting deadline of **2026-09-11**.
> The SaaS instance at `sbomhub.app` / `api.sbomhub.app` was sunset in 2026-06; self-host (Docker Compose) is the only supported path. Examples in this document use the self-host default URL `http://localhost:8080`.

## Base URL

- Self-host (recommended): `http://localhost:8080`
- Self-host behind a reverse proxy: `https://sbomhub.example.com`

## Authentication

### API Key Authentication

For CI/CD integration, use API keys:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8080/api/v1/projects
```

API keys can be created in the project settings page.

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

#### Create API Key

```
POST /api/v1/projects/:id/api-keys
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

#### List API Keys

```
GET /api/v1/projects/:id/api-keys
```

#### Revoke API Key

```
DELETE /api/v1/projects/:id/api-keys/:key_id
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

Self-host has no built-in rate limiting; apply it at a reverse proxy (Nginx, Caddy, etc.) if needed.

For a future SaaS comeback, the planned rate-limit header format is:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1704067200
```
