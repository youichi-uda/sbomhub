# Snippet: SBOM upload via `curl`

<!-- check-snippets:signature: curl -X POST -H "Authorization: Bearer $SBOMHUB_API_KEY" -H "Content-Type: application/json" --data-binary "@sbom.json" "$SBOMHUB_URL/api/v1/projects/$SBOMHUB_PROJECT_ID/sbom" -->

> **Canonical source.** This file is the single source of truth for the raw
> `curl` SBOM upload command. Other docs (README, `docs/api*.md`,
> `docs/github-actions*.md`, the in-product API Keys page) link here instead
> of duplicating the command.

## Required parameters

| Variable               | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `SBOMHUB_URL`          | Base URL of your self-hosted SBOMHub (e.g. `http://localhost:8080`).        |
| `SBOMHUB_PROJECT_ID`   | Target project UUID (from the dashboard or `sbomhub projects list`).        |
| `SBOMHUB_API_KEY`      | API key with `write` permission (prefix `sbh_...`).                         |

## Canonical command (raw body, recommended)

The canonical SBOM upload endpoint is `POST /api/v1/projects/:id/sbom`. It
accepts the **raw CycloneDX or SPDX JSON body** (auto-detected server-side)
and authenticates via `Authorization: Bearer <api-key>` (Trust Rescue 9.3.1 / #9).

<!-- ci:smoke-test:start -->
```bash
curl -X POST \
  -H "Authorization: Bearer $SBOMHUB_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary "@sbom.json" \
  "$SBOMHUB_URL/api/v1/projects/$SBOMHUB_PROJECT_ID/sbom"
```
<!-- /ci:smoke-test -->

> This block is executed verbatim in CI against a live api on every PR that
> touches the snippet or the SBOM upload code path. See
> [.github/workflows/docs-curl-smoke.yml](../../.github/workflows/docs-curl-smoke.yml)
> (Trust Rescue 9.3.3 / #11). If you edit the command, the smoke job will
> re-run it; if the new form does not produce HTTP 201, CI fails.

> Do **not** use `-F sbom=@sbom.json` against `/projects/:id/sbom`. The
> canonical endpoint reads the raw request body; multipart form data is
> rejected as malformed SBOM JSON.

## Deprecated endpoint (3-month overlap)

The legacy multipart endpoint stays alive until **2026-09-24** so existing
CI pipelines do not break. Every response from this route carries
`Deprecation: true`, `Sunset: Thu, 24 Sep 2026 00:00:00 GMT`, and a
`Link: </api/v1/projects/{id}/sbom>; rel="successor-version"` header.

```bash
# DEPRECATED — Sunset 2026-09-24. Use the raw-body endpoint above.
curl -X POST \
  -H "Authorization: Bearer $SBOMHUB_API_KEY" \
  -F "sbom=@sbom.json" \
  "$SBOMHUB_URL/api/v1/cli/upload"
```

Migrate to the canonical command at your next CI maintenance window.

## Smoke-testing the upload

```bash
# 1. Generate a SBOM with the tool of your choice.
syft . -o cyclonedx-json > sbom.json

# 2. Upload it.
curl -X POST \
  -H "Authorization: Bearer $SBOMHUB_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary "@sbom.json" \
  "$SBOMHUB_URL/api/v1/projects/$SBOMHUB_PROJECT_ID/sbom"

# 3. Verify the upload landed.
curl -fsS \
  -H "Authorization: Bearer $SBOMHUB_API_KEY" \
  "$SBOMHUB_URL/api/v1/projects/$SBOMHUB_PROJECT_ID/sbom" | jq '.created_at'
```
