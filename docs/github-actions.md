# GitHub Actions Integration

This guide explains how to wire SBOMHub into GitHub Actions so every push /
release produces an SBOM and uploads it as CRA / VEX evidence.

> The SaaS instance at `sbomhub.app` was sunset in 2026-06. `SBOMHUB_URL`
> in this guide refers to a **self-host instance** (Docker Compose) — for
> example an internal URL such as `https://sbomhub.internal.example.com`,
> or any URL reachable from the GitHub Actions runner you use.

> **Where the YAML lives.** All canonical workflow snippets are in
> [`snippets/github-actions.yml.md`](./snippets/github-actions.yml.md).
> This document covers setup, prerequisites, troubleshooting, and the
> per-tool generation step; the upload step itself is single-sourced in
> the snippet and stays in sync with [`snippets/curl-upload.md`](./snippets/curl-upload.md).

## Overview

Automate your SBOM workflow:

1. Generate an SBOM on every push / release.
2. Upload it to your self-host SBOMHub for vulnerability tracking and as
   VEX / CRA evidence.
3. Optionally gate the workflow on critical findings.

## Prerequisites

1. Self-host SBOMHub instance.
2. Project created in SBOMHub.
3. API key generated for the project (Settings → API Keys, shown once).

## Setup

### 1. Create API Key

1. Go to your project in SBOMHub.
2. Navigate to **Settings → API Keys**.
3. Click **Create API Key**.
4. Save the key securely (it is shown only once).

### 2. Add GitHub Secrets

In your GitHub repository:

1. Go to **Settings → Secrets and variables → Actions**.
2. Add the following secrets:

| Secret               | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `SBOMHUB_API_KEY`    | Your API key from step 1.                                                   |
| `SBOMHUB_URL`        | Your self-host SBOMHub URL (e.g. `https://sbomhub.internal.example.com`).   |
| `SBOMHUB_PROJECT_ID` | Your project UUID.                                                          |

## Workflow

See [`snippets/github-actions.yml.md`](./snippets/github-actions.yml.md)
for the full YAML. Two flavours are supported:

- **Recommended.** Install `sbomhub-cli` and call `sbomhub scan` in one
  step. The CLI uploads through the canonical contract automatically and
  exposes `--fail-on critical` for CI gating.
- **Fallback.** Install your generator of choice (Syft / Trivy / cdxgen)
  and call the canonical `curl` upload from
  [`snippets/curl-upload.md`](./snippets/curl-upload.md). Use this when
  the runner cannot install `sbomhub-cli`.

The two flavours target the same endpoint:

- `POST /api/v1/projects/:id/sbom`
- `Authorization: Bearer <SBOMHUB_API_KEY>`
- `Content-Type: application/json` with the raw CycloneDX / SPDX JSON body
  (`--data-binary @sbom.json`). **Do not** send multipart form data to the
  canonical endpoint — it will be rejected as malformed SBOM JSON.

## SBOM generation tools

| Tool             | Best for                       | Generation command                              |
|------------------|--------------------------------|-------------------------------------------------|
| Syft             | General purpose, containers    | `syft . -o cyclonedx-json > sbom.json`          |
| Trivy            | Containers, security focus     | `trivy fs --format cyclonedx . > sbom.json`     |
| cdxgen           | Multi-language, mono-repos     | `cdxgen -o sbom.json`                           |
| cyclonedx-gomod  | Go projects                    | `cyclonedx-gomod mod -json > sbom.json`         |
| cyclonedx-npm    | Node.js projects               | `cyclonedx-npm --output-file sbom.json`         |

The upload step in
[`snippets/github-actions.yml.md`](./snippets/github-actions.yml.md) is
identical across generators; only the generation step changes.

## Troubleshooting

### Authentication Failed

Verify your API key:

```bash
curl -fsS -H "Authorization: Bearer $SBOMHUB_API_KEY" \
  "$SBOMHUB_URL/api/v1/projects"
```

### Invalid SBOM Format

Ensure the SBOM is valid JSON:

```bash
cat sbom.json | jq .
```

Check the format (CycloneDX or SPDX):

```bash
cat sbom.json | jq '.bomFormat // .spdxVersion'
```

### Connection Timeout

For self-host instances, ensure:

- The server is reachable from your GitHub Actions runner.
- Firewall rules allow incoming connections.
- For internal networks, use GitHub self-hosted runners.

### "415 Unsupported Media Type" or "malformed SBOM JSON"

The canonical endpoint expects the **raw** CycloneDX / SPDX JSON body, not
multipart form data. Use `--data-binary @sbom.json`, not
`-F sbom=@sbom.json`. The canonical command in
[`snippets/curl-upload.md`](./snippets/curl-upload.md) is correct by
construction.

## Best Practices

1. **Generate on main branch.** Upload SBOMs for releases, not every commit.
2. **Use secrets.** Never hardcode API keys in workflows.
3. **Pin action versions.** Use specific versions for reproducibility.
4. **Monitor notifications.** Set up Slack / Discord alerts for new
   vulnerabilities.
5. **Review regularly.** Check the SBOMHub dashboard weekly.
