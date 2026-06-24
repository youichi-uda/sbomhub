# Snippet: GitHub Actions workflow

<!-- check-snippets:signature: name: Upload to SBOMHub (canonical) -->

> **Canonical source.** This file is the single source of truth for
> SBOMHub GitHub Actions workflows. `docs/github-actions*.md` and the
> README link here; please update this file (not the docs) when the upload
> contract changes.

## Required GitHub repository secrets

| Secret               | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `SBOMHUB_URL`        | Base URL of your self-hosted SBOMHub (e.g. `https://sbomhub.example.com`).  |
| `SBOMHUB_PROJECT_ID` | Target project UUID.                                                        |
| `SBOMHUB_API_KEY`    | API key with `write` permission.                                            |

## Recommended: `sbomhub-cli` (one-step scan + upload)

```yaml
name: SBOM
on:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sbomhub-cli
        run: go install github.com/youichi-uda/sbomhub-cli/cmd/sbomhub@latest

      - name: Scan and upload
        env:
          SBOMHUB_API_KEY: ${{ secrets.SBOMHUB_API_KEY }}
          SBOMHUB_URL:     ${{ secrets.SBOMHUB_URL }}
        run: |
          sbomhub login --api-key "$SBOMHUB_API_KEY" --url "$SBOMHUB_URL"
          sbomhub scan . --project "${{ secrets.SBOMHUB_PROJECT_ID }}" --fail-on critical
```

## Fallback: raw `curl` upload (canonical contract)

Use when you cannot install `sbomhub-cli` on the runner. The upload step
matches [`curl-upload.md`](./curl-upload.md) exactly — raw body, Bearer auth,
canonical `/projects/:id/sbom` endpoint.

```yaml
# name: Upload to SBOMHub (canonical)
- name: Generate SBOM with Syft
  uses: anchore/sbom-action@v0
  with:
    format: cyclonedx-json
    output-file: sbom.json

- name: Upload to SBOMHub
  env:
    SBOMHUB_API_KEY:    ${{ secrets.SBOMHUB_API_KEY }}
    SBOMHUB_URL:        ${{ secrets.SBOMHUB_URL }}
    SBOMHUB_PROJECT_ID: ${{ secrets.SBOMHUB_PROJECT_ID }}
  run: |
    curl -fsS -X POST \
      -H "Authorization: Bearer $SBOMHUB_API_KEY" \
      -H "Content-Type: application/json" \
      --data-binary "@sbom.json" \
      "$SBOMHUB_URL/api/v1/projects/$SBOMHUB_PROJECT_ID/sbom"
```

## Variants

The upload step above is identical in every variant; only the SBOM generation
step changes. Drop in the generator you need:

| Tool    | Generation step                                                                                       |
|---------|-------------------------------------------------------------------------------------------------------|
| Syft    | `uses: anchore/sbom-action@v0` with `format: cyclonedx-json` and `output-file: sbom.json`.            |
| Trivy   | `uses: aquasecurity/trivy-action@master` with `scan-type: fs`, `format: cyclonedx`, `output: sbom.json`. |
| cdxgen  | `npm install -g @cyclonedx/cdxgen && cdxgen -o sbom.json`.                                            |
| Docker  | `syft <image>:<tag> -o cyclonedx-json > sbom.json` after `docker build`.                              |

For matrix builds across multiple projects, swap `SBOMHUB_PROJECT_ID` for
`matrix.project_id` and define the matrix entries with per-project secrets.

## Optional: vulnerability gate

Block the workflow when critical vulnerabilities are reported after upload:

```yaml
- name: Block on critical vulnerabilities
  env:
    SBOMHUB_API_KEY:    ${{ secrets.SBOMHUB_API_KEY }}
    SBOMHUB_URL:        ${{ secrets.SBOMHUB_URL }}
    SBOMHUB_PROJECT_ID: ${{ secrets.SBOMHUB_PROJECT_ID }}
  run: |
    CRITICAL=$(curl -fsS \
      -H "Authorization: Bearer $SBOMHUB_API_KEY" \
      "$SBOMHUB_URL/api/v1/projects/$SBOMHUB_PROJECT_ID/vulnerabilities?severity=critical" \
      | jq '.total')
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::Found $CRITICAL critical vulnerabilities!"
      exit 1
    fi
```
