# Snippet: GitLab CI job

<!-- check-snippets:signature: sbomhub-upload: -->

> **Canonical source.** This file is the single source of truth for the
> SBOMHub GitLab CI job. The upload command matches
> [`curl-upload.md`](./curl-upload.md) — raw body, Bearer auth, canonical
> `/projects/:id/sbom` endpoint.

## Required GitLab CI/CD variables

Define these as **protected**, **masked** variables under
*Settings → CI/CD → Variables*:

| Variable             | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `SBOMHUB_URL`        | Base URL of your self-hosted SBOMHub (e.g. `https://sbomhub.example.com`).  |
| `SBOMHUB_PROJECT_ID` | Target project UUID.                                                        |
| `SBOMHUB_API_KEY`    | API key with `write` permission.                                            |

## Recommended: `sbomhub-cli` (one-step scan + upload)

```yaml
stages:
  - sbom

sbomhub-scan:
  stage: sbom
  image: golang:1.22
  script:
    - go install github.com/youichi-uda/sbomhub-cli/cmd/sbomhub@latest
    - sbomhub login --api-key "$SBOMHUB_API_KEY" --url "$SBOMHUB_URL"
    - sbomhub scan . --project "$SBOMHUB_PROJECT_ID" --fail-on critical
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

## Fallback: raw `curl` upload

Use when you cannot install `sbomhub-cli` on the runner.

```yaml
stages:
  - sbom

sbomhub-upload:
  stage: sbom
  image: alpine:3.20
  before_script:
    - apk add --no-cache curl jq
    # Install Syft (or substitute Trivy / cdxgen).
    - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - syft . -o cyclonedx-json > sbom.json
    - |
      curl -fsS -X POST \
        -H "Authorization: Bearer $SBOMHUB_API_KEY" \
        -H "Content-Type: application/json" \
        --data-binary "@sbom.json" \
        "$SBOMHUB_URL/api/v1/projects/$SBOMHUB_PROJECT_ID/sbom"
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```
