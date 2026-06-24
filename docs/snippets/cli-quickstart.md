# Snippet: `sbomhub` CLI quickstart

<!-- check-snippets:signature: sbomhub login --api-key "$SBOMHUB_API_KEY" --url "$SBOMHUB_URL" -->

> **Canonical source.** This file is the single source of truth for the
> three-step CLI flow (`login → scan → doctor`). Other docs link here.

## Install

```bash
# Homebrew (macOS / Linux)
brew install sbomhub/tap/sbomhub

# Or with Go
go install github.com/youichi-uda/sbomhub-cli/cmd/sbomhub@latest
```

## Three-step flow

```bash
# 1. Point the CLI at your self-hosted SBOMHub.
sbomhub login --api-key "$SBOMHUB_API_KEY" --url "$SBOMHUB_URL"

# 2. Scan the current directory and upload the generated SBOM.
#    Use --fail-on critical to exit non-zero when a critical CVE is found
#    (suitable for CI gating).
sbomhub scan . --project "$SBOMHUB_PROJECT_ID" --fail-on critical

# 3. Sanity-check the self-hosted instance (DB / Redis / encryption key /
#    LLM provider configuration). Safe to run before every scan.
sbomhub doctor
```

## Required environment

| Variable             | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `SBOMHUB_URL`        | Base URL of your self-hosted SBOMHub (e.g. `http://localhost:8080`).        |
| `SBOMHUB_PROJECT_ID` | Target project UUID (from the dashboard or `sbomhub projects list`).        |
| `SBOMHUB_API_KEY`    | API key with `write` permission (prefix `sbh_...`).                         |

## Related snippets

- [`curl-upload.md`](./curl-upload.md) — when you cannot install the CLI on a runner.
- [`github-actions.yml.md`](./github-actions.yml.md) — same flow as a GitHub Actions job.
- [`gitlab-ci.yml.md`](./gitlab-ci.yml.md) — same flow as a GitLab CI job.
