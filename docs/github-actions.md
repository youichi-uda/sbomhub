# GitHub Actions Integration

This guide explains how to integrate SBOMHub with GitHub Actions for automated SBOM generation and upload.

## Overview

Automate your SBOM workflow:

1. Generate SBOM on every push/release
2. Upload to SBOMHub for vulnerability tracking
3. Receive notifications for new vulnerabilities

## Prerequisites

1. SBOMHub instance (self-hosted or SaaS)
2. Project created in SBOMHub
3. API key generated for the project

## Setup

### 1. Create API Key

1. Go to your project in SBOMHub
2. Navigate to Settings → API Keys
3. Click "Create API Key"
4. Save the key securely (shown only once)

### 2. Add GitHub Secrets

In your GitHub repository:

1. Go to Settings → Secrets and variables → Actions
2. Add the following secrets:

| Secret | Description |
|--------|-------------|
| `SBOMHUB_API_KEY` | Your API key from step 1 |
| `SBOMHUB_URL` | Your SBOMHub URL (e.g., `https://sbomhub.app` or `http://your-server:8080`) |
| `SBOMHUB_PROJECT_ID` | Your project UUID |

## Workflow Examples

### Basic SBOM Upload

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

      - name: Generate SBOM with Syft
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json

      - name: Upload to SBOMHub
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom"
```

### With Container Image Scanning

```yaml
name: Container SBOM

on:
  push:
    branches: [main]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Generate SBOM from container
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft myapp:${{ github.sha }} -o cyclonedx-json > sbom.json

      - name: Upload to SBOMHub
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom"
```

### Using Trivy

```yaml
name: Trivy SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'cyclonedx'
          output: 'sbom.json'

      - name: Upload to SBOMHub
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom"
```

### Using cdxgen (Multi-language Support)

```yaml
name: cdxgen SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Generate SBOM with cdxgen
        run: |
          npm install -g @cyclonedx/cdxgen
          cdxgen -o sbom.json

      - name: Upload to SBOMHub
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom"
```

### Matrix Build for Multiple Projects

```yaml
name: Multi-project SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - path: ./frontend
            project_id: ${{ secrets.SBOMHUB_FRONTEND_PROJECT_ID }}
          - path: ./backend
            project_id: ${{ secrets.SBOMHUB_BACKEND_PROJECT_ID }}

    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft ${{ matrix.path }} -o cyclonedx-json > sbom.json

      - name: Upload to SBOMHub
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ matrix.project_id }}/sbom"
```

### With Vulnerability Check Gate

```yaml
name: SBOM with Gate

on:
  pull_request:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json

      - name: Upload to SBOMHub
        id: upload
        run: |
          RESPONSE=$(curl -s -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom")
          echo "response=$RESPONSE" >> $GITHUB_OUTPUT

      - name: Check Vulnerabilities
        run: |
          CRITICAL=$(curl -s \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/vulnerabilities?severity=critical" \
            | jq '.total')
          
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Found $CRITICAL critical vulnerabilities!"
            exit 1
          fi
```

## SBOM Generation Tools

| Tool | Best For | Command |
|------|----------|---------|
| Syft | General purpose, containers | `syft . -o cyclonedx-json` |
| Trivy | Containers, security focus | `trivy fs --format cyclonedx .` |
| cdxgen | Multi-language, mono-repos | `cdxgen -o sbom.json` |
| cyclonedx-gomod | Go projects | `cyclonedx-gomod mod -json` |
| cyclonedx-npm | Node.js projects | `cyclonedx-npm --output-file sbom.json` |

## Troubleshooting

### Authentication Failed

Verify your API key:

```bash
curl -H "Authorization: Bearer $SBOMHUB_API_KEY" \
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

For self-hosted instances, ensure:
- The server is accessible from GitHub Actions
- Firewall rules allow incoming connections
- Use a public URL or GitHub self-hosted runners

## Best Practices

1. **Generate on main branch**: Upload SBOMs for releases, not every commit
2. **Use secrets**: Never hardcode API keys in workflows
3. **Pin action versions**: Use specific versions for reproducibility
4. **Monitor notifications**: Set up Slack/Discord alerts for new vulnerabilities
5. **Review regularly**: Check the SBOMHub dashboard weekly
