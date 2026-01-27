# API Reference

This document describes the SBOMHub REST API.

## Base URL

- Self-hosted: `http://localhost:8080`
- SaaS: `https://api.sbomhub.app`

## Authentication

### API Key Authentication

For CI/CD integration, use API keys:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.sbomhub.app/api/v1/projects
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

#### Upload SBOM

```
POST /api/v1/projects/:id/sbom
```

**Request:**
- Content-Type: `multipart/form-data`
- Body: `sbom` file (CycloneDX or SPDX JSON)

**Example:**
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "sbom=@sbom.json" \
  https://api.sbomhub.app/api/v1/projects/{project_id}/sbom
```

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

- Self-hosted: No rate limiting
- SaaS Free: 100 requests/hour
- SaaS Pro: 1000 requests/hour
- SaaS Team: 10000 requests/hour

Rate limit headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1704067200
```
