# SBOM ingest → diff webhook auto-trigger: real-PG smoke verification

**Status**: M12-4 (#85) ship verification.

**Why this doc exists**: sqlmock covers the auto-trigger control flow
(tx envelope, stub interface contracts) but it CANNOT verify the
end-to-end chain that production operators actually depend on:

1. SBOM upload persists a row in `sboms` under the correct tenant
   via RLS.
2. The post-commit goroutine opens its own tx with
   `SET LOCAL app.current_tenant_id` bound.
3. The diff service resolves the predecessor SBOM by tenant-scoped
   read (no leakage across tenants).
4. The webhook service decrypts the per-tenant AES-256-GCM secret,
   computes the HMAC-SHA256 signature, and POSTs the payload.
5. The receiver verifies the signature with its copy of the secret.
6. Two audit rows land in `audit_logs`:
   `diff_webhook_fired` (delivery outcome) and
   `diff_webhook_auto_fired` (auto-trigger decision).
7. `tenant_diff_webhook_settings.last_fired_at` updates so the
   webhook settings page surfaces the most recent delivery.

The sqlmock tests in `internal/handler/sbom_test.go` only exercise the
test doubles at the service interface boundary — they do not exercise
the real `diff_webhook.Service`, the real `repository.AuditRepository`,
or the real Postgres tx + RLS. Past M8 lessons (#21 — sqlmock limits)
confirm this gap closes only with a live Postgres + receiver smoke.

## Pre-requisites

- A running self-host stack: `docker compose up -d postgres redis`
  + `cd apps/api && go run ./cmd/server` (port 8080 by default).
- A second tenant **not** under test for cross-tenant negative
  assertion (RLS scope verification).
- Test API keys for both tenants (`sbh_...`) created via the
  settings UI or `cd apps/api && go run ./cmd/migrate`-seeded
  fixtures.
- `jq` and `curl` in PATH.
- A real or stub HTTP receiver. Two options:
  - **Recommended**: a one-shot Go listener (snippet below) that
    prints the payload + signature header for visual inspection
    and verifies the HMAC against the operator-provided secret.
  - **Alternative**: a public webhook bin (e.g. webhook.site) —
    visual inspection only, no signature verification.

## Step 1 — configure the webhook with low thresholds

The thresholds you pick are the load-bearing knob — they decide
whether the test triggers. Set them low enough that a CycloneDX
fixture with one Critical vuln will cross the gate:

```bash
SBOMHUB_URL=http://localhost:8080
API_KEY=sbh_<your_key>

curl -s -X PUT "$SBOMHUB_URL/api/v1/tenant/settings/diff-webhook" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "http://host.docker.internal:9999/hook",
    "secret": "smoke-test-shared-secret-CHANGE-ME",
    "critical_threshold": 1,
    "high_threshold": 1,
    "license_violation_threshold": 0,
    "format": "json",
    "enabled": true
  }' | jq .
```

Verify the row landed (RLS-scoped read):

```bash
curl -s "$SBOMHUB_URL/api/v1/tenant/settings/diff-webhook" \
  -H "Authorization: Bearer $API_KEY" | jq .
```

The `secret` field must come back as `"***"` (placeholder) — the
plaintext is never round-tripped through the API.

## Step 2 — start the receiver

Save as `/tmp/diff-webhook-smoke-recv.go`:

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "os"
)

func main() {
    secret := []byte(os.Getenv("SHARED_SECRET"))
    if len(secret) == 0 {
        panic("SHARED_SECRET env var required")
    }
    http.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        defer r.Body.Close()
        mac := hmac.New(sha256.New, secret)
        mac.Write(body)
        expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
        got := r.Header.Get("X-SBOMHub-Signature")
        match := hmac.Equal([]byte(expected), []byte(got))
        fmt.Println("=== diff-webhook delivery ===")
        fmt.Println("event:", r.Header.Get("X-SBOMHub-Event"))
        fmt.Println("signature match:", match)
        fmt.Println("signature got:   ", got)
        fmt.Println("signature want:  ", expected)
        fmt.Println("payload:", string(body))
        w.WriteHeader(http.StatusOK)
    })
    fmt.Println("listening on :9999")
    if err := http.ListenAndServe(":9999", nil); err != nil {
        panic(err)
    }
}
```

Run it in a separate terminal:

```bash
SHARED_SECRET=smoke-test-shared-secret-CHANGE-ME go run /tmp/diff-webhook-smoke-recv.go
```

## Step 3 — ingest the BASELINE SBOM

Upload the first SBOM. This is the "no predecessor" path; the
auto-trigger MUST NOT fire but MUST audit.

```bash
PROJECT_ID=$(curl -s -X POST "$SBOMHUB_URL/api/v1/projects" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"diff-webhook-smoke"}' | jq -r .id)
echo "PROJECT_ID=$PROJECT_ID"

curl -s -X POST "$SBOMHUB_URL/api/v1/projects/$PROJECT_ID/sbom" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @docs/test-data/cyclonedx-baseline.json
```

Wait for the scan (poll scan-status until `completed`). Then check
the audit log:

```bash
curl -s "$SBOMHUB_URL/api/v1/audit-logs?action=diff_webhook_auto_fired&limit=5" \
  -H "Authorization: Bearer $API_KEY" | jq .
```

Expected: ONE row with `details.status="no_predecessor"`, no
`diff_webhook_fired` row, no receiver log line.

## Step 4 — ingest the SECOND SBOM (threshold-exceeding diff)

Upload a second SBOM with at least one NEW Critical or High CVE
relative to the baseline. The auto-trigger MUST fire.

```bash
curl -s -X POST "$SBOMHUB_URL/api/v1/projects/$PROJECT_ID/sbom" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @docs/test-data/cyclonedx-with-new-critical.json
```

Wait for the scan to complete (~5-30s depending on NVD response).

Expected within ~30s of scan completion:

1. The receiver prints **one** delivery with `signature match: true`.
   Mismatch here is the canonical M11-4 regression — secret
   decrypt path broken or HMAC computation drifted.
2. The audit log shows TWO new rows:

```bash
curl -s "$SBOMHUB_URL/api/v1/audit-logs?limit=10" \
  -H "Authorization: Bearer $API_KEY" | \
  jq '.audit_logs[] | select(.action | startswith("diff_webhook")) | {action, details}'
```

   - `diff_webhook_fired` (delivery audit, written by
     `diff_webhook.Service.FireIfThreshold`)
     with `details.http_status=200`.
   - `diff_webhook_auto_fired` (auto-trigger audit, written by
     `SbomHandler.runDiffWebhookAutoTrigger`)
     with `details.status="success"` AND `details.sbom_id` =
     the newly uploaded SBOM's id.

3. The settings page reflects the delivery:

```bash
curl -s "$SBOMHUB_URL/api/v1/tenant/settings/diff-webhook" \
  -H "Authorization: Bearer $API_KEY" | jq '{last_fired_at, last_response_status, last_error}'
```

   - `last_fired_at` is within the last minute.
   - `last_response_status` = 200.
   - `last_error` is null or empty.

## Step 5 — ingest a THIRD SBOM (below threshold)

Upload an SBOM whose diff against #2 has no new Critical / High vulns
(e.g. a minor patch bump of one component). The auto-trigger MUST
audit but MUST NOT deliver.

Expected:

- Receiver prints nothing for this ingest.
- `diff_webhook_auto_fired` row with `details.status="threshold_not_exceeded"`,
  `details.reason="below_thresholds"`,
  NO `diff_webhook_fired` row,
  NO new `last_fired_at` update.

## Step 6 — pause the webhook, ingest a FOURTH SBOM

Set `enabled=false` via the settings PUT, then upload a threshold-
exceeding SBOM. The auto-trigger MUST audit (`status="disabled"`)
and NOT deliver. This validates the "intentionally paused" UX
distinction from `no_config`.

## Step 7 — cross-tenant RLS assertion (negative)

From the **second tenant's** API key, query the audit log for the
first tenant's project:

```bash
curl -s "$SBOMHUB_URL/api/v1/audit-logs?limit=50" \
  -H "Authorization: Bearer $TENANT_B_API_KEY" | \
  jq '.audit_logs[] | select(.action | startswith("diff_webhook"))'
```

Expected: empty array. The auto_fired rows MUST be scoped to the
ingesting tenant.

## Failure-mode triage

| Symptom | Likely cause | Where to look |
|---|---|---|
| receiver sees ZERO deliveries on step 4 | scan goroutine not started, GUC not bound, predecessor not found | `slog.Info "Auto NVD scan completed"` + `slog.Error "diff_webhook auto-trigger failed"` |
| receiver sees delivery, `signature match: false` | encryption key rotated since secret stored, OR HMAC body marshal drift | `cmd/migrate-encryption` history, payload byte order |
| `diff_webhook_fired` row present but `diff_webhook_auto_fired` missing | F168 audit-or-nothing regression — auto_fired Log error swallowed | `slog.Error "diff_webhook auto-trigger audit write failed"` |
| both audit rows present but `last_fired_at` not updated | settings.UpdateFireResult silently failing | `repository.DiffWebhookRepository.UpdateFireResult` query |
| cross-tenant negative (step 7) returns rows | RLS bypass — F167 class regression | migration 047 policy presence + role grants |

## Audit log replay (operator query)

For every SBOM ingest in the last 24h, what did the auto-trigger
decide?

```sql
SELECT
    created_at,
    (details->>'sbom_id')::uuid AS ingest_sbom_id,
    details->>'status'          AS auto_status,
    details->>'http_status'     AS delivery_status,
    details->>'reason'          AS reason
FROM audit_logs
WHERE action = 'diff_webhook_auto_fired'
  AND tenant_id = current_setting('app.current_tenant_id')::uuid
  AND created_at > now() - interval '24 hours'
ORDER BY created_at DESC;
```

This is the canonical "did my ingests trigger webhooks?" replay.
Pair with the matching `diff_webhook_fired` row (same `tenant_id`,
`resource_id`=project_id, `created_at` within a few seconds) to
reconstruct the full chain.
