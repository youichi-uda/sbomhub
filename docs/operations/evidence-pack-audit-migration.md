# Evidence Pack audit log migration note (M15-4 / F236)

**Status**: M15-4 (#101) — one-time audit_logs schema convention shift.
Applies to any operator running forensic queries over historical
`audit_logs` rows that span the pre-M15 → post-M15 boundary.

## What changed

Before M15-4, `POST /api/v1/projects/:id/evidence-pack/build` produced
**two** rows in `audit_logs` for a single successful request:

| source          | `action`               | `resource_type` | notes                                                          |
| --------------- | ---------------------- | --------------- | -------------------------------------------------------------- |
| middleware Audit| `evidence_pack.built`  | `evidence_pack` | generic per-request row (path/method/status/latency)           |
| handler audit_pair | `evidence_pack_built` | `evidence_pack` | rich details map (vex/cra/meti counts, filename, `built_at`)   |

Two facts about the pre-M15 shape mattered for forensic queries:

1. The two rows used **different action strings** — dotted vs.
   underscore — even though they described the same business event.
   Any `GROUP BY action` over evidence pack builds double-counted
   without an explicit alias (`WHEN action IN
   ('evidence_pack.built', 'evidence_pack_built') THEN
   'evidence_pack.built'`).
2. Only the handler-side row carried the rich details map. The
   middleware-side row was a redundant per-request generic entry.

## Post-M15 shape

After M15-4 the middleware `/evidence-pack` branch is skipped (returns
`("", "")` from `determineActionAndResource`, which triggers the
`if action == "" { return err }` guard in `Audit()`), so the
middleware does **not** write an evidence pack row. The handler-level
audit_pair (F168 audit-or-nothing semantics — fails the request 500
and rolls back the `TenantTx` on audit write failure) is the sole
emit source, and it now uses `model.ActionEvidencePackBuilt =
"evidence_pack.built"` (dotted, unified with every other audit action
verb).

| source          | `action`              | `resource_type` | notes                                        |
| --------------- | --------------------- | --------------- | -------------------------------------------- |
| middleware Audit| — (skipped)           | — (skipped)     | no row emitted for `/evidence-pack/*` paths  |
| handler audit_pair | `evidence_pack.built` | `evidence_pack` | rich details map (unchanged)                 |

Net effect for new rows: **one row per build, action =
`evidence_pack.built` (dotted only)**.

## Forensic query implications

### Cross-boundary queries (spanning pre-M15 and post-M15 rows)

Filter on BOTH action strings when reading historical rows that
straddle the M15-4 deploy:

```sql
SELECT id, action, resource_type, resource_id, created_at,
       details->>'filename' AS filename,
       details->>'vex_approved_count' AS vex_count
FROM audit_logs
WHERE tenant_id = $1
  AND action IN ('evidence_pack.built', 'evidence_pack_built')
  AND created_at >= NOW() - INTERVAL '90 days'
ORDER BY created_at DESC;
```

### Deduplicating historical double rows

To collapse the two pre-M15 rows for a single build into one logical
event, group by `resource_id` (both rows carry the same `project_id`)
+ a coarse time bucket:

```sql
-- Buckets to 1-second precision — the two rows for a single build
-- are written from the same request within the same TenantTx, so
-- they share created_at to millisecond precision in practice.
SELECT
    tenant_id,
    resource_id,
    date_trunc('second', created_at) AS bucket,
    MIN(CASE WHEN action = 'evidence_pack.built' THEN action END) AS canonical_action,
    COUNT(*) AS pre_m15_row_count
FROM audit_logs
WHERE action IN ('evidence_pack.built', 'evidence_pack_built')
GROUP BY tenant_id, resource_id, date_trunc('second', created_at)
HAVING COUNT(*) > 1;  -- rows with COUNT=2 are pre-M15 doubles
```

The `HAVING COUNT(*) > 1` filter isolates the pre-M15 double rows so
they can be counted, migrated, or purged separately from post-M15
single rows.

### New rows only (post-M15 deploy)

Filter on the dotted form only:

```sql
SELECT * FROM audit_logs
WHERE action = 'evidence_pack.built'
  AND created_at >= '2026-07-01';  -- adjust to your M15-4 deploy date
```

## Rich details map (both eras)

The details map on the handler-side row has been stable across the
change; only the action string moved:

```json
{
  "project_id": "<uuid>",
  "format": "markdown",
  "filename": "sbomhub-evidence-pack-<slug>-<yyyymmdd>.md",
  "vex_approved_count": <int>,
  "cra_approved_count": <int>,
  "meti_assessment_included": <bool>,
  "meti_row_count": <int>,
  "meti_achieved_count": <int>,
  "include_vex_approved": <bool>,
  "include_cra_approved": <bool>,
  "include_meti_assessment": <bool>,
  "built_at": "<RFC3339 UTC>"
}
```

Pre-M15 the middleware-side (redundant) row only carried the generic
`{path, method, status, latency_ms}` envelope plus the M14-4
non-UUID-path-param entries. That row is retired.

## Rationale note (why Option A — handler wins, middleware skips)

- **Handler side** carries the rich details map compliance auditors
  need (vex/cra/meti counts, filename, built_at). Losing it silently
  in a middleware-side outage would defeat the audit contract.
- **Handler side** uses F168 audit-or-nothing semantics (audit write
  failure surfaces 500 and rolls back the surrounding TenantTx), which
  is the correct posture for a compliance artifact minting event.
- **Middleware side** is by-design best-effort (F227 dual-path audit
  design docstring in `apps/api/internal/middleware/audit.go`) — its
  Log error is swallowed so a per-request audit outage does not take
  the whole product down with a 500-storm. The best-effort semantics
  are correct for the generic per-request forensic trail, but they
  are incorrect for the specific evidence_pack.built business event
  where the row MUST land or the whole build must be rolled back.

Keeping both paths active meant the same row was written twice with
incompatible failure semantics. Skipping the middleware side for the
`/evidence-pack` family collapses this to the correct single-row
handler audit_pair.

## Related pins

- `apps/api/internal/middleware/audit.go` — the `/evidence-pack`
  branch of `determineActionAndResource` (returns `("", "")` per
  F236).
- `apps/api/internal/middleware/audit_test.go` —
  `TestDetermineActionAndResource_EvidencePackSkipped_F236` pins the
  middleware skip; `TestDetermineActionAndResource_
  AllHoistedFamilies_NoProjectFallthrough` intentionally OMITS
  evidence-pack because the family is expected to skip.
- `apps/api/internal/handler/evidence_pack.go` — the handler
  audit_pair site (references `model.ActionEvidencePackBuilt`
  directly; the local `AuditActionEvidencePackBuilt` underscore
  constant was removed in M15-4).
- `apps/api/internal/handler/evidence_pack_test.go` —
  `TestEvidencePackHandler_Build_HappyPath_EmitsSingleAuditRow_F236`
  pins the handler side "exactly one row, action =
  evidence_pack.built" contract via sqlmock.
- `apps/api/internal/model/audit.go` — `ActionEvidencePackBuilt =
  "evidence_pack.built"` and `ResourceEvidencePack = "evidence_pack"`.
