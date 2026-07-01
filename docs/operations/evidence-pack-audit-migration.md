# Audit-row single-source migration notes (M15-4 / F236 + M15 Phase D round 1 / F237)

**Status**:
- M15-4 (#101) — `POST /projects/:id/evidence-pack/build` (F236).
- M15 Phase D round 1 — `GET /projects/:id/diff/graph` (F237).

Both are one-time `audit_logs` schema-convention shifts of the same
shape: a route was previously emitting **two** audit rows per request
(one middleware-generic, one handler-rich) and post-M15 emits **one**
row via the handler-level audit_pair only. Applies to any operator
running forensic queries over historical `audit_logs` rows that span
the pre-M15 → post-M15 boundary.

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

## F237 — `GET /projects/:id/diff/graph` (M15 Phase D round 1)

The same dual-path double-audit pattern applied to the M12-3 dependency-
graph diff view endpoint, with a sharper failure mode: the middleware
and handler emitted the **identical** `action` string.

### Pre-M15 shape (F237)

| source          | `action`          | `resource_type` | notes                                                              |
| --------------- | ----------------- | --------------- | ------------------------------------------------------------------ |
| middleware Audit| `diff.graph.view` | `diff`          | generic per-request row (`model.ActionDiffGraphViewed` / `model.ResourceDiff`) |
| handler audit_pair | `diff.graph.view` | `sbom_diff`  | rich details map (`node_count` / `edge_count` / `added` / `removed` / `changed` / `from_sbom_id` / `to_sbom_id`) via local const `ActionDiffGraphView` and `diff_summary.ResourceTypeSbomDiff` |

The two rows had:

1. **Identical action strings** (`diff.graph.view`). Every forensic
   `SELECT COUNT(*) FROM audit_logs WHERE action = 'diff.graph.view'`
   double-counted every render — no alias trick could disambiguate.
2. **Different resource_type** — `diff` (middleware side) vs.
   `sbom_diff` (handler side). Any `JOIN` on `(resource_type,
   resource_id)` picked one row or the other but not both, depending
   on the target table.

### Post-M15 shape (F237)

The middleware `/diff` branch INTENTIONALLY returns `("", "")` when the
path ends with `/graph`, so `Audit()` skips its per-request row. The
handler-level audit_pair in `DiffHandler.ProjectDiffGraph` (F168
audit-or-nothing — 500 on audit write failure, no render leaked) is the
sole emit source, and it now references `model.ActionDiffGraphViewed`
directly (the local `ActionDiffGraphView` const in `handler/diff.go`
was removed).

| source          | `action`          | `resource_type` | notes                                        |
| --------------- | ----------------- | --------------- | -------------------------------------------- |
| middleware Audit| — (skipped)       | — (skipped)     | no row emitted for `/diff/graph`             |
| handler audit_pair | `diff.graph.view` | `sbom_diff`  | rich details map (unchanged)                 |

**Net effect for new rows: one row per graph render, action =
`diff.graph.view`, resource_type = `sbom_diff` (only).**

The other `/diff` sub-paths (`/diff`, `/diff/summary`, `/diff.csv`,
`/diff.pdf`) are **unaffected** — those routes continue to be
classified by the middleware (`diff.viewed` / `diff.summary` on
`resource_type=diff`).

### Forensic query implications (F237)

#### Cross-boundary queries (spanning pre-M15 and post-M15 rows)

Pre-M15 `diff.graph.view` rows come in two flavours distinguishable
only by `resource_type`. Query BOTH resource_types when reading history
that straddles the M15 deploy:

```sql
SELECT id, action, resource_type, resource_id, created_at,
       details->>'node_count'   AS node_count,
       details->>'from_sbom_id' AS from_sbom_id,
       details->>'to_sbom_id'   AS to_sbom_id
FROM audit_logs
WHERE tenant_id = $1
  AND action = 'diff.graph.view'
  AND resource_type IN ('sbom_diff', 'diff')
  AND created_at >= NOW() - INTERVAL '90 days'
ORDER BY created_at DESC;
```

#### Deduplicating historical double rows

The two pre-M15 rows for a single render share the same request /
`TenantTx`, so they land at the same `created_at` to millisecond
precision. Group by `(action, date_trunc('second', created_at))`
partitioned by tenant to collapse pairs:

```sql
SELECT
    tenant_id,
    action,
    date_trunc('second', created_at) AS bucket,
    array_agg(DISTINCT resource_type)  AS resource_types,
    COUNT(*)                           AS pre_m15_row_count
FROM audit_logs
WHERE action = 'diff.graph.view'
GROUP BY tenant_id, action, date_trunc('second', created_at)
HAVING COUNT(*) > 1;  -- COUNT=2 rows are pre-M15 doubles (one per resource_type)
```

Rows returned by this query with `resource_types = {sbom_diff, diff}`
and `pre_m15_row_count = 2` are the middleware+handler pairs; keeping
the `sbom_diff` row (rich details) and discarding the `diff` row is
the canonical dedupe.

#### New rows only (post-M15 deploy)

Filter on resource_type to select only the handler-side row:

```sql
SELECT * FROM audit_logs
WHERE action = 'diff.graph.view'
  AND resource_type = 'sbom_diff'
  AND created_at >= '2026-07-01';  -- adjust to your M15 deploy date
```

### Rich details map (F237, both eras)

The handler-side details map has been stable across the change:

```json
{
  "node_count":  <int>,
  "edge_count":  <int>,
  "added":       <int>,
  "removed":     <int>,
  "changed":     <int>,
  "from_sbom_id": "<uuid>",
  "to_sbom_id":   "<uuid>"
}
```

Pre-M15 the middleware-side (redundant) row only carried the generic
`{path, method, status, latency_ms}` envelope. That row is retired.

### Related pins (F237)

- `apps/api/internal/middleware/audit.go` — the `/diff` branch of
  `determineActionAndResource` returns `("", "")` when the path ends
  with `/graph` (per F237 head comment).
- `apps/api/internal/middleware/audit_test.go` —
  `TestDetermineActionAndResource_DiffGraphSkipped_F237` pins the
  middleware skip and the sibling `/diff*` non-skip invariants;
  `TestDetermineActionAndResource_ProjectChildResources` intentionally
  OMITS the `/diff/graph` case because the family is expected to skip.
- `apps/api/internal/handler/diff.go` — the handler audit_pair site
  (references `model.ActionDiffGraphViewed` directly; the local
  `ActionDiffGraphView` const was removed in M15 Phase D round 1).
- `apps/api/internal/handler/diff_test.go` —
  `TestDiffGraphHandler_Build_EmitsSingleAuditRow_F237` pins the
  handler side "exactly one row, action = diff.graph.view,
  resource_type = sbom_diff" contract via sqlmock.
- `apps/api/internal/model/audit.go` — `ActionDiffGraphViewed =
  "diff.graph.view"`.
- `apps/api/internal/service/diff_summary` — `ResourceTypeSbomDiff =
  "sbom_diff"`.
