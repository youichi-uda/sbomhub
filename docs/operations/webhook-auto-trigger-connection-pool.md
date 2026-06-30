# Webhook auto-trigger: connection-pool sizing for the long-tx ingest path

**Status**: M13-4 (#90) operator guidance.

**Audience**: self-host operators planning capacity for a deployment that
has `auto_trigger_on_ingest: true` enabled (M12-4 / #85), and SaaS
operators reviewing PostgreSQL `max_connections` / pgbouncer pooling
posture.

**Companion docs**:

- [`diff-webhook-auto-trigger-smoke.md`](./diff-webhook-auto-trigger-smoke.md)
  — real-PG smoke verification of the same code path (M12-4).

---

## 1. Background — why the ingest tx holds a connection for ~tens of seconds

The M12-4 auto-trigger reuses the post-commit goroutine the SBOM upload
already starts (`apps/api/internal/handler/sbom.go::startBackgroundScan`).
After the vulnerability scan completes, the goroutine calls
`runDiffWebhookAutoTrigger`, which:

1. Opens **its own** transaction via `database.WithTxFunc` (the
   request-scoped `TenantTx` is already committed by then — the goroutine
   outlives the request).
2. Binds `app.current_tenant_id` to that tx with
   `SELECT set_config(..., true)` so every downstream RLS-protected read
   (project scope, predecessor SBOM lookup, webhook settings) is
   tenant-scoped. Without the GUC the diff service short-circuits on a
   `NULL → UUID` cast — the exact regression class F167 catalogued.
3. Computes the diff against the immediate predecessor inside the tx.
4. Calls `diff_webhook.Service.FireIfThreshold`, which evaluates
   thresholds and, on a fire decision, **issues the outbound HTTP POST to
   the operator's webhook URL with up to 3 attempts** under the per-attempt
   timeout and backoff schedule defined in
   `apps/api/internal/service/diff_webhook/diff_webhook.go`
   (`DefaultHTTPTimeout = 10s`, `DefaultRetryBackoffs = [0, 500ms, 2s]`).
5. Writes both `diff_webhook_fired` (delivery side, inside
   `FireIfThreshold`) and `diff_webhook_auto_fired` (decision side,
   inside `writeAutoFiredAudit`) audit rows.

Steps 4 and 5 all happen **inside the same tx that step 2 opened**. The
tx is the load-bearing primitive enforcing F168 audit-or-nothing: if the
audit `Log` call fails, the tx rolls back and there is no record of a
phantom fire. The trade-off is that the tx — and the pooled DB
connection backing it — stays open for the full webhook delivery window.

### Worst-case tx lifetime

| Segment | Duration (worst case) |
|---|---|
| Attempt 1 (no backoff) | up to 10s (DefaultHTTPTimeout) |
| Backoff before attempt 2 | 500 ms |
| Attempt 2 | up to 10s |
| Backoff before attempt 3 | 2 s |
| Attempt 3 | up to 10s |
| Audit write + commit | tens of ms |
| **Total (5xx-retry chain)** | **~32.5 s** |

A non-retrying success path (2xx on attempt 1) stays sub-second. A
deterministic 4xx (auth fail, bad URL shape) returns after attempt 1 with
no retry. The 32.5 s ceiling is hit only on consecutive 5xx / network
timeouts from the receiver — i.e. exactly when the receiver is unhealthy
and operators most want the system to keep delivering.

This is the **deliberate trade-off**: F168 audit-or-nothing demands that
the audit row and the fire decision be atomic, so we cannot release the
DB connection before the delivery resolves.

---

## 2. Sizing formula

The operator-facing knob is PostgreSQL `max_connections` (or, when
pgbouncer is in the path, the upstream session-pool size). Size it from
the workload, not from defaults.

### Formula

This is a direct application of **Little's law** to the long-tx ingest
path: the steady-state number of concurrently-open auto-trigger
transactions is approximately `arrival_rate × tx_duration`. Plug in the
**throughput** (uploads/sec), not an already-multiplied concurrent count
— that is what the `_per_s` suffix on the variable name is there to
enforce.

```
max_connections  =  ceil( (ingest_rate_per_s × avg_tx_duration_s) / target_tx_pool_utilization )
                  + baseline_connections
```

Where:

- `ingest_rate_per_s` = peak SBOM upload **throughput** in uploads/second
  the deployment must absorb without queueing — i.e. `λ` in Little's law,
  NOT a concurrency count. 90th percentile of historical
  `POST /api/v1/projects/:id/sbom` rate is a reasonable proxy. If you
  already measured "concurrent open tx" directly, skip this formula and
  size `max_connections` from that observation; the formula exists to
  derive that quantity from arrival rate and tx duration.
- `avg_tx_duration_s` = expected tx lifetime per ingest. Use **5 s** when
  most webhooks succeed on attempt 1 with a fast receiver, **15 s** when
  the receiver is on a different network / slow path, **32.5 s** for the
  full-retry ceiling planning.
- `target_tx_pool_utilization` = headroom factor, typically `0.7-0.8`
  (i.e. leave 20-30 % of `max_connections` as buffer for non-ingest
  traffic, migrations, admin queries).
- `baseline_connections` = 10-20 for non-ingest traffic (web requests,
  CLI scan-status polls, audit reads, redis-less polling, idle pool
  minimums).

### Worked example

Mid-sized SaaS-like tenant, 10 ingests/sec sustained peak, average tx
duration 5 s under a healthy receiver, 80 % utilization budget,
baseline 15:

```
(10 × 5) / 0.8  +  15
= 62.5 + 15
≈ 78  →  round up to 100 for headroom (default PG max_connections)
```

Same workload, planning for the **full 32.5 s retry ceiling** (worst
case where the receiver is degraded but not unreachable):

```
(10 × 32.5) / 0.8  +  15
= 406 + 15
≈ 421  →  round up to 500
```

Use the worst-case figure when sizing absolute upper bounds (i.e. when
choosing the PostgreSQL instance class). Use the steady-state figure
when sizing the application pool (`DATABASE_MAX_OPEN_CONNS` etc.) so
healthy operation does not over-allocate idle connections.

### Standard recommendations for sbomhub self-host deployments

| Profile | Ingests / sec | `max_connections` | App pool max-open | Notes |
|---|---|---|---|---|
| **Small** (single team, < 100 projects) | ≤ 1 | 50 | 20 | Default `docker-compose.yml` posture is sufficient (PG 15 default 100 is generous). |
| **Medium** (multi-team, 100-1000 projects) | 1-10 | 200 | 80 | Override `max_connections` in `docker/docker-compose.yml` postgres `command:` or via a config map; bump pool max-open to match. |
| **Large** (multi-tenant SaaS, > 1000 projects) | 10-50 | 500 | 200 | Strongly consider pgbouncer (see §3) and split read-replicas for non-tx reads (audit log queries, dashboards). |

The shipped `docker/docker-compose.yml` does not override
`max_connections` — PostgreSQL 15 defaults to 100. That is fine for the
Small profile and adequate for Medium with a healthy receiver, but the
Large profile needs explicit tuning. The shipped compose stack runs a
**single `api` replica**, which is the baseline assumption behind the
`App pool max-open` column above. The moment an operator scales
`apps/api` horizontally (compose `deploy.replicas`, Kubernetes
`replicas`, autoscaling group desired count, etc.), the next
sub-section's per-replica constraint must hold.

### Per-replica pool constraint (multi-replica deployments)

`App pool max-open` is the Go `database/sql.SetMaxOpenConns` ceiling and
is **per-replica**, not cluster-wide. PostgreSQL `max_connections` is
cluster-wide. The table above implicitly assumes a single `api` replica;
once you scale horizontally, the sum of every replica's open-conn
ceiling — plus baseline — must fit under `max_connections` with
headroom:

```
pool_max_open_per_replica × api_replica_count
  + baseline_connections
  ≤ max_connections × target_utilization
```

Solve for `pool_max_open_per_replica` when sizing a new deployment:

```
pool_max_open_per_replica  =  floor(
    ( max_connections × target_utilization - baseline_connections )
      / api_replica_count
)
```

Worked examples — Medium profile (`max_connections = 200`, `target_utilization = 0.8`, `baseline = 15`):

| Replicas | Budget for app pools | Per-replica max-open | Notes |
|---|---|---|---|
| **1** (docker-compose default) | 200 × 0.8 − 15 = 145 | 145 → use table default **80** (under-allocation is fine; the table figure leaves room for connection bursts) | Single-replica matches the §2 table verbatim. |
| **2** (compose `deploy.replicas: 2`) | 145 | **72** per replica (2 × 72 + 15 = 159 ≤ 160) | Drop `DATABASE_MAX_OPEN_CONNS` from 80 → 72 on each replica. |
| **3** (small Kubernetes deployment) | 145 | **48** per replica (3 × 48 + 15 = 159 ≤ 160) | Without this drop, 3 × 80 + 15 = 255 > 200 — replicas would race for connections and trip `FATAL: sorry, too many clients already`. |

When operators forget this constraint and leave `DATABASE_MAX_OPEN_CONNS`
at the single-replica default while scaling horizontally, the symptom
is exactly the §6.2 "Connection exhaustion" failure mode firing under
otherwise-healthy ingest load. **Always re-derive `pool_max_open_per_replica`
from the formula above when changing replica count, not from the table
defaults alone.** The pgbouncer path (§3) does not relax this constraint
— a session-pool pgbouncer still pins one backend per checked-out client
connection, so the same arithmetic applies, with pgbouncer
`max_client_conn` replacing PostgreSQL `max_connections` as the binding
ceiling.

---

## 3. Connection pooling guidance

### pgbouncer pool mode — session pooling REQUIRED

If pgbouncer (or any equivalent pooler such as Odyssey, pgpool) is in
the path between the API and PostgreSQL, it **MUST run in session
pool mode**. Transaction pool mode and statement pool mode are
incompatible with the auto-trigger path:

| Pool mode | Compatible? | Why |
|---|---|---|
| **session** | YES (required) | Each client holds one backend connection for the lifetime of the application's connection. The 32.5 s tx survives because nothing tries to multiplex the backend mid-tx. |
| **transaction** | NO | A tx-pool backend is pinned for the full BEGIN..COMMIT span, **so `set_config(..., true)` does survive within a single auto-trigger tx** — the tenant GUC binding is not silently dropped, and RLS stays enforced. The reasons to still reject tx-pool for this path are operational, not correctness-based: **(1)** the ~32.5 s tx ceiling means every ingest pins a backend for tens of seconds, which negates the whole point of tx-pool's multiplexing (you pay the pooler's latency overhead while getting session-pool's connection-pinning characteristics); **(2)** Go `database/sql` keeps a per-connection cache of server-side prepared statements (`PREPARE`d on the backend), which interact poorly with pgbouncer's tx-pool because the backend a `*sql.Conn` lands on for tx N+1 may not have the prepared statements that were issued on tx N's backend, surfacing as `prepared statement "..." does not exist` errors; **(3)** failure-mode debugging becomes harder because the application-side connection identity no longer maps 1:1 to a backend `pid`, so `pg_stat_activity` traces and the §4 monitoring queries lose their pid-stable view of long-running auto-trigger transactions. Use session-pool. |
| **statement** | NO | Forbids any multi-statement tx outright. The auto-trigger tx contains `set_config` + several reads + audit insert + commit; statement pooling rejects it. |

The pooler's max client connections sets a ceiling unrelated to (and
typically lower than) `max_connections`. Size **both**: backend
`max_connections` from §2, then pgbouncer `max_client_conn` ≥ the
application's expected concurrent ingests **plus** baseline traffic.

### Direct connection vs. pgbouncer

| Choice | When to pick it |
|---|---|
| **Direct connection** (no pgbouncer) | Small / Medium profile. Single API replica or a few, all in the same VPC as Postgres. Simpler operationally. |
| **pgbouncer in session mode** | Large profile, or when API runs as many short-lived replicas (e.g. autoscaling). The connection re-use across replica restarts is the win, **not** multiplexing — session pooling does not multiplex. |

---

## 4. Monitoring & alerting

### PostgreSQL — connection utilization

Track active and waiting connections from `pg_stat_activity`. The
auto-trigger tx surfaces as `state = 'idle in transaction'` for most of
the HTTP delivery window (the tx is open but no SQL is in flight while
the HTTP POST is outstanding):

```sql
SELECT state,
       wait_event_type,
       wait_event,
       count(*) AS n,
       max(now() - xact_start) AS oldest_xact
FROM pg_stat_activity
WHERE datname = current_database()
  AND backend_type = 'client backend'
GROUP BY state, wait_event_type, wait_event
ORDER BY oldest_xact DESC NULLS LAST;
```

Healthy steady-state pattern:

- `state = 'active'`: bounded by application worker count.
- `state = 'idle in transaction'`: roughly `ingest_rate × avg_tx_duration_s`.
  A non-zero baseline IS expected on a busy deployment — it does not
  itself indicate a leak.
- `wait_event_type = 'Client'` on those `idle in transaction` rows: the
  backend is waiting on the application, which is waiting on the
  receiver. Sustained `Client` wait > `max_connections × 0.5` means the
  receiver is becoming the bottleneck.

### Application — webhook retry rate

The new `diff_webhook_auto_fired` audit row records every auto-trigger
decision. Failure rate over a rolling window is the canonical operator
signal:

```sql
SELECT
    date_trunc('hour', created_at) AS hour,
    count(*) FILTER (WHERE details->>'status' = 'success')       AS ok,
    count(*) FILTER (WHERE details->>'status' = 'failure')       AS fail,
    count(*) FILTER (WHERE details->>'status' = 'error')         AS err,
    count(*)                                                     AS total
FROM audit_logs
WHERE action = 'diff_webhook_auto_fired'
  AND tenant_id = current_setting('app.current_tenant_id')::uuid
  AND created_at > now() - interval '24 hours'
GROUP BY 1
ORDER BY 1 DESC;
```

Pair this with `diff_webhook_fired` (delivery audit, written by
`FireIfThreshold`) to attribute failures to a specific HTTP status —
see `diff-webhook-auto-trigger-smoke.md` § "Audit log replay" for the
joining replay query.

### Suggested alert thresholds

| Signal | Warn | Page |
|---|---|---|
| `pg_stat_activity` total connections | > 70 % of `max_connections` for 5 min | > 90 % of `max_connections` for 1 min |
| `idle in transaction` (Client wait) | > 25 % of `max_connections` for 5 min | > 50 % of `max_connections` for 1 min |
| `diff_webhook_auto_fired` failure rate (hourly) | > 10 % | > 25 % |
| Oldest `xact_start` age | > 60 s | > 120 s |

The "oldest xact_start age" page-level alert is the canonical signal
that something has wedged a webhook delivery beyond the 32.5 s ceiling
(receiver hanging without returning 5xx). It implies either a missing
`statement_timeout` (see §6) or a receiver SLA breach.

---

## 5. Latency mitigation

Operators who hit the 32.5 s ceiling regularly have three tunable knobs,
in order of operational simplicity:

### 5.1 Raise the fire thresholds

The webhook only fires when `new_critical >= critical_threshold` or
`new_high >= high_threshold` or
`new_license_violations >= license_violation_threshold`. Tightening
those thresholds upward reduces fire frequency proportionally. Operators
running noisy first-party SBOM ingests (e.g. nightly CI scans of every
PR build) typically over-fire at `critical_threshold = 1`. Moving to
`critical_threshold = 3` with `high_threshold` disabled cuts fire rate
by ~10× on typical npm / Go monorepos.

Tune via the existing settings endpoint:

```bash
curl -s -X PUT "$SBOMHUB_URL/api/v1/tenant/settings/diff-webhook" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "critical_threshold": 3, "high_threshold": 0, "enabled": true }'
```

### 5.2 Negotiate a receiver SLA

The default per-attempt timeout is 10 s. Receivers should target a
sub-1 s ACK and offload heavy work to their own queue. Document this in
the receiver-side runbook with the same SLA the operator wants
sbomhub's tx to honour:

- **5 s** receiver-side response budget — recommended for healthy
  steady-state; keeps total worst-case tx ≤ ~18 s.
- **10 s** — matches `DefaultHTTPTimeout`; the receiver is allowed to
  use the entire per-attempt budget. This is the current behaviour.

When a receiver cannot meet either SLA, an intermediate webhook relay
(e.g. a small HTTP listener inside the operator's VPC that 202-ACKs and
forwards via a message queue) is the standard remediation.

### 5.3 Retry backoff tuning (future work)

`DefaultRetryBackoffs = [0, 500ms, 2s]` is hard-coded as of M11-4. A
shorter schedule (e.g. `[0, 250ms, 750ms]`) would compress the worst
case to ~31 s; a longer one (e.g. `[0, 2s, 8s]`) gives a flaky receiver
more recovery time at the cost of holding the tx longer. Tunability via
the settings endpoint is a known M14+ candidate — see § "M13 持ち越し
pool" in `sbomhub-internal/planning/STATUS.md`. Operators needing this
today can patch the constant locally; the upstream change must keep the
default backoff schedule conservative (no implicit ingestion latency
regression for unaware operators).

---

## 6. Failure modes

### 6.1 Statement / transaction timeout

PostgreSQL's `statement_timeout` and `idle_in_transaction_session_timeout`
default to `0` (unlimited). For sbomhub:

- **`statement_timeout = 60s`** (recommended). The auto-trigger never
  issues a single SQL statement that should exceed a second; 60 s is a
  safety net against pathological seeds / index misses, not a
  steady-state budget. Set it on the application role, not globally on
  postgres, so migrations and admin queries are unaffected.
- **`idle_in_transaction_session_timeout = 60s`** (recommended for
  large deployments). The auto-trigger tx sits in
  `idle in transaction` for at most ~32.5 s (the 3-retry ceiling), so
  a 60 s timeout is a hard ceiling that catches truly wedged
  deliveries (e.g. receiver TCP keepalive holding the connection open
  without ever responding). If you set this, also extend the
  per-attempt HTTP timeout downward (`DefaultHTTPTimeout = 5s`) to
  preserve the safety margin.

Apply at the database role granularity to scope the change:

```sql
ALTER ROLE sbomhub_app SET statement_timeout = '60s';
ALTER ROLE sbomhub_app SET idle_in_transaction_session_timeout = '60s';
```

When the timeout fires, the auto-trigger's `database.WithTxFunc` returns
an error, the goroutine logs `diff_webhook auto-trigger failed`, and
**no `diff_webhook_auto_fired` audit row is written** (the tx rolled
back). The corresponding `diff_webhook_fired` row may have been
persisted by `FireIfThreshold` before the timeout depending on
which statement was active — operators should treat a `_fired` row
without a paired `_auto_fired` row as the audit-side signal of a
timeout-rollback.

### 6.2 Connection exhaustion

When `max_connections` is reached, PostgreSQL refuses new connections
with `FATAL: sorry, too many clients already`. The Go side surfaces
this as `dial tcp: connection refused` or as `pq: too many connections`
from the driver depending on whether the rejection is at the pooler or
the postgres backend.

The application response in `docker-compose.yml` posture:

- New HTTP requests that need a DB connection fail with 500 immediately
  after the `*sql.DB` pool's wait timeout (default 0 = wait forever, but
  the request's own context cancels it).
- The auto-trigger goroutine inside an existing request **completes** if
  it acquired its connection before exhaustion; otherwise it fails the
  `WithTxFunc` call and logs `diff_webhook auto-trigger failed`. No
  webhook fires; no audit row is written.

Recovery is identical to any other DB-side capacity exhaustion: bump
`max_connections` (requires postgres restart) or kill long-running
sessions (`pg_terminate_backend`). The §4 alert thresholds exist so
operators get a warn-page-page chain well before reaching this state.

### 6.3 Receiver returns 5xx through all 3 attempts (dead-letter)

When all 3 attempts return 5xx (or all time out), `FireIfThreshold`
returns a `FireDecision` with `Status` = the last HTTP status and
`ErrorMessage` set. The auto-trigger then:

1. Persists `diff_webhook_fired` (the delivery audit, status=5xx, with
   error text) — written by the webhook service.
2. Persists `diff_webhook_auto_fired` with `status="failure"`,
   `http_status` = last 5xx, `error_text` = last error — written by
   `writeAutoFiredAudit`.
3. Updates `tenant_diff_webhook_settings.last_fired_at` /
   `last_response_status` / `last_error` so the settings page surfaces
   the failure.

The audit row IS the dead-letter record. There is no separate
dead-letter queue and no auto-retry beyond the 3 in-flight attempts —
that is by design (F168 keeps the audit chain bounded and operator
intervention explicit). Operators wishing to replay a failed delivery
can re-ingest the SBOM (the auto-trigger re-fires the same predecessor
diff against the same payload) once the receiver is healthy, or wire
a dashboards-side alert off the `diff_webhook_auto_fired` failure rate
(§4) to drive manual replay.

---

## 7. Cross-references

- [`diff-webhook-auto-trigger-smoke.md`](./diff-webhook-auto-trigger-smoke.md)
  — real-PG smoke verification (M12-4): exercises this same code path
  end-to-end with a live receiver and the 2-tenant RLS assertion.
- `apps/api/internal/handler/sbom.go::runDiffWebhookAutoTrigger`
  (M12-4) — the long-tx implementation this doc covers; read-only
  reference.
- `apps/api/internal/service/diff_webhook/diff_webhook.go`
  (M11-4) — the underlying `FireIfThreshold` retry policy
  (`DefaultHTTPTimeout`, `DefaultRetryBackoffs`).
- `docker/docker-compose.yml` — current default postgres posture
  (no `max_connections` override; PG 15 default 100).
- `sbomhub-internal/planning/STATUS.md` § "M12 持ち越し" — origin of
  this guidance (long-tx connection-pool sizing call-out).

---

*Japanese translation: TBD (deferred to M14+ alongside the rest of the
`docs/operations/` set).*
