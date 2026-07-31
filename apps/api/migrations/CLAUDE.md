# apps/api/migrations — author guide

This directory holds the project's PostgreSQL migrations (one numbered
`<NNN>_<name>.up.sql` + matching `.down.sql` per step). The notes below
are the author-facing contract; the operational background lives in the
in-repo header comments of individual migrations and in the
`lint-migration-rls` tool that gates this directory in CI.

## Tenant-scoped tables

A "tenant-scoped" table is any table whose rows belong to exactly one
tenant — most product data tables, in practice. The project enforces
tenant isolation via PostgreSQL Row-Level Security (RLS) as the
authoritative boundary, with the application-layer `WHERE tenant_id = $1`
filter treated as defence-in-depth.

### Naming convention

**New tenant-scoped tables SHOULD use the `tenant_*` prefix.** Examples:

  - `tenant_llm_config` (migration 036 / 037)
  - `tenant_diff_webhook_settings` (migration 046 / 047)

The prefix is what made the lint trivially auditable in its first
iteration. The F183 (M13-5 #91) scope extension widened detection to
cover non-prefixed tables that declare a `tenant_id` column or are
promoted with `ALTER TABLE … ADD COLUMN tenant_id`, but a `tenant_*`
prefix still keeps grep / code-review trivial — please follow it for
anything new.

### Legacy non-`tenant_*` tables

The 007 / 023 hardening sweep predates the prefix convention. The
following tables carry `tenant_id` (or were ALTER-promoted to do so)
without the prefix:

  - `projects`, `sboms`, `components`, `vex_statements`,
    `license_policies`, `notification_settings`, `notification_logs`,
    `api_keys`, `audit_logs` — full RLS triple (`ENABLE` + `FORCE` +
    `CREATE POLICY tenant_isolation_<table>`) across 007 / 023.
  - `github_connections`, `github_repositories` — RLS added in partner
    migration 043.
  - `compliance_checklist_responses`, `sbom_visualization_settings` —
    RLS added in partner migration 040.
  - `report_settings`, `generated_reports`, `ipa_sync_settings`,
    `vulnerability_resolution_events`, `slo_targets`,
    `vulnerability_snapshots`, `compliance_snapshots`,
    `ssvc_project_defaults`, `ssvc_assessments` — RLS in the owning
    migration, FORCE harmonised by partner migration 042.
  - `issue_tracker_connections`, `vulnerability_tickets` — full RLS
    triple across 015 / 023.
  - `scan_settings`, `scan_logs` — RLS added in partner migration 048
    (F185 follow-up to the legacy 010 schema; companion changes to
    `internal/scheduler/vulnerability_scan.go` +
    `internal/service/scan_settings.go` switch the scheduler and the
    API handlers to per-tenant transactions so the new FORCE policy
    fires correctly).
  - Post-031 tables (`llm_calls`, `advisory_excerpts`,
    `reachability_results`, `vex_drafts`, `cra_reports`,
    `meti_assessments`) — already follow the `ENABLE + FORCE + POLICY`
    pattern in their owning migration.

These are accepted by the lint via directory-wide RLS evidence
aggregation (the partner-file pattern) — no exemption list needed.

### Structural exemptions

A small set of tables are intentionally NOT RLS-protected. The lint
records each with a one-line justification (see
`tools/lint-migration-rls/main.go::structuralExemptions`):

  - `tenant_users` — membership join table; RLS would be self-referential.
  - `vulnerabilities` — global CVE / advisory data shared across tenants.
    007 added a `tenant_id` column here; **063 dropped it** (dead column,
    no reader, and its presence made the shared catalogue look scoped).
    The exemption stays only because the lint scans migration files and
    007's additive DDL is still one of them.
  - `public_links`, `public_link_access_logs` — RLS removed in 030 to
    allow the anonymous `/api/v1/public/:token` flow; tenant scope
    enforced application-side.
  - `subscriptions`, `subscription_events`, `usage_records` — RLS
    removed in 031 to allow Lemon Squeezy webhook lookups; tenant scope
    enforced application-side.

`scan_settings` / `scan_logs` (legacy 010 schema) previously appeared in
this list as a pending follow-up; their RLS partner migration was added
in 048 (F185 fix, M13 Phase D round 2) together with the matching
scheduler + service refactor.

Adding a new entry requires the same care as removing an RLS policy —
PR review + an explicit narrative in the migration's header.

## RLS pattern for new tables

When adding a new `tenant_*` table (or any table with a `tenant_id`
column), include all three of these statements somewhere in this
directory — either inline in the owning `*.up.sql`, or in a dedicated
`<n>_<table>_rls.up.sql` partner file:

  1. `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;`
  2. `ALTER TABLE <table> FORCE  ROW LEVEL SECURITY;`
  3. `CREATE POLICY tenant_isolation_<table> ON <table> FOR ALL`
     `USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)`
     `WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);`

The `tenant_isolation_<table>` policy name is the project-wide
convention — the lint requires it. `FORCE` matters: without it the
table owner (the migrator role) silently bypasses the policy.

## Suppressing the lint

If a `tenant_*`-prefixed table or a tenant_id-bearing table genuinely
cannot carry RLS, add a one-line marker comment INSIDE the migration
file that defines it. Two forms are accepted (F195 / M13 Phase D
round 3):

```sql
-- lint:no-rls-required: <reason>                  -- unscoped
-- lint:no-rls-required(<table>): <reason>          -- table-scoped
```

The reason is mandatory in both forms and is echoed by the lint in
`--verbose` mode for the audit trail.

The unscoped form is the common case for migrations that define a
single tenant-scoped table. In a migration that defines MORE THAN ONE
tenant-scoped table the unscoped form is rejected as ambiguous (the
marker cannot disambiguate which table is being exempted, and silently
widening to file-wide would defeat the gate — the original 036 / 046
misses were exactly the "one table in a multi-table migration" shape).
Use the table-scoped form to exempt one specific table while keeping
its siblings under the full RLS contract:

```sql
-- lint:no-rls-required(tenant_global_mirror): shared upstream cache mirror
CREATE TABLE tenant_global_mirror (
    advisory_id TEXT PRIMARY KEY,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tenant_per_org_settings (
    tenant_id   UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    payload     JSONB NOT NULL
);

ALTER TABLE tenant_per_org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_per_org_settings FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_tenant_per_org_settings ON tenant_per_org_settings
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
```

Suppression should be rare — prefer the `structuralExemptions` map in
the lint source for tables that genuinely cannot ever carry RLS by
construction.

## What the lint actually checks

`tools/lint-migration-rls` runs as a hard CI gate on every PR that
touches `apps/api/migrations/**`. Its detection rule, after F183 /
F191 / F194 / F195:

  1. Detect a table as tenant-scoped if EITHER its name matches
     `tenant_*`, OR its `CREATE TABLE` body declares a `tenant_id`
     column, OR a later `ALTER TABLE … ADD [COLUMN] tenant_id`
     promotes it. Schema-qualified (`public.<table>`) and
     double-quoted (`"<table>"`) identifiers are recognised the same
     way (F194). The `COLUMN` keyword is optional per the SQL standard
     (F191).
  2. Require the `ENABLE` + `FORCE` + `CREATE POLICY tenant_isolation_*`
     triple to appear somewhere in the directory (any file).
  3. Skip tables listed in `structuralExemptions` or with a
     `-- lint:no-rls-required[(<table>)]: <reason>` inline marker
     (F195: unscoped form is rejected in multi-table migrations).

If you add a new `*.up.sql` and the lint fails, the error message names
the offending table + file:line and lists which of the three statements
is missing. Add the missing statement(s), or add a partner
`<n>_<table>_rls.up.sql` following the pattern of 037 / 047.

## Lock budgets

Both runners (`cmd/migrate/main.go` and the startup path in
`internal/database/migrate.go`) wrap each migration FILE in a single
transaction and neither sets `lock_timeout`, so the migrator role
inherits the server default of `0` — wait forever.

**Every new migration that acquires a lock conflicting with live traffic
must declare a budget before the first statement that needs one** (the
convention is to put it first in the file, and 063 / 064 / 065 do):

```sql
SET LOCAL lock_timeout = '5s';
```

`tools/lint-migration-locks` gates this in CI on every PR that touches
this directory.

### What this lint is, and is not

**It catches an honest author's oversight. It is not a boundary against
an author working around it.** That is structural, not a gap to be
closed: the rule is "declare a budget", and the value is yours to choose.
Measured on PostgreSQL 15.18:

| budget written | PostgreSQL | lint |
|---|---|---|
| `'5s'` | accepted | passes |
| `'1h'` | accepted, `eff=1h` | passes |
| `'24h'` | accepted, `eff=1d` | passes |

One plausible-looking line buys an effectively unbounded wait, so
hardening the tool against subtler evasions buys nothing. The lint is
calibrated for the mistake it actually prevents: adding
`ALTER TABLE components ADD COLUMN …` to a new migration without thinking
about locks at all.

The full list of things it deliberately does not detect — each measured,
implemented, then removed as out of scope — is in the package comment of
`tools/lint-migration-locks/main.go` under "What this lint deliberately
does NOT detect". In short: over-long budgets; GUCs changed by anything
other than `SET`/`RESET`; anything that changes what an unqualified name
resolves to mid-file (`search_path`, `SET SCHEMA`, `SET ROLE`); relations
whose identity moves (`RENAME TO`, `SET SCHEMA`); `U&"…"` identifiers;
teardown locks from `DROP TABLE`; savepoint rollback; locks taken by user
code a statement CALLS; `.down.sql` files; and how long a lock is HELD
once acquired.

### Why the rule exists

Measured on PostgreSQL 15.18, second session running the DDL under
`SET LOCAL lock_timeout = '1500ms'` while a first session holds a lock:

| holder | statement | result |
|---|---|---|
| `SELECT` (ACCESS SHARE) | `ALTER TABLE … ADD COLUMN` | canceling statement due to lock timeout |
| `SELECT` (ACCESS SHARE) | `CREATE INDEX` (non-concurrent) | proceeded |
| `SELECT` (ACCESS SHARE) | `ALTER TABLE … VALIDATE CONSTRAINT` | proceeded |
| `UPDATE` (ROW EXCLUSIVE) | `CREATE INDEX` (non-concurrent) | canceling statement due to lock timeout |
| `UPDATE` (ROW EXCLUSIVE) | `ALTER TABLE … VALIDATE CONSTRAINT` | proceeded |
| `UPDATE` on the *referenced* table | `CREATE TABLE … REFERENCES` it | canceling statement due to lock timeout |

Without a budget those waits are unbounded, and because PostgreSQL queues
later lock requests behind a blocked stronger request, one stalled
`ALTER TABLE` takes the whole table offline rather than just itself. With
a budget the migration fails fast and the runner's per-file transaction
rolls the DDL and the `schema_migrations` row back together, so the
deploy is safe to retry when the table is quiet.

### What needs a budget

The lint measures each statement's lock mode and requires a budget for
**SHARE and stronger on a relation that already exists**. SHARE is the
weakest mode in PostgreSQL's conflict table that conflicts with ROW
EXCLUSIVE, i.e. the weakest that can queue behind an ordinary write.

  - **ACCESS EXCLUSIVE** (conflicts with everything, incl. `SELECT`) —
    most `ALTER TABLE` forms (`ADD`/`DROP COLUMN`, `ADD`/`DROP
    CONSTRAINT … CHECK/UNIQUE`, `SET`/`DROP NOT NULL`, `SET`/`DROP
    DEFAULT`, `ALTER COLUMN … TYPE`, `RENAME`), `ENABLE`/`DISABLE`/
    `FORCE`/`NO FORCE ROW LEVEL SECURITY`, `CREATE`/`DROP POLICY`,
    `DROP INDEX`, `DROP TRIGGER`, `TRUNCATE`, `DROP TABLE`,
    `CREATE OR REPLACE VIEW` over an existing view, and
    `CREATE TABLE … PARTITION OF` (on the **parent**).
  - **EXCLUSIVE** (conflicts with everything but a plain reader) —
    `LOCK TABLE … IN EXCLUSIVE MODE`,
    `REFRESH MATERIALIZED VIEW CONCURRENTLY`.
  - **SHARE ROW EXCLUSIVE** (conflicts with writers) —
    `ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY`, `CREATE TRIGGER`,
    `ALTER SEQUENCE`, and **an inline `REFERENCES` inside `CREATE
    TABLE`** — the lock lands on the *referenced* (pre-existing) table,
    not on the new one.
  - **SHARE** (conflicts with writers) — non-concurrent `CREATE INDEX`.

Below the bar, and therefore **not** required to carry a budget:
`VALIDATE CONSTRAINT`, `COMMENT ON`, `SET STATISTICS`, `ANALYZE`, and
`ALTER TABLE … SET (…)` **for the weak-lock storage parameters only** —
`fillfactor`, `parallel_workers`, the `autovacuum_*` and `toast.*`
families. `SET (user_catalog_table = true)` was measured at ACCESS
EXCLUSIVE, and any parameter the lint does not recognise is charged the
same way. `INSERT`/`UPDATE`/`DELETE` are ROW EXCLUSIVE and also below the
bar. Migration 065 budgets its `VALIDATE` anyway as belt and braces; the
lint does not demand it.

Statements against a relation **created in the same file** are exempt:
the creating transaction is the only session that can see the new
relation, so its ACCESS EXCLUSIVE lock has nobody to block. Two limits:

  - It is **same-file only**. A table created in migration N is fully
    live by the time N+1 runs on an instance that already applied N.
  - It is **not granted for `IF NOT EXISTS`**. `CREATE TABLE IF NOT
    EXISTS t` / `CREATE INDEX IF NOT EXISTS i` prove nothing: if the
    relation already existed the statement was a no-op and everything
    after it in the file contends with live traffic. Migration 026 is
    baselined for exactly this reason.

Two further shapes the lint charges rather than waves through:

  - **`DO $$ … $$` blocks** are charged ACCESS EXCLUSIVE on an unnamed
    relation. A DO body is PL/pgSQL and needs no `EXECUTE` to run DDL —
    measured, `DO $$ BEGIN ALTER TABLE t ADD COLUMN c int; END $$;` takes
    ACCESS EXCLUSIVE on `t`. Every DO block in this directory today is a
    read-only pre-flight assertion, but a gate cannot rely on "usually",
    and DO blocks ARE a shape honest authors write here.
  - **Statements the lint has never measured** are a hard failure, not a
    pass. Anything unrecognised reports `unrecognised statement` and must
    be measured and taught to `classifyStatement` in the same PR.

The lint also refuses to certify a file it could not lex — reaching
end-of-file inside a comment, string literal or dollar-quoted body means
its view of the file diverged from PostgreSQL's.

### `CREATE INDEX CONCURRENTLY` is not available here

The usual advice for a SHARE-taking `CREATE INDEX` is "use
CONCURRENTLY". That does not work in this repository — both runners
always open a transaction, and PostgreSQL refuses:

```
BEGIN; CREATE INDEX CONCURRENTLY … ;  ERROR: CREATE INDEX CONCURRENTLY cannot run inside a transaction block
BEGIN; DROP INDEX CONCURRENTLY … ;    ERROR: DROP INDEX CONCURRENTLY cannot run inside a transaction block
BEGIN; REINDEX INDEX CONCURRENTLY … ; ERROR: REINDEX CONCURRENTLY cannot run inside a transaction block
BEGIN; REINDEX SCHEMA public;         ERROR: REINDEX SCHEMA cannot run inside a transaction block
BEGIN; REINDEX DATABASE … ;           ERROR: REINDEX DATABASE cannot run inside a transaction block
BEGIN; REINDEX SYSTEM … ;             ERROR: REINDEX SYSTEM cannot run inside a transaction block
BEGIN; VACUUM … ;                     ERROR: VACUUM cannot run inside a transaction block
BEGIN; CLUSTER;                       ERROR: CLUSTER cannot run inside a transaction block
```

All of these are hard runtime failures of the migration, so the lint
reports them as their own finding kind and the legacy baseline does not
waive them. Use the non-concurrent form plus a budget, or run the
operation outside the runner as a documented operator step.

`REFRESH MATERIALIZED VIEW [CONCURRENTLY]` and `CLUSTER <table>` were
measured to run fine inside a transaction and are **not** in that set —
they still take locks above the bar, so they still need a budget.

`REINDEX INDEX` / `REINDEX TABLE` sit in between: they run inside a
transaction for an ordinary table but are refused when the target is
PARTITIONED (measured). A static scan cannot tell which, so the lint
reports them as `unrecognised statement` rather than let a budget make
them green.

`ALTER TYPE … ADD VALUE` takes no lock on any user relation (measured)
and needs no budget. It has a different constraint of its own: the added
value cannot be USED until the transaction commits, so a migration that
adds an enum value and then writes it in the same file will fail. That is
PostgreSQL's rule, not this lint's.

### `SET LOCAL`, not `SET`

Measured on the same instance:

```
BEGIN; SET       lock_timeout='5s'; COMMIT;  -- after commit: 5s
BEGIN; SET LOCAL lock_timeout='5s'; COMMIT;  -- after commit: 0
```

Both runners hold a pooled `*sql.DB`, so a plain `SET` leaks the budget
onto whichever connection runs the next migration file — the budget stops
being a property of the file you are reading. `SET LOCAL` is scoped to
exactly the transaction the runner rolls back.

A budget that resolves to zero is rejected, because `0` is PostgreSQL's
"wait forever". PostgreSQL rounds the value to whole milliseconds
half-to-even, so several spellings collapse to zero — measured on 15.18,
`'+0'`, `'-0ms'`, `'00'`, `'0.0s'`, `'0.4ms'` and `'0.5ms'` all report an
effective `0`, while `'0.6ms'` reports `1ms`. `DEFAULT` and
`RESET lock_timeout` are also rejected. Only the budget in force **at** a
statement counts, so a file that sets `'5s'`, later resets it, and then
runs DDL still fails.

### Splitting across files when a statement needs a table scan

`lock_timeout` bounds lock **acquisition**, not execution. A statement
that holds ACCESS EXCLUSIVE across a full-table scan
(`ADD CONSTRAINT … CHECK` without `NOT VALID`) still blocks everything
for the scan's duration once it has the lock. The remedy is the 064 / 065
split: `ADD CONSTRAINT … NOT VALID` in one file, `VALIDATE CONSTRAINT` in
the next. The split must be across FILES, not statements — the runner
holds one transaction per file, so both statements in one file keep the
first statement's ACCESS EXCLUSIVE held across the validation scan. See
064's header for the `pg_locks` measurement that proved it.

### The legacy baseline

Of the 65 existing migrations, the lint's own scan (638 statements)
classifies them as:

  - **5** take no contending lock and need nothing — `001_init`
    (everything targets relations it creates itself), `024`, `025`, `049`
    (data-only `UPDATE`s) and `065` (SHARE UPDATE EXCLUSIVE only).
  - **2** take a contending lock and declare a budget — `063` and `064`.
    (Three files contain a `SET LOCAL lock_timeout`: `065` declares one
    for a statement the lint does not require it for. These counts are
    about locks, not budget lines.)
  - **58** predate the convention and are grandfathered.

The 58 are grandfathered by an explicit allowlist, `legacyBaseline` in
`tools/lint-migration-locks/main.go`, not by editing them: a shipped
migration is immutable by convention once it is recorded in
`schema_migrations`, so on an instance that already applied it a
retroactive budget would be dead text, and a fresh install runs the whole
sequence against a database that has no application traffic yet. (That
second half assumes a single runner: neither runner takes an advisory
lock, so two replicas booting against the same empty database can both
see an empty `schema_migrations` and race.)

**That is not the same as "no operational effect."** An instance that is
*behind* — applied through, say, 025 — really does execute 026 onwards on
its next upgrade, and those files run with `lock_timeout = 0` against
live traffic. The baseline accepts that residual for the already-shipped
files rather than pretending it away.

Each entry is a **fingerprint**, not just a filename: it records how many
statements were waived, their strongest lock class, and a digest over
that ordered sequence. Appending an unbudgeted `ALTER TABLE` to a
grandfathered migration therefore does *not* inherit its waiver — the
lint reports `baseline entry no longer matches the file`. The digest is
computed over statement text with outer comments removed and runs of
outer whitespace canonicalised, so reindenting a migration or adding a
comment around a statement does not churn it; string literals, quoted
identifiers and `$$ … $$` bodies are reproduced byte for byte, so editing
`DEFAULT 'a'` to `DEFAULT 'b'` or a comment *inside* a DO body does.

**The list should only ever shrink.** A new migration belongs in this
directory with a budget, never in that map. Regenerate it with:

```bash
(cd tools/lint-migration-locks && go run . --dir ../../apps/api/migrations --emit-baseline)
```

The digests cannot be written by hand. Regeneration refuses to add a
filename that is not already grandfathered, and refuses to emit from a
scan carrying a non-waivable finding.

## See also

  - `tools/lint-migration-locks/main.go` — lock classification (each mode
    measured against PostgreSQL 15.18), the same-file exemption, and the
    legacy baseline with a per-file note on what each waived migration
    does.
  - `tools/lint-migration-locks/main_test.go` — fixture-driven tests
    covering budget-before / budget-after / session-scoped / zero /
    reset-to-zero, the same-file exemption, `CREATE TABLE … REFERENCES`,
    the SHARE-UPDATE-EXCLUSIVE threshold, CONCURRENTLY rejection, and the
    dollar-quote lexer.
  - `tools/lint-migration-rls/main.go` — detector implementation and
    full structural-exemption catalogue.
  - `tools/lint-migration-rls/main_test.go` — fixture-driven tests
    covering positive / negative / suppression / partner-file /
    ALTER-promote / phantom-comment / schema-qualified / quoted-name /
    multi-table-marker cases.
  - Migration 023 (`023_rls_security_hardening.up.sql`) — the M0 Trust
    Rescue sweep that established the `ENABLE + FORCE + POLICY` triple
    as the standard.
  - Migration 042 (`042_rls_force_uniformity.up.sql`) — the FORCE
    harmonisation sweep that retrofitted USING-only legacy policies.
