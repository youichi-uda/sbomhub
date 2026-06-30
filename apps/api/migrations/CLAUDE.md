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
  - `vulnerabilities` — global CVE / advisory data shared across tenants;
    `tenant_id` is a soft-join hint with `ON DELETE SET NULL`.
  - `public_links`, `public_link_access_logs` — RLS removed in 030 to
    allow the anonymous `/api/v1/public/:token` flow; tenant scope
    enforced application-side.
  - `subscriptions`, `subscription_events`, `usage_records` — RLS
    removed in 031 to allow Lemon Squeezy webhook lookups; tenant scope
    enforced application-side.
  - `scan_settings`, `scan_logs` — legacy 010 schema with no RLS
    partner. Application-side scope only; tracked as F185 (M13 Phase D
    round 2) for a follow-up partner migration.

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
file that defines it:

```sql
-- lint:no-rls-required: shared global cache mirroring upstream advisory data
```

The reason is mandatory and is echoed by the lint in `--verbose` mode
for the audit trail. Suppression should be rare — prefer the
`structuralExemptions` map in the lint source for tables that
genuinely cannot ever carry RLS by construction.

## What the lint actually checks

`tools/lint-migration-rls` runs as a hard CI gate on every PR that
touches `apps/api/migrations/**`. Its detection rule, after F183:

  1. Detect a table as tenant-scoped if EITHER its name matches
     `tenant_*`, OR its `CREATE TABLE` body declares a `tenant_id`
     column, OR a later `ALTER TABLE … ADD COLUMN tenant_id` promotes
     it.
  2. Require the `ENABLE` + `FORCE` + `CREATE POLICY tenant_isolation_*`
     triple to appear somewhere in the directory (any file).
  3. Skip tables listed in `structuralExemptions` or with a
     `-- lint:no-rls-required: <reason>` inline marker.

If you add a new `*.up.sql` and the lint fails, the error message names
the offending table + file:line and lists which of the three statements
is missing. Add the missing statement(s), or add a partner
`<n>_<table>_rls.up.sql` following the pattern of 037 / 047.

## See also

  - `tools/lint-migration-rls/main.go` — detector implementation and
    full structural-exemption catalogue.
  - `tools/lint-migration-rls/main_test.go` — fixture-driven tests
    covering positive / negative / suppression / partner-file /
    ALTER-promote / phantom-comment cases.
  - Migration 023 (`023_rls_security_hardening.up.sql`) — the M0 Trust
    Rescue sweep that established the `ENABLE + FORCE + POLICY` triple
    as the standard.
  - Migration 042 (`042_rls_force_uniformity.up.sql`) — the FORCE
    harmonisation sweep that retrofitted USING-only legacy policies.
