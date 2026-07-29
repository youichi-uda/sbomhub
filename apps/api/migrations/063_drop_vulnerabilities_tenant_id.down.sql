-- ============================================
-- Reverse of 063_drop_vulnerabilities_tenant_id.up.sql (M48 follow-up).
--
-- Restores the COLUMN AND INDEX exactly as migration 007 declared them: a
-- nullable `tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL` plus
-- the plain btree `idx_vulnerabilities_tenant_id`. The FK is re-created as a
-- side effect of the column definition, so the restored schema is
-- structurally identical to the pre-063 state (constraint name included:
-- Postgres derives `vulnerabilities_tenant_id_fkey` from table + column +
-- suffix, the same name 007 got).
--
-- DATA IS NOT RESTORED, and cannot be. 063 discards the column's contents;
-- nothing else in the schema recorded them, so after this down every row has
-- tenant_id NULL. That loss is intentional. What the values MEANT is
-- unsupported — no product INSERT ever supplied the column, so the only
-- writers we can name are E2E fixtures, and any other non-NULL value could
-- only have come from operator SQL or a historical path not in this tree
-- (Codex round 2, #7 — the earlier wording here claimed they recorded the
-- tenant that created the row first, which the writer analysis contradicts).
-- Nothing ever read the column, so nothing depended on whatever it held, and
-- there is no correct value to reconstruct for a row shared by every tenant —
-- which is the finding 063 fixes.
--
-- What this down does NOT restore is the property that made the column
-- dangerous: it comes back as a column that still has no reader, no writer,
-- no RLS policy and no isolation meaning on a table that is a structural
-- exemption in lint-migration-rls. Rolling back re-arms the misreading trap
-- (a future `WHERE tenant_id = $1` on the global CVE catalogue that silently
-- matches nothing, with no RLS backstop to catch it) without buying back any
-- behaviour. Prefer rolling forward.
--
-- ROLLBACK SEQUENCING — read before running this down:
--   Order does not matter relative to the API binary. No API build reads or
--   writes vulnerabilities.tenant_id, in either direction, so no deployed
--   binary can tell whether the column is present. This is unlike 062, whose
--   down had to run BEFORE the API rollback because a pre-062 binary required
--   the column.
--
--   The E2E fixtures are the only consumers that care, and they only care in
--   one direction: docker/seed/web-e2e.sql and scripts/golden-path-e2e.sh as
--   of M48 no longer name the column, and they replay correctly against BOTH
--   the pre-063 and post-063 schema (the column is nullable and has no
--   default beyond NULL). A pre-M48 checkout of those fixtures requires the
--   column, so this down is what makes replaying one of them possible again.
-- ============================================

-- LOCK BUDGET (Codex round 2, Medium): same reasoning as the up migration —
-- `ALTER TABLE ... ADD COLUMN` takes ACCESS EXCLUSIVE and `CREATE INDEX`
-- (non-CONCURRENTLY) takes SHARE, both of which queue behind a live reader and
-- then block everything queued behind them. Round 1 added the budget to the up
-- migration only; round 2 measured this file still waiting indefinitely (held
-- ACCESS SHARE for 8s, ran the real `migrate down 1`, observed it block until
-- the holder committed, with no timeout). The runner wraps a down migration in
-- one transaction too, so a timeout rolls back the DDL and restores the
-- schema_migrations row together.
SET LOCAL lock_timeout = '5s';

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_tenant_id ON vulnerabilities(tenant_id);
