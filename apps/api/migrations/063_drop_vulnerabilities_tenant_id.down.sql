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
-- tenant_id NULL. That loss is intentional and is not a loss of anything
-- meaningful: the values were "whichever tenant's request happened to create
-- this shared CVE row first", never maintained afterwards and never read by
-- any code path. There is no correct value to reconstruct for a row that is
-- shared by every tenant — which is the finding 063 fixes.
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

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_tenant_id ON vulnerabilities(tenant_id);
