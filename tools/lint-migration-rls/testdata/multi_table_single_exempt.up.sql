-- ============================================
-- Positive fixture (F195 / M13 Phase D round 3): two tenant-scoped
-- tables in a single migration, where one carries the full RLS triple
-- and the other carries a table-scoped suppression marker.
--
-- Pre-F195 the suppressions map was file-keyed (one reason per file)
-- and an unscoped `-- lint:no-rls-required:` marker silently widened
-- to cover every tenant-scoped table in the file. That was the exact
-- defeat-vector the lint exists to prevent — the original 036/046
-- misses were the same "one table in a multi-table migration" shape.
--
-- The new table-scoped marker syntax
-- `-- lint:no-rls-required(<table>): <reason>` lets a multi-table
-- migration exempt one specific table without bypassing the gate on
-- its siblings. The fixture exercises that: `tenant_foo_a` MUST be
-- audited as RLS-clean (full triple present), and `tenant_foo_b` MUST
-- be audited as suppressed-clean (table-scoped marker present). The
-- lint exits 0 with `1 suppressed`.
-- ============================================

CREATE TABLE IF NOT EXISTS tenant_foo_a (
    tenant_id  UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    payload    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE tenant_foo_a ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_foo_a FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_foo_a ON tenant_foo_a
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- lint:no-rls-required(tenant_foo_b): shared global cache mirror; tenant_id stored for join convenience only.
CREATE TABLE IF NOT EXISTS tenant_foo_b (
    tenant_id  UUID PRIMARY KEY,
    cached_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
