-- ============================================
-- Positive fixture: tenant_* table created AND RLS-protected in the
-- same file.
--
-- This shape matches migrations where the original author remembered to
-- add the RLS triple in line with the CREATE TABLE (i.e. the "good"
-- pattern that the lint exists to enforce).
--
-- Modelled on apps/api/migrations/047_tenant_diff_webhook_settings_rls.up.sql,
-- but with the CREATE TABLE inlined so the fixture stands alone (the
-- testdata directory is intentionally NOT cross-file — each fixture is
-- one self-contained expectation).
-- ============================================

CREATE TABLE IF NOT EXISTS tenant_good_example (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    payload   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE tenant_good_example ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_good_example FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_good_example ON tenant_good_example
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
