-- ============================================
-- Revert RLS hardening for tenant_diff_webhook_settings.
-- See 047_tenant_diff_webhook_settings_rls.up.sql header.
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_tenant_diff_webhook_settings
    ON tenant_diff_webhook_settings;

ALTER TABLE tenant_diff_webhook_settings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_diff_webhook_settings DISABLE ROW LEVEL SECURITY;
