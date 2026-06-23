-- ============================================
-- Restore RLS on api_keys (rollback of P0 #18)
--
-- WARNING: This revives the chicken-and-egg between authn lookup and tenant
-- context. Under `sbomhub_app` (NOBYPASSRLS) every API-key request will
-- return 401 again. Only roll back if you have switched the runtime role
-- back to a BYPASSRLS / superuser one.
-- ============================================

-- Restore the comment to whatever the previous state implied (no explicit
-- COMMENT was set before migration 028; reset to NULL so we don't leave a
-- stale note behind).
COMMENT ON TABLE api_keys IS NULL;

-- Re-enable + force RLS (mirrors 007 + 023).
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

-- Recreate the FOR ALL policy from migration 023.
CREATE POLICY tenant_isolation_api_keys ON api_keys
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
