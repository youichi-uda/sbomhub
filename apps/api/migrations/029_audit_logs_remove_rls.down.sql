-- ============================================
-- Restore RLS on audit_logs (rollback of P0 #18 follow-up)
--
-- WARNING: This revives the chicken-and-egg between webhook handlers
-- (Clerk / Lemon Squeezy) and the tenant context. Under sbomhub_app
-- (NOBYPASSRLS), every webhook-driven `auditRepo.Log(...)` INSERT will
-- silently fail again because the policy WITH CHECK expression evaluates
-- to NULL when `app.current_tenant_id` is unset. Only roll back if you have
-- switched the runtime role to a BYPASSRLS / superuser one, OR if you have
-- separately moved every audit_logs INSERT into a TenantTx-managed
-- transaction (including ones that have no tenant context — which is
-- impossible for some webhooks by construction).
-- ============================================

-- Reset the comment so we don't leave a stale note behind.
COMMENT ON TABLE audit_logs IS NULL;

-- Re-enable + force RLS (mirrors 007 + 023).
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;

-- Recreate the FOR ALL policy from migration 023.
CREATE POLICY tenant_isolation_audit_logs ON audit_logs
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
