-- ============================================
-- Restore RLS on subscriptions / subscription_events / usage_records
-- (rollback of P0 #18 follow-up / codex-r15)
--
-- WARNING: This revives the chicken-and-egg between the Lemon Squeezy
-- webhook lookup (GetByLSSubscriptionID) and the tenant context. Under
-- `sbomhub_app` (NOBYPASSRLS) every webhook handler that runs outside
-- TenantTx (which is all of them — the webhook route is mounted directly
-- on the Echo instance) will silently fail again because the policy
-- predicate `tenant_id = current_setting('app.current_tenant_id',
-- true)::UUID` evaluates to NULL when the GUC is unset, and Postgres
-- returns zero rows (for SELECT) or rejects the row (for INSERT under
-- the implicit WITH CHECK fallback).
--
-- Only roll back if you have switched the runtime role to a BYPASSRLS /
-- superuser one, OR if you have separately wrapped every webhook
-- handler in a TenantTx-managed transaction (impractical for events
-- that arrive without a custom_data tenant hint).
-- ============================================

-- Reset comments to NULL so we don't leave a stale note behind.
COMMENT ON TABLE subscriptions IS NULL;
COMMENT ON TABLE subscription_events IS NULL;
COMMENT ON TABLE usage_records IS NULL;

-- Re-enable RLS (mirrors migration 008). Note: 008 did NOT add FORCE,
-- and migration 023 did not touch these three tables, so we do not
-- re-add FORCE here either — we restore the original 008 state.
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscription_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_records ENABLE ROW LEVEL SECURITY;

-- Recreate the original USING-only policies from migration 008.
CREATE POLICY tenant_isolation_subscriptions ON subscriptions
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_subscription_events ON subscription_events
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_usage_records ON usage_records
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
