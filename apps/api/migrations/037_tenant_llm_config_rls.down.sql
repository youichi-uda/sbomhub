-- ============================================
-- Reverse of 037_tenant_llm_config_rls.up.sql.
--
-- Restores the pre-037 state: RLS off, no policy. The table itself is
-- owned by migration 036 and is NOT dropped here.
--
-- Order matters: drop the policy first, then NO FORCE, then DISABLE.
-- ALTER TABLE ... DISABLE ROW LEVEL SECURITY does NOT drop attached
-- policies, so leaving the policy behind on a re-up would conflict with
-- the CREATE POLICY in 037.up.sql.
--
-- Codex review M1 round 1 / F1, issue #22.
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_tenant_llm_config ON tenant_llm_config;

ALTER TABLE tenant_llm_config NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_llm_config DISABLE  ROW LEVEL SECURITY;
