-- ============================================
-- Reverse of 043_rls_enable_github_ssvc_history.up.sql.
--
-- Restores the pre-043 state: RLS off, no policies on the three
-- target tables. The tables themselves are owned by migrations 011
-- and 021 and are NOT dropped here.
--
-- Order matters: drop the policy first, then NO FORCE, then DISABLE.
-- ALTER TABLE DISABLE ROW LEVEL SECURITY does NOT drop attached
-- policies, so a stale policy would conflict with the up's CREATE
-- POLICY on re-apply.
--
-- M5 Wave M5-1 / issue #50.
-- ============================================

-- ---------- migration 021 / SSVC ----------

DROP POLICY IF EXISTS tenant_isolation_ssvc_assessment_history ON ssvc_assessment_history;
ALTER TABLE ssvc_assessment_history NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ssvc_assessment_history DISABLE  ROW LEVEL SECURITY;


-- ---------- migration 011 / GitHub integration ----------

DROP POLICY IF EXISTS tenant_isolation_github_repositories ON github_repositories;
ALTER TABLE github_repositories NO FORCE ROW LEVEL SECURITY;
ALTER TABLE github_repositories DISABLE  ROW LEVEL SECURITY;


DROP POLICY IF EXISTS tenant_isolation_github_connections ON github_connections;
ALTER TABLE github_connections NO FORCE ROW LEVEL SECURITY;
ALTER TABLE github_connections DISABLE  ROW LEVEL SECURITY;
