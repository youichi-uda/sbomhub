-- ============================================
-- Reverse of 040_rls_compliance_visualization.up.sql.
--
-- Restores the pre-040 state: RLS off, no policies. The tables
-- themselves are owned by migration 018 and are NOT dropped here.
--
-- Order matters: drop the policy first, then NO FORCE, then DISABLE.
-- ALTER TABLE ... DISABLE ROW LEVEL SECURITY does NOT drop attached
-- policies, so leaving a policy behind on a re-up would conflict with
-- the CREATE POLICY in 040.up.sql.
--
-- Codex review M4 round 13 / F73.
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_visualization ON sbom_visualization_settings;
ALTER TABLE sbom_visualization_settings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sbom_visualization_settings DISABLE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_compliance_checklist ON compliance_checklist_responses;
ALTER TABLE compliance_checklist_responses NO FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_checklist_responses DISABLE  ROW LEVEL SECURITY;
