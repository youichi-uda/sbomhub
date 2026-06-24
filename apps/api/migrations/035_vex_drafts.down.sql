-- ============================================
-- Rollback for 035_vex_drafts.up.sql
--
-- DROP TABLE cascades the indexes (idx_vex_drafts_project_cve,
-- idx_vex_drafts_decision), the CHECK constraints, the foreign keys
-- (advisory_excerpt_id / reachability_result_id / llm_call_id), and
-- the RLS policy (tenant_isolation_vex_drafts), so we do not need to
-- drop them explicitly. The explicit DROP POLICY + DROP INDEX lines
-- below are belt-and-braces for environments where the table was
-- somehow left behind by a partial rollback -- they are wrapped in
-- IF EXISTS so a true full-table-drop scenario stays no-op.
--
-- Issue: youichi-uda/sbomhub#27 (M1 Wave M1-5)
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_vex_drafts ON vex_drafts;

DROP INDEX IF EXISTS idx_vex_drafts_decision;
DROP INDEX IF EXISTS idx_vex_drafts_project_cve;

DROP TABLE IF EXISTS vex_drafts;
