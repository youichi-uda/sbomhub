-- ============================================
-- Rollback for 034_reachability_results.up.sql
--
-- DROP TABLE cascades the indexes (idx_reachability_project_cve,
-- idx_reachability_component), the unique constraint, and the RLS
-- policy (tenant_isolation_reachability_results), so we do not need to
-- drop them explicitly. The explicit DROP POLICY + DROP INDEX lines
-- below are belt-and-braces for environments where the table was
-- somehow left behind by a partial rollback -- they are wrapped in IF
-- EXISTS so a true full-table-drop scenario stays no-op.
--
-- Issue: youichi-uda/sbomhub#26 (M1 Wave M1-3)
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_reachability_results ON reachability_results;

DROP INDEX IF EXISTS idx_reachability_component;
DROP INDEX IF EXISTS idx_reachability_project_cve;

DROP TABLE IF EXISTS reachability_results;
