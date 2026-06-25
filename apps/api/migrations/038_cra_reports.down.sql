-- ============================================
-- Rollback for 038_cra_reports.up.sql
--
-- DROP TABLE cascades the indexes (idx_cra_reports_project_cve,
-- idx_cra_reports_decision), the CHECK constraints, the foreign keys
-- (source_vex_draft_id / llm_call_id), and the RLS policy
-- (tenant_isolation_cra_reports), so we do not need to drop them
-- explicitly. The explicit DROP POLICY + DROP INDEX lines below are
-- belt-and-braces for environments where the table was somehow left
-- behind by a partial rollback -- they are wrapped in IF EXISTS so a
-- true full-table-drop scenario stays no-op.
--
-- Order matters: drop the policy before NO FORCE / DISABLE would, but
-- DROP TABLE on the policy's parent table is sufficient on its own.
--
-- Issue: youichi-uda/sbomhub#35 (M2 Wave M2-2)
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_cra_reports ON cra_reports;

DROP INDEX IF EXISTS idx_cra_reports_decision;
DROP INDEX IF EXISTS idx_cra_reports_project_cve;

DROP TABLE IF EXISTS cra_reports;
