-- ============================================
-- Rollback for 039_meti_assessments.up.sql
--
-- DROP TABLE cascades the indexes (idx_meti_assessments_project_phase),
-- the UNIQUE constraint, the CHECK constraints, and the RLS policy
-- (tenant_isolation_meti_assessments), so we do not need to drop them
-- explicitly. The explicit DROP POLICY + DROP INDEX lines below are
-- belt-and-braces for environments where the table was somehow left
-- behind by a partial rollback -- they are wrapped in IF EXISTS so a
-- true full-table-drop scenario stays no-op.
--
-- Issue: youichi-uda/sbomhub#41 (M3 Wave M3-1).
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_meti_assessments ON meti_assessments;

DROP INDEX IF EXISTS idx_meti_assessments_project_phase;

DROP TABLE IF EXISTS meti_assessments;
