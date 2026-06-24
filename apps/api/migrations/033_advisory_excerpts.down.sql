-- ============================================
-- Rollback for 033_advisory_excerpts.up.sql
--
-- DROP TABLE cascades the indexes (idx_advisory_excerpts_cve,
-- idx_advisory_excerpts_fetched), the unique constraint, and the RLS
-- policy (tenant_isolation_advisory_excerpts), so we do not need to drop
-- them explicitly. The explicit DROP POLICY + DROP INDEX lines below are
-- belt-and-braces for environments where the table was somehow left
-- behind by a partial rollback -- they are wrapped in IF EXISTS so a
-- true full-table-drop scenario stays no-op.
--
-- Issue: youichi-uda/sbomhub#23 (M1 Wave M1-2)
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_advisory_excerpts ON advisory_excerpts;

DROP INDEX IF EXISTS idx_advisory_excerpts_fetched;
DROP INDEX IF EXISTS idx_advisory_excerpts_cve;

DROP TABLE IF EXISTS advisory_excerpts;
