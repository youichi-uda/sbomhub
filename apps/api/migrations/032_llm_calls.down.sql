-- ============================================
-- Rollback for 032_llm_calls.up.sql
--
-- DROP TABLE cascades the indexes (idx_llm_calls_tenant_created,
-- idx_llm_calls_purpose) and the RLS policy (tenant_isolation_llm_calls)
-- so we do not need to drop them explicitly. The explicit DROP POLICY +
-- DROP INDEX lines below are belt-and-braces for environments where the
-- table was somehow left behind by a partial rollback -- they are wrapped
-- in IF EXISTS so a true full-table-drop scenario stays no-op.
--
-- Issue: youichi-uda/sbomhub#20 (M1 Wave M1-1)
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_llm_calls ON llm_calls;

DROP INDEX IF EXISTS idx_llm_calls_purpose;
DROP INDEX IF EXISTS idx_llm_calls_tenant_created;

DROP TABLE IF EXISTS llm_calls;
