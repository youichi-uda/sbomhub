-- ============================================
-- Revert 057: drop advisory_excerpts.vuln_funcs_scoped
-- (M43 Phase D round 8 / R8f).
--
-- Dropping the column loses the module attribution written since 057;
-- the flat vuln_funcs column (unchanged by 057) still carries the full
-- symbol union, so a downgraded server degrades to the pre-057
-- behaviour (CVE-level union served to every target row) rather than
-- losing symbols outright. RLS untouched, mirroring the up migration.
-- ============================================

ALTER TABLE advisory_excerpts
    DROP COLUMN IF EXISTS vuln_funcs_scoped;
