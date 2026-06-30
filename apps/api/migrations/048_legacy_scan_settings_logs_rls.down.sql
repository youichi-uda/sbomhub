-- ============================================
-- Revert RLS partner for scan_settings + scan_logs (M13 Phase D round 2 / F185).
-- See 048_legacy_scan_settings_logs_rls.up.sql header.
--
-- Down order mirrors the up sequence: DROP POLICY, NO FORCE, then DISABLE.
-- We DROP the scan_logs policy first to match the up file's table order,
-- though the operations on the two tables are independent.
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_scan_logs ON scan_logs;

ALTER TABLE scan_logs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_logs DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_scan_settings ON scan_settings;

ALTER TABLE scan_settings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_settings DISABLE ROW LEVEL SECURITY;
