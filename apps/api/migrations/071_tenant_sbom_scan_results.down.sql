-- Reverse of 071_tenant_sbom_scan_results.up.sql. DROP TABLE takes the
-- policy, the index, the trigger and the foreign keys along; the trigger
-- function goes after it.
SET LOCAL lock_timeout = '5s';

DROP TABLE IF EXISTS tenant_sbom_scan_results;

DROP FUNCTION IF EXISTS tenant_sbom_scan_results_sbom_tenant();
