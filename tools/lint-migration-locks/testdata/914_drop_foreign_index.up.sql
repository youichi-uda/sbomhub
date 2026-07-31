-- DROP INDEX on an index created by an earlier migration takes ACCESS
-- EXCLUSIVE on a table this scan cannot name.
DROP INDEX IF EXISTS idx_vulnerabilities_tenant_id;
