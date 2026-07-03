-- Reverse of 052_vex_statement_provenance.up.sql (M27-A #132 / F381).
-- DROP TABLE cascades the tenant_isolation policy, both indexes, and the
-- FK constraints, so no separate DROP POLICY / DROP INDEX is required.
DROP TABLE IF EXISTS vex_statement_provenance;
