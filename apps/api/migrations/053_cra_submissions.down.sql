-- Reverse of 053_cra_submissions.up.sql (M33-A / F418).
-- DROP TABLE cascades the tenant_isolation policy, both indexes, and the
-- FK constraints, so no separate DROP POLICY / DROP INDEX is required.
DROP TABLE IF EXISTS cra_submissions;
