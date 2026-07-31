-- A single ALTER TABLE may carry several comma-separated actions. Only
-- the first is VALIDATE CONSTRAINT (SHARE UPDATE EXCLUSIVE); the ADD
-- COLUMN alongside it pushes the whole statement to ACCESS EXCLUSIVE.
--
-- Measured on PostgreSQL 15.18:
--   ALTER TABLE probe_t VALIDATE CONSTRAINT ckm, ADD COLUMN multi_probe int;
--   -> pg_locks: AccessExclusiveLock
ALTER TABLE components
    VALIDATE CONSTRAINT components_eol_status_check,
    ADD COLUMN multi_probe INTEGER;
