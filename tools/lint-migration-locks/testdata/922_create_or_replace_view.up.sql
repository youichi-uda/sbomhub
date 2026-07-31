-- Measured on PostgreSQL 15.18: CREATE OR REPLACE VIEW over an existing
-- view takes AccessExclusiveLock on it.
CREATE OR REPLACE VIEW component_summary AS SELECT id, name FROM components;
