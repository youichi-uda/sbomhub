-- The budget exists but is declared too late to bound the DDL above it.
ALTER TABLE projects ADD COLUMN sample_flag BOOLEAN DEFAULT FALSE;

SET LOCAL lock_timeout = '5s';
