-- A budget that is subsequently disabled before the DDL runs.
SET LOCAL lock_timeout = '5s';

COMMENT ON TABLE projects IS 'covered, but takes only SHARE UPDATE EXCLUSIVE';

SET LOCAL lock_timeout = '0';

ALTER TABLE projects ADD COLUMN sample_flag BOOLEAN DEFAULT FALSE;
