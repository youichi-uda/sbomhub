-- `SET` without LOCAL survives COMMIT and leaks onto the connection the
-- next migration file runs on.
SET lock_timeout = '5s';

ALTER TABLE projects ADD COLUMN sample_flag BOOLEAN DEFAULT FALSE;
