-- Canonical happy path: a budget is declared before the ACCESS EXCLUSIVE
-- DDL, in the form migrations 063 / 064 / 065 use.
SET LOCAL lock_timeout = '5s';

ALTER TABLE projects ADD COLUMN sample_flag BOOLEAN DEFAULT FALSE;
