-- lock_timeout = 0 is PostgreSQL's "wait forever", i.e. no budget at all.
SET LOCAL lock_timeout = 0;

ALTER TABLE projects ADD COLUMN sample_flag BOOLEAN DEFAULT FALSE;
