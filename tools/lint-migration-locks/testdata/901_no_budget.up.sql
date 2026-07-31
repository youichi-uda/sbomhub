-- Negative control: ACCESS EXCLUSIVE on a pre-existing table with no
-- budget anywhere in the file.
ALTER TABLE projects ADD COLUMN sample_flag BOOLEAN DEFAULT FALSE;
