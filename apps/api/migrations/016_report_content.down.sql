-- Remove file_content column
ALTER TABLE generated_reports DROP COLUMN IF EXISTS file_content;

-- Restore NOT NULL constraint on file_path
ALTER TABLE generated_reports ALTER COLUMN file_path SET NOT NULL;
