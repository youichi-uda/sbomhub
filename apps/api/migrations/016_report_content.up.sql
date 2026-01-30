-- Add file_content column to store report data in database
-- This allows reports to persist across container restarts in cloud environments

ALTER TABLE generated_reports ADD COLUMN IF NOT EXISTS file_content BYTEA;

-- Make file_path nullable since we'll store content in DB
ALTER TABLE generated_reports ALTER COLUMN file_path DROP NOT NULL;
