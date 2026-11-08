-- ============================================
-- Rollback of 068: narrow cra_reports.report_type back to VARCHAR(20).
--
-- 'detailed_notification' (21 characters) does not fit VARCHAR(20). Any 72h
-- report written after 068 therefore blocks this rollback, and the file
-- refuses with a message saying so instead of a bare 22001. It deliberately
-- does NOT delete or truncate those rows -- they are human-approved
-- regulatory evidence. To roll back, export them (e.g. through the
-- Compliance Evidence Pack) and remove them by an explicit operator decision
-- first, or stay on 068.
--
-- Why the check is an exception handler and not a pre-flight COUNT: the
-- migrator role is subject to cra_reports' FORCE ROW LEVEL SECURITY and has
-- no tenant set, so a SELECT here sees zero rows (measured 2026-11-09: a
-- pre-flight count passed and the ALTER then failed with 22001). The ALTER's
-- own table scan is not filtered by RLS, so its failure is the reliable
-- signal.
--
-- Binary compatibility: no code depends on the width, so the current and
-- older binaries both run on either schema. On the narrowed schema every 72h
-- report insert fails with 500 again -- the defect 068 fixed.
--
-- LOCK BUDGET: same lock_timeout rationale as the up file. Unlike the up
--   file, narrowing is NOT metadata-only: PostgreSQL rewrites the table
--   (measured 2026-11-09, PostgreSQL 15, 300,000 rows with 500-character
--   drafts: pg_relation_filenode changed, 0.53 s) while holding ACCESS
--   EXCLUSIVE, and lock_timeout does not bound that. statement_timeout does:
--   a rewrite that has not finished within 60 s is cancelled and the whole
--   rollback (DDL and schema_migrations row) is undone, so the table is never
--   blocked for longer than that. On a table large enough to need more, run
--   the rollback in a maintenance window with a larger value.
-- ============================================

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

DO $$
BEGIN
    ALTER TABLE cra_reports ALTER COLUMN report_type TYPE VARCHAR(20);
EXCEPTION WHEN string_data_right_truncation THEN
    RAISE EXCEPTION 'migration 068 down: cra_reports holds report_type values longer than 20 characters (detailed_notification); export and remove those reports first, or stay on 068'
        USING ERRCODE = 'string_data_right_truncation';
END
$$;
