-- Rollback: Remove auto-created scan_settings
-- Note: This only removes settings that were created by the backfill
-- It does not remove settings that were manually configured by users

-- We cannot reliably identify which settings were created by backfill vs user,
-- so this is a no-op to preserve user settings
-- If you need to remove all settings, do it manually

SELECT 1; -- No-op
