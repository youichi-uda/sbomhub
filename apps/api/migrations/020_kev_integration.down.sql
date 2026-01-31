-- Rollback KEV integration

DROP TABLE IF EXISTS kev_sync_logs;
DROP TABLE IF EXISTS kev_sync_settings;

ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS in_kev;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS kev_date_added;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS kev_due_date;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS kev_ransomware_use;

DROP TABLE IF EXISTS kev_catalog;
