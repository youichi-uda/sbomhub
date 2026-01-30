-- Drop report tables

DROP POLICY IF EXISTS "generated_reports_tenant_isolation" ON generated_reports;
DROP POLICY IF EXISTS "report_settings_tenant_isolation" ON report_settings;

DROP TABLE IF EXISTS generated_reports;
DROP TABLE IF EXISTS report_settings;
