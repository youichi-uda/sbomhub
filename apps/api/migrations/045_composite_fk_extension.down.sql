-- ============================================
-- Reverse of 045_composite_fk_extension.up.sql.
--
-- Drops the seven composite (tenant_id, project_id) FOREIGN KEYs added by
-- 045. The projects_tenant_id_id_unique anchor remains owned by migration 041.
--
-- The up migration also promoted legacy nullable tenant_id columns on
-- vex_statements, license_policies, notification_settings, and
-- notification_logs to NOT NULL after backfill. Rollback restores the pre-045
-- nullable shape for those four columns only.
-- ============================================

ALTER TABLE vulnerability_tickets
    DROP CONSTRAINT IF EXISTS vulnerability_tickets_tenant_project_fk;

ALTER TABLE public_links
    DROP CONSTRAINT IF EXISTS public_links_tenant_project_fk;

ALTER TABLE notification_logs
    DROP CONSTRAINT IF EXISTS notification_logs_tenant_project_fk;

ALTER TABLE notification_settings
    DROP CONSTRAINT IF EXISTS notification_settings_tenant_project_fk;

ALTER TABLE license_policies
    DROP CONSTRAINT IF EXISTS license_policies_tenant_project_fk;

ALTER TABLE vex_statements
    DROP CONSTRAINT IF EXISTS vex_statements_tenant_project_fk;

ALTER TABLE sboms
    DROP CONSTRAINT IF EXISTS sboms_tenant_project_fk;

ALTER TABLE notification_logs     ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE notification_settings ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE license_policies      ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE vex_statements        ALTER COLUMN tenant_id DROP NOT NULL;
