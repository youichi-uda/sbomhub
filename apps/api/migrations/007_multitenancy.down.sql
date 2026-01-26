-- Drop RLS policies first
DROP POLICY IF EXISTS tenant_isolation_audit_logs ON audit_logs;
DROP POLICY IF EXISTS tenant_isolation_api_keys ON api_keys;
DROP POLICY IF EXISTS tenant_isolation_notification_logs ON notification_logs;
DROP POLICY IF EXISTS tenant_isolation_notification_settings ON notification_settings;
DROP POLICY IF EXISTS tenant_isolation_license ON license_policies;
DROP POLICY IF EXISTS tenant_isolation_vex ON vex_statements;
DROP POLICY IF EXISTS tenant_isolation_components ON components;
DROP POLICY IF EXISTS tenant_isolation_sboms ON sboms;
DROP POLICY IF EXISTS tenant_isolation_projects ON projects;

-- Disable RLS
ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;
ALTER TABLE notification_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE notification_settings DISABLE ROW LEVEL SECURITY;
ALTER TABLE license_policies DISABLE ROW LEVEL SECURITY;
ALTER TABLE vex_statements DISABLE ROW LEVEL SECURITY;
ALTER TABLE components DISABLE ROW LEVEL SECURITY;
ALTER TABLE sboms DISABLE ROW LEVEL SECURITY;
ALTER TABLE projects DISABLE ROW LEVEL SECURITY;

-- Drop audit_logs table
DROP TABLE IF EXISTS audit_logs;

-- Drop indexes
DROP INDEX IF EXISTS idx_api_keys_tenant_id;
DROP INDEX IF EXISTS idx_notification_logs_tenant_id;
DROP INDEX IF EXISTS idx_notification_settings_tenant_id;
DROP INDEX IF EXISTS idx_license_policies_tenant_id;
DROP INDEX IF EXISTS idx_vex_statements_tenant_id;
DROP INDEX IF EXISTS idx_vulnerabilities_tenant_id;
DROP INDEX IF EXISTS idx_components_tenant_id;
DROP INDEX IF EXISTS idx_sboms_tenant_id;
DROP INDEX IF EXISTS idx_projects_tenant_id;
DROP INDEX IF EXISTS idx_tenant_users_user_id;
DROP INDEX IF EXISTS idx_tenant_users_tenant_id;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_clerk_user_id;
DROP INDEX IF EXISTS idx_tenants_slug;
DROP INDEX IF EXISTS idx_tenants_clerk_org_id;

-- Remove tenant_id from existing tables
ALTER TABLE api_keys DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE notification_logs DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE notification_settings DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE license_policies DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE vex_statements DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE components DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE sboms DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE projects DROP COLUMN IF EXISTS tenant_id;

-- Drop tenant tables
DROP TABLE IF EXISTS tenant_users;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
