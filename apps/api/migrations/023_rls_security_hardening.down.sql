-- ============================================
-- RLS Security Hardening Rollback
-- WARNING: Rolling back this migration will weaken tenant isolation
-- ============================================

-- Remove FORCE RLS (revert to weaker isolation)
ALTER TABLE projects NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sboms NO FORCE ROW LEVEL SECURITY;
ALTER TABLE components NO FORCE ROW LEVEL SECURITY;
ALTER TABLE vex_statements NO FORCE ROW LEVEL SECURITY;
ALTER TABLE license_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_settings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_logs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE issue_tracker_connections NO FORCE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets NO FORCE ROW LEVEL SECURITY;

-- Drop comprehensive policies
DROP POLICY IF EXISTS tenant_isolation_projects ON projects;
DROP POLICY IF EXISTS tenant_isolation_sboms ON sboms;
DROP POLICY IF EXISTS tenant_isolation_components ON components;
DROP POLICY IF EXISTS tenant_isolation_vex ON vex_statements;
DROP POLICY IF EXISTS tenant_isolation_license ON license_policies;
DROP POLICY IF EXISTS tenant_isolation_notification_settings ON notification_settings;
DROP POLICY IF EXISTS tenant_isolation_notification_logs ON notification_logs;
DROP POLICY IF EXISTS tenant_isolation_api_keys ON api_keys;
DROP POLICY IF EXISTS tenant_isolation_audit_logs ON audit_logs;
DROP POLICY IF EXISTS tenant_isolation_issue_tracker_connections ON issue_tracker_connections;
DROP POLICY IF EXISTS tenant_isolation_vulnerability_tickets ON vulnerability_tickets;

-- Recreate original SELECT-only policies
CREATE POLICY tenant_isolation_projects ON projects
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_sboms ON sboms
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_components ON components
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_vex ON vex_statements
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_license ON license_policies
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_notification_settings ON notification_settings
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_notification_logs ON notification_logs
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_api_keys ON api_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_audit_logs ON audit_logs
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Disable RLS on issue tracker tables
ALTER TABLE issue_tracker_connections DISABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets DISABLE ROW LEVEL SECURITY;
