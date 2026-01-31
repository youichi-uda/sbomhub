-- ============================================
-- RLS Security Hardening Migration
-- Fixes: Tenant isolation bypass vulnerability
-- ============================================

-- FORCE RLS: Ensures RLS is enforced even for table owners
-- Without FORCE, the DB role that owns tables bypasses RLS entirely
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
ALTER TABLE sboms FORCE ROW LEVEL SECURITY;
ALTER TABLE components FORCE ROW LEVEL SECURITY;
ALTER TABLE vex_statements FORCE ROW LEVEL SECURITY;
ALTER TABLE license_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_settings FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;

-- Drop existing SELECT-only policies
DROP POLICY IF EXISTS tenant_isolation_projects ON projects;
DROP POLICY IF EXISTS tenant_isolation_sboms ON sboms;
DROP POLICY IF EXISTS tenant_isolation_components ON components;
DROP POLICY IF EXISTS tenant_isolation_vex ON vex_statements;
DROP POLICY IF EXISTS tenant_isolation_license ON license_policies;
DROP POLICY IF EXISTS tenant_isolation_notification_settings ON notification_settings;
DROP POLICY IF EXISTS tenant_isolation_notification_logs ON notification_logs;
DROP POLICY IF EXISTS tenant_isolation_api_keys ON api_keys;
DROP POLICY IF EXISTS tenant_isolation_audit_logs ON audit_logs;

-- Create comprehensive policies with USING (for SELECT/UPDATE/DELETE) and WITH CHECK (for INSERT/UPDATE)
-- This ensures all CRUD operations are tenant-isolated

CREATE POLICY tenant_isolation_projects ON projects
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_sboms ON sboms
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_components ON components
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_vex ON vex_statements
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_license ON license_policies
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_notification_settings ON notification_settings
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_notification_logs ON notification_logs
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_api_keys ON api_keys
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_audit_logs ON audit_logs
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Add RLS to issue tracker tables (added in migration 015)
ALTER TABLE issue_tracker_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE issue_tracker_connections FORCE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_issue_tracker_connections ON issue_tracker_connections
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_vulnerability_tickets ON vulnerability_tickets
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
