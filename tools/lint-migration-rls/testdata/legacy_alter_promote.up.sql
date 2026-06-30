-- ============================================
-- Positive fixture (F183 / M13-5 #91): non-`tenant_*` table whose
-- CREATE TABLE does NOT yet have a tenant_id column, but a later
-- ALTER TABLE … ADD COLUMN tenant_id promotes it to tenant-scoped, and
-- the same file (or a partner file — see TestPartnerFile_AlterPromote)
-- supplies the RLS triple.
--
-- This mirrors migration 007's pattern: tables like `projects` / `sboms`
-- / `audit_logs` were CREATEd in earlier migrations (001-006) without a
-- tenant_id column, then promoted in 007 via ADD COLUMN. Without the
-- ALTER-aware detector, the lint would miss those tables entirely.
-- ============================================

-- This stand-in for an earlier CREATE TABLE — kept here so the fixture
-- is one self-contained file (the real production case spans two
-- migrations). The detector treats the ALTER below as the tenant-scoped
-- birth site for `legacy_widget` because the CREATE has no tenant_id.
CREATE TABLE legacy_widget (
    id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL
);

ALTER TABLE legacy_widget ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE legacy_widget ENABLE ROW LEVEL SECURITY;
ALTER TABLE legacy_widget FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_legacy_widget ON legacy_widget
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
