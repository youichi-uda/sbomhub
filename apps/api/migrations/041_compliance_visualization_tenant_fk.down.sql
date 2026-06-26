-- ============================================
-- Reverse of 041_compliance_visualization_tenant_fk.up.sql.
--
-- Drops the composite FKs first (children), then the composite UNIQUE
-- on projects (parent). Dropping the UNIQUE while a dependent FK
-- still references it would fail.
--
-- The orphan-check DO $$ block in the up migration has no DDL effect
-- to undo -- if it ran, it either succeeded (no diagnostic side
-- effect) or RAISE EXCEPTION'd (transaction rolled back, nothing to
-- reverse here).
--
-- Codex review M4 round 15 / F75.
-- ============================================

ALTER TABLE sbom_visualization_settings
    DROP CONSTRAINT IF EXISTS sbom_visualization_tenant_project_fk;

ALTER TABLE compliance_checklist_responses
    DROP CONSTRAINT IF EXISTS compliance_checklist_tenant_project_fk;

ALTER TABLE projects
    DROP CONSTRAINT IF EXISTS projects_tenant_id_id_unique;
