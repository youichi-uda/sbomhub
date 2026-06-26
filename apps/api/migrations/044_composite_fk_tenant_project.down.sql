-- ============================================
-- Reverse of 044_composite_fk_tenant_project.up.sql.
--
-- Drops the five composite (tenant_id, project_id) FOREIGN KEYs
-- added in 044.up. The projects_tenant_id_id_unique composite
-- UNIQUE on projects(tenant_id, id) is owned by migration 041 and
-- is NOT dropped here (other FKs from 041 still depend on it).
--
-- The orphan-check DO $$ block in the up migration has no DDL
-- effect to undo -- if it ran, it either succeeded (no diagnostic
-- side effect) or RAISE EXCEPTION'd (transaction rolled back,
-- nothing to reverse here).
--
-- M5 Wave M5-1 / issue #50.
-- ============================================

ALTER TABLE ssvc_assessments
    DROP CONSTRAINT IF EXISTS ssvc_assessments_tenant_project_fk;

ALTER TABLE ssvc_project_defaults
    DROP CONSTRAINT IF EXISTS ssvc_project_defaults_tenant_project_fk;

ALTER TABLE compliance_snapshots
    DROP CONSTRAINT IF EXISTS compliance_snapshots_tenant_project_fk;

ALTER TABLE vulnerability_resolution_events
    DROP CONSTRAINT IF EXISTS vuln_resolution_events_tenant_project_fk;

ALTER TABLE github_repositories
    DROP CONSTRAINT IF EXISTS github_repositories_tenant_project_fk;
