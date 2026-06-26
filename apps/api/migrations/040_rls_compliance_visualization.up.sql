-- ============================================
-- RLS hardening for compliance_checklist_responses + sbom_visualization_settings
-- (M4 Codex review round 13 / F73, blocker class).
--
-- Source of truth:
--   * sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §9.1
--     ("M0 Trust Rescue / RLS / tenant isolation")
--   * Codex review M4 round 13 finding F73 (severity high, cross-tenant
--     data leak):
--       "compliance_checklist_responses and sbom_visualization_settings
--        are tenant-scoped (tenant_id column present) but migration 018
--        never enabled RLS on them, and the repository layer scopes
--        every read/write by project_id only. A tenant-A user that
--        knows -- or guesses -- a tenant-B project UUID can read,
--        overwrite, or delete tenant B's manual METI checklist
--        responses and visualization settings."
--
-- Why a separate migration (not amending 018):
--   Migration 018 is the original M2-era seed for the METI checklist
--   feature; operators that already migrated past 018 must pick up the
--   RLS state transition through the normal migrate-up sequence.
--   Rewriting 018 would silently skip the change for them, which is
--   exactly the regression class M0 Trust Rescue is meant to close.
--   We follow the same precedent as 037 (tenant_llm_config_rls), which
--   patched a missing RLS state on a previously-shipped table.
--
-- RLS model (matches the post-023 / post-037 hardened convention):
--   * ENABLE ROW LEVEL SECURITY so the policy is consulted at all.
--   * FORCE  ROW LEVEL SECURITY so the table owner (the migrator role)
--     does not bypass the policy during ad-hoc maintenance queries.
--   * Single tenant_isolation_* policy with FOR ALL, USING + WITH CHECK
--     both bound to current_setting('app.current_tenant_id', true)::UUID.
--     The `true` second argument makes the GUC return '' (rather than
--     raising) when unset; the cast to UUID then fails the predicate,
--     so an unauthenticated path gets zero rows / a rejected INSERT
--     instead of a SQL error.
--
-- Defense in depth:
--   This migration is the SQL-layer half of the F73 fix. The repository
--   layer (apps/api/internal/repository/checklist.go +
--   apps/api/internal/repository/visualization.go) is independently
--   updated in the same review wave to require tenantID on every
--   ListByProject / GetByProject / Upsert / Delete entry point, so a
--   crash in the GUC-set middleware (or a future caller that forgets
--   to call SET LOCAL app.current_tenant_id) does not silently regress
--   to project_id-only filtering.
-- ============================================

ALTER TABLE compliance_checklist_responses ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_checklist_responses FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_compliance_checklist ON compliance_checklist_responses
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_compliance_checklist ON compliance_checklist_responses IS
    'M4 Codex review round 13 / F73: enforce tenant isolation on METI '
    'checklist responses. See migrations/040_rls_compliance_visualization.up.sql header.';

ALTER TABLE sbom_visualization_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE sbom_visualization_settings FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_visualization ON sbom_visualization_settings
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_visualization ON sbom_visualization_settings IS
    'M4 Codex review round 13 / F73: enforce tenant isolation on SBOM '
    'visualization framework settings. See migrations/040_rls_compliance_visualization.up.sql header.';
