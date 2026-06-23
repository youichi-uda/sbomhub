-- ============================================
-- Enforce tenant_id NOT NULL on sboms / components
--
-- Background:
--   - 007_multitenancy added `tenant_id UUID REFERENCES tenants(id)` to both
--     tables but left them NULL-able.
--   - 023_rls_security_hardening installed a FORCE ROW LEVEL SECURITY policy
--     with `WITH CHECK (tenant_id = current_setting('app.current_tenant_id',
--     true)::UUID)`. A NULL tenant_id therefore violates the policy at INSERT
--     time, but old rows that pre-date 023 may still be present with NULL.
--
-- This migration:
--   1. Backfills tenant_id on existing rows using the parent project / sbom
--      relationship so RLS can keep enforcing tenancy.
--   2. Aborts if any orphan rows remain (no parent project / no parent sbom)
--      because we cannot guess their tenant.
--   3. Marks the column NOT NULL so future inserts without tenant_id fail at
--      the schema layer, not just the RLS policy.
--
-- Scope: sboms + components only. vex_statements / license_policies /
-- notification_* are tracked separately (see ROADMAP §9.1.x).
-- ============================================

-- Backfill sboms.tenant_id from their parent project.
UPDATE sboms s
SET tenant_id = p.tenant_id
FROM projects p
WHERE s.project_id = p.id
  AND s.tenant_id IS NULL;

-- Backfill components.tenant_id from their parent sbom (post-sbom backfill).
UPDATE components c
SET tenant_id = s.tenant_id
FROM sboms s
WHERE c.sbom_id = s.id
  AND c.tenant_id IS NULL;

-- Fail fast on orphan rows: if we cannot derive tenant_id, refuse to install
-- the NOT NULL constraint so the operator notices instead of getting a
-- mid-migration ALTER failure with no diagnostics.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM sboms WHERE tenant_id IS NULL) THEN
        RAISE EXCEPTION
            'tenant_id NULL row remaining in sboms (orphan); resolve manually before migrating';
    END IF;
    IF EXISTS (SELECT 1 FROM components WHERE tenant_id IS NULL) THEN
        RAISE EXCEPTION
            'tenant_id NULL row remaining in components (orphan); resolve manually before migrating';
    END IF;
END $$;

-- Promote tenant_id to NOT NULL. Tenant-aware indexes (idx_sboms_tenant_id,
-- idx_components_tenant_id) already exist from 007_multitenancy.
ALTER TABLE sboms ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE components ALTER COLUMN tenant_id SET NOT NULL;
