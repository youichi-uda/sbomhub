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
--   1. Temporarily lifts FORCE / ENABLE ROW LEVEL SECURITY on projects,
--      sboms, components so the backfill UPDATE can see and modify pre-023
--      rows. Without this, the migrator role (sbomhub_migrator, created with
--      NOBYPASSRLS by apps/api/cmd/migrate/init.sh) runs the UPDATE under the
--      tenant policy with no `app.current_tenant_id` GUC set, the predicate
--      evaluates to NULL, and the UPDATE silently affects zero rows — the
--      subsequent `ALTER COLUMN ... SET NOT NULL` then fails on any leftover
--      NULL row, bricking the upgrade for existing self-host users
--      (codex R2 P1).
--   2. Backfills tenant_id on existing rows using the parent project / sbom
--      relationship so RLS can keep enforcing tenancy.
--   3. Aborts if any orphan rows remain (no parent project / no parent sbom)
--      because we cannot guess their tenant.
--   4. Marks the column NOT NULL so future inserts without tenant_id fail at
--      the schema layer, not just the RLS policy.
--   5. Restores ENABLE + FORCE ROW LEVEL SECURITY on the three tables so the
--      post-migration state matches 023.
--
-- Atomicity: the whole script is executed by the in-process migrator
-- (apps/api/internal/database/migrate.go) inside a single tx.Begin()/Commit()
-- block, so any failure rolls back DDL + DML together — including the RLS
-- disable in step 1, which is automatically restored on rollback. We do not
-- add an explicit BEGIN/COMMIT here because that would emit
-- "transaction already in progress" warnings from PostgreSQL and split the
-- outer transaction boundary the migrator relies on for the
-- schema_migrations bookkeeping insert.
--
-- Scope: sboms + components only. vex_statements / license_policies /
-- notification_* are tracked separately (see ROADMAP §9.1.x).
-- ============================================

-- Step 1: Temporarily disable RLS on the three tables touched by the backfill.
-- The migrator role is NOBYPASSRLS, so FORCE + tenant policy would otherwise
-- hide every row from the UPDATE (no app.current_tenant_id GUC during migrate).
ALTER TABLE projects   NO FORCE ROW LEVEL SECURITY;
ALTER TABLE projects   DISABLE ROW LEVEL SECURITY;
ALTER TABLE sboms      NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sboms      DISABLE ROW LEVEL SECURITY;
ALTER TABLE components NO FORCE ROW LEVEL SECURITY;
ALTER TABLE components DISABLE ROW LEVEL SECURITY;

-- Step 2: Backfill sboms.tenant_id from their parent project.
UPDATE sboms s
SET tenant_id = p.tenant_id
FROM projects p
WHERE s.project_id = p.id
  AND s.tenant_id IS NULL;

-- Step 2b: Backfill components.tenant_id from their parent sbom (post-sbom backfill).
UPDATE components c
SET tenant_id = s.tenant_id
FROM sboms s
WHERE c.sbom_id = s.id
  AND c.tenant_id IS NULL;

-- Step 3: Fail fast on orphan rows: if we cannot derive tenant_id, refuse to
-- install the NOT NULL constraint so the operator notices instead of getting a
-- mid-migration ALTER failure with no diagnostics. Transaction rollback also
-- restores the RLS state lifted in step 1.
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

-- Step 4: Promote tenant_id to NOT NULL. Tenant-aware indexes
-- (idx_sboms_tenant_id, idx_components_tenant_id) already exist from 007_multitenancy.
ALTER TABLE sboms      ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE components ALTER COLUMN tenant_id SET NOT NULL;

-- Step 5: Restore ENABLE + FORCE ROW LEVEL SECURITY so post-migration state
-- matches what 007 (ENABLE) + 023 (FORCE) established.
ALTER TABLE projects   ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects   FORCE  ROW LEVEL SECURITY;
ALTER TABLE sboms      ENABLE ROW LEVEL SECURITY;
ALTER TABLE sboms      FORCE  ROW LEVEL SECURITY;
ALTER TABLE components ENABLE ROW LEVEL SECURITY;
ALTER TABLE components FORCE  ROW LEVEL SECURITY;
