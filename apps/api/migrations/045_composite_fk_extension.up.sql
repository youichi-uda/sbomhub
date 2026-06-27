-- ============================================
-- Composite (tenant_id, project_id) FK extension for legacy project-child
-- tables missed by migration 044 (M5 Phase D Codex review Round 1 / F81).
--
-- Scope:
--   044 hardened the M5-1 sweep tables but missed older project-child tables
--   with the same shape. This migration keeps the 041/044 pattern: fail loudly
--   on existing F75 pollution, then add child(tenant_id, project_id) ->
--   projects(tenant_id, id) with ON DELETE CASCADE.
--
-- Tables covered:
--   1. sboms                  (001 + 007 + 027): tenant_id is NOT NULL.
--   2. vex_statements         (003 + 007): tenant_id was nullable; backfilled
--      from projects and promoted to NOT NULL here.
--   3. license_policies       (004 + 007): tenant_id was nullable; backfilled
--      from projects and promoted to NOT NULL here.
--   4. notification_settings  (006 + 007): tenant_id was nullable; backfilled
--      from projects and promoted to NOT NULL here.
--   5. notification_logs      (006 + 007): tenant_id was nullable; backfilled
--      from projects and promoted to NOT NULL here.
--   6. public_links           (009): tenant_id is NOT NULL.
--   7. vulnerability_tickets  (015): tenant_id is NOT NULL.
--
-- Tables intentionally not covered:
--   * components: no direct project_id; project ownership is through sboms.
--   * public_link_access_logs: no project_id; ownership is through public_links.
--   * issue_tracker_connections: tenant-scoped but no project_id.
--   * ssvc_assessment_history: already scoped through ssvc_assessments policy.
--   * cra_reports / meti_assessments: soft project UUID references by design.
--   * 041/044 tables: already hardened by their owning migrations.
--
-- The projects_tenant_id_id_unique anchor is owned by migration 041.
--
-- M5 Phase D Round 4 / F87:
--   The Step 3 diagnostic SELECTs must see sboms and vulnerability_tickets
--   even when the migrator role is NOBYPASSRLS and no app.current_tenant_id
--   GUC is set. Those two tables were FORCE RLS in migration 023, so Step 1
--   temporarily lifts their RLS alongside the other project-child tables and
--   Step 5 restores ENABLE + FORCE before adding the composite FKs. The DDL
--   takes ACCESS EXCLUSIVE locks, so concurrent app sessions cannot race
--   through the lifted state; a non-tenant DBA monitoring query run during
--   the migration could briefly observe cross-tenant rows.
-- ============================================

-- Step 1: Temporarily lift FORCE RLS so the migrator can backfill legacy
-- nullable tenant_id rows and run diagnostics without an app.current_tenant_id
-- GUC.
ALTER TABLE projects              NO FORCE ROW LEVEL SECURITY;
ALTER TABLE projects              DISABLE ROW LEVEL SECURITY;
ALTER TABLE sboms                 NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sboms                 DISABLE ROW LEVEL SECURITY;
ALTER TABLE vex_statements        NO FORCE ROW LEVEL SECURITY;
ALTER TABLE vex_statements        DISABLE ROW LEVEL SECURITY;
ALTER TABLE license_policies      NO FORCE ROW LEVEL SECURITY;
ALTER TABLE license_policies      DISABLE ROW LEVEL SECURITY;
ALTER TABLE notification_settings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_settings DISABLE ROW LEVEL SECURITY;
ALTER TABLE notification_logs     NO FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_logs     DISABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets NO FORCE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets DISABLE ROW LEVEL SECURITY;

-- Step 2: Backfill legacy nullable tenant_id columns from parent projects.
UPDATE vex_statements v
SET tenant_id = p.tenant_id
FROM projects p
WHERE v.project_id = p.id
  AND v.tenant_id IS NULL;

UPDATE license_policies lp
SET tenant_id = p.tenant_id
FROM projects p
WHERE lp.project_id = p.id
  AND lp.tenant_id IS NULL;

UPDATE notification_settings ns
SET tenant_id = p.tenant_id
FROM projects p
WHERE ns.project_id = p.id
  AND ns.tenant_id IS NULL;

UPDATE notification_logs nl
SET tenant_id = p.tenant_id
FROM projects p
WHERE nl.project_id = p.id
  AND nl.tenant_id IS NULL;

-- Step 3: Orphan / pollution pre-flight. Any NULL child tenant after backfill,
-- missing parent project, NULL parent tenant, or child/parent tenant mismatch
-- must be fixed by ops before the composite FK can be installed.
DO $$
DECLARE
    sboms_mismatch INTEGER;
    vex_mismatch INTEGER;
    license_mismatch INTEGER;
    notification_settings_mismatch INTEGER;
    notification_logs_mismatch INTEGER;
    public_links_mismatch INTEGER;
    vulnerability_tickets_mismatch INTEGER;
BEGIN
    SELECT COUNT(*) INTO sboms_mismatch
    FROM sboms s
    LEFT JOIN projects p ON p.id = s.project_id
    WHERE s.tenant_id IS NULL
       OR p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> s.tenant_id;
    IF sboms_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 045: sboms has % row(s) with tenant_id NULL, missing parent project, or tenant_id != parent projects.tenant_id (F75 pollution / orphan). Inspect with: SELECT s.id, s.tenant_id AS child_tenant, s.project_id, p.tenant_id AS parent_tenant FROM sboms s LEFT JOIN projects p ON p.id = s.project_id WHERE s.tenant_id IS NULL OR p.id IS NULL OR p.tenant_id IS NULL OR p.tenant_id <> s.tenant_id;', sboms_mismatch;
    END IF;

    SELECT COUNT(*) INTO vex_mismatch
    FROM vex_statements v
    LEFT JOIN projects p ON p.id = v.project_id
    WHERE v.tenant_id IS NULL
       OR p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> v.tenant_id;
    IF vex_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 045: vex_statements has % row(s) with tenant_id NULL, missing parent project, or tenant_id != parent projects.tenant_id (F75 pollution / orphan). Inspect with: SELECT v.id, v.tenant_id AS child_tenant, v.project_id, p.tenant_id AS parent_tenant FROM vex_statements v LEFT JOIN projects p ON p.id = v.project_id WHERE v.tenant_id IS NULL OR p.id IS NULL OR p.tenant_id IS NULL OR p.tenant_id <> v.tenant_id;', vex_mismatch;
    END IF;

    SELECT COUNT(*) INTO license_mismatch
    FROM license_policies lp
    LEFT JOIN projects p ON p.id = lp.project_id
    WHERE lp.tenant_id IS NULL
       OR p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> lp.tenant_id;
    IF license_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 045: license_policies has % row(s) with tenant_id NULL, missing parent project, or tenant_id != parent projects.tenant_id (F75 pollution / orphan). Inspect with: SELECT lp.id, lp.tenant_id AS child_tenant, lp.project_id, p.tenant_id AS parent_tenant FROM license_policies lp LEFT JOIN projects p ON p.id = lp.project_id WHERE lp.tenant_id IS NULL OR p.id IS NULL OR p.tenant_id IS NULL OR p.tenant_id <> lp.tenant_id;', license_mismatch;
    END IF;

    SELECT COUNT(*) INTO notification_settings_mismatch
    FROM notification_settings ns
    LEFT JOIN projects p ON p.id = ns.project_id
    WHERE ns.tenant_id IS NULL
       OR p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> ns.tenant_id;
    IF notification_settings_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 045: notification_settings has % row(s) with tenant_id NULL, missing parent project, or tenant_id != parent projects.tenant_id (F75 pollution / orphan). Inspect with: SELECT ns.id, ns.tenant_id AS child_tenant, ns.project_id, p.tenant_id AS parent_tenant FROM notification_settings ns LEFT JOIN projects p ON p.id = ns.project_id WHERE ns.tenant_id IS NULL OR p.id IS NULL OR p.tenant_id IS NULL OR p.tenant_id <> ns.tenant_id;', notification_settings_mismatch;
    END IF;

    SELECT COUNT(*) INTO notification_logs_mismatch
    FROM notification_logs nl
    LEFT JOIN projects p ON p.id = nl.project_id
    WHERE nl.tenant_id IS NULL
       OR p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> nl.tenant_id;
    IF notification_logs_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 045: notification_logs has % row(s) with tenant_id NULL, missing parent project, or tenant_id != parent projects.tenant_id (F75 pollution / orphan). Inspect with: SELECT nl.id, nl.tenant_id AS child_tenant, nl.project_id, p.tenant_id AS parent_tenant FROM notification_logs nl LEFT JOIN projects p ON p.id = nl.project_id WHERE nl.tenant_id IS NULL OR p.id IS NULL OR p.tenant_id IS NULL OR p.tenant_id <> nl.tenant_id;', notification_logs_mismatch;
    END IF;

    SELECT COUNT(*) INTO public_links_mismatch
    FROM public_links pl
    LEFT JOIN projects p ON p.id = pl.project_id
    WHERE pl.tenant_id IS NULL
       OR p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> pl.tenant_id;
    IF public_links_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 045: public_links has % row(s) with tenant_id NULL, missing parent project, or tenant_id != parent projects.tenant_id (F75 pollution / orphan). Inspect with: SELECT pl.id, pl.tenant_id AS child_tenant, pl.project_id, p.tenant_id AS parent_tenant FROM public_links pl LEFT JOIN projects p ON p.id = pl.project_id WHERE pl.tenant_id IS NULL OR p.id IS NULL OR p.tenant_id IS NULL OR p.tenant_id <> pl.tenant_id;', public_links_mismatch;
    END IF;

    SELECT COUNT(*) INTO vulnerability_tickets_mismatch
    FROM vulnerability_tickets vt
    LEFT JOIN projects p ON p.id = vt.project_id
    WHERE vt.tenant_id IS NULL
       OR p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> vt.tenant_id;
    IF vulnerability_tickets_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 045: vulnerability_tickets has % row(s) with tenant_id NULL, missing parent project, or tenant_id != parent projects.tenant_id (F75 pollution / orphan). Inspect with: SELECT vt.id, vt.tenant_id AS child_tenant, vt.project_id, p.tenant_id AS parent_tenant FROM vulnerability_tickets vt LEFT JOIN projects p ON p.id = vt.project_id WHERE vt.tenant_id IS NULL OR p.id IS NULL OR p.tenant_id IS NULL OR p.tenant_id <> vt.tenant_id;', vulnerability_tickets_mismatch;
    END IF;
END $$;

-- Step 4: Promote legacy nullable columns to NOT NULL now that they are
-- backfilled and validated.
ALTER TABLE vex_statements        ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE license_policies      ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE notification_settings ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE notification_logs     ALTER COLUMN tenant_id SET NOT NULL;

-- Step 5: Restore ENABLE + FORCE RLS to match the 023/042 hardened posture.
ALTER TABLE projects              ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects              FORCE  ROW LEVEL SECURITY;
ALTER TABLE sboms                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE sboms                 FORCE  ROW LEVEL SECURITY;
ALTER TABLE vex_statements        ENABLE ROW LEVEL SECURITY;
ALTER TABLE vex_statements        FORCE  ROW LEVEL SECURITY;
ALTER TABLE license_policies      ENABLE ROW LEVEL SECURITY;
ALTER TABLE license_policies      FORCE  ROW LEVEL SECURITY;
ALTER TABLE notification_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_settings FORCE  ROW LEVEL SECURITY;
ALTER TABLE notification_logs     ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_logs     FORCE  ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets FORCE  ROW LEVEL SECURITY;

-- Step 6: Add composite FKs. Existing single-column project_id FKs stay in
-- place; this migration is additive hardening.
ALTER TABLE sboms
    ADD CONSTRAINT sboms_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE vex_statements
    ADD CONSTRAINT vex_statements_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE license_policies
    ADD CONSTRAINT license_policies_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE notification_settings
    ADD CONSTRAINT notification_settings_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE notification_logs
    ADD CONSTRAINT notification_logs_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE public_links
    ADD CONSTRAINT public_links_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE vulnerability_tickets
    ADD CONSTRAINT vulnerability_tickets_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

COMMENT ON CONSTRAINT sboms_tenant_project_fk ON sboms IS
    'M5 Phase D review Round 1 / F81: rejects tenant_id/project_id pairs whose parent project belongs to a different tenant.';
COMMENT ON CONSTRAINT vex_statements_tenant_project_fk ON vex_statements IS
    'M5 Phase D review Round 1 / F81: rejects tenant_id/project_id pairs whose parent project belongs to a different tenant.';
COMMENT ON CONSTRAINT license_policies_tenant_project_fk ON license_policies IS
    'M5 Phase D review Round 1 / F81: rejects tenant_id/project_id pairs whose parent project belongs to a different tenant.';
COMMENT ON CONSTRAINT notification_settings_tenant_project_fk ON notification_settings IS
    'M5 Phase D review Round 1 / F81: rejects tenant_id/project_id pairs whose parent project belongs to a different tenant.';
COMMENT ON CONSTRAINT notification_logs_tenant_project_fk ON notification_logs IS
    'M5 Phase D review Round 1 / F81: rejects tenant_id/project_id pairs whose parent project belongs to a different tenant.';
COMMENT ON CONSTRAINT public_links_tenant_project_fk ON public_links IS
    'M5 Phase D review Round 1 / F81: rejects tenant_id/project_id pairs whose parent project belongs to a different tenant.';
COMMENT ON CONSTRAINT vulnerability_tickets_tenant_project_fk ON vulnerability_tickets IS
    'M5 Phase D review Round 1 / F81: rejects tenant_id/project_id pairs whose parent project belongs to a different tenant.';
