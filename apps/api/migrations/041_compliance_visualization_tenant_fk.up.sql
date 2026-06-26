-- ============================================
-- Composite (tenant_id, project_id) ownership enforcement for
-- compliance_checklist_responses + sbom_visualization_settings
-- (M4 Codex review round 15 / F75, F73+F74 extension).
--
-- Source of truth:
--   * Codex review M4 round 15 finding F75 (severity medium, cross-
--     tenant data pollution + DoS):
--       "F73 part 2 made the repository require tenantID and F74 routed
--        every write through the TenantTx-aware Querier, so RLS now
--        fires on the right connection. But the write path still does
--        not validate that project_id belongs to the same tenant: a
--        tenant-A session that submits tenant_id=A + project_id=<B's
--        project UUID> passes WITH CHECK (the inserted row's tenant_id
--        is A, matching app.current_tenant_id=A), and lands a tenant-A
--        child row attached to a tenant-B project. Two consequences:
--        (1) cross-tenant data pollution -- the orphan child row carries
--        tenant-A audit content but hangs off a tenant-B project graph;
--        (2) DoS for tenant B -- when tenant B later tries to write its
--        own (project_id, check_id) / (project_id) row, the UNIQUE
--        constraint rejects it because tenant A's pollution row already
--        occupies the slot, and tenant B has no RLS visibility to
--        UPDATE it away."
--
-- Why a DB-level fix (option (a)) instead of an app-layer guard:
--   An app-layer Upsert that rewrites to `INSERT ... SELECT FROM
--   projects WHERE id = $project_id AND tenant_id = $tenant_id` would
--   close this hole at the cost of one bug per repository -- a future
--   importer / migration tool / one-off CLI that bypasses the
--   repository regresses silently. A composite FOREIGN KEY in the
--   schema is checked unconditionally regardless of how the row arrives
--   (REST API, CLI, batch importer, psql ad-hoc, future MCP tool), so
--   the property is permanent. The cost is one extra UNIQUE constraint
--   on projects(tenant_id, id) which is logically already implied by
--   id being PRIMARY KEY (PostgreSQL will satisfy it with an index that
--   shadows the existing pkey index).
--
-- Why a separate migration (not amending 040):
--   Same precedent as 040 itself: rewriting an already-shipped
--   migration silently skips operators that have migrated past that
--   number. Adding this hardening as 041 makes it surface through the
--   normal migrate-up sequence on every existing install.
--
-- Defense in depth model:
--   migration 018: tenant_id + project_id columns, single-column FKs
--   migration 040: RLS ENABLE + FORCE + tenant_isolation_* policies
--                  (rejects cross-tenant tenant_id forgery at write)
--   migration 041: composite FK projects(tenant_id, id)
--                  (rejects cross-tenant project_id targeting at write)
--   repository.go: tenantID required + filtered in every WHERE clause
--                  (app-layer twin -- catches a missing GUC regression)
--
-- All four are independent; any one alone is sufficient to stop the
-- F75 attack. We ship all four so a regression in one is caught by the
-- others.
--
-- Operator note about the orphan sanity check below:
--   The DO $$ block fails the migration loudly if any
--   compliance_checklist_responses / sbom_visualization_settings row
--   already has a tenant_id that disagrees with its parent project's
--   tenant_id. In a clean install (no F75 exploitation yet) this is a
--   no-op. In a hypothetical install where the F75 vector was already
--   exercised (whether by an attacker or by an internal bug) the
--   migration aborts with a clear message so ops can clean up before
--   replaying. See the down migration for the inverse and
--   docs/security or PRODUCT_REBOOT_PLAN.md §9 for the cleanup
--   procedure (TBD: ※要確認 -- the cleanup runbook is M5 scope).
-- ============================================

-- Step 1: composite uniqueness on projects(tenant_id, id).
-- id is already PRIMARY KEY so this constraint is logically redundant
-- for uniqueness, but PostgreSQL requires a referenced column set to
-- be backed by either a PRIMARY KEY or a UNIQUE constraint to be a
-- valid FOREIGN KEY target. The PRIMARY KEY on id alone covers
-- references to (id) but NOT to (tenant_id, id) -- so we need an
-- explicit composite UNIQUE here.
ALTER TABLE projects
    ADD CONSTRAINT projects_tenant_id_id_unique UNIQUE (tenant_id, id);

-- Step 2: pre-flight orphan / mismatch check.
-- If any existing child row has tenant_id != projects.tenant_id (the
-- F75 pollution signature), the composite FK in step 3 would fail
-- with a generic "violates foreign key constraint" error that does
-- not tell ops which rows to clean up. Surface a precise diagnostic
-- here instead, before any DDL that would lock the child tables for
-- the FK validation scan.
DO $$
DECLARE
    checklist_mismatch INTEGER;
    visualization_mismatch INTEGER;
BEGIN
    -- compliance_checklist_responses: child tenant_id vs project tenant_id.
    SELECT COUNT(*) INTO checklist_mismatch
    FROM compliance_checklist_responses ccr
    LEFT JOIN projects p ON p.id = ccr.project_id
    WHERE p.id IS NULL  -- orphan (parent project deleted but child survived)
       OR p.tenant_id IS NULL  -- legacy pre-multitenancy project that never got a tenant
       OR p.tenant_id <> ccr.tenant_id;  -- F75 pollution signature
    IF checklist_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 041: compliance_checklist_responses has % row(s) '
            'with tenant_id != parent projects.tenant_id (F75 pollution / orphan). '
            'Composite FK cannot be installed until ops cleanup. To inspect: '
            'SELECT ccr.id, ccr.tenant_id AS child_tenant, ccr.project_id, '
            'p.tenant_id AS parent_tenant FROM compliance_checklist_responses ccr '
            'LEFT JOIN projects p ON p.id = ccr.project_id WHERE p.id IS NULL OR '
            'p.tenant_id IS NULL OR p.tenant_id <> ccr.tenant_id;',
            checklist_mismatch;
    END IF;

    -- sbom_visualization_settings: same check.
    SELECT COUNT(*) INTO visualization_mismatch
    FROM sbom_visualization_settings svs
    LEFT JOIN projects p ON p.id = svs.project_id
    WHERE p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> svs.tenant_id;
    IF visualization_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 041: sbom_visualization_settings has % row(s) '
            'with tenant_id != parent projects.tenant_id (F75 pollution / orphan). '
            'Composite FK cannot be installed until ops cleanup. To inspect: '
            'SELECT svs.id, svs.tenant_id AS child_tenant, svs.project_id, '
            'p.tenant_id AS parent_tenant FROM sbom_visualization_settings svs '
            'LEFT JOIN projects p ON p.id = svs.project_id WHERE p.id IS NULL OR '
            'p.tenant_id IS NULL OR p.tenant_id <> svs.tenant_id;',
            visualization_mismatch;
    END IF;
END $$;

-- Step 3: composite FOREIGN KEY child(tenant_id, project_id) ->
-- projects(tenant_id, id). The existing single-column
-- child.project_id -> projects(id) FK is intentionally kept so
-- ON DELETE CASCADE behaviour (introduced in migration 018) does not
-- depend on the new composite constraint -- we treat 041 as additive
-- hardening, not a refactor.
--
-- ON DELETE CASCADE is duplicated here for the same reason: if the
-- parent row goes away, both constraints react the same way, and
-- PostgreSQL handles the overlapping CASCADE cleanly (it cascades
-- once, not twice).
ALTER TABLE compliance_checklist_responses
    ADD CONSTRAINT compliance_checklist_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE sbom_visualization_settings
    ADD CONSTRAINT sbom_visualization_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

COMMENT ON CONSTRAINT compliance_checklist_tenant_project_fk
    ON compliance_checklist_responses IS
    'M4 Codex review round 15 / F75: rejects (tenant_id, project_id) pairs '
    'whose parent project does not belong to the same tenant. Closes the '
    'cross-tenant data pollution + DoS vector that RLS WITH CHECK on tenant_id '
    'alone could not. See migrations/041_compliance_visualization_tenant_fk.up.sql.';

COMMENT ON CONSTRAINT sbom_visualization_tenant_project_fk
    ON sbom_visualization_settings IS
    'M4 Codex review round 15 / F75: rejects (tenant_id, project_id) pairs '
    'whose parent project does not belong to the same tenant. See '
    'migrations/041_compliance_visualization_tenant_fk.up.sql.';

COMMENT ON CONSTRAINT projects_tenant_id_id_unique
    ON projects IS
    'M4 Codex review round 15 / F75: composite uniqueness that anchors the '
    'compliance_checklist_responses + sbom_visualization_settings composite '
    'FKs. Logically redundant with the id PRIMARY KEY but required by '
    'PostgreSQL FK semantics.';
