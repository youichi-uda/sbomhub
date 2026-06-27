-- ============================================
-- Composite (tenant_id, project_id) FK hardening for the five
-- remaining tables that carry a hard project_id reference but no
-- tenant-coupling at the FK layer (M5 Wave M5-1 / issue #50, F75
-- pattern extension).
--
-- Source of truth:
--   * sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §9.1
--   * sbomhub-internal/planning/M5_AGENT_PROMPT_TEMPLATE.md §1.A §2 M5-1
--   * GitHub issue #50 (M5 Wave M5-1: RLS uniformity sweep)
--   * Migration 041 (F75 fix for compliance_checklist + visualization).
--     This migration is the horizontal sweep of the same pattern over
--     every other table that has the same shape.
--     Review Round 1 (F81) found additional legacy project-child tables
--     with the same tenant_id + project_id shape; migration 045 extends
--     the sweep to those tables without amending this migration body.
--
-- F75 vector recap (see 041 header for the full story):
--   RLS WITH CHECK on tenant_id alone rejects "row has wrong
--   tenant_id" but does NOT verify that project_id actually belongs
--   to the writing tenant. A tenant-A session that submits
--   tenant_id=A + project_id=<B's project UUID> passes WITH CHECK
--   (the row's tenant_id is A, matching app.current_tenant_id=A) and
--   lands a tenant-A child row attached to a tenant-B project graph.
--   Consequences:
--     (1) cross-tenant data pollution -- tenant-A audit content
--         hanging off tenant-B's project,
--     (2) DoS for tenant B -- if the child table has a UNIQUE
--         (project_id, ...) constraint, tenant B's own future writes
--         are rejected by the pollution row that tenant B has no RLS
--         visibility to UPDATE / DELETE.
--
--   Migration 041 closed this hole for compliance_checklist_responses
--   and sbom_visualization_settings via a composite FOREIGN KEY
--   (tenant_id, project_id) -> projects(tenant_id, id). The composite
--   UNIQUE on projects(tenant_id, id) needed to anchor the FK was
--   added in 041 (constraint projects_tenant_id_id_unique), so 044
--   only needs to add the child-side FKs.
--
-- Tables covered (all have hard `REFERENCES projects(id) ON DELETE
-- CASCADE` from their original migration, plus a tenant_id column):
--
--   1. github_repositories            (migration 011)
--   2. vulnerability_resolution_events (migration 012, analytics)
--   3. compliance_snapshots           (migration 012, analytics)
--   4. ssvc_project_defaults          (migration 021)
--   5. ssvc_assessments               (migration 021)
--
-- Tables INTENTIONALLY NOT covered (and why):
--
--   * cra_reports, meti_assessments (migrations 038, 039)
--       -- migration headers explicitly call these out as soft
--          references (project_id is a UUID column with no FK, by
--          design, so that project deletion doesn't cascade-delete
--          historical compliance evidence). Adding a composite FK
--          here would change that semantic. Out of scope for M5-1,
--          covered by the design intent of M2 / M3.
--
--   * compliance_checklist_responses, sbom_visualization_settings
--       -- already closed by migration 041 (F75 origin).
--
--   * Tables without a project_id column at all (scan_settings,
--     scan_logs, github_connections, vulnerability_snapshots,
--     report_settings, generated_reports, ipa_sync_settings,
--     slo_targets, subscriptions, audit_logs, ...) -- nothing to
--     compose against.
--
--   * ssvc_assessment_history -- the audit-trail child references
--     `ssvc_assessments(id) ON DELETE CASCADE` only, no direct
--     project_id. Tenant scope is already enforced via the subquery
--     policy added in 043; no composite FK applicable.
--
-- Orphan pre-flight (DO $$ block):
--   The composite FK installation will fail with a generic
--   "violates foreign key constraint" error if any existing row has
--   a tenant_id that disagrees with its parent project's tenant_id
--   (the F75 pollution signature). The DO $$ block below probes
--   every covered table and RAISE EXCEPTION's with a precise
--   diagnostic so ops can clean up before replaying. In a clean
--   install (no F75 exploitation yet) this is a no-op.
--
-- Why a separate migration (not amending the originals):
--   Same precedent as 041. Operators already past 011 / 012 / 021
--   must pick up the hardening through the normal migrate-up sequence.
--
-- Ordering vs 041:
--   041 added the projects_tenant_id_id_unique composite UNIQUE
--   that ALL composite FKs to projects(tenant_id, id) need to
--   anchor. 044 piggybacks on that constraint; it does not add a
--   new UNIQUE.
--
-- Ordering vs 042 / 043:
--   042 hardened the RLS state on these tables so the orphan
--   pre-flight block below sees consistent rows when run under
--   sbomhub_migrator (which is NOBYPASSRLS-equivalent under FORCE).
--   043 added RLS to the github_* tables. Adding the composite FK
--   after both makes the "tenant_id-consistent" invariant strict.
-- ============================================

-- Step 1: orphan pre-flight. Surface the F75 pollution signature
-- precisely so ops can fix it before the composite FK fails opaquely.
DO $$
DECLARE
    gh_mismatch INTEGER;
    vre_mismatch INTEGER;
    cs_mismatch INTEGER;
    sspd_mismatch INTEGER;
    ssa_mismatch INTEGER;
BEGIN
    -- github_repositories
    SELECT COUNT(*) INTO gh_mismatch
    FROM github_repositories gh
    LEFT JOIN projects p ON p.id = gh.project_id
    WHERE p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> gh.tenant_id;
    IF gh_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 044: github_repositories has % row(s) '
            'with tenant_id != parent projects.tenant_id (F75 pollution / orphan). '
            'Composite FK cannot be installed until ops cleanup. To inspect: '
            'SELECT gh.id, gh.tenant_id AS child_tenant, gh.project_id, '
            'p.tenant_id AS parent_tenant FROM github_repositories gh '
            'LEFT JOIN projects p ON p.id = gh.project_id WHERE p.id IS NULL OR '
            'p.tenant_id IS NULL OR p.tenant_id <> gh.tenant_id;',
            gh_mismatch;
    END IF;

    -- vulnerability_resolution_events
    SELECT COUNT(*) INTO vre_mismatch
    FROM vulnerability_resolution_events vre
    LEFT JOIN projects p ON p.id = vre.project_id
    WHERE p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> vre.tenant_id;
    IF vre_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 044: vulnerability_resolution_events has % row(s) '
            'with tenant_id != parent projects.tenant_id (F75 pollution / orphan). '
            'Composite FK cannot be installed until ops cleanup. To inspect: '
            'SELECT vre.id, vre.tenant_id AS child_tenant, vre.project_id, '
            'p.tenant_id AS parent_tenant FROM vulnerability_resolution_events vre '
            'LEFT JOIN projects p ON p.id = vre.project_id WHERE p.id IS NULL OR '
            'p.tenant_id IS NULL OR p.tenant_id <> vre.tenant_id;',
            vre_mismatch;
    END IF;

    -- compliance_snapshots: NOTE project_id is NULLABLE on this table.
    -- The composite FK is itself NULL-safe (PostgreSQL FK semantics:
    -- a NULL in any composite column makes the FK row vacuously
    -- satisfied). The pre-flight here therefore filters out rows
    -- where project_id IS NULL.
    SELECT COUNT(*) INTO cs_mismatch
    FROM compliance_snapshots cs
    LEFT JOIN projects p ON p.id = cs.project_id
    WHERE cs.project_id IS NOT NULL
      AND (p.id IS NULL
           OR p.tenant_id IS NULL
           OR p.tenant_id <> cs.tenant_id);
    IF cs_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 044: compliance_snapshots has % row(s) '
            'with tenant_id != parent projects.tenant_id (F75 pollution / orphan). '
            'Composite FK cannot be installed until ops cleanup. To inspect: '
            'SELECT cs.id, cs.tenant_id AS child_tenant, cs.project_id, '
            'p.tenant_id AS parent_tenant FROM compliance_snapshots cs '
            'LEFT JOIN projects p ON p.id = cs.project_id WHERE cs.project_id IS NOT NULL '
            'AND (p.id IS NULL OR p.tenant_id IS NULL OR p.tenant_id <> cs.tenant_id);',
            cs_mismatch;
    END IF;

    -- ssvc_project_defaults
    SELECT COUNT(*) INTO sspd_mismatch
    FROM ssvc_project_defaults sspd
    LEFT JOIN projects p ON p.id = sspd.project_id
    WHERE p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> sspd.tenant_id;
    IF sspd_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 044: ssvc_project_defaults has % row(s) '
            'with tenant_id != parent projects.tenant_id (F75 pollution / orphan). '
            'Composite FK cannot be installed until ops cleanup. To inspect: '
            'SELECT sspd.id, sspd.tenant_id AS child_tenant, sspd.project_id, '
            'p.tenant_id AS parent_tenant FROM ssvc_project_defaults sspd '
            'LEFT JOIN projects p ON p.id = sspd.project_id WHERE p.id IS NULL OR '
            'p.tenant_id IS NULL OR p.tenant_id <> sspd.tenant_id;',
            sspd_mismatch;
    END IF;

    -- ssvc_assessments
    SELECT COUNT(*) INTO ssa_mismatch
    FROM ssvc_assessments ssa
    LEFT JOIN projects p ON p.id = ssa.project_id
    WHERE p.id IS NULL
       OR p.tenant_id IS NULL
       OR p.tenant_id <> ssa.tenant_id;
    IF ssa_mismatch > 0 THEN
        RAISE EXCEPTION 'migration 044: ssvc_assessments has % row(s) '
            'with tenant_id != parent projects.tenant_id (F75 pollution / orphan). '
            'Composite FK cannot be installed until ops cleanup. To inspect: '
            'SELECT ssa.id, ssa.tenant_id AS child_tenant, ssa.project_id, '
            'p.tenant_id AS parent_tenant FROM ssvc_assessments ssa '
            'LEFT JOIN projects p ON p.id = ssa.project_id WHERE p.id IS NULL OR '
            'p.tenant_id IS NULL OR p.tenant_id <> ssa.tenant_id;',
            ssa_mismatch;
    END IF;
END $$;

-- Step 2: composite FOREIGN KEY child(tenant_id, project_id) ->
-- projects(tenant_id, id). The existing single-column
-- child.project_id -> projects(id) FK is intentionally kept on every
-- child table so ON DELETE CASCADE behaviour (introduced in the
-- original migrations) does not depend on the new composite
-- constraint -- 044 is additive hardening, not a refactor.
--
-- ON DELETE CASCADE is duplicated on the composite FK for the same
-- reason as 041: if the parent row goes away, both constraints
-- react the same way and PostgreSQL handles the overlapping CASCADE
-- cleanly (cascades once, not twice).

ALTER TABLE github_repositories
    ADD CONSTRAINT github_repositories_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE vulnerability_resolution_events
    ADD CONSTRAINT vuln_resolution_events_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

-- compliance_snapshots.project_id is nullable; the composite FK is
-- NULL-safe by default in PostgreSQL (a NULL in either column makes
-- the FK row vacuously satisfied).
ALTER TABLE compliance_snapshots
    ADD CONSTRAINT compliance_snapshots_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE ssvc_project_defaults
    ADD CONSTRAINT ssvc_project_defaults_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

ALTER TABLE ssvc_assessments
    ADD CONSTRAINT ssvc_assessments_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id)
    REFERENCES projects (tenant_id, id)
    ON DELETE CASCADE;

COMMENT ON CONSTRAINT github_repositories_tenant_project_fk
    ON github_repositories IS
    'M5 Wave M5-1 / issue #50: rejects (tenant_id, project_id) pairs '
    'whose parent project does not belong to the same tenant. F75 pattern '
    'extension (see migration 041 header).';

COMMENT ON CONSTRAINT vuln_resolution_events_tenant_project_fk
    ON vulnerability_resolution_events IS
    'M5 Wave M5-1 / issue #50: rejects (tenant_id, project_id) pairs '
    'whose parent project does not belong to the same tenant. F75 pattern '
    'extension (see migration 041 header).';

COMMENT ON CONSTRAINT compliance_snapshots_tenant_project_fk
    ON compliance_snapshots IS
    'M5 Wave M5-1 / issue #50: rejects (tenant_id, project_id) pairs '
    'whose parent project does not belong to the same tenant. NULL-safe '
    '(project_id is nullable on this table). F75 pattern extension.';

COMMENT ON CONSTRAINT ssvc_project_defaults_tenant_project_fk
    ON ssvc_project_defaults IS
    'M5 Wave M5-1 / issue #50: rejects (tenant_id, project_id) pairs '
    'whose parent project does not belong to the same tenant. F75 pattern '
    'extension (see migration 041 header).';

COMMENT ON CONSTRAINT ssvc_assessments_tenant_project_fk
    ON ssvc_assessments IS
    'M5 Wave M5-1 / issue #50: rejects (tenant_id, project_id) pairs '
    'whose parent project does not belong to the same tenant. F75 pattern '
    'extension (see migration 041 header).';
