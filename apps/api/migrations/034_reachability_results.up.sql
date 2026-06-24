-- ============================================
-- Reachability results (M1 Wave M1-3, AI VEX MVP foundation)
--
-- Source of truth: sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §8.1
-- Issue: youichi-uda/sbomhub#26 (M1 Wave M1-3 schema half; the analyser
-- itself lands as #25 under internal/service/reachability/).
--
-- Purpose:
--   For every (project, component, cve) the reachability analyser
--   evaluates, persist the verdict (not_present / import_only /
--   reachable / unknown), its supporting evidence (callgraph nodes /
--   import paths / heuristic explanation), the analyser version that
--   produced it, and a calibrated confidence score. The triage LLM
--   call (#28 / M1-4) loads the latest verdict per (project, component,
--   cve) as context and the vex_drafts row (#27 / M1-5) references
--   reachability_results.id alongside advisory_excerpts.id as one of
--   the two evidence pointers the design doc requires.
--
-- Tenancy:
--   Reachability output is highly tenant-specific (it depends on the
--   tenant's project graph, version of the dependency, callsite usage),
--   so tenant_id is NOT NULL + RLS-enforced from day one with the
--   post-023 hardened pattern (FORCE + WITH CHECK + missing_ok GUC
--   read) -- same shape as 032_llm_calls / 033_advisory_excerpts.
--
-- RLS model:
--   * ENABLE + FORCE ROW LEVEL SECURITY.
--   * Single tenant_isolation_reachability_results policy with USING +
--     WITH CHECK bound to
--     `current_setting('app.current_tenant_id', true)::UUID`.
--   * The missing_ok `true` second arg makes the GUC degrade to '' on
--     unauthenticated paths; the UUID cast then fails the predicate,
--     so the surface is "zero rows / rejected INSERT" rather than
--     "SQL error".
--
-- Indexes:
--   * Unique (tenant_id, project_id, component_id, cve_id) -- enables
--     upsert-by-target ("we re-ran the analyser on this triple, replace
--     the verdict") and stops duplicate rows piling up from re-runs.
--   * idx_reachability_project_cve (tenant_id, project_id, cve_id) --
--     supports the dominant lookup "give me every component's
--     reachability for CVE X in project P" that the triage prompt
--     builder issues.
--   * idx_reachability_component (tenant_id, component_id) -- supports
--     "what verdicts do we have for this component across CVEs" that
--     the per-component drill-down UI uses.
--
-- Storage shape decisions:
--   * status VARCHAR(20) constrained with a CHECK to the four states
--     called out in the AC. Adding a new state is a one-line ALTER ...
--     DROP / ADD, not a full enum migration.
--   * ecosystem VARCHAR(20) (e.g. 'go', 'npm', 'maven', 'pypi') is
--     nullable because some analyser passes (e.g. callgraph-only) do
--     not need to record an ecosystem. ※要確認: should this be NOT
--     NULL once both Go and npm analysers ship in M1?
--   * evidence JSONB stores arbitrary analyser-specific shape
--     (callgraph nodes for the Go analyser, import-tree slices for the
--     npm analyser, heuristic reasoning for the fallback). Defaulted
--     to '{}'::JSONB so partial writes stay well-formed.
--   * confidence NUMERIC(3,2) covers [0.00, 1.00]; CHECK pins the range
--     so a buggy analyser cannot record 1.5 or -0.2 and silently break
--     the triage threshold (M1 横断 issue #29 enforces a per-tenant
--     minimum, comparing against this value).
--   * analyzer_version VARCHAR(20) -- enables filtering "show me
--     verdicts produced by analyser >= v2 so we can re-triage older
--     ones". ※要確認: ROADMAP does not yet specify the analyser
--     version scheme (semver vs git-sha). VARCHAR(20) handles either.
--   * analyzed_at TIMESTAMPTZ -- when the analyser produced this
--     verdict. Nullable so an offline replay can still write a row.
--   * project_id / component_id are NOT NULL but intentionally NOT
--     declared as FOREIGN KEYs to projects(id) / components(id). Two
--     reasons:
--       1. Mirrors the soft-reference convention from llm_calls
--          (triage_target_component_id) -- when the parent row is
--          deleted, we want the analysis history to persist for audit
--          rather than CASCADE-vanish.
--       2. The components table is itself tenant-scoped under RLS;
--          a FOREIGN KEY check from a different tenant context would
--          trip on its own policy. Leaving the FK off keeps the
--          insert path uncomplicated.
--     ※要確認: M2 may want a soft-cleanup job that reaps orphan
--     reachability rows whose project_id / component_id no longer
--     exist. Tracking separately.
-- ============================================

CREATE TABLE reachability_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenancy. NOT NULL so RLS WITH CHECK has something to compare,
    -- ON DELETE CASCADE so tenant teardown reaps the rows.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Soft references (no FK -- see header). NOT NULL because a
    -- verdict that does not name its target is meaningless.
    project_id   UUID NOT NULL,
    component_id UUID NOT NULL,

    -- Advisory identifier (matches advisory_excerpts.cve_id /
    -- llm_calls.triage_target_cve conventions).
    cve_id VARCHAR(30) NOT NULL,

    -- Ecosystem this verdict applies to. Nullable -- see header.
    ecosystem VARCHAR(20),

    -- Verdict. CHECK-constrained to the four states the analyser
    -- contract defines today.
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('not_present', 'import_only', 'reachable', 'unknown')),

    -- Analyser-specific evidence (callgraph nodes, import-tree slices,
    -- heuristic explanation). JSONB object shape, default {} so a
    -- partial write stays well-formed.
    evidence JSONB NOT NULL DEFAULT '{}'::JSONB,

    -- Calibrated confidence in [0.00, 1.00]; below the per-tenant
    -- threshold the triage stage forces under_investigation
    -- (cross-cutting issue #29).
    confidence NUMERIC(3, 2)
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),

    -- Analyser identification + analysis timestamp.
    analyzer_version VARCHAR(20),
    analyzed_at      TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One verdict per (tenant, project, component, cve). Upserts
    -- target this constraint.
    CONSTRAINT reachability_results_tenant_project_component_cve_uniq
        UNIQUE (tenant_id, project_id, component_id, cve_id)
);

-- "Give me every component's reachability for CVE X in project P" --
-- the dominant triage-prompt builder lookup. Named per AC.
CREATE INDEX idx_reachability_project_cve
    ON reachability_results (tenant_id, project_id, cve_id);

-- "What verdicts do we have for this component across CVEs" -- the
-- per-component drill-down UI uses this shape.
CREATE INDEX idx_reachability_component
    ON reachability_results (tenant_id, component_id);

-- RLS: tenant_isolation. Same shape as 032_llm_calls /
-- 033_advisory_excerpts: FORCE + WITH CHECK + missing_ok GUC read.
ALTER TABLE reachability_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE reachability_results FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_reachability_results ON reachability_results
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON TABLE reachability_results IS
    'Reachability analyser verdicts (PRODUCT_REBOOT_PLAN.md §8.1, '
    'issue #26). One row per (tenant_id, project_id, component_id, '
    'cve_id); referenced by vex_drafts as one of the two evidence '
    'pointers (the other being advisory_excerpts.id). RLS is ENABLE + '
    'FORCE with WITH CHECK so foreign-tenant INSERTs are rejected and '
    'migrator/owner connections do not bypass tenant scope.';
