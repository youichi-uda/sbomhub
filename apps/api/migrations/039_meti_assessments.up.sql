-- ============================================
-- METI self-assessment persisted store (M3 Wave M3-1)
--
-- Source of truth:
--   * sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §13 M3 / §7.3
--     ("M3 -- METI self-assessment prefill")
--   * 経済産業省「ソフトウェア管理に向けた SBOM の導入に関する手引 ver 2.0」
--     (2024-08 公表) -- https://www.meti.go.jp/policy/netsecurity/wg1/SBOMv2.pdf
--   * Issue: youichi-uda/sbomhub#41 (M3 Wave M3-1).
--
-- Purpose:
--   Persisted store of the METI self-assessment evaluator's verdict per
--   (tenant, project, criterion). The evaluator (M3-2 / issue #40) walks
--   the criteria catalog (M3-3 / issue #39) for a project, inspects the
--   tenant's CI configs, SBOM history, and matching history, and writes
--   one row per criterion with status + evidence pointers. The UI
--   (M3-5 / issue #38) renders the resulting status matrix and exposes
--   a per-criterion override affordance for items where the operator
--   disagrees with the auto-verdict (e.g. "the evaluator marked this as
--   not_achieved but we use Renovate which is functionally equivalent").
--
--   Two layers of state per criterion:
--     1. (status, evidence, evaluator_version, evaluated_at) -- written
--        by the evaluator, immutable from the operator's point of view.
--        Re-evaluation overwrites these via Upsert ON CONFLICT.
--     2. (override_status, override_by, override_at, override_note,
--        improvement_action) -- written by the operator through the
--        /meti/assessment/:criterion_id/override handler (M3-4 / #37).
--        Override never mutates the evaluator's record so the audit
--        trail keeps "what the system thought" vs "what the operator
--        decided" separable for METI auditors.
--
-- Tenancy:
--   tenant_id is NOT NULL + RLS-enforced from day one. A METI
--   assessment leak across tenants would disclose the manufacturer's
--   self-reported compliance posture (which criteria they DO NOT meet)
--   -- directly competitive-intelligence sensitive and a regulator-
--   facing artefact under the METI 手引 ver 2.0 framework. Same RLS
--   posture as vex_drafts (035) / cra_reports (038).
--
-- RLS model (matches 032 / 033 / 034 / 035 / 037 / 038 hardened
-- convention):
--   * ENABLE + FORCE ROW LEVEL SECURITY (FORCE keeps the migrator /
--     owner connection from bypassing the policy during ad-hoc
--     maintenance).
--   * Single tenant_isolation_meti_assessments policy with FOR ALL,
--     USING + WITH CHECK both bound to
--     current_setting('app.current_tenant_id', true)::UUID. The
--     `true` second arg makes the GUC return '' when unset; the
--     cast to UUID then fails the predicate, so an unauthenticated
--     path gets zero rows / rejected INSERT instead of a SQL error.
--
-- Uniqueness:
--   UNIQUE(tenant_id, project_id, criterion_id) so re-evaluation can
--   ON CONFLICT-upsert without first checking for an existing row, and
--   so a project's per-criterion status matrix is canonical (one row
--   per criterion per project per tenant). The (tenant_id, project_id,
--   criterion_id) leading order also doubles as a lookup index for
--   Get / Upsert by composite key.
--
-- Index:
--   * idx_meti_assessments_project_phase (tenant_id, project_id,
--     criterion_phase) -- supports the dominant "give me every criterion
--     in phase X for project P" lookup the UI issues to render the
--     three-phase tabbed status matrix (env_setup / sbom_creation /
--     sbom_operation, per METI 手引 ver 2.0 §3-§5).
--
-- Storage shape decisions:
--   * criterion_id VARCHAR(50) -- the METI criterion identifier, e.g.
--     "ENV-SBOM-001". Catalog-driven (M3-3); kept as a free-form string
--     so a catalog addition does not require an enum migration. Length
--     50 leaves headroom over the current catalog's longest id while
--     still tripping accidental over-long writes at the column level.
--   * criterion_phase VARCHAR(30) CHECK-constrained to the three METI
--     手引 ver 2.0 phases ('env_setup' / 'sbom_creation' /
--     'sbom_operation'). VARCHAR(30) leaves room for a future "phase 4"
--     addition without column widening.
--   * status VARCHAR(20) CHECK-constrained to four lifecycle states
--     ('achieved' / 'not_achieved' / 'needs_review' / 'not_applicable').
--     DEFAULT 'needs_review' so a partially-seeded row (e.g. catalog
--     rev bump introduces a new criterion the evaluator does not yet
--     know how to score) lands in a clearly-untriaged bucket rather
--     than masquerading as achieved.
--   * evidence JSONB NOT NULL CHECK (jsonb_array_length(evidence) >= 0).
--     Note the `>= 0` (NOT `> 0`): unlike vex_drafts / cra_reports
--     where empty evidence means "AI output without grounding" and is
--     forbidden, METI assessments can legitimately produce
--     status='not_applicable' or status='needs_review' for criteria
--     the evaluator cannot inspect (e.g. SBOM not yet uploaded ->
--     SBOM-creation criteria are unevaluable). Those rows still need
--     evidence='[]' to be NOT NULL-compliant. The constraint pattern is
--     therefore "must be a JSON array" (length predicate trips on
--     non-arrays via jsonb_array_length raising) rather than "must be
--     non-empty". F4 regression-class guard variant: keep evidence
--     mandatory at the schema layer; relax only the non-emptiness.
--   * evaluator_version VARCHAR(20) -- semver string of the evaluator
--     that produced this row (e.g. "1.0.0"). Required for the audit
--     trail so a later re-evaluation that disagrees with an older
--     verdict can be attributed. Nullable for hand-seeded rows.
--   * evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW() -- when the
--     evaluator wrote this row. Re-evaluation overwrites this via
--     Upsert. NOT NULL because every row in this table represents a
--     point-in-time verdict.
--   * override_status VARCHAR(20) CHECK (override_status IS NULL OR
--     override_status IN (...)). Nullable -- NULL means "no override,
--     trust the evaluator's status". Set means "operator overrode the
--     evaluator". Same allow-list as status; an override of
--     'needs_review' is legitimate when an operator wants to flag a
--     criterion for follow-up. The OverrideStatus state-machine guard
--     (F31 pattern) lives at the repository layer: WHERE
--     override_status IS NULL to ensure re-override goes through an
--     explicit "clear override first, then re-override" path the
--     handler controls.
--   * override_by UUID -- the user who applied the override. Required
--     for audit (handler-layer enforced; the schema makes it nullable
--     because NULL is the "no override" state).
--   * override_at TIMESTAMPTZ -- when the override was applied.
--     Together with override_by + override_note this forms the audit-
--     log-shadow record on the row itself; audit_logs ALSO carries a
--     'meti_override' action row per the M3-4 (issue #37) handler spec.
--   * override_note TEXT -- operator's free-form reason for overriding.
--     Required for METI auditor review (handler-layer enforced).
--   * improvement_action TEXT -- operator-authored action plan for
--     criteria that are not yet achieved. Independent from override:
--     an operator can leave status='not_achieved' AS IS but still
--     record what they plan to do to remediate. The UI surfaces this
--     in the /meti/improvement-actions list (M3-4 endpoint).
--
-- Soft references:
--   project_id is NOT declared as a FOREIGN KEY. Same rationale as
--   vex_drafts / cra_reports: projects is tenant-scoped under RLS, so
--   a FK check from a different tenant context would trip on its own
--   policy, and we want assessment history to persist for audit even
--   if the parent project rows are later purged. tenant_id retains
--   its FK to tenants(id) ON DELETE CASCADE so tenant teardown still
--   reaps the rows.
--
-- Dual-recording in audit_logs:
--   The override handler (M3-4 / #37) writes one audit_logs row with
--   action='meti_override', resource_type='meti_assessment',
--   resource_id=<meti_assessments.id>. The evaluator (M3-2 / #40)
--   may also write a 'meti_evaluator_run' action per re-evaluation
--   sweep. No DB-side uniqueness on (resource_id, action) so both
--   coexist (same pattern as vex_drafts / cra_reports).
-- ============================================

CREATE TABLE meti_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenancy. NOT NULL so RLS WITH CHECK has something to compare,
    -- ON DELETE CASCADE so tenant teardown reaps the rows.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Soft reference (no FK -- see header). project_id is NOT NULL
    -- because a criterion verdict that does not name its project is
    -- meaningless.
    project_id UUID NOT NULL,

    -- METI criterion identifier (catalog-driven, M3-3 / #39).
    criterion_id VARCHAR(50) NOT NULL,

    -- METI 手引 ver 2.0 phase: env_setup (§3) / sbom_creation (§4) /
    -- sbom_operation (§5). CHECK-constrained allow-list.
    criterion_phase VARCHAR(30) NOT NULL
        CHECK (criterion_phase IN ('env_setup', 'sbom_creation', 'sbom_operation')),

    -- Evaluator verdict. DEFAULT 'needs_review' so a partially-seeded
    -- row lands in a clearly-untriaged bucket.
    status VARCHAR(20) NOT NULL DEFAULT 'needs_review'
        CHECK (status IN ('achieved', 'not_achieved', 'needs_review', 'not_applicable')),

    -- Evidence array. NOT NULL + CHECK length >= 0 (vs > 0 for
    -- vex_drafts / cra_reports). See header for rationale -- METI
    -- "not_applicable" / "needs_review" rows can legitimately have
    -- evidence='[]'. The constraint enforces "must be a JSON array";
    -- jsonb_array_length raises on non-arrays so the CHECK still
    -- catches scalar / object writes.
    evidence JSONB NOT NULL
        CHECK (evidence IS NOT NULL AND jsonb_array_length(evidence) >= 0),

    -- Evaluator provenance. Semver string of the evaluator that
    -- produced this row. Nullable for hand-seeded rows.
    evaluator_version VARCHAR(20),

    -- When the evaluator wrote this row. NOT NULL DEFAULT NOW() so the
    -- evaluator does not need to set it explicitly on every Upsert.
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Override layer. NULL = no override; set = operator overrode the
    -- evaluator's status. Same allow-list as status.
    override_status VARCHAR(20)
        CHECK (override_status IS NULL OR override_status IN ('achieved', 'not_achieved', 'needs_review', 'not_applicable')),
    override_by   UUID,
    override_at   TIMESTAMPTZ,
    override_note TEXT,

    -- Operator-authored remediation plan for not-yet-achieved criteria.
    -- Independent from override: an operator can leave status as-is
    -- and still record what they plan to do.
    improvement_action TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Canonical "one row per criterion per project per tenant"
    -- uniqueness. Drives ON CONFLICT in Upsert and doubles as a
    -- composite-key lookup index.
    UNIQUE (tenant_id, project_id, criterion_id)
);

-- "Give me every criterion in phase X for project P" -- the dominant
-- UI lookup that renders the three-phase tabbed status matrix.
-- Named per AC (issue #41).
CREATE INDEX idx_meti_assessments_project_phase
    ON meti_assessments (tenant_id, project_id, criterion_phase);

-- RLS: tenant_isolation. Same shape as 032 / 033 / 034 / 035 / 037 /
-- 038: FORCE + WITH CHECK + missing_ok GUC read, so an unauthenticated
-- session degrades to zero rows instead of crashing, and a foreign-
-- tenant INSERT is rejected at write time rather than merely hidden
-- at read time.
ALTER TABLE meti_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE meti_assessments FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_meti_assessments ON meti_assessments
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON TABLE meti_assessments IS
    'Persisted METI 手引 ver 2.0 self-assessment verdicts '
    '(PRODUCT_REBOOT_PLAN.md §13 M3, issue #41). One row per '
    '(tenant, project, criterion). Evidence is mandatory (NOT NULL) '
    'but may be empty for not_applicable / needs_review cases. RLS is '
    'ENABLE + FORCE with WITH CHECK so foreign-tenant INSERTs are '
    'rejected and migrator/owner connections do not bypass tenant scope.';

COMMENT ON COLUMN meti_assessments.evidence IS
    'JSONB array of {kind, ref} or {kind, value} evidence entries the '
    'evaluator gathered. NOT NULL + CHECK jsonb_array_length(...) >= 0 '
    'enforces "must be a JSON array" while permitting empty arrays for '
    'not_applicable / needs_review rows -- this is the explicit '
    'relaxation from the vex_drafts / cra_reports "> 0" rule (see '
    'migration header for rationale).';

COMMENT ON COLUMN meti_assessments.status IS
    'Evaluator verdict: achieved | not_achieved | needs_review | '
    'not_applicable. DEFAULT needs_review so a partially-seeded row '
    'lands in an untriaged bucket rather than masquerading as achieved.';

COMMENT ON COLUMN meti_assessments.override_status IS
    'Operator override of the evaluator verdict. NULL = no override. '
    'OverrideStatus state-machine guard at the repository layer uses '
    'WHERE override_status IS NULL so re-override goes through an '
    'explicit clear-first path the handler controls (M2 F31 pattern).';
