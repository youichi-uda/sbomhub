-- ============================================
-- VEX statement provenance (M27-A / F381, issue #132)
--
-- Source of truth:
--   * sbomhub-internal/planning/M27_KICKOFF_PROMPT.md (VEX apply Phase 2)
--   * Issue: youichi-uda/sbomhub#132 (M27 Wave A backend apply).
--
-- Purpose:
--   M26 (F375-F380) surfaced read-only cross-project VEX reuse
--   suggestions: an approved vex_statement in project A of tenant T is
--   offered to project B (same tenant) when B has a component affected
--   by the same vulnerability (purl match) or when A's judgement was
--   component-agnostic (vulnerability_only match). M27 lets a human
--   1-click confirm such a suggestion, which materialises a NEW
--   vex_statements row in the target project (B) via the same
--   VEXService.CreateStatement path the manual-authoring flow uses.
--
--   This table records the provenance of each reused decision: which
--   source statement (and source project) the target statement was
--   derived from, who applied it, and when. It powers:
--     1. audit / compliance reconstruction ("project B's not_affected
--        verdict for CVE-X on libfoo was reused from project A's
--        approved statement on <date> by <user>"), and
--     2. the M28+ UI affordance that annotates a reused statement with
--        "from project X".
--
--   The apply endpoint ALSO emits an audit_logs row
--   (action='vex_statement_reused_cross_project', resource_type='vex',
--   resource_id=<target vex_statements.id>) inside the SAME request
--   TenantTx. That audit row is the IMMUTABLE forensic record and is
--   deliberately independent of this table's row lifecycle (see the
--   ON DELETE note below): audit_logs survives even if the source or
--   target statement is later purged, whereas this table is the LIVE
--   attribution join the product UI reads.
--
-- Tenancy:
--   tenant_id is NOT NULL + RLS-enforced from day one. A provenance
--   leak across tenants would disclose that tenant T's project reused a
--   specific vulnerability verdict — competitive-intelligence sensitive
--   the same way vex_statements / cra_reports are. Same ENABLE + FORCE
--   + WITH CHECK convention as 038 (cra_reports) / 037 / 047.
--
-- ON DELETE policy (history-preservation reasoning, per the F381 brief):
--   * target_statement_id -> vex_statements(id) ON DELETE CASCADE. The
--     provenance row is an ATTRIBUTE of the target statement (it
--     describes THAT statement's origin); a provenance row for a
--     deleted target statement is dangling noise that would break the
--     UI join, so it is reaped with its owner.
--   * source_statement_id -> vex_statements(id) ON DELETE CASCADE and
--     source_project_id -> projects(id) ON DELETE CASCADE. The columns
--     are NOT NULL (pinned by the F381 spec), so ON DELETE SET NULL is
--     not available; CASCADE is the integrity-preserving choice for a
--     NOT NULL FK. History is NOT lost by this: the audit_logs row
--     emitted at apply time carries source_statement_id /
--     source_project_id in its Details JSON and is never cascaded, so
--     the immutable "who reused what from where, when" record survives
--     a later source deletion. This table intentionally holds only the
--     LIVE attribution (which disappears if the source disappears),
--     mirroring the existing cra_reports / audit_logs split.
--   * tenant_id -> tenants(id) ON DELETE CASCADE so tenant teardown
--     reaps the rows (matches cra_reports 038).
--
--   applied_by is a soft reference (no FK to users, nullable) — same
--   convention as cra_reports.created_by / decision_by, so tenant
--   teardown ordering never CASCADE-vanishes the row before the audit
--   trail is read, and a self-hosted request without a resolvable user
--   id still records the reuse.
--
-- Indexes:
--   * idx_vex_statement_provenance_target (tenant_id, target_statement_id)
--     — the dominant "show me where THIS statement was reused from"
--     lookup the M28+ provenance UI issues.
--   * idx_vex_statement_provenance_source (tenant_id, source_statement_id)
--     — the reverse "what target statements reused THIS source" sweep.
--
-- This is a brand-new table, so the RLS triple is inlined here (no
-- NOT VALID / partner-file dance needed).
-- ============================================

CREATE TABLE vex_statement_provenance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenancy. NOT NULL so RLS WITH CHECK has something to compare;
    -- ON DELETE CASCADE so tenant teardown reaps the rows.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The vex_statements row this provenance describes (the reused
    -- statement materialised in the target project). CASCADE: the row
    -- is meaningless without its target statement.
    target_statement_id UUID NOT NULL REFERENCES vex_statements(id) ON DELETE CASCADE,

    -- The cross-project source the target was derived from. CASCADE
    -- (NOT NULL pinned); the immutable copy lives in audit_logs.Details.
    source_statement_id UUID NOT NULL REFERENCES vex_statements(id) ON DELETE CASCADE,
    source_project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,

    -- Who applied the reuse (soft reference; NULL for self-hosted
    -- requests without a resolvable user id). No FK to users, matching
    -- the cra_reports.created_by / decision_by convention.
    applied_by UUID,

    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vex_statement_provenance_target
    ON vex_statement_provenance (tenant_id, target_statement_id);

CREATE INDEX idx_vex_statement_provenance_source
    ON vex_statement_provenance (tenant_id, source_statement_id);

-- RLS: tenant_isolation. Same shape as 038 (cra_reports) / 037 / 047:
-- FORCE + WITH CHECK + missing_ok GUC read, so an unauthenticated
-- session degrades to zero rows instead of crashing, and a foreign-
-- tenant INSERT is rejected at write time rather than merely hidden at
-- read time.
ALTER TABLE vex_statement_provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE vex_statement_provenance FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_vex_statement_provenance ON vex_statement_provenance
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON TABLE vex_statement_provenance IS
    'Provenance of cross-project VEX reuse (M27-A #132 / F381). One row '
    'per applied cross-project suggestion, linking the target '
    'vex_statements row to its source statement + source project. The '
    'immutable forensic record is the vex_statement_reused_cross_project '
    'audit_logs row emitted at apply time; this table is the LIVE '
    'attribution join (CASCADE-reaped if source/target is deleted). '
    'RLS is ENABLE + FORCE with WITH CHECK so foreign-tenant INSERTs are '
    'rejected and migrator/owner connections do not bypass tenant scope.';
