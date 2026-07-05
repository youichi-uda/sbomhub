-- ============================================
-- CRA submissions (M33 Wave A / F418, issue M33-A)
--
-- Source of truth:
--   * sbomhub-internal/planning/M33_KICKOFF_PROMPT.md (Wave A — data layer)
--   * PRODUCT_REBOOT_PLAN.md §13 M2 core principle
--     "No auto-submitted CRA reports".
--
-- Purpose:
--   Migration 038 (cra_reports header, :22-35 / :88-91) explicitly
--   RESERVED this table: it split cra_reports (AI drafts + human
--   decisions) from "a future cra_submissions table (records of what
--   was actually submitted when, to which authority)" and left the
--   `state='submitted'` transition to "a separate human action
--   (manual submission-record)". M33 implements that reservation.
--
--   CRA (EU Cyber Resilience Act) Art.14 requires a reporting timeline
--   per incident: a 24h early warning, a 72h detailed notification,
--   and a final report -- plus corrections. SBOMHub drafts those reports
--   (cra_reports) and a human approves them, but there was no central
--   artefact recording the fact that a human ACTUALLY submitted an
--   approved report to an authority: when, to whom, and under which
--   reference number. This table is that ledger. It is the last-mile of
--   "AI drafts, humans approve" -- the step AFTER approve: "human
--   attests they submitted".
--
--   The product NEVER auto-submits (PRODUCT_REBOOT_PLAN.md core
--   principle). A cra_submissions row is a HUMAN-ATTESTED record that a
--   submission happened, not an outbound send. `submitted_at` is the
--   time the operator attests, not a wall-clock the system stamps on a
--   network call.
--
-- Append-only event log (NO uniqueness constraint, by design):
--   One incident produces MANY submissions over its lifetime -- the
--   Art.14 timeline (early_warning -> detailed_notification ->
--   final_report) plus post-hoc corrections / re-submissions. There is
--   therefore deliberately NO unique constraint on
--   (tenant_id, cra_report_id) or any subset: each row is one event in
--   an append-only timeline for a report. ListByReport orders by
--   submitted_at DESC to render that timeline. The Record path also
--   flips cra_reports.state -> 'submitted' (approved reports only), which
--   is idempotent across repeat submissions.
--
-- Tenancy:
--   tenant_id is NOT NULL + RLS-enforced from day one. A submission-
--   record leak across tenants would disclose that tenant T submitted a
--   specific vulnerability report to a named authority under a specific
--   reference number -- directly competitive-intelligence sensitive the
--   same way cra_reports / vex_statements are (it reveals the
--   operator's incident timeline and regulatory posture). Same
--   ENABLE + FORCE + WITH CHECK convention as 038 (cra_reports) /
--   052 (vex_statement_provenance).
--
-- Foreign keys:
--   * cra_report_id -> cra_reports(id) ON DELETE CASCADE. A single-
--     column FK is available because cra_reports.id is a single-column
--     PRIMARY KEY (038:170). A composite (tenant_id, id) FK is NOT
--     available: cra_reports carries no UNIQUE(tenant_id, id) constraint.
--     This mirrors 052, which references the RLS-protected
--     vex_statements(id) with a single-column FK; the FK check runs
--     inside the same per-request tenant tx, so the parent row is
--     visible under RLS.
--   * tenant_id -> tenants(id) ON DELETE CASCADE so tenant teardown
--     reaps the rows (matches cra_reports 038 / 052).
--
--   submitted_by is a SOFT reference (no FK to users, nullable) -- same
--   convention as cra_reports.created_by / decision_by. A self-hosted
--   request without a resolvable user id still records the submission,
--   and tenant-teardown ordering never CASCADE-vanishes the row before
--   the audit trail is read.
--
-- ON DELETE rationale (history-preservation):
--   The Record endpoint (Wave B) emits, inside the SAME request
--   TenantTx, an audit_logs row (action='cra_submission_recorded',
--   resource_type='cra_submission', resource_id=<cra_submissions.id>).
--   That audit row is the IMMUTABLE forensic copy of the submission
--   event and is deliberately independent of this table's row lifecycle:
--   it is NEVER cascaded. If the parent cra_report (and with it this
--   submission row) is later deleted, the "who submitted what, to which
--   authority, when" record survives in audit_logs. This table holds
--   only the LIVE ledger the product UI (submission timeline) reads,
--   mirroring the existing cra_reports / audit_logs and 052 split.
--
-- Deadline / on-time judgement is intentionally NOT stored here:
--   awareness_time is not persisted on cra_reports (it only flows into
--   the rendered template prose), so a derived deadline_at column would
--   be stale + unsourced. Only the human-attested submitted_at is
--   recorded; Art.14 24h/72h on-time computation is deferred to a later
--   milestone (or captured free-form in `notes`).
--
-- authority is free text (VARCHAR(255), no enum / CHECK): the ENISA
--   single reporting platform and the national CSIRT list are not yet
--   finalised, so an allow-list would be premature -- same free-form
--   rationale as cra_reports.provider / model.
--
-- Indexes:
--   * idx_cra_submissions_report (tenant_id, cra_report_id) -- the
--     dominant "show me this report's submission timeline" lookup.
--   * idx_cra_submissions_submitted_at (tenant_id, submitted_at DESC) --
--     the tenant-wide submission ledger / most-recent-first sweep.
--
-- This is a brand-new table, so the RLS triple is inlined here (no
-- NOT VALID / partner-file dance needed).
-- ============================================

CREATE TABLE cra_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenancy. NOT NULL so RLS WITH CHECK has something to compare;
    -- ON DELETE CASCADE so tenant teardown reaps the rows.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The approved cra_reports row this submission attests to. Single-
    -- column FK (cra_reports.id is a single-column PK); CASCADE so a
    -- deleted report reaps its submission ledger (the immutable copy
    -- lives in the cra_submission_recorded audit_logs row).
    cra_report_id UUID NOT NULL REFERENCES cra_reports(id) ON DELETE CASCADE,

    -- The authority the report was submitted to. Free text: the
    -- reporting platform / national CSIRT list is not yet finalised.
    authority VARCHAR(255) NOT NULL,

    -- Human-attested submission time. NOT NULL. This is the time the
    -- operator asserts they submitted, not a system-stamped send time
    -- (the product never auto-submits).
    submitted_at TIMESTAMPTZ NOT NULL,

    -- Who recorded the submission (soft reference; NULL for self-hosted
    -- requests without a resolvable user id). No FK to users, matching
    -- the cra_reports.created_by / decision_by convention.
    submitted_by UUID,

    -- Optional authority-issued acknowledgement / tracking number.
    reference_number VARCHAR(255),

    -- Optional operator free-text (e.g. which Art.14 milestone this
    -- covers, or a correction note).
    notes TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cra_submissions_report
    ON cra_submissions (tenant_id, cra_report_id);

CREATE INDEX idx_cra_submissions_submitted_at
    ON cra_submissions (tenant_id, submitted_at DESC);

-- RLS: tenant_isolation. Same shape as 038 (cra_reports) / 052
-- (vex_statement_provenance): FORCE + WITH CHECK + missing_ok GUC read,
-- so an unauthenticated session degrades to zero rows instead of
-- crashing, and a foreign-tenant INSERT is rejected at write time
-- rather than merely hidden at read time. The tenant_isolation_<table>
-- policy name is the project-wide convention the lint-migration-rls
-- gate requires.
ALTER TABLE cra_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cra_submissions FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_cra_submissions ON cra_submissions
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON TABLE cra_submissions IS
    'Human-attested CRA (Art.14) submission ledger (M33-A / F418). One '
    'append-only row per submission event for an approved cra_reports '
    'row (24h/72h/final timeline + corrections; deliberately no '
    'uniqueness constraint). The immutable forensic record is the '
    'cra_submission_recorded audit_logs row emitted at record time; this '
    'table is the LIVE timeline the product UI reads (CASCADE-reaped if '
    'the parent report is deleted). The product never auto-submits: '
    'submitted_at is human-attested. RLS is ENABLE + FORCE with WITH '
    'CHECK so foreign-tenant INSERTs are rejected and migrator/owner '
    'connections do not bypass tenant scope.';
