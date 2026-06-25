-- ============================================
-- CRA reports (M2 Wave M2-2, CRA report drafting MVP central artefact)
--
-- Source of truth:
--   * sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §13 M2 / §6.1
--   * Issue: youichi-uda/sbomhub#35 (M2 Wave M2-2).
--
-- Purpose:
--   AI-generated CRA (EU Cyber Resilience Act) report drafts live here
--   until a human operator approves them. The CRA report runner
--   (#31 / M2-3) reads an approved vex_drafts row, renders the chosen
--   24h "early_warning" / 72h "detailed_notification" / "final_report"
--   template (#33 / M2-1) in the requested language, and writes one
--   cra_reports row per (project, cve, report_type, lang) it processes.
--   The /cra/reports UI later flips `decision` from 'pending' to
--   'approved' / 'edited' / 'rejected' and records who decided and
--   when. An approved report is what the operator submits to the
--   authority (manually -- the product never auto-submits per
--   PRODUCT_REBOOT_PLAN.md core principle "No auto-submitted CRA
--   reports").
--
--   The split between `cra_reports` (drafts + decisions) and a future
--   `cra_submissions` table (records of what was actually submitted
--   when, to which authority) keeps three invariants:
--     1. We never auto-submit. A row in cra_reports with
--        decision='approved' is read-only evidence the human OKed the
--        text; the act of submission is a separate event recorded by
--        the operator.
--     2. AI drafts have evidence + model fingerprint captured at write
--        time so the audit trail can be reconstructed years later.
--     3. The same vex_drafts row can feed multiple report variants
--        (24h ja + 24h en + 72h ja + ...), so we key on
--        (project_id, vulnerability_id, report_type, lang) rather than
--        on vex_drafts.id alone -- the source_vex_draft_id column is a
--        soft pointer back, not a uniqueness anchor.
--
-- The "no AI output without evidence" rule (PRODUCT_REBOOT_PLAN.md
-- §8.5) is enforced at the SCHEMA layer here, not at the application
-- layer: `evidence` is NOT NULL and the CHECK constraint requires
-- jsonb_array_length(evidence) > 0. Same regression-class guard as
-- vex_drafts (migration 035) and the M1 F4 discipline that turned
-- "service forgets to attach evidence" into a constraint violation
-- rather than a silent landing.
--
-- Tenancy:
--   tenant_id is NOT NULL + RLS-enforced from day one. A CRA report
--   leak across tenants would disclose both the vulnerability surface
--   AND the draft text that names the operator's product, supplier
--   chain, and remediation timeline -- all directly competitive-
--   intelligence sensitive for the manufacturer ICP. The leak shape is
--   strictly worse than vex_drafts leak because the report text is
--   already authority-facing prose.
--
-- RLS model (matches 032 / 033 / 034 / 035 / 037 hardened convention):
--   * ENABLE + FORCE ROW LEVEL SECURITY (FORCE keeps the migrator /
--     owner connection from bypassing the policy during ad-hoc
--     maintenance).
--   * Single tenant_isolation_cra_reports policy with FOR ALL,
--     USING + WITH CHECK both bound to
--     current_setting('app.current_tenant_id', true)::UUID. The
--     `true` second arg makes the GUC return '' when unset; the
--     cast to UUID then fails the predicate, so an unauthenticated
--     path gets zero rows / rejected INSERT instead of a SQL error.
--
-- Indexes:
--   * idx_cra_reports_project_cve (tenant_id, project_id, cve_id) --
--     supports the dominant "give me every report variant for CVE X
--     in project P" lookup the /cra/reports UI issues to render a
--     CVE-grouped queue.
--   * idx_cra_reports_decision (tenant_id, decision) -- supports the
--     "give me everything still pending" sweep the triage queue
--     opens on, and the per-decision analytics (approval rate,
--     rejection rate by tenant). Named per AC.
--
-- Storage shape decisions:
--   * report_type VARCHAR(20) CHECK-constrained to the three CRA
--     reporting milestones the design supports today (early_warning =
--     24h, detailed_notification = 72h, final_report = post-mitigation).
--     A future addition (e.g. "interim_update") lands as ALTER ... DROP
--     / ADD CONSTRAINT, not a full enum migration.
--   * lang CHAR(2) CHECK-constrained to ('ja', 'en'). CHAR(2) (not
--     VARCHAR) so an accidental 3+ char land is rejected at write time
--     by length rather than only by the CHECK. Two languages match
--     templates (#33 / M2-1) M2 scope; further languages are out of
--     scope for M2 (PRODUCT_REBOOT_PLAN.md §13 M2).
--   * state VARCHAR(20) CHECK-constrained to
--     (draft / approved / submitted / archived). DEFAULT 'draft' so
--     the runner does not have to remember to set it. `submitted` is
--     written by the (manual) submission-record action; `archived` is
--     for superseded reports the operator wants to keep for audit but
--     hide from the active queue.
--     ※要確認: should 'submitted' transition be guarded against
--     decision != 'approved' at the DB layer? Currently a CHECK can
--     express this but at the cost of locking the workflow into a
--     specific transition order. Sticking with application-layer
--     guard for M2 (handler / runner will enforce).
--   * draft_text TEXT NOT NULL -- the rendered report body. NOT NULL
--     because an empty report would defeat the purpose of the row;
--     even a sparse "we are still investigating" draft has prose.
--   * provider VARCHAR(20) / model VARCHAR(100) match
--     llm_calls.provider / llm_calls.model / vex_drafts.provider /
--     vex_drafts.model conventions. Free-form strings -- no schema
--     CHECK -- so a new BYOK provider does not require a migration.
--     Nullable for the hand-authored case (operator drafted the
--     report directly in the UI without LLM assistance).
--   * prompt_hash / response_hash CHAR(64) -- SHA-256 hex of the
--     full prompt / response payload that produced this draft.
--     Match the llm_calls hash columns so cross-table joins work.
--     Nullable for hand-authored drafts.
--   * evidence JSONB NOT NULL with the CHECK constraint
--     `jsonb_array_length(evidence) > 0` is the load-bearing
--     "no AI output without evidence" enforcement. Shape: an array
--     of {kind, ref} objects, e.g.
--     [{"kind":"vex_draft","ref":"<uuid>"},
--      {"kind":"advisory_excerpt","ref":"<uuid>"},
--      {"kind":"template","ref":"early_warning_ja"}].
--     The dedicated source_vex_draft_id / llm_call_id columns below
--     carry the primary FK pointers; the JSONB array is where the
--     runner records the full citation chain the UI surfaces
--     alongside the draft (incl. which template was used).
--   * source_vex_draft_id UUID FK to vex_drafts(id) ON DELETE SET
--     NULL. The CRA report runner pulls the approved VEX context as
--     part of generation; SET NULL preserves the report if the
--     upstream draft is later purged.
--   * llm_call_id UUID FK to llm_calls(id) ON DELETE SET NULL. Same
--     rationale as vex_drafts.llm_call_id.
--   * decision VARCHAR(20) CHECK-constrained to the four lifecycle
--     states (pending / approved / edited / rejected). decision_by /
--     decision_at / decision_note populate when the human acts.
--     decision defaults to 'pending' so the runner does not have to
--     remember to set it.
--     ※要確認: `state` and `decision` overlap conceptually -- state
--     covers the publication lifecycle (draft -> approved -> submitted
--     -> archived), decision covers the human approval lifecycle
--     (pending -> approved | edited | rejected). They are separate
--     columns so an `edited` decision can still leave state='draft'
--     (operator tweaked the text but has not greenlit publication).
--     A future schema cleanup may collapse them; M2 keeps both per
--     the issue #35 spec.
--   * created_by UUID -- the user who triggered the report run, or
--     NULL for background / scheduled runs. No FK to users(id) to
--     match the soft-reference convention from vex_drafts.created_by
--     and to keep tenant teardown from CASCADE-vanishing the report
--     before it has been reviewed.
--
-- Soft references:
--   project_id / vulnerability_id are NOT declared as FOREIGN KEYs.
--   Same rationale as vex_drafts: those parent tables are tenant-
--   scoped under RLS, so a FK check from a different tenant context
--   would trip on its own policy, and we want report history to
--   persist for audit even if the parent rows are later purged.
--   ※要確認: M2-6 (Evidence Pack bundle, issue #34) may want a soft-
--   cleanup job that reaps orphan cra_reports rows whose project_id
--   no longer exists. Tracking separately.
--
-- Dual-recording in audit_logs:
--   The runner writes one audit_logs row with
--   action='cra_report_ai_generated', resource_type='cra_report',
--   resource_id=<cra_reports.id>; the /cra/reports decision handler
--   writes a SECOND row with action='cra_report_approved' /
--   'cra_report_edited' / 'cra_report_rejected' on the same
--   resource_id. The two-row pattern is enforced by handler/service
--   code (M2-3 / M2-4), not by a schema constraint -- audit_logs has
--   no DB-side uniqueness on (resource_id, action) so the AI-generated
--   and human-decision events can both land. Same pattern as #27
--   established for vex_drafts.
-- ============================================

CREATE TABLE cra_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenancy. NOT NULL so RLS WITH CHECK has something to compare,
    -- ON DELETE CASCADE so tenant teardown reaps the rows.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Soft references (no FK -- see header). project_id /
    -- vulnerability_id are NOT NULL because a report that does not
    -- name its target is meaningless.
    project_id       UUID NOT NULL,
    vulnerability_id UUID NOT NULL,

    -- Advisory identifier. CVE-YYYY-NNNN(NNN) is the canonical form;
    -- VARCHAR(30) matches vex_drafts.cve_id / llm_calls.triage_target_cve.
    -- ※要確認: issue #35 spec did not include NOT NULL on cve_id.
    -- Made NOT NULL here for index efficiency
    -- (idx_cra_reports_project_cve includes cve_id) and because every
    -- M2 report variant the runner emits IS tied to a specific CVE
    -- (the LLM context is rendered from advisory_excerpts +
    -- vex_drafts which both require cve_id). If a future non-CVE CRA
    -- report case appears (e.g. a "vendor disclosure with no CVE
    -- assignment yet"), this constraint can be dropped via ALTER
    -- TABLE without data migration.
    cve_id VARCHAR(30) NOT NULL,

    -- CRA reporting milestone. CHECK-constrained to the three
    -- recognised stages (see header). VARCHAR(20) leaves room for a
    -- future "interim_update" without column widening.
    report_type VARCHAR(20) NOT NULL
        CHECK (report_type IN ('early_warning', 'detailed_notification', 'final_report')),

    -- Language. CHAR(2) so length itself is a guard; CHECK pins the
    -- two languages M2 templates ship in (#33 / M2-1).
    lang CHAR(2) NOT NULL
        CHECK (lang IN ('ja', 'en')),

    -- Publication lifecycle (separate axis from decision -- see
    -- header). DEFAULT 'draft' so the runner does not have to set it.
    state VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft', 'approved', 'submitted', 'archived')),

    -- Rendered report body. NOT NULL -- an empty CRA report is not a
    -- meaningful artefact.
    draft_text TEXT NOT NULL,

    -- LLM provenance. Free-form strings -- no CHECK -- so a new BYOK
    -- provider does not require a migration. NULL for hand-authored
    -- drafts.
    provider      VARCHAR(20),
    model         VARCHAR(100),
    prompt_hash   CHAR(64),
    response_hash CHAR(64),

    -- Evidence array. NOT NULL + CHECK length > 0 is the load-bearing
    -- "no AI output without evidence" enforcement
    -- (PRODUCT_REBOOT_PLAN.md §8.5, M1 F4 regression-class guard).
    evidence JSONB NOT NULL
        CHECK (evidence IS NOT NULL AND jsonb_array_length(evidence) > 0),

    -- Primary evidence pointers. FK + ON DELETE SET NULL preserves
    -- the report if upstream evidence is later replaced or the parent
    -- vex_drafts row is purged.
    source_vex_draft_id UUID REFERENCES vex_drafts(id) ON DELETE SET NULL,
    llm_call_id         UUID REFERENCES llm_calls(id) ON DELETE SET NULL,

    -- Human decision lifecycle (separate from `state`).
    decision VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (decision IN ('pending', 'approved', 'edited', 'rejected')),
    decision_by   UUID,
    decision_at   TIMESTAMPTZ,
    decision_note TEXT,

    -- Who triggered the report run (NULL for background / scheduled
    -- runs). Soft reference; see header.
    created_by UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- "Give me every report variant for CVE X in project P" -- the
-- dominant /cra/reports UI lookup. Named per AC (issue #35).
CREATE INDEX idx_cra_reports_project_cve
    ON cra_reports (tenant_id, project_id, cve_id);

-- "Give me everything still pending" sweep + per-decision analytics.
-- Named per AC (issue #35).
CREATE INDEX idx_cra_reports_decision
    ON cra_reports (tenant_id, decision);

-- RLS: tenant_isolation. Same shape as 032 / 033 / 034 / 035 / 037:
-- FORCE + WITH CHECK + missing_ok GUC read, so an unauthenticated
-- session degrades to zero rows instead of crashing, and a foreign-
-- tenant INSERT is rejected at write time rather than merely hidden
-- at read time.
ALTER TABLE cra_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE cra_reports FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_cra_reports ON cra_reports
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON TABLE cra_reports IS
    'AI-generated CRA report drafts pending human approval '
    '(PRODUCT_REBOOT_PLAN.md §13 M2, issue #35). Evidence is mandatory '
    '(NOT NULL + jsonb_array_length > 0). No auto-submission -- '
    'state=''submitted'' is a separate human action. RLS is ENABLE '
    '+ FORCE with WITH CHECK so foreign-tenant INSERTs are rejected '
    'and migrator/owner connections do not bypass tenant scope.';

COMMENT ON COLUMN cra_reports.evidence IS
    'JSONB array of {kind, ref} citations. NOT NULL + jsonb_array_length > 0 '
    'enforces the "no AI output without evidence" rule (PRODUCT_REBOOT_PLAN.md '
    '§8.5). Primary pointers (source_vex_draft_id, llm_call_id) live in their '
    'own columns; this array carries the full citation chain (incl. which '
    'template was used) for the UI.';

COMMENT ON COLUMN cra_reports.decision IS
    'Human decision lifecycle: pending (default) -> approved | edited | rejected. '
    'The decision transition emits a second audit_logs row alongside the '
    'original cra_report_ai_generated row (no DB uniqueness on '
    '(resource_id, action) so both can coexist). Independent from `state` '
    '(publication lifecycle).';

COMMENT ON COLUMN cra_reports.state IS
    'Publication lifecycle: draft (default) -> approved -> submitted -> archived. '
    'Independent from `decision` (human approval lifecycle); a decision=edited '
    'report can still have state=draft while the operator tweaks the text.';
