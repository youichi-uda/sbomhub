-- ============================================
-- VEX drafts (M1 Wave M1-5, AI VEX MVP central artefact)
--
-- Source of truth: sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §8.5
-- Issue: youichi-uda/sbomhub#27 (M1 Wave M1-5).
--
-- Purpose:
--   AI-generated VEX statements live here in draft form until a human
--   operator approves them. The triage runner (#28 / M1-4) writes one
--   row per (project, component, cve) it processes, populating the
--   AI fields (state / justification / detail / confidence /
--   provider / model / prompt_hash / response_hash / evidence) and
--   the soft pointers to the audit evidence (advisory_excerpt_id,
--   reachability_result_id, llm_call_id). The /vex/drafts UI later
--   flips `decision` from 'pending' to 'approved' / 'edited' /
--   'rejected' and records who decided and when. The approved subset
--   is later promoted into the confirmed `vex_statements` table
--   (migration 003) for CycloneDX export.
--
--   The split between `vex_drafts` (AI output / pending human review)
--   and `vex_statements` (human-approved, exportable) keeps two
--   invariants:
--     1. We never auto-confirm `not_affected` (core principle from
--        sbomhub/CLAUDE.md). A row in vex_statements is by definition
--        human-approved; a row in vex_drafts is by definition not yet
--        approved (or has been explicitly rejected/edited).
--     2. AI drafts have evidence + confidence + model fingerprint
--        captured at write time; vex_statements would otherwise have
--        to carry those columns even for hand-authored statements
--        that never went through the LLM path.
--
-- The "no AI output without evidence" rule (PRODUCT_REBOOT_PLAN.md
-- §8.5) is enforced at the SCHEMA layer here, not at the application
-- layer: `evidence` is NOT NULL and the CHECK constraint requires
-- jsonb_array_length(evidence) > 0. A future agent that forgets to
-- attach evidence cannot silently land draft rows.
--
-- Tenancy:
--   tenant_id is NOT NULL + RLS-enforced from day one. A draft leak
--   across tenants would disclose both the vulnerability surface
--   (which CVEs the analyser flagged on which components) and the
--   AI's draft text, both of which are competitive-intelligence
--   sensitive for the manufacturer ICP.
--
-- RLS model:
--   * ENABLE + FORCE ROW LEVEL SECURITY (matches 032 / 033 / 034
--     hardened pattern: FORCE keeps migrator/owner connections from
--     bypassing the policy during ad-hoc maintenance).
--   * Single tenant_isolation_vex_drafts policy with USING + WITH
--     CHECK bound to
--     `current_setting('app.current_tenant_id', true)::UUID`. The
--     missing_ok `true` second arg makes the GUC return '' when
--     unset; the cast to UUID then fails the predicate, so
--     unauthenticated paths get zero rows / rejected INSERTs rather
--     than a SQL error.
--
-- Indexes:
--   * idx_vex_drafts_project_cve (tenant_id, project_id, cve_id) --
--     supports the dominant lookup "give me every component's draft
--     for CVE X in project P" that the /vex/drafts triage queue UI
--     issues.
--   * idx_vex_drafts_decision (tenant_id, decision) -- supports the
--     "give me everything still pending" sweep the triage queue
--     opens on, and the per-decision analytics (approval rate,
--     rejection rate by tenant).
--
-- Storage shape decisions:
--   * state VARCHAR(20) CHECK-constrained to the four CycloneDX VEX
--     states the design supports today
--     (not_affected / affected / under_investigation / resolved).
--     A future state lands as ALTER ... DROP / ADD CONSTRAINT, not
--     a full enum migration. The under_investigation state is also
--     the forced fallback when the LLM's confidence is below the
--     per-tenant triage threshold (cross-cutting issue #29).
--   * justification VARCHAR(40) -- nullable because under_investigation
--     and affected draft states often have no CycloneDX-compatible
--     justification to record yet. CycloneDX justifications
--     ("code_not_present", "code_not_reachable", etc.) max out at
--     ~30 chars; 40 leaves headroom for vendor extensions.
--     ※要確認: should we CHECK-constrain this to the CycloneDX
--     enum? Design doc does not pin the set. Leaving open for now.
--   * detail TEXT -- free-form human-readable explanation the LLM
--     drafts. Nullable so a deterministic verdict (e.g.
--     reachability=not_present with confidence=1.0) can land with
--     no extra prose.
--   * confidence NUMERIC(3,2) covers [0.00, 1.00]; CHECK pins the
--     range so a buggy provider cannot record 1.5 or -0.2 and
--     silently break the triage threshold. Nullable for the case
--     where a draft is hand-authored by a human (draft seeded from
--     the UI; provider is then NULL too).
--   * provider VARCHAR(20) / model VARCHAR(100) match
--     llm_calls.provider / llm_calls.model conventions. Free-form
--     strings -- no schema-level CHECK -- so adding a new BYOK
--     provider does not require a migration.
--   * prompt_hash / response_hash CHAR(64) -- SHA-256 hex of the
--     full prompt / response payload that produced this draft.
--     Match the llm_calls hash columns so cross-table joins work.
--     Nullable for hand-authored drafts.
--   * evidence JSONB NOT NULL with the CHECK constraint
--     `jsonb_array_length(evidence) > 0` is the load-bearing
--     "no AI output without evidence" enforcement. Shape: an array
--     of {kind, ref} objects (e.g. {"kind":"advisory_excerpt","ref":"<uuid>"},
--     {"kind":"reachability","ref":"<uuid>"}). The dedicated
--     advisory_excerpt_id / reachability_result_id / llm_call_id
--     columns below carry the primary pointers; the JSONB array is
--     where the analyser records the full citation chain (line
--     numbers in the advisory text, callgraph node ids, etc.) that
--     the UI surfaces alongside the draft.
--   * advisory_excerpt_id / reachability_result_id -- FK references
--     to the two evidence tables installed in 033 / 034. ON DELETE
--     SET NULL because the advisory parser or reachability analyser
--     may re-run and replace rows; we want the draft to keep
--     pointing at "we had evidence at draft time" rather than
--     CASCADE-vanish.
--   * llm_call_id -- FK reference to the llm_calls audit row that
--     produced this draft. ON DELETE SET NULL same rationale.
--   * decision VARCHAR(20) CHECK-constrained to the four lifecycle
--     states (pending / approved / edited / rejected). decision_by
--     / decision_at / decision_note populate when the human acts.
--     decision defaults to 'pending' so the triage runner does not
--     have to remember to set it.
--   * created_by UUID -- the user who triggered the triage run, or
--     NULL for background / scheduled runs. No FK to users(id) to
--     match the soft-reference convention from llm_calls.user_id
--     and to keep tenant deletion from CASCADE-vanishing the draft
--     before it has been reviewed.
--
-- Soft references:
--   project_id / component_id / vulnerability_id / sbom_id are NOT
--   declared as FOREIGN KEYs. Same rationale as
--   reachability_results: those parent tables are tenant-scoped
--   under RLS, so a FK check from a different tenant context would
--   trip on its own policy, and we want draft history to persist
--   for audit if the parent rows are later purged.
--   ※要確認: M2 may want a soft-cleanup job that reaps orphan
--   draft rows whose project_id / component_id no longer exist.
--   Tracking separately.
--
-- Dual-recording in audit_logs:
--   The "二重記録" requirement (issue #27 body) is satisfied by the
--   existing audit_logs (migration 007 + 029) without schema
--   changes here: the triage runner writes one audit_logs row with
--   action='vex_draft_ai_generated', resource_type='vex_draft',
--   resource_id=<vex_drafts.id>, and the /vex/drafts decision
--   handler writes a SECOND row with action='vex_draft_approved'
--   / 'vex_draft_edited' / 'vex_draft_rejected' on the same
--   resource_id. The two-row pattern is enforced by handler/service
--   code (agent B), not by a schema constraint -- audit_logs has
--   no DB-side uniqueness on (resource_id, action) precisely so
--   the AI-generated and human-decision events can both land.
-- ============================================

CREATE TABLE vex_drafts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenancy. NOT NULL so RLS WITH CHECK has something to compare,
    -- ON DELETE CASCADE so tenant teardown reaps the rows.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Soft references (no FK -- see header). project_id /
    -- component_id / vulnerability_id are NOT NULL because a draft
    -- that does not name its target is meaningless. sbom_id is
    -- nullable because the triage runner may operate on the latest
    -- SBOM for a project without recording which exact SBOM
    -- snapshot it used (the snapshot can be reconstructed from
    -- component_id -> sbom_id at read time).
    project_id        UUID NOT NULL,
    sbom_id           UUID,
    component_id      UUID NOT NULL,
    vulnerability_id  UUID NOT NULL,

    -- Advisory identifier. CVE-YYYY-NNNN(NNN) is the canonical form;
    -- VARCHAR(30) matches advisory_excerpts.cve_id /
    -- reachability_results.cve_id / llm_calls.triage_target_cve.
    cve_id VARCHAR(30) NOT NULL,

    -- AI / human VEX content fields.
    state VARCHAR(20) NOT NULL
        CHECK (state IN ('not_affected', 'affected', 'under_investigation', 'resolved')),
    justification VARCHAR(40),
    detail        TEXT,

    -- Calibrated confidence in [0.00, 1.00]; below the per-tenant
    -- triage threshold the runner forces state='under_investigation'
    -- (cross-cutting issue #29).
    confidence NUMERIC(3, 2)
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),

    -- LLM provenance. Free-form strings -- no CHECK -- so a new BYOK
    -- provider does not require a migration. NULL for hand-authored
    -- drafts.
    provider      VARCHAR(20),
    model         VARCHAR(100),
    prompt_hash   CHAR(64),
    response_hash CHAR(64),

    -- Evidence array. NOT NULL + CHECK length > 0 is the load-bearing
    -- "no AI output without evidence" enforcement
    -- (PRODUCT_REBOOT_PLAN.md §8.5). The application MAY include
    -- extra citation detail beyond the dedicated FK columns below.
    evidence JSONB NOT NULL
        CHECK (evidence IS NOT NULL AND jsonb_array_length(evidence) > 0),

    -- Primary evidence pointers. FK + ON DELETE SET NULL preserves
    -- the draft if upstream evidence is later replaced.
    advisory_excerpt_id    UUID REFERENCES advisory_excerpts(id)    ON DELETE SET NULL,
    reachability_result_id UUID REFERENCES reachability_results(id) ON DELETE SET NULL,
    llm_call_id            UUID REFERENCES llm_calls(id)            ON DELETE SET NULL,

    -- Human decision lifecycle.
    decision VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (decision IN ('pending', 'approved', 'edited', 'rejected')),
    decision_by   UUID,
    decision_at   TIMESTAMPTZ,
    decision_note TEXT,

    -- Who triggered the triage run (NULL for background / scheduled
    -- runs). Soft reference; see header.
    created_by UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- "Give me every component's draft for CVE X in project P" -- the
-- dominant triage queue UI lookup. Named per AC.
CREATE INDEX idx_vex_drafts_project_cve
    ON vex_drafts (tenant_id, project_id, cve_id);

-- "Give me everything still pending" sweep + per-decision analytics.
-- Named per AC.
CREATE INDEX idx_vex_drafts_decision
    ON vex_drafts (tenant_id, decision);

-- RLS: tenant_isolation. Same shape as 032 / 033 / 034: FORCE + WITH
-- CHECK + missing_ok GUC read, so an unauthenticated session degrades
-- to zero rows instead of crashing, and a foreign-tenant INSERT is
-- rejected at write time rather than merely hidden at read time.
ALTER TABLE vex_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE vex_drafts FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_vex_drafts ON vex_drafts
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON TABLE vex_drafts IS
    'AI-generated VEX drafts pending human approval (PRODUCT_REBOOT_PLAN.md '
    '§8.5, issue #27). Evidence is mandatory (NOT NULL + jsonb_array_length > 0). '
    'Promoted into vex_statements only after decision=approved. RLS is ENABLE '
    '+ FORCE with WITH CHECK so foreign-tenant INSERTs are rejected and '
    'migrator/owner connections do not bypass tenant scope.';

COMMENT ON COLUMN vex_drafts.evidence IS
    'JSONB array of {kind, ref} citations. NOT NULL + jsonb_array_length > 0 '
    'enforces the "no AI output without evidence" rule (PRODUCT_REBOOT_PLAN.md '
    '§8.5). Primary pointers (advisory_excerpt_id, reachability_result_id, '
    'llm_call_id) live in their own columns; this array carries the full '
    'citation chain for the UI.';

COMMENT ON COLUMN vex_drafts.decision IS
    'Human decision lifecycle: pending (default) -> approved | edited | rejected. '
    'The decision transition emits a second audit_logs row alongside the '
    'original vex_draft_ai_generated row (no DB uniqueness on '
    '(resource_id, action) so both can coexist).';
