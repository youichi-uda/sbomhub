-- ============================================
-- LLM call audit log (M1 / AI VEX MVP foundation)
--
-- Source of truth: sbomhub-internal/planning/LLM_PROVIDER_DESIGN.md §6.1
-- Issue: youichi-uda/sbomhub#20 (M1 Wave M1-1)
--
-- Purpose:
--   Every LLM Complete() / Embed() call performed by internal/service/llm/*
--   writes one row here. The row records who/what/when (tenant, user, model,
--   purpose), reproducibility material (prompt_hash, response_hash, optional
--   previews), and cost accounting (input/output tokens, USD). Operators use
--   this table to audit AI-drafted VEX statements and CRA reports, to detect
--   prompt-injection abuse, and to attribute spend per tenant.
--
-- RLS model:
--   * ENABLE + FORCE ROW LEVEL SECURITY (matches the post-023 hardened
--     pattern: the design-doc §6.1 sketch only enabled RLS, but every
--     tenant-scoped table touched by Trust Rescue 023 also carries FORCE +
--     WITH CHECK to keep migrator/owner connections from bypassing the
--     policy and to reject INSERTs that point at the wrong tenant).
--   * Single `tenant_isolation_llm_calls` policy with USING + WITH CHECK
--     both bound to `current_setting('app.current_tenant_id', true)::UUID`.
--     The `true` second arg (missing_ok) makes the GUC return '' instead of
--     erroring when unset; the cast to UUID then fails the predicate, so
--     unauthenticated paths get zero rows / rejected INSERTs rather than a
--     SQL error.
--   * audit_logs / api_keys / public_links each disabled RLS in 028/029/030
--     because their access patterns include a tenant-unscoped lookup. The
--     llm_calls table has no such requirement -- writes always happen
--     inside a tenant-scoped request -- so RLS stays on.
--
-- Indexes:
--   * idx_llm_calls_tenant_created -- the dominant read pattern is "show me
--     this tenant's recent LLM calls", served by an index-only scan on the
--     (tenant_id, created_at DESC) composite.
--   * idx_llm_calls_purpose -- supports "how many vex_triage calls did we
--     make this month?" analytics and per-purpose retention sweeps.
--
-- BYOK / OSS posture:
--   No vendor-specific columns. provider/model are free-form strings so
--   self-host operators can plug ollama, BYOK openai/anthropic/gemini, or
--   azure_openai without a schema migration. response_body is nullable and
--   only populated when SBOMHUB_LLM_AUDIT_STORE_RESPONSE=true (default
--   false in OSS to keep storage bounded).
-- ============================================

CREATE TABLE llm_calls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenancy / actor (NOT NULL tenant_id matches design-doc §6.1 and the
    -- AC of issue #20; nullable user_id covers background jobs / scheduled
    -- triage runs that have no authenticated end-user).
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id   UUID REFERENCES users(id) ON DELETE SET NULL,

    -- What this call was for. Enumerated in §6.1 as
    -- 'vex_triage' / 'cra_draft' / 'meti_prefill' / 'embed'. Kept as a
    -- VARCHAR(50) so new purposes (e.g. 'reachability_explain') can land
    -- without a migration. ※要確認: should this be a CHECK-constrained
    -- enum or a separate llm_call_purposes lookup? Design doc does not say.
    purpose VARCHAR(50) NOT NULL,

    -- Provider/model identifiers. Provider is the abstraction layer name
    -- ('openai' / 'anthropic' / 'gemini' / 'managed_gemini' / 'azure_openai'
    -- / 'ollama'); model is the concrete model id sent over the wire.
    provider VARCHAR(20)  NOT NULL,
    model    VARCHAR(100) NOT NULL,

    -- Reproducibility / tamper-evidence. Hashes are SHA-256 hex (64 chars)
    -- of the full prompt / response payload. Previews are first 500 chars
    -- for human debugging; they are optional and may be elided by config.
    prompt_hash      CHAR(64) NOT NULL,
    prompt_preview   TEXT,
    response_hash    CHAR(64) NOT NULL,
    response_preview TEXT,

    -- Full response body. Populated only when
    -- SBOMHUB_LLM_AUDIT_STORE_RESPONSE=true (design-doc §6.2). Nullable so
    -- the default OSS install does not pay storage for it.
    response_body TEXT,

    -- Cost accounting. INTEGER token counts are sufficient for any model
    -- currently in scope (largest context windows ~2M tokens fit in int4).
    -- NUMERIC(10,6) USD gives sub-cent precision up to $9,999 per call,
    -- which covers worst-case GPT-4 long-context bursts with headroom.
    input_tokens  INTEGER       NOT NULL,
    output_tokens INTEGER       NOT NULL,
    cost_usd      NUMERIC(10,6) NOT NULL,
    duration_ms   INTEGER       NOT NULL,

    -- Provider-reported termination state ('stop' / 'length' /
    -- 'tool_calls' / 'content_filter' / etc.). Nullable because some
    -- failure modes return no finish_reason at all.
    finish_reason VARCHAR(30),
    error_message TEXT,

    -- Soft references to the work product this call contributed to. They
    -- are intentionally NOT declared as FOREIGN KEYs because the target
    -- tables (vex_statements.cve, components, cra_reports) either use
    -- different key shapes (CVE id, not UUID) or do not exist yet in the
    -- schema (cra_reports lands in M2). When those tables solidify, a
    -- later migration can promote these to FKs without a data rewrite.
    -- ※要確認: cra_reports table name + key shape (M2 design pending).
    triage_target_cve          VARCHAR(30),
    triage_target_component_id UUID,
    cra_report_id              UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- "List my recent LLM calls" is the dominant tenant-scoped read.
CREATE INDEX idx_llm_calls_tenant_created
    ON llm_calls (tenant_id, created_at DESC);

-- Per-purpose analytics + retention sweeps.
CREATE INDEX idx_llm_calls_purpose
    ON llm_calls (purpose);

-- RLS: tenant_isolation. FORCE so the migrator/owner role does not
-- accidentally bypass it during ad-hoc maintenance queries; WITH CHECK so
-- an INSERT that names a foreign tenant_id is rejected at write time, not
-- merely hidden at read time. The `true` second argument to
-- current_setting() makes an unset GUC return '' (rather than raising) so
-- unauthenticated reads degrade to zero rows instead of crashing.
ALTER TABLE llm_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_calls FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_llm_calls ON llm_calls
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON TABLE llm_calls IS
    'LLM call audit log (LLM_PROVIDER_DESIGN.md §6.1, issue #20). '
    'Every Complete()/Embed() through internal/service/llm writes one row. '
    'RLS is ENABLE + FORCE with WITH CHECK so foreign-tenant INSERTs are '
    'rejected and migrator/owner connections do not bypass tenant scope.';
