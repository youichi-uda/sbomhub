-- ============================================
-- RLS hardening for tenant_llm_config (M1 Codex review round 1 / F1)
--
-- Source of truth:
--   * sbomhub-internal/planning/LLM_PROVIDER_DESIGN.md §3.3 (BYOK schema)
--   * Codex review M1 round 1 finding F1 (severity high, tenant-isolation):
--     "The BYOK key table is the only new M1 tenant-scoped table without RLS,
--      leaving encrypted tenant API keys protected only by application
--      filters."
--   * Issue: youichi-uda/sbomhub#22 (M1 Wave M1-1 follow-up)
--
-- Why a separate migration:
--   Migration 036_tenant_llm_config explicitly deferred RLS, arguing that
--   self-host is effectively single-tenant in M1 and that other settings
--   tables (scan_settings 010, system_settings 026) also ship without RLS.
--   The Codex round-1 review rejected that argument for this specific table:
--   tenant_llm_config stores `encrypted_api_key` (BYOK ciphertext), so a
--   cross-tenant read/write here leaks operator-supplied LLM credentials --
--   the exact attack surface the Trust Rescue 023 hardening was supposed to
--   close. We treat the table the same way 032 (llm_calls) / 033
--   (advisory_excerpts) / 034 (reachability_results) / 035 (vex_drafts)
--   handle their tenant-scoped data: ENABLE + FORCE + WITH CHECK.
--
-- We do NOT amend 036 in place because operators that already migrated past
-- 036 must pick up the RLS state transition through the normal migrate-up
-- sequence; rewriting 036 would silently skip the change for them.
--
-- RLS model (matches post-023 hardened convention):
--   * ENABLE ROW LEVEL SECURITY so the policy is consulted at all.
--   * FORCE  ROW LEVEL SECURITY so the table owner (the migrator role)
--     does not bypass the policy during ad-hoc maintenance queries.
--   * Single tenant_isolation_tenant_llm_config policy with FOR ALL,
--     USING + WITH CHECK both bound to
--     current_setting('app.current_tenant_id', true)::UUID. The `true`
--     second argument makes the GUC return '' (rather than raising)
--     when unset; the cast to UUID then fails the predicate, so an
--     unauthenticated path gets zero rows / a rejected INSERT instead
--     of a SQL error.
--
-- BYOK posture preserved:
--   The encrypted_api_key column still holds nonce||sealed AES-256-GCM
--   ciphertext from internal/service/llm.Encrypt. RLS is a defense-in-depth
--   layer ON TOP of the application-layer encryption, not a substitute --
--   if the encryption key leaks, an attacker still needs RLS bypass to read
--   another tenant's ciphertext directly via SQL.
-- ============================================

ALTER TABLE tenant_llm_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_llm_config FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_llm_config ON tenant_llm_config
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_tenant_llm_config ON tenant_llm_config IS
    'M1 Codex review round 1 / F1: enforce tenant isolation on BYOK config. '
    'See migrations/037_tenant_llm_config_rls.up.sql header.';
