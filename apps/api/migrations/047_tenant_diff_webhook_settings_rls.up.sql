-- ============================================
-- RLS hardening for tenant_diff_webhook_settings (M11 Phase D / F167)
--
-- Source of truth:
--   * Codex review M11 round 1 finding F167 (severity high, tenant-isolation):
--     "tenant_diff_webhook_settings stores encrypted webhook secrets but
--      explicitly ships with no RLS. That repeats the tenant_llm_config 036
--      mistake that was later corrected by 037_tenant_llm_config_rls, and
--      violates the M0-M10 FORCE RLS + tenant GUC discipline."
--   * Issue: youichi-uda/sbomhub#79 (M11-4 Wave Phase D follow-up)
--
-- Why a separate migration:
--   Migration 046_diff_webhook_settings explicitly deferred RLS in its
--   header comment, arguing that the application-layer `WHERE tenant_id = $1`
--   filter was sufficient. The Codex round-1 review rejected that argument
--   for the same reason 037 rejected it for tenant_llm_config: the table
--   stores `webhook_secret` (AES-256-GCM ciphertext of the HMAC shared
--   secret), so a cross-tenant read here leaks the cryptographic material
--   that authenticates outgoing webhook payloads -- a downstream consumer
--   verifying the HMAC would then trust a forged event from a different
--   tenant. We treat the table the same way 037 (tenant_llm_config) does:
--   ENABLE + FORCE + WITH CHECK.
--
-- We do NOT amend 046 in place because operators that already migrated past
-- 046 must pick up the RLS state transition through the normal migrate-up
-- sequence; rewriting 046 would silently skip the change for them.
--
-- RLS model (matches 037 / post-023 hardened convention):
--   * ENABLE ROW LEVEL SECURITY so the policy is consulted at all.
--   * FORCE  ROW LEVEL SECURITY so the table owner (the migrator role)
--     does not bypass the policy during ad-hoc maintenance queries.
--   * Single tenant_isolation_tenant_diff_webhook_settings policy with
--     FOR ALL, USING + WITH CHECK both bound to
--     current_setting('app.current_tenant_id', true)::UUID. The `true`
--     second argument makes the GUC return NULL (rather than raising)
--     when unset; the cast to UUID then fails the predicate, so an
--     unauthenticated path gets zero rows / a rejected INSERT instead
--     of a SQL error.
--
-- BYOK / HMAC posture preserved:
--   The webhook_secret column still holds nonce||sealed AES-256-GCM
--   ciphertext from internal/service/llm.Encrypt. RLS is a defense-in-depth
--   layer ON TOP of the application-layer encryption, not a substitute --
--   if the encryption key leaks, an attacker still needs RLS bypass to read
--   another tenant's ciphertext directly via SQL.
-- ============================================

ALTER TABLE tenant_diff_webhook_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_diff_webhook_settings FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_diff_webhook_settings ON tenant_diff_webhook_settings
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_tenant_diff_webhook_settings ON tenant_diff_webhook_settings IS
    'M11 Codex review round 1 / F167: enforce tenant isolation on '
    'AES-GCM webhook secret + URL. Mirror of 037 tenant_llm_config policy. '
    'See migrations/047_tenant_diff_webhook_settings_rls.up.sql header.';
