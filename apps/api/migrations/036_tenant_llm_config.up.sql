-- ============================================
-- Tenant LLM provider configuration (M1 / BYOK)
--
-- Source of truth: sbomhub-internal/planning/LLM_PROVIDER_DESIGN.md §3.3
-- Issue: youichi-uda/sbomhub#22 (M1 Wave M1-1)
--
-- Purpose:
--   Stores the per-tenant BYOK LLM configuration that the
--   /settings/llm UI writes. The encrypted_api_key column holds the
--   application-layer AES-256-GCM ciphertext of the operator-supplied API
--   key (see internal/service/llm/crypto.go). The plaintext key is NEVER
--   persisted and never leaves the request-handler memory frame.
--
--   The `mode` column is included now (CHECK against 'byok' / 'managed_gemini')
--   so the SaaS reopen does not require a schema migration. The OSS build
--   only writes 'byok'.
--
-- RLS posture:
--   No RLS in this migration. ※要確認:
--     * OSS / self-host is effectively single-tenant in M1 (one tenants row
--       per install), so the table is small enough that an application-layer
--       `WHERE tenant_id = $1` filter is sufficient.
--     * Other tenant-scoped settings tables (scan_settings 010, system_settings
--       026) also ship without RLS. We follow that convention here for
--       consistency and to avoid the chicken-and-egg INSERT issues that 028
--       / 029 / 030 / 031 had to undo.
--     * When SaaS reopens (LLM_PROVIDER_DESIGN.md §4.2), a follow-up migration
--       will ENABLE + FORCE RLS the same way 032 (llm_calls) does and add a
--       tenant_isolation policy. The schema is forward-compatible.
--
-- BYOK / OSS posture:
--   - encrypted_api_key is BYTEA (raw nonce||sealed bytes from
--     llm.Encrypt). No base64 wrapper so the column reflects exactly what
--     llm.Decrypt expects.
--   - provider / model are free-form strings; the application validates
--     against the supported list (openai / anthropic / gemini / azure_openai
--     / ollama). A schema-level CHECK is deliberately omitted so that adding
--     a new provider does not require a migration.
--   - quota_monthly_tokens and quota_monthly_triage_count are NULL in OSS;
--     they will be populated by the SaaS managed-gemini flow only.
-- ============================================

CREATE TABLE IF NOT EXISTS tenant_llm_config (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    -- 'byok' (operator-supplied API key) or 'managed_gemini' (SaaS only).
    -- OSS only ever writes 'byok'.
    mode VARCHAR(20) NOT NULL DEFAULT 'byok'
        CHECK (mode IN ('byok', 'managed_gemini')),

    -- BYOK fields. provider/model are free-form; the Go handler validates
    -- against the supported set. encrypted_api_key holds the nonce||sealed
    -- AES-256-GCM ciphertext produced by llm.Encrypt; the plaintext is never
    -- persisted.
    provider          VARCHAR(20),
    encrypted_api_key BYTEA,
    model             VARCHAR(100),

    -- Provider-specific config (only one set is populated per row).
    azure_endpoint   TEXT,
    azure_deployment VARCHAR(100),
    ollama_url       TEXT,

    -- SaaS-only quota counters (NULL in OSS). Kept here so the schema is
    -- forward-compatible with the SaaS managed-gemini flow without a
    -- breaking migration. ※要確認: SaaS may want a separate tenant_llm_usage
    -- table for monthly counters (LLM_PROVIDER_DESIGN.md §3.3 sketches it).
    quota_monthly_tokens       BIGINT,
    quota_monthly_triage_count INTEGER,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE tenant_llm_config IS
    'Per-tenant BYOK LLM configuration (LLM_PROVIDER_DESIGN.md §3.3, issue #22). '
    'OSS / self-host only ever uses mode = byok. encrypted_api_key holds the '
    'nonce||sealed AES-256-GCM ciphertext from llm.Encrypt — the plaintext '
    'API key is never persisted.';

COMMENT ON COLUMN tenant_llm_config.encrypted_api_key IS
    'AES-256-GCM (nonce||sealed) ciphertext produced by '
    'internal/service/llm.Encrypt. Plaintext API key is never stored.';
