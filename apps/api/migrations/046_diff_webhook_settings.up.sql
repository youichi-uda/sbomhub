-- ============================================
-- Diff webhook settings (M11-4 / issue #79)
--
-- Stores the per-tenant webhook destination + threshold configuration
-- that fires when an SBOM ingest produces a diff exceeding the
-- configured severity / license-violation thresholds.
--
-- Issue: youichi-uda/sbomhub#79 (M11-4 Wave)
--
-- Purpose:
--   When a fresh SBOM is ingested for a tenant project, the M11-4
--   diff_webhook service computes the deterministic diff vs the
--   previous SBOM (via internal/service/diff) and, if any of the three
--   configured thresholds is exceeded, POSTs a JSON / Slack-shaped
--   payload to webhook_url with HMAC-SHA256 X-SBOMHub-Signature so
--   downstream consumers can verify authenticity.
--
-- BYOK / encryption posture (matches tenant_llm_config 036):
--   - webhook_secret is AES-256-GCM (nonce||sealed) ciphertext from
--     internal/service/llm.Encrypt. The plaintext secret is never
--     persisted — the application decrypts it just-in-time before
--     each signing operation.
--   - webhook_url is plain TEXT (operators may want to inspect /
--     audit-log it via /audit-logs without bouncing through the
--     decryption layer). A leaked URL alone cannot forge requests
--     thanks to the HMAC signature.
--
-- RLS posture:
--   No RLS in this migration (same as tenant_llm_config / scan_settings).
--   This is a 1-row-per-tenant settings table; the application-layer
--   `WHERE tenant_id = $1` filter is sufficient.
-- ============================================

CREATE TABLE IF NOT EXISTS tenant_diff_webhook_settings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    -- Webhook destination. NULL means the webhook is configured-but-
    -- pending or has been transiently cleared. enabled=false is the
    -- canonical "off" state.
    webhook_url TEXT,

    -- AES-256-GCM (nonce||sealed) ciphertext produced by llm.Encrypt.
    -- The plaintext shared secret is never persisted. May be NULL when
    -- enabled=false.
    webhook_secret BYTEA,

    -- Threshold knobs. Default = 1 critical / 5 high / 0 licence
    -- violation rows trigger a fire. Operators may relax (set to a
    -- very large number) or tighten (1) per tenant. NULL is not
    -- permitted — the migration enforces sensible defaults so a
    -- partial INSERT cannot accidentally disable a threshold.
    critical_threshold          INTEGER NOT NULL DEFAULT 1
        CHECK (critical_threshold >= 0),
    high_threshold              INTEGER NOT NULL DEFAULT 5
        CHECK (high_threshold >= 0),
    license_violation_threshold INTEGER NOT NULL DEFAULT 0
        CHECK (license_violation_threshold >= 0),

    -- Payload format. 'json' is the canonical SBOMHub-defined shape
    -- (see internal/service/diff_webhook). 'slack' is an interoperable
    -- subset that fits Slack incoming webhooks (text + attachments).
    format VARCHAR(16) NOT NULL DEFAULT 'json'
        CHECK (format IN ('json', 'slack')),

    -- Master enable bit. Set to FALSE to soft-disable without
    -- discarding the URL / threshold config.
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Operational visibility. The webhook firer updates these
    -- inside its own short tx after each delivery attempt so an
    -- operator can debug failures via /api/v1/tenant/settings/diff-webhook
    -- without having to rummage in audit_logs.
    last_fired_at        TIMESTAMPTZ,
    last_response_status INTEGER,
    last_error           TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE tenant_diff_webhook_settings IS
    'Per-tenant SBOM diff webhook configuration (M11-4 #79). '
    'Fires when a fresh SBOM produces a diff exceeding the configured '
    'critical / high / license-violation thresholds. webhook_secret is '
    'AES-256-GCM ciphertext from llm.Encrypt — plaintext is never persisted.';

COMMENT ON COLUMN tenant_diff_webhook_settings.webhook_secret IS
    'AES-256-GCM (nonce||sealed) ciphertext of the HMAC shared secret. '
    'The application decrypts just-in-time before signing each outgoing '
    'webhook payload; plaintext never leaves the request frame.';

COMMENT ON COLUMN tenant_diff_webhook_settings.format IS
    'Payload format: ''json'' = SBOMHub canonical envelope, ''slack'' = '
    'Slack incoming-webhook-compatible text + attachments.';

-- updated_at trigger (mirror of tenant_llm_config 036)
CREATE OR REPLACE FUNCTION tenant_diff_webhook_settings_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tenant_diff_webhook_settings_updated_at
    ON tenant_diff_webhook_settings;

CREATE TRIGGER trg_tenant_diff_webhook_settings_updated_at
    BEFORE UPDATE ON tenant_diff_webhook_settings
    FOR EACH ROW
    EXECUTE FUNCTION tenant_diff_webhook_settings_set_updated_at();
