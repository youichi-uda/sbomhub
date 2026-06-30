-- ============================================
-- Negative fixture (F183 / M13-5 #91): non-`tenant_*` table that DOES
-- declare a tenant_id column but has NO RLS partner anywhere.
--
-- This mirrors the failure class the F183 scope extension exists to
-- catch — a future migration that adds, say, `billing_records (tenant_id
-- UUID, …)` without the `tenant_*` prefix and without RLS. Before the
-- extension the lint would silently accept this (only `tenant_*` names
-- were inspected); after the extension it must fail with the canonical
-- missing-RLS triple.
-- ============================================

CREATE TABLE billing_records (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    amount_cents BIGINT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No ENABLE / FORCE / POLICY anywhere. Intentionally.
