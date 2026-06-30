-- ============================================
-- Negative fixture (F194 / M13 Phase D round 3): schema-qualified
-- table reference (`CREATE TABLE public.billing_records (…)`).
--
-- Pre-F194 the table-name capture char-class was `[a-z][a-z0-9_]*`,
-- which silently bypassed any CREATE TABLE that prefixed the table
-- with a schema name. A future migration that happens to be authored
-- with explicit `public.` qualification (or any other schema prefix)
-- would have slipped past the lint regardless of its RLS posture.
--
-- This fixture defines a tenant-scoped table under the `public`
-- schema with no RLS partner anywhere — the lint must FAIL with the
-- canonical missing-triple to prove the widened detector catches the
-- schema-qualified form.
-- ============================================

CREATE TABLE public.billing_records_schema (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    amount_cents BIGINT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No ENABLE / FORCE / POLICY anywhere. Intentionally.
