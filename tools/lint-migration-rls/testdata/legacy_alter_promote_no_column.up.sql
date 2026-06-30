-- ============================================
-- Negative fixture (F191 / M13 Phase D round 3): `ALTER TABLE … ADD
-- tenant_id` — the SQL-standard shorter form without the `COLUMN`
-- keyword. PostgreSQL accepts both forms; the lint must too.
--
-- Pre-F191 the detector required the literal `ADD COLUMN tenant_id`
-- shape, which silently bypassed any migration written with the
-- idiomatic shorter form. That undermined the F183 widening (the
-- whole point of which was to catch non-`tenant_*` tables promoted to
-- tenant-scoped via ALTER). This fixture exercises the omitted-COLUMN
-- path with no RLS evidence anywhere — the lint must FAIL with the
-- canonical missing-triple, identical to legacy_no_rls.up.sql modulo
-- the promotion vector.
-- ============================================

CREATE TABLE billing_records_promoted (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    amount_cents BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Idiomatic shorter form: `ADD tenant_id <type>`, no `COLUMN` keyword.
ALTER TABLE billing_records_promoted ADD tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE;

-- No ENABLE / FORCE / POLICY anywhere. Intentionally.
