-- ============================================
-- Negative fixture (F194 / M13 Phase D round 3): double-quoted
-- table identifier (`CREATE TABLE "tenant_foo_quoted" (…)`).
--
-- PostgreSQL allows any character inside a quoted identifier; our
-- migrations don't use this in practice, but the pre-F194 detector's
-- `[a-z]`-only char-class would have silently bypassed any future
-- migration that does — including one authored by an external tool
-- that auto-quotes identifiers for safety.
--
-- The fixture defines a `tenant_*`-prefixed table inside double
-- quotes with no RLS evidence anywhere. The lint must FAIL with the
-- canonical missing-triple (suppression markers are not present, so
-- the table is held to the standard RLS contract).
-- ============================================

CREATE TABLE "tenant_foo_quoted" (
    tenant_id  UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    payload    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No ENABLE / FORCE / POLICY anywhere. Intentionally.
