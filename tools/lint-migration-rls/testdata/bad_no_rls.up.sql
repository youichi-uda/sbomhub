-- ============================================
-- Negative fixture: tenant_* table created WITHOUT any RLS.
--
-- This is exactly the shape of the historical 046_diff_webhook_settings
-- mistake the lint exists to catch — a tenant-scoped table with a
-- "WHERE tenant_id = $1 is enough" justification in the header comment
-- and no ENABLE / FORCE / POLICY anywhere in the file.
--
-- The fixture must fail the lint with the canonical
--   "missing: ALTER TABLE ... ENABLE ROW LEVEL SECURITY"
--   "missing: ALTER TABLE ... FORCE ROW LEVEL SECURITY"
--   "missing: CREATE POLICY tenant_isolation_... ON ..."
-- triple. main_test.go asserts on each line of that output, so if you
-- edit this file, expect to update the test alongside it.
-- ============================================

CREATE TABLE IF NOT EXISTS tenant_bad_example (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    secret    BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No ENABLE ROW LEVEL SECURITY. No FORCE. No POLICY. Intentionally.
