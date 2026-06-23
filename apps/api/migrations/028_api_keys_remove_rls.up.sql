-- ============================================
-- Remove RLS from api_keys (Trust Rescue P0 #18)
--
-- Background:
--   - Migration 007 (multitenancy) added ENABLE ROW LEVEL SECURITY on api_keys
--     with a tenant-scoped policy.
--   - Migration 023 (RLS security hardening) added FORCE ROW LEVEL SECURITY,
--     so even the table owner now obeys the policy:
--       USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
--   - Migration 002 (#2) switched the runtime role to `sbomhub_app`
--     (NOBYPASSRLS), which is also subject to that policy.
--
-- Why this is a problem:
--   The MultiAuth / APIKeyAuth middlewares need to look up an API key by its
--   hash (SELECT ... FROM api_keys WHERE key_hash = $1) BEFORE any tenant
--   context can be set — the lookup is itself what reveals which tenant the
--   caller belongs to. Under FORCE ROW LEVEL SECURITY this SELECT runs with
--   `app.current_tenant_id` unset, the policy expression evaluates to a UUID
--   cast of an empty string and rejects every row, so every API-key request
--   fails 401. sqlmock unit tests don't catch this because they short-circuit
--   the policy; only a real Postgres + the non-superuser app role does.
--
-- Resolution chosen (see Trust Rescue P0 #18):
--   Drop the RLS policy on api_keys and enforce tenant scope in the Go
--   application layer instead. Concretely:
--     * List/Get/Update/Delete in APIKeyRepository all carry an explicit
--       `tenant_id = $N` clause.
--     * GetByKeyHash deliberately runs tenant-unscoped (this is the authn
--       lookup); its caller then derives the tenant from key.TenantID.
--   Alternatives considered and rejected:
--     * SECURITY DEFINER function — FORCE RLS applies to the owner too.
--     * Dedicated BYPASSRLS authn role — extra ops surface for a single
--       lookup, disproportionate for an OSS deploy.
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_api_keys ON api_keys;
ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;

COMMENT ON TABLE api_keys IS
    'API key store. Tenant scope is enforced in the Go application layer '
    '(APIKeyRepository), not via RLS, because the authn lookup by key_hash '
    'must run before the current tenant is known. See migration 028 and '
    'Trust Rescue P0 #18.';
