-- ============================================
-- Remove RLS from public_links + public_link_access_logs
-- (Trust Rescue codex-r5 P1 #19 follow-up)
--
-- Background:
--   - Migration 009 (public links) added ENABLE ROW LEVEL SECURITY on
--     public_links and public_link_access_logs with tenant-scoped policies:
--       public_links:
--         USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
--       public_link_access_logs:
--         USING (public_link_id IN (
--           SELECT id FROM public_links
--           WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
--         ))
--   - Migration 002 (#2) switched the runtime role to `sbomhub_app`
--     (NOBYPASSRLS), which is subject to those policies (note: migration
--     023 did not add FORCE on public_links, but the migrator-owner DDL
--     path is irrelevant; the app role is NOBYPASSRLS and is what the
--     server uses at runtime).
--
-- Why this is a problem:
--   The anonymous `/api/v1/public/:token` endpoint runs WITHOUT any tenant
--   middleware — by definition, the caller has no session, no API key, no
--   tenant context. PublicLinkRepository.GetByToken does a token lookup
--   that is itself what reveals which tenant the share link belongs to.
--   Under RLS, that SELECT runs with `app.current_tenant_id` unset, the
--   policy expression reduces to a UUID cast of an empty string and
--   rejects every row, so every public share link fails 403/404. The
--   downstream IncrementView / IncrementDownload / CreateAccessLog
--   INSERTs / UPDATEs also live under RLS and silently no-op.
--   Result: dashboard-generated "external share link" is completely
--   broken in production.
--
-- Resolution chosen (see migration 028 / 029 for the same pattern):
--   Drop the RLS policies on public_links and public_link_access_logs
--   and enforce tenant scope in the Go application layer instead.
--   Concretely:
--     * GetByToken deliberately runs tenant-unscoped (this is the public
--       lookup; the token itself is the secret — 64 hex chars = 256 bits
--       of entropy via crypto/rand, brute-force-infeasible).
--     * Every other read (ListByProject), every mutation (Update / Delete
--       / IncrementView / IncrementDownload / IsDownloadLimitReached /
--       UpdateCounts / Touch) carries an explicit `tenant_id = $N` clause
--       in PublicLinkRepository.
--     * GetByID requires the tenant id derived from the authenticated
--       session — never a tenant_id read from a user-supplied request
--       body — otherwise this becomes a cross-tenant
--       information-disclosure primitive.
--     * The access-log INSERT (CreateAccessLog) writes by public_link_id
--       only; cross-tenant probing requires guessing a UUID + having a
--       way to read public_link_access_logs, which no API exposes.
--   Alternatives considered and rejected:
--     * SECURITY DEFINER function for the token lookup — adds an ops
--       surface and a stored-proc maintenance burden for one query.
--     * Dedicated BYPASSRLS role just for /public/:token — proliferates
--       roles and connection pools for a single endpoint.
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_public_links ON public_links;
DROP POLICY IF EXISTS tenant_isolation_public_link_access_logs ON public_link_access_logs;

ALTER TABLE public_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public_links DISABLE ROW LEVEL SECURITY;

ALTER TABLE public_link_access_logs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public_link_access_logs DISABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public_links IS
    'Public share links for SBOM views. Tenant scope is enforced in the '
    'Go application layer (PublicLinkRepository) via explicit '
    '`tenant_id = $N` clauses on every read/mutation, not via RLS, '
    'because the anonymous /api/v1/public/:token endpoint must look up '
    'a link by token BEFORE any tenant context is known. The token '
    '(64 hex chars = 256 bits of entropy) is the application-layer '
    'secret. See migration 030 and Trust Rescue codex-r5.';

COMMENT ON TABLE public_link_access_logs IS
    'Access trail for public_links. RLS removed alongside public_links '
    '(migration 030) because access-log INSERTs run inside anonymous '
    'public-link flows that have no tenant context. The table is only '
    'written to by the server (CreateAccessLog) and there is no API that '
    'reads it, so application-layer tenant scoping is unnecessary on the '
    'read side.';
