-- ============================================
-- Remove RLS from audit_logs (Trust Rescue P0 #18 follow-up)
--
-- Background:
--   - Migration 007 (multitenancy) added ENABLE ROW LEVEL SECURITY on
--     audit_logs with a tenant-scoped SELECT policy.
--   - Migration 023 (RLS security hardening) added FORCE ROW LEVEL SECURITY
--     plus a FOR ALL policy:
--       USING       (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
--       WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
--   - Migration 002 (#2) switched the runtime role to `sbomhub_app`
--     (NOBYPASSRLS), which is also subject to that policy.
--   - Trust Rescue Wave 3 (#3) introduced the TenantTx middleware so that
--     authenticated request audit writes land in a tx that has the GUC bound;
--     this works for the Audit / MCPAudit middleware chains.
--
-- Why this is a problem:
--   Several `audit_logs` INSERT paths run OUTSIDE any TenantTx-managed
--   transaction and therefore have no `app.current_tenant_id` GUC set:
--
--     * apps/api/internal/handler/webhook_clerk.go — every Clerk webhook
--       (user.created/updated/deleted, organization.created/updated/deleted)
--       calls `auditRepo.Log(...)`. The /api/webhooks/clerk route is mounted
--       directly on the Echo instance (no Auth → no TenantTx).
--     * apps/api/internal/handler/webhook_lemonsqueezy.go — every
--       Lemon Squeezy subscription event (created / updated / cancelled)
--       calls `auditRepo.Log(...)`. Same routing pattern: no TenantTx.
--
--   With FORCE ROW LEVEL SECURITY on, those INSERTs run under the
--   sbomhub_app (NOBYPASSRLS) role on a connection that has no tenant GUC.
--   `current_setting('app.current_tenant_id', true)` returns NULL, the WITH
--   CHECK predicate becomes `tenant_id = NULL` which evaluates to NULL
--   (treated as false), and Postgres rejects the row. The error is swallowed
--   by the webhook handlers (the return value of `Log` is discarded), so the
--   failure is silent: the audit record never appears and operators have no
--   trail of webhook-driven tenant/subscription lifecycle events.
--
--   This is the same class of chicken-and-egg bug as #18 (api_keys): code
--   expects an SQL operation to succeed but RLS quietly blocks it because
--   the tenant context was never established. sqlmock unit tests don't
--   catch it because they short-circuit the policy; only a real Postgres
--   plus the non-superuser app role exercises the failure.
--
-- Resolution chosen (Option A in the #18 follow-up issue):
--   Drop the RLS policy on `audit_logs` and rely on the application-layer
--   tenant filter that AuditRepository already enforces on every read:
--     * List / ListByUser / ListByResource / Count / DeleteOlderThan /
--       ListWithFilter / GetActionCounts / GetDailyActionCounts all carry
--       an explicit `WHERE tenant_id = $1` clause.
--     * The handler/service layer always passes the authenticated tenant id
--       (from middleware.TenantContext) into those calls — never a
--       caller-supplied value.
--     * System-level events (webhook-driven Clerk user.created/updated
--       audits, for example) can now legitimately INSERT with `tenant_id
--       IS NULL`. Tenant-scoped reads still skip those rows because
--       `tenant_id = $1` excludes NULLs, so they remain invisible to any
--       tenant's audit view — which is the right behavior for system events.
--
--   Alternatives considered and rejected:
--     * Separate `system_audit_logs` table (Option B in the issue) — splits
--       the audit trail across two tables and forces downstream consumers
--       (CSV export, list view, statistics) to UNION them. Operational
--       overhead disproportionate to the benefit, especially given that
--       AuditRepository already enforces tenant scope in the WHERE clauses.
--     * Wrap webhook handlers in their own per-tenant transactions —
--       impossible for events that have no tenant (Clerk user.created has
--       no org yet) and unnatural for events that do (the webhook isn't a
--       "tenant request", it's a system event ABOUT a tenant).
--     * SECURITY DEFINER function for the INSERT — FORCE RLS applies to
--       the owner too, so SECURITY DEFINER doesn't help here.
--
-- See also: migration 028 (api_keys), which removed RLS for the analogous
-- authn-before-tenant problem and established this pattern.
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_audit_logs ON audit_logs;
ALTER TABLE audit_logs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;

COMMENT ON TABLE audit_logs IS
    'Audit trail. Tenant scope is enforced in the Go application layer '
    '(AuditRepository) via explicit `WHERE tenant_id = $N` clauses on '
    'every read, not via RLS, because webhook-driven INSERTs (Clerk / '
    'Lemon Squeezy) legitimately run outside any tenant context. '
    'System-level events MAY be inserted with tenant_id IS NULL; they '
    'are invisible to tenant-scoped queries by construction. See '
    'migration 029 and Trust Rescue P0 #18 follow-up.';
