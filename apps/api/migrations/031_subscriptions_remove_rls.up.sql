-- ============================================
-- Remove RLS from subscriptions / subscription_events / usage_records
-- (Trust Rescue P0 #18 follow-up / codex-r15)
--
-- Background:
--   - Migration 008 (subscriptions / Lemon Squeezy integration) ENABLEs
--     row-level security on `subscriptions`, `subscription_events`, and
--     `usage_records`, with a USING-only policy per table:
--
--       USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
--
--     A USING-only policy without an explicit WITH CHECK falls back to
--     reusing USING for INSERTs as well — so every CRUD path on these
--     three tables is subject to the predicate.
--   - Migration 002 (#2) switched the runtime role to `sbomhub_app`
--     (NOBYPASSRLS). `sbomhub_app` is not the table owner, so it is
--     subject to the policy regardless of FORCE.
--
-- Why this is a problem:
--   `handler/webhook_lemonsqueezy.go` is mounted directly on the Echo
--   instance — outside the Auth → TenantTx middleware chain — because at
--   webhook receipt time the tenant is unknown (the handler discovers it
--   from `payload.Meta.CustomData["tenant_id"]` or by looking up the
--   subscription record). The very first DB call every handler makes is:
--
--       sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
--
--   That SELECT runs under `sbomhub_app` on a raw `*sql.DB` connection
--   that has no `app.current_tenant_id` GUC set. The USING predicate
--   becomes `tenant_id = NULL` which evaluates to NULL (treated as false),
--   so Postgres returns zero rows. Every downstream branch
--   (`subscription_updated`, `subscription_cancelled`,
--   `subscription_resumed`, `subscription_expired`,
--   `subscription_paused`, `subscription_unpaused`) then reports
--   "subscription not found" and the SaaS subscription lifecycle is
--   silently broken: tenants who upgrade in Lemon Squeezy never get the
--   plan change persisted; cancellations never flip status; expirations
--   never downgrade to free.
--
--   `subscription_created` is the only path that partially survived,
--   because it falls through the "existingSub == nil" branch and tries
--   `subRepo.Create(...)` — which itself fails under the same WITH CHECK
--   (the GUC is still unset). `CreateEvent(...)` and `RecordUsage(...)`
--   are equally broken on the webhook path for the same reason.
--
--   This is the same class of chicken-and-egg bug as #18 (api_keys
--   authn lookup) and #18-followup / migration 029 (audit_logs system
--   writes). sqlmock tests do not catch it because they short-circuit
--   the policy; only a real Postgres plus the non-superuser app role
--   exercises the failure.
--
-- Resolution chosen (same pattern as migrations 028 and 029):
--   Drop the RLS policy on the three Lemon Squeezy tables and enforce
--   tenant scope in the Go application layer. Concretely:
--
--     * `GetByLSSubscriptionID` is the webhook authn-equivalent lookup
--       (the Lemon Squeezy subscription ID is a secret-like opaque
--       identifier delivered over an HMAC-verified webhook); it stays
--       tenant-unscoped because it is the call that reveals which
--       tenant the event belongs to.
--     * `GetByTenantID`, `GetEvents`, `GetUsage` already carry an
--       explicit `WHERE tenant_id = $1` clause.
--     * `Update`, `UpdateStatus`, `Delete` add an explicit tenant_id
--       guard so an authenticated request cannot mutate another
--       tenant's subscription rows even if the application-layer
--       caller is buggy.
--     * `Create`, `CreateEvent`, `RecordUsage` write the caller-supplied
--       TenantID and the FK to `tenants(id) ON DELETE CASCADE` still
--       enforces referential integrity.
--
--   Alternatives considered and rejected:
--     * Wrap webhook handlers in per-tenant transactions — the tenant
--       is not known until after the first lookup, which is itself the
--       statement being blocked. Bootstrapping the GUC from
--       `custom_data.tenant_id` would still leave the lookup-by-LS-ID
--       path broken for events that don't carry custom_data (every
--       event except `subscription_created`).
--     * SECURITY DEFINER function for the lookup — FORCE RLS would
--       apply to the owner too, and adding FORCE here would only make
--       the situation worse.
--     * Separate `system_subscriptions` table — splits the lifecycle
--       across two tables and forces the billing handlers to UNION.
--       Operational overhead disproportionate to the benefit, given
--       that the application-layer tenant filter already exists.
--
-- See also: migration 028 (api_keys), migration 029 (audit_logs),
-- migration 030 (public_links) — same pattern, same rationale.
-- ============================================

DROP POLICY IF EXISTS tenant_isolation_subscriptions ON subscriptions;
DROP POLICY IF EXISTS tenant_isolation_subscription_events ON subscription_events;
DROP POLICY IF EXISTS tenant_isolation_usage_records ON usage_records;

-- Migration 008 did not FORCE RLS on these tables, so the NO FORCE call
-- is a no-op in the common case; it is included for safety in case an
-- operator added FORCE manually between deploys.
ALTER TABLE subscriptions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE subscription_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_records NO FORCE ROW LEVEL SECURITY;

ALTER TABLE subscriptions DISABLE ROW LEVEL SECURITY;
ALTER TABLE subscription_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE usage_records DISABLE ROW LEVEL SECURITY;

COMMENT ON TABLE subscriptions IS
    'Lemon Squeezy subscription state. Tenant scope is enforced in the Go '
    'application layer (SubscriptionRepository) via explicit `WHERE '
    'tenant_id = $N` clauses on every tenant-scoped read/mutation, not '
    'via RLS, because the webhook lookup by ls_subscription_id must run '
    'before any tenant context is known. See migration 031 and Trust '
    'Rescue P0 #18 follow-up (codex-r15).';

COMMENT ON TABLE subscription_events IS
    'Lemon Squeezy subscription event history. Tenant scope is enforced '
    'in the Go application layer (SubscriptionRepository.GetEvents has '
    'WHERE tenant_id = $1); webhook handlers INSERT with the tenant_id '
    'derived from the looked-up subscription. See migration 031.';

COMMENT ON TABLE usage_records IS
    'Per-tenant usage counters for metered billing. Tenant scope is '
    'enforced in the Go application layer (SubscriptionRepository.GetUsage '
    'has WHERE tenant_id = $1); writers INSERT with the caller-supplied '
    'tenant_id. See migration 031.';
