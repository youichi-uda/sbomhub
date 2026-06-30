-- ============================================
-- RLS partner for scan_settings + scan_logs (M13 Phase D round 2 / F185)
--
-- Source of truth:
--   * M13 Phase D round 1 finding F185 (severity medium, production-impact):
--     "scan_settings / scan_logs (legacy 010 schema) carry tenant_id but
--      have never had an RLS partner migration. Tenant scope is enforced
--      app-side in ScanSettingsService only. The lint exempts these two
--      tables (tools/lint-migration-rls/main.go::structuralExemptions)
--      pending a follow-up partner migration — that follow-up is this
--      file."
--   * Issue: youichi-uda/sbomhub#91 (M13-5 Wave Phase D follow-up)
--   * Lint trail: tools/lint-migration-rls/main.go (F183 scope extension)
--
-- Why a separate migration:
--   Migration 010_scan_settings predates the 023 RLS hardening sweep — at
--   the time, scan_settings + scan_logs were treated as "self-host /
--   scheduler bookkeeping" and intentionally left without RLS so the
--   scheduler could read scan_settings cross-tenant under the bare app
--   role. The M11 Codex review (F167) re-litigated that decision for
--   diff_webhook_settings and rejected the same argument: app-side
--   filtering alone is insufficient defense in depth for a multi-tenant
--   compliance product. F185 applies the same standard to the legacy
--   010 schema.
--
--   We do NOT amend 010 in place because operators that already migrated
--   past 010 must pick up the RLS state transition through the normal
--   migrate-up sequence; rewriting 010 would silently skip the change
--   for them. This mirrors the 036→037 and 046→047 partner-file pattern.
--
-- Scheduler refactor companion:
--   internal/scheduler/vulnerability_scan.go has been updated in the same
--   commit to:
--     1. Enumerate tenants via the non-RLS `tenants` table (matches the
--        codex-r4 pattern from CVE sync) instead of cross-tenant reading
--        scan_settings directly.
--     2. Wrap scan_settings + scan_logs reads / writes in runWithTenantTx
--        so they pass the new RLS WITH CHECK / USING predicates.
--   See vulnerability_scan.go's package header for the full narrative.
--
-- App-layer companion:
--   internal/service/scan_settings.go has been updated to use
--   database.Querier(ctx, s.db) so handler-path queries piggyback on the
--   TenantTx middleware's transaction (and therefore the GUC). Without
--   this, the API endpoints GET/PUT /api/v1/settings/scan would return
--   500s under the new policy.
--
-- RLS model (matches 037 / 047 / post-023 hardened convention):
--   * ENABLE ROW LEVEL SECURITY so the policy is consulted at all.
--   * FORCE  ROW LEVEL SECURITY so the table owner (the migrator role)
--     does not bypass the policy during ad-hoc maintenance queries —
--     this is the exact gap the M5 042 uniformity sweep was retrofitting
--     for older tables.
--   * Single tenant_isolation_<table> policy per table, FOR ALL,
--     USING + WITH CHECK both bound to
--     current_setting('app.current_tenant_id', true)::UUID. The `true`
--     second argument makes the GUC return '' (rather than raising)
--     when unset; the cast to UUID then fails the predicate, so an
--     unauthenticated path gets zero rows / a rejected INSERT instead
--     of a SQL error.
--
-- Production-impact note:
--   scan_settings is read by the scheduler (`SELECT tenant_id FROM
--   scan_settings WHERE enabled = true …`) and by the API. scan_logs is
--   written by the scheduler and read by the API. Without the scheduler
--   refactor above, this migration would silently disable the scheduled
--   vulnerability scan for every tenant — same failure mode codex-r4 P1
--   originally found on the projects / sboms RLS rollout. The companion
--   Go change is therefore non-optional.
-- ============================================

ALTER TABLE scan_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_settings FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_scan_settings ON scan_settings
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_scan_settings ON scan_settings IS
    'M13 Phase D round 2 / F185: enforce tenant isolation on scheduled '
    'scan configuration (one row per tenant). Mirror of 037 / 047 policies. '
    'See migrations/048_legacy_scan_settings_logs_rls.up.sql header.';

ALTER TABLE scan_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_logs FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_scan_logs ON scan_logs
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_scan_logs ON scan_logs IS
    'M13 Phase D round 2 / F185: enforce tenant isolation on scheduled '
    'scan execution history. Mirror of 037 / 047 policies. '
    'See migrations/048_legacy_scan_settings_logs_rls.up.sql header.';
