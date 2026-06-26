-- ============================================
-- RLS FORCE + WITH CHECK uniformity sweep over M0-M2 era tenant-scoped
-- tables (M5 Wave M5-1 / issue #50, RLS uniformity sweep).
--
-- Source of truth:
--   * sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §9.1
--     ("M0 Trust Rescue / RLS / tenant isolation")
--   * sbomhub-internal/planning/M5_AGENT_PROMPT_TEMPLATE.md §1.A §2 M5-1
--   * GitHub issue #50 (M5 Wave M5-1: RLS uniformity sweep)
--
-- Background (what state these tables were in before 042):
--   Several tenant-scoped tables shipped in migrations 012-021 were
--   given RLS via the early `ENABLE ROW LEVEL SECURITY` + USING-only
--   policy idiom -- a pattern that predates the M4 / round-13 hardened
--   convention established by migrations 023, 037 and 040. The early
--   idiom has two known gaps:
--
--     1. NO FORCE -- the table owner (sbomhub_migrator) bypasses the
--        policy. Any ad-hoc psql session run under that role can read
--        or mutate cross-tenant rows. The Trust Rescue threat model
--        (#2 / migration 023) treats this as a P1 leak even though
--        the request path runs under sbomhub_app.
--
--     2. USING-only policy without explicit `WITH CHECK` -- in
--        PostgreSQL, FOR ALL without WITH CHECK falls back to using
--        USING for INSERT/UPDATE row checks. The behaviour is
--        equivalent today, but the next reviewer who reads
--        `FOR ALL USING (...)` cannot tell whether INSERT enforcement
--        was intended or forgotten. The M4 convention writes them
--        explicitly so review intent is unambiguous, and a future
--        switch to `FOR SELECT USING ... FOR INSERT/UPDATE WITH
--        CHECK ...` style would not silently lose write protection.
--
--   A third uniformity gap is the missing `, true` second argument to
--   `current_setting('app.current_tenant_id')`. Without it, an unset
--   GUC raises an exception instead of returning '' (which then casts
--   to UUID failure and the predicate fails closed). The M4 convention
--   uses `, true` so the failure mode is "zero rows / rejected INSERT"
--   instead of "SQL error surfaces in the response".
--
-- Why a separate migration (not amending 012 / 013 / 014 / 021):
--   Same precedent as 023 / 037 / 040 / 041: rewriting an already-
--   shipped migration silently skips operators that have migrated
--   past that number. Patching forward in 042 makes every existing
--   install pick up the FORCE / WITH CHECK / `, true` transition on
--   the next `go run ./cmd/migrate up`.
--
-- Tables covered (9 total, all of which already have ENABLE + USING
-- policy from their original migration):
--
--   * vulnerability_resolution_events  (migration 012, analytics)
--   * slo_targets                      (migration 012, analytics)
--   * vulnerability_snapshots          (migration 012, analytics)
--   * compliance_snapshots             (migration 012, analytics)
--   * report_settings                  (migration 013, reports)
--   * generated_reports                (migration 013, reports)
--   * ipa_sync_settings                (migration 014, IPA)
--   * ssvc_project_defaults            (migration 021, SSVC)
--   * ssvc_assessments                 (migration 021, SSVC)
--
-- Tables INTENTIONALLY NOT covered here (read the rationale before
-- adding them in a future migration!):
--
--   * scan_settings, scan_logs (migration 010)
--       -- by design, no RLS. The scheduler at
--          internal/scheduler/vulnerability_scan.go enumerates ALL
--          tenants from scan_settings on a system-level connection
--          that has no app.current_tenant_id GUC set; adding RLS
--          would silently return zero tenants and the nightly scan
--          would stop running. The scheduler comment at
--          vulnerability_scan.go:22-26 documents this contract.
--          Same architectural pattern as audit_logs (029) and
--          api_keys (028): tenant scope is enforced at the app layer
--          via `WHERE tenant_id = $1` filters, not RLS.
--
--   * subscription_events, usage_records (migration 008)
--       -- migration 031 explicitly DROPPED RLS on these tables to
--          fix the Lemon Squeezy webhook lookup which runs OUTSIDE
--          the TenantTx middleware chain (the very lookup that
--          *discovers* which tenant an event belongs to). Re-enabling
--          RLS here would re-introduce the bug migration 031 closed.
--          Same app-layer scoping rationale.
--
--   * subscriptions (migration 008)
--       -- same as above (migration 031).
--
--   * ssvc_assessment_history (migration 021)
--       -- handled in 043 instead, because that table is missing both
--          ENABLE *and* a tenant_id column. Adding ENABLE+FORCE+policy
--          requires a subquery policy that joins to the parent
--          ssvc_assessments row, which is a different shape from the
--          straightforward `WHERE tenant_id = current_setting(...)`
--          policies in this file. See 043 for the rationale.
--
-- RLS model after 042 (matches the M4 / post-040 hardened convention):
--   * ENABLE ROW LEVEL SECURITY   (was already on, kept on)
--   * FORCE  ROW LEVEL SECURITY   (added by this migration)
--   * Single tenant_isolation_<table> policy with FOR ALL, USING
--     + WITH CHECK both bound to
--     current_setting('app.current_tenant_id', true)::UUID, EXCEPT
--     slo_targets which preserves its NULL-tenant_id global-default
--     row semantics (see below).
--
-- slo_targets special case:
--   The original migration 012 policy reads
--     `tenant_id IS NULL OR tenant_id = current_setting(...)`
--   because the seed inserts four "global default" rows with
--   tenant_id NULL that all tenants are allowed to read (defer 24h /
--   high 168h / medium 720h / low 2160h). Stripping the NULL clause
--   would hide those rows from every tenant. We preserve the NULL
--   clause in USING (read side) and additionally add an explicit
--   `tenant_id IS NOT NULL` constraint to WITH CHECK so a tenant
--   cannot use this table to create new global rows by submitting
--   tenant_id=NULL. Global defaults remain readable; per-tenant
--   overrides are still tenant-scoped on both read and write. The
--   migrator role retains the ability to install / update the global
--   seed rows via direct ad-hoc DML, which is fine -- the migrator
--   is operationally trusted.
--
-- Naming convention:
--   The original migration 012 / 013 / 014 / 021 policies used
--   snake_case_within_quotes names like
--   "vuln_resolution_tenant_isolation". The M4 convention (migration
--   023 / 040) uses the unquoted form
--   `tenant_isolation_<table>`. We DROP the old names and CREATE the
--   new names so a future reviewer can grep for
--   `tenant_isolation_*` and find every guarded table consistently.
--   The down migration restores the original names for clean
--   reversibility.
--
-- Defense in depth:
--   Repositories that touch these tables already route every
--   statement through database.Querier(ctx, r.db) (analytics.go,
--   report.go, ipa.go, ssvc.go -- audited 2026-06-27 for issue #50),
--   so the TenantTx middleware's `SET LOCAL app.current_tenant_id`
--   GUC is visible to the policy on the same connection. The FORCE
--   added here additionally closes the cross-tenant leak path
--   through the migrator role.
-- ============================================

-- ---------- migration 012 / analytics ----------

ALTER TABLE vulnerability_resolution_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "vuln_resolution_tenant_isolation" ON vulnerability_resolution_events;
DROP POLICY IF EXISTS tenant_isolation_vulnerability_resolution_events ON vulnerability_resolution_events;
CREATE POLICY tenant_isolation_vulnerability_resolution_events ON vulnerability_resolution_events
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_vulnerability_resolution_events ON vulnerability_resolution_events IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK '
    'so the tenant-scope predicate fires on every CRUD path including from the '
    'sbomhub_migrator role. See migrations/042_rls_force_uniformity.up.sql header.';


ALTER TABLE slo_targets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "slo_targets_tenant_isolation" ON slo_targets;
DROP POLICY IF EXISTS tenant_isolation_slo_targets ON slo_targets;
-- slo_targets retains the NULL-tenant_id global-default semantics on the
-- READ side. The WRITE side additionally requires tenant_id IS NOT NULL
-- so a regular tenant cannot install / overwrite global defaults; only
-- the migrator role can do that via ad-hoc DML.
CREATE POLICY tenant_isolation_slo_targets ON slo_targets
    FOR ALL
    USING (
        tenant_id IS NULL
        OR tenant_id = current_setting('app.current_tenant_id', true)::UUID
    )
    WITH CHECK (
        tenant_id IS NOT NULL
        AND tenant_id = current_setting('app.current_tenant_id', true)::UUID
    );

COMMENT ON POLICY tenant_isolation_slo_targets ON slo_targets IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK. '
    'READ side preserves the NULL-tenant_id global defaults (CRITICAL=24h / '
    'HIGH=168h / MEDIUM=720h / LOW=2160h seeded in migration 012). WRITE side '
    'rejects tenant_id=NULL submissions so tenants cannot forge new global rows.';


ALTER TABLE vulnerability_snapshots FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "vuln_snapshot_tenant_isolation" ON vulnerability_snapshots;
DROP POLICY IF EXISTS tenant_isolation_vulnerability_snapshots ON vulnerability_snapshots;
CREATE POLICY tenant_isolation_vulnerability_snapshots ON vulnerability_snapshots
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_vulnerability_snapshots ON vulnerability_snapshots IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK.';


ALTER TABLE compliance_snapshots FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "compliance_snapshot_tenant_isolation" ON compliance_snapshots;
DROP POLICY IF EXISTS tenant_isolation_compliance_snapshots ON compliance_snapshots;
CREATE POLICY tenant_isolation_compliance_snapshots ON compliance_snapshots
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_compliance_snapshots ON compliance_snapshots IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK.';


-- ---------- migration 013 / reports ----------

ALTER TABLE report_settings FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "report_settings_tenant_isolation" ON report_settings;
DROP POLICY IF EXISTS tenant_isolation_report_settings ON report_settings;
CREATE POLICY tenant_isolation_report_settings ON report_settings
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_report_settings ON report_settings IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK.';


ALTER TABLE generated_reports FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "generated_reports_tenant_isolation" ON generated_reports;
DROP POLICY IF EXISTS tenant_isolation_generated_reports ON generated_reports;
CREATE POLICY tenant_isolation_generated_reports ON generated_reports
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_generated_reports ON generated_reports IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK.';


-- ---------- migration 014 / IPA ----------

ALTER TABLE ipa_sync_settings FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "ipa_sync_settings_tenant_isolation" ON ipa_sync_settings;
DROP POLICY IF EXISTS tenant_isolation_ipa_sync_settings ON ipa_sync_settings;
CREATE POLICY tenant_isolation_ipa_sync_settings ON ipa_sync_settings
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_ipa_sync_settings ON ipa_sync_settings IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK.';


-- ---------- migration 021 / SSVC ----------

ALTER TABLE ssvc_project_defaults FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "ssvc_project_defaults_tenant_isolation" ON ssvc_project_defaults;
DROP POLICY IF EXISTS tenant_isolation_ssvc_project_defaults ON ssvc_project_defaults;
CREATE POLICY tenant_isolation_ssvc_project_defaults ON ssvc_project_defaults
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_ssvc_project_defaults ON ssvc_project_defaults IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK.';


ALTER TABLE ssvc_assessments FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "ssvc_assessments_tenant_isolation" ON ssvc_assessments;
DROP POLICY IF EXISTS tenant_isolation_ssvc_assessments ON ssvc_assessments;
CREATE POLICY tenant_isolation_ssvc_assessments ON ssvc_assessments
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_ssvc_assessments ON ssvc_assessments IS
    'M5 Wave M5-1 / issue #50: uniformity sweep -- FORCE + explicit WITH CHECK.';
