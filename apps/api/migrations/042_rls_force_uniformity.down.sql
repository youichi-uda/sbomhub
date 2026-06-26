-- ============================================
-- Reverse of 042_rls_force_uniformity.up.sql.
--
-- Restores the original USING-only policies (with their original
-- snake_case_within_quotes names) and drops FORCE. The tables
-- themselves are owned by migrations 012 / 013 / 014 / 021 and are
-- NOT dropped here. ENABLE ROW LEVEL SECURITY remains because the
-- original migration set it; only the post-042 hardening (FORCE +
-- renamed policy + explicit WITH CHECK + `, true`) is reverted.
--
-- Order matters: DROP policy first, then NO FORCE -- ALTER TABLE
-- DISABLE ROW LEVEL SECURITY would also keep the policy attached so
-- a re-up would conflict with CREATE POLICY. We intentionally do
-- NOT call DISABLE here because the pre-042 state had ENABLE on.
--
-- M5 Wave M5-1 / issue #50.
-- ============================================

-- ---------- migration 021 / SSVC ----------

DROP POLICY IF EXISTS tenant_isolation_ssvc_assessments ON ssvc_assessments;
ALTER TABLE ssvc_assessments NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "ssvc_assessments_tenant_isolation" ON ssvc_assessments
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);


DROP POLICY IF EXISTS tenant_isolation_ssvc_project_defaults ON ssvc_project_defaults;
ALTER TABLE ssvc_project_defaults NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "ssvc_project_defaults_tenant_isolation" ON ssvc_project_defaults
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);


-- ---------- migration 014 / IPA ----------

DROP POLICY IF EXISTS tenant_isolation_ipa_sync_settings ON ipa_sync_settings;
ALTER TABLE ipa_sync_settings NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "ipa_sync_settings_tenant_isolation" ON ipa_sync_settings
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);


-- ---------- migration 013 / reports ----------

DROP POLICY IF EXISTS tenant_isolation_generated_reports ON generated_reports;
ALTER TABLE generated_reports NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "generated_reports_tenant_isolation" ON generated_reports
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);


DROP POLICY IF EXISTS tenant_isolation_report_settings ON report_settings;
ALTER TABLE report_settings NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "report_settings_tenant_isolation" ON report_settings
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);


-- ---------- migration 012 / analytics ----------

DROP POLICY IF EXISTS tenant_isolation_compliance_snapshots ON compliance_snapshots;
ALTER TABLE compliance_snapshots NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "compliance_snapshot_tenant_isolation" ON compliance_snapshots
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);


DROP POLICY IF EXISTS tenant_isolation_vulnerability_snapshots ON vulnerability_snapshots;
ALTER TABLE vulnerability_snapshots NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "vuln_snapshot_tenant_isolation" ON vulnerability_snapshots
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);


DROP POLICY IF EXISTS tenant_isolation_slo_targets ON slo_targets;
ALTER TABLE slo_targets NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "slo_targets_tenant_isolation" ON slo_targets
    FOR ALL USING (
        tenant_id IS NULL OR
        tenant_id = current_setting('app.current_tenant_id')::uuid
    );


DROP POLICY IF EXISTS tenant_isolation_vulnerability_resolution_events ON vulnerability_resolution_events;
ALTER TABLE vulnerability_resolution_events NO FORCE ROW LEVEL SECURITY;
CREATE POLICY "vuln_resolution_tenant_isolation" ON vulnerability_resolution_events
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
