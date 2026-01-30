-- Drop analytics tables

DROP POLICY IF EXISTS "compliance_snapshot_tenant_isolation" ON compliance_snapshots;
DROP POLICY IF EXISTS "vuln_snapshot_tenant_isolation" ON vulnerability_snapshots;
DROP POLICY IF EXISTS "slo_targets_tenant_isolation" ON slo_targets;
DROP POLICY IF EXISTS "vuln_resolution_tenant_isolation" ON vulnerability_resolution_events;

DROP TABLE IF EXISTS compliance_snapshots;
DROP TABLE IF EXISTS vulnerability_snapshots;
DROP TABLE IF EXISTS slo_targets;
DROP TABLE IF EXISTS vulnerability_resolution_events;
