-- Analytics tables for trend analysis

-- Vulnerability resolution events for MTTR calculation
CREATE TABLE vulnerability_resolution_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_type VARCHAR(50), -- 'fixed', 'mitigated', 'accepted', 'false_positive'
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vuln_resolution_tenant ON vulnerability_resolution_events(tenant_id);
CREATE INDEX idx_vuln_resolution_project ON vulnerability_resolution_events(project_id);
CREATE INDEX idx_vuln_resolution_dates ON vulnerability_resolution_events(detected_at, resolved_at);
CREATE INDEX idx_vuln_resolution_severity ON vulnerability_resolution_events(severity);

-- SLO targets per severity
CREATE TABLE slo_targets (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,
    target_hours INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, severity)
);

-- Insert default SLO targets (null tenant_id = global defaults)
INSERT INTO slo_targets (id, tenant_id, severity, target_hours) VALUES
    (gen_random_uuid(), NULL, 'CRITICAL', 24),
    (gen_random_uuid(), NULL, 'HIGH', 168),     -- 7 days
    (gen_random_uuid(), NULL, 'MEDIUM', 720),   -- 30 days
    (gen_random_uuid(), NULL, 'LOW', 2160);     -- 90 days

-- Daily vulnerability snapshots for trend analysis
CREATE TABLE vulnerability_snapshots (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    snapshot_date DATE NOT NULL,
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    medium_count INT NOT NULL DEFAULT 0,
    low_count INT NOT NULL DEFAULT 0,
    total_count INT NOT NULL DEFAULT 0,
    resolved_count INT NOT NULL DEFAULT 0,
    mttr_hours DECIMAL(10, 2), -- Average MTTR for the day
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, snapshot_date)
);

CREATE INDEX idx_vuln_snapshot_tenant_date ON vulnerability_snapshots(tenant_id, snapshot_date DESC);

-- Compliance score history
CREATE TABLE compliance_snapshots (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_date DATE NOT NULL,
    overall_score INT NOT NULL,
    max_score INT NOT NULL,
    sbom_generation_score INT NOT NULL DEFAULT 0,
    vulnerability_management_score INT NOT NULL DEFAULT 0,
    license_management_score INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, project_id, snapshot_date)
);

CREATE INDEX idx_compliance_snapshot_tenant ON compliance_snapshots(tenant_id, snapshot_date DESC);
CREATE INDEX idx_compliance_snapshot_project ON compliance_snapshots(project_id, snapshot_date DESC);

-- Enable RLS
ALTER TABLE vulnerability_resolution_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE slo_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_snapshots ENABLE ROW LEVEL SECURITY;

-- RLS policies
CREATE POLICY "vuln_resolution_tenant_isolation" ON vulnerability_resolution_events
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY "slo_targets_tenant_isolation" ON slo_targets
    FOR ALL USING (
        tenant_id IS NULL OR
        tenant_id = current_setting('app.current_tenant_id')::uuid
    );

CREATE POLICY "vuln_snapshot_tenant_isolation" ON vulnerability_snapshots
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY "compliance_snapshot_tenant_isolation" ON compliance_snapshots
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
