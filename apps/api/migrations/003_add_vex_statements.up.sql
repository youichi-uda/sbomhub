-- VEX (Vulnerability Exploitability eXchange) statements table
CREATE TABLE vex_statements (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    component_id UUID REFERENCES components(id) ON DELETE SET NULL,
    status VARCHAR(30) NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation')),
    justification VARCHAR(100),
    action_statement TEXT,
    impact_statement TEXT,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for efficient queries
CREATE INDEX idx_vex_statements_project_id ON vex_statements(project_id);
CREATE INDEX idx_vex_statements_vulnerability_id ON vex_statements(vulnerability_id);
CREATE INDEX idx_vex_statements_status ON vex_statements(status);

-- Unique constraint to prevent duplicate VEX statements for same project/vulnerability/component combination
CREATE UNIQUE INDEX idx_vex_statements_unique ON vex_statements(project_id, vulnerability_id, COALESCE(component_id, '00000000-0000-0000-0000-000000000000'::uuid));
