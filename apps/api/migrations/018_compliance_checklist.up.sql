-- METI Guideline Compliance Checklist Responses
-- Stores manual responses for checklist items that cannot be auto-verified

CREATE TABLE compliance_checklist_responses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    check_id VARCHAR(50) NOT NULL,
    response BOOLEAN NOT NULL DEFAULT FALSE,
    note TEXT,
    updated_by VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(project_id, check_id)
);

CREATE INDEX idx_compliance_checklist_project ON compliance_checklist_responses(project_id);
CREATE INDEX idx_compliance_checklist_tenant ON compliance_checklist_responses(tenant_id);

-- SBOM Visualization Framework Settings
-- Stores project-level settings for METI visualization framework

CREATE TABLE sbom_visualization_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,

    -- (a) SBOM作成主体 (Who)
    sbom_author_scope VARCHAR(50) DEFAULT 'self',
    -- 'self', 'supplier_contracted', 'supplier_thirdparty'

    -- (b) 依存関係 (What, Where)
    dependency_scope VARCHAR(50) DEFAULT 'direct_only',
    -- 'direct_only', 'indirect_included'

    -- (c) 生成手段 (How)
    generation_method VARCHAR(50) DEFAULT 'tool_no_review',
    -- 'manual', 'tool_no_review', 'tool_with_review', 'independent_verification'

    -- (d) データ様式・項目 (What)
    data_format VARCHAR(50) DEFAULT 'standard',
    -- 'standard', 'minimum_elements', 'partial'

    -- (e) 活用範囲 (Why) - stored as JSON array
    utilization_scope JSONB DEFAULT '["vuln_identification"]',
    -- ["vuln_identification", "severity_assessment", "exploitability_assessment", "license_check"]

    -- (f) 活用主体 (Who)
    utilization_actor VARCHAR(50) DEFAULT 'product_vendor',
    -- 'end_user', 'product_vendor', 'component_developer'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(project_id)
);

CREATE INDEX idx_visualization_settings_project ON sbom_visualization_settings(project_id);
CREATE INDEX idx_visualization_settings_tenant ON sbom_visualization_settings(tenant_id);
