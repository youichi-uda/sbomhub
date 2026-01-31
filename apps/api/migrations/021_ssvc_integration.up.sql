-- SSVC (Stakeholder-Specific Vulnerability Categorization) integration
-- Based on CISA SSVC Decision Tree for Deployers

-- SSVC parameter types
CREATE TYPE ssvc_exploitation AS ENUM ('none', 'poc', 'active');
CREATE TYPE ssvc_automatable AS ENUM ('yes', 'no');
CREATE TYPE ssvc_technical_impact AS ENUM ('partial', 'total');
CREATE TYPE ssvc_mission_prevalence AS ENUM ('minimal', 'support', 'essential');
CREATE TYPE ssvc_safety_impact AS ENUM ('minimal', 'significant');
CREATE TYPE ssvc_decision AS ENUM ('defer', 'scheduled', 'out_of_cycle', 'immediate');

-- SSVC project defaults (organization/system-specific settings)
CREATE TABLE ssvc_project_defaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Default parameter values for this project/system
    mission_prevalence ssvc_mission_prevalence NOT NULL DEFAULT 'support',
    safety_impact ssvc_safety_impact NOT NULL DEFAULT 'minimal',
    -- Exposure context
    system_exposure VARCHAR(50) NOT NULL DEFAULT 'internet', -- 'internet', 'internal', 'airgap'
    -- Auto-assessment settings
    auto_assess_enabled BOOLEAN NOT NULL DEFAULT true,
    auto_assess_exploitation BOOLEAN NOT NULL DEFAULT true, -- Use KEV for exploitation
    auto_assess_automatable BOOLEAN NOT NULL DEFAULT true, -- Use EPSS for automatable
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(project_id)
);

CREATE INDEX idx_ssvc_project_defaults_project ON ssvc_project_defaults(project_id);
CREATE INDEX idx_ssvc_project_defaults_tenant ON ssvc_project_defaults(tenant_id);

-- Enable RLS
ALTER TABLE ssvc_project_defaults ENABLE ROW LEVEL SECURITY;

CREATE POLICY "ssvc_project_defaults_tenant_isolation" ON ssvc_project_defaults
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- SSVC assessments (per project per vulnerability)
CREATE TABLE ssvc_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    -- SSVC Parameters
    exploitation ssvc_exploitation NOT NULL,
    automatable ssvc_automatable NOT NULL,
    technical_impact ssvc_technical_impact NOT NULL,
    mission_prevalence ssvc_mission_prevalence NOT NULL,
    safety_impact ssvc_safety_impact NOT NULL,
    -- Computed decision
    decision ssvc_decision NOT NULL,
    -- Auto-assessed flags (true if parameter was auto-determined)
    exploitation_auto BOOLEAN NOT NULL DEFAULT false,
    automatable_auto BOOLEAN NOT NULL DEFAULT false,
    -- Metadata
    assessed_by UUID REFERENCES users(id),
    assessed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    notes TEXT,
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    -- One assessment per project-vulnerability pair
    UNIQUE(project_id, vulnerability_id)
);

CREATE INDEX idx_ssvc_assessments_project ON ssvc_assessments(project_id);
CREATE INDEX idx_ssvc_assessments_tenant ON ssvc_assessments(tenant_id);
CREATE INDEX idx_ssvc_assessments_vuln ON ssvc_assessments(vulnerability_id);
CREATE INDEX idx_ssvc_assessments_cve ON ssvc_assessments(cve_id);
CREATE INDEX idx_ssvc_assessments_decision ON ssvc_assessments(decision);
CREATE INDEX idx_ssvc_assessments_immediate ON ssvc_assessments(project_id) WHERE decision = 'immediate';

-- Enable RLS
ALTER TABLE ssvc_assessments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "ssvc_assessments_tenant_isolation" ON ssvc_assessments
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- SSVC assessment history (audit trail)
CREATE TABLE ssvc_assessment_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES ssvc_assessments(id) ON DELETE CASCADE,
    -- Previous values
    prev_exploitation ssvc_exploitation,
    prev_automatable ssvc_automatable,
    prev_technical_impact ssvc_technical_impact,
    prev_mission_prevalence ssvc_mission_prevalence,
    prev_safety_impact ssvc_safety_impact,
    prev_decision ssvc_decision,
    -- New values
    new_exploitation ssvc_exploitation NOT NULL,
    new_automatable ssvc_automatable NOT NULL,
    new_technical_impact ssvc_technical_impact NOT NULL,
    new_mission_prevalence ssvc_mission_prevalence NOT NULL,
    new_safety_impact ssvc_safety_impact NOT NULL,
    new_decision ssvc_decision NOT NULL,
    -- Metadata
    changed_by UUID REFERENCES users(id),
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    change_reason TEXT
);

CREATE INDEX idx_ssvc_assessment_history_assessment ON ssvc_assessment_history(assessment_id);
CREATE INDEX idx_ssvc_assessment_history_changed_at ON ssvc_assessment_history(changed_at DESC);

-- Add SSVC decision column to vulnerabilities for quick filtering
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_decision ssvc_decision;

CREATE INDEX idx_vulnerabilities_ssvc_decision ON vulnerabilities(ssvc_decision) WHERE ssvc_decision IS NOT NULL;
