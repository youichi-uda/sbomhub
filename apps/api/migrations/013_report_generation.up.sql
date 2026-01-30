-- Report generation tables

-- Report settings for scheduled reports
CREATE TABLE report_settings (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    report_type VARCHAR(50) NOT NULL, -- 'executive', 'technical', 'compliance'
    schedule_type VARCHAR(20) NOT NULL DEFAULT 'monthly', -- 'weekly', 'monthly'
    schedule_day INTEGER NOT NULL DEFAULT 1, -- 1-7 for weekly, 1-28 for monthly
    schedule_hour INTEGER NOT NULL DEFAULT 9, -- 0-23
    format VARCHAR(10) NOT NULL DEFAULT 'pdf', -- 'pdf', 'xlsx'
    email_enabled BOOLEAN NOT NULL DEFAULT false,
    email_recipients TEXT[], -- array of email addresses
    include_sections TEXT[] DEFAULT ARRAY['summary', 'vulnerabilities', 'compliance'], -- sections to include
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, report_type)
);

CREATE INDEX idx_report_settings_tenant ON report_settings(tenant_id);
CREATE INDEX idx_report_settings_enabled ON report_settings(enabled) WHERE enabled = true;

-- Generated reports history
CREATE TABLE generated_reports (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    settings_id UUID REFERENCES report_settings(id) ON DELETE SET NULL,
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(10) NOT NULL,
    title VARCHAR(255) NOT NULL,
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    file_path TEXT NOT NULL, -- path to stored file
    file_size INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'generating', 'completed', 'failed', 'emailed'
    error_message TEXT,
    generated_by UUID REFERENCES users(id) ON DELETE SET NULL, -- null for scheduled
    email_sent_at TIMESTAMP WITH TIME ZONE,
    email_recipients TEXT[],
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_generated_reports_tenant ON generated_reports(tenant_id, created_at DESC);
CREATE INDEX idx_generated_reports_status ON generated_reports(status);

-- Enable RLS
ALTER TABLE report_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE generated_reports ENABLE ROW LEVEL SECURITY;

-- RLS policies
CREATE POLICY "report_settings_tenant_isolation" ON report_settings
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY "generated_reports_tenant_isolation" ON generated_reports
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
