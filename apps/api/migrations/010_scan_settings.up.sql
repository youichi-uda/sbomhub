-- Scan settings for scheduled vulnerability scanning
CREATE TABLE scan_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    enabled BOOLEAN DEFAULT true,
    schedule_type VARCHAR(20) DEFAULT 'daily',  -- 'hourly', 'daily', 'weekly'
    schedule_hour INTEGER DEFAULT 6,            -- 0-23
    schedule_day INTEGER,                       -- 0-6 (Sunday-Saturday) for weekly
    
    notify_critical BOOLEAN DEFAULT true,
    notify_high BOOLEAN DEFAULT true,
    notify_medium BOOLEAN DEFAULT false,
    notify_low BOOLEAN DEFAULT false,
    
    last_scan_at TIMESTAMP WITH TIME ZONE,
    next_scan_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(tenant_id)
);

-- Scan execution logs
CREATE TABLE scan_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'completed', 'failed'
    
    projects_scanned INTEGER DEFAULT 0,
    new_vulnerabilities INTEGER DEFAULT 0,
    error_message TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for efficient queries
CREATE INDEX idx_scan_settings_tenant_id ON scan_settings(tenant_id);
CREATE INDEX idx_scan_settings_next_scan ON scan_settings(next_scan_at) WHERE enabled = true;
CREATE INDEX idx_scan_logs_tenant_id ON scan_logs(tenant_id);
CREATE INDEX idx_scan_logs_created_at ON scan_logs(created_at DESC);
