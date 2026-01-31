-- KEV (Known Exploited Vulnerabilities) integration
-- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

-- KEV catalog entries
CREATE TABLE kev_catalog (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    vendor_project VARCHAR(255) NOT NULL,
    product VARCHAR(255) NOT NULL,
    vulnerability_name TEXT NOT NULL,
    short_description TEXT,
    required_action TEXT,
    date_added DATE NOT NULL,
    due_date DATE NOT NULL,
    known_ransomware_use BOOLEAN NOT NULL DEFAULT false,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kev_catalog_cve ON kev_catalog(cve_id);
CREATE INDEX idx_kev_catalog_date_added ON kev_catalog(date_added DESC);
CREATE INDEX idx_kev_catalog_due_date ON kev_catalog(due_date);
CREATE INDEX idx_kev_catalog_vendor ON kev_catalog(vendor_project);
CREATE INDEX idx_kev_catalog_ransomware ON kev_catalog(known_ransomware_use) WHERE known_ransomware_use = true;

-- Add KEV fields to vulnerabilities table
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS in_kev BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS kev_date_added DATE;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS kev_due_date DATE;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS kev_ransomware_use BOOLEAN;

CREATE INDEX idx_vulnerabilities_kev ON vulnerabilities(in_kev) WHERE in_kev = true;

-- KEV sync settings (global, not per-tenant)
CREATE TABLE kev_sync_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enabled BOOLEAN NOT NULL DEFAULT true,
    sync_interval_hours INTEGER NOT NULL DEFAULT 24,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_catalog_version VARCHAR(50),
    total_entries INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Insert default settings
INSERT INTO kev_sync_settings (enabled, sync_interval_hours)
VALUES (true, 24);

-- KEV sync logs
CREATE TABLE kev_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL DEFAULT 'running', -- 'running', 'success', 'failed'
    new_entries INTEGER NOT NULL DEFAULT 0,
    updated_entries INTEGER NOT NULL DEFAULT 0,
    total_processed INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    catalog_version VARCHAR(50)
);

CREATE INDEX idx_kev_sync_logs_started ON kev_sync_logs(started_at DESC);
