-- IPA integration tables

-- IPA announcements (from RSS feeds)
CREATE TABLE ipa_announcements (
    id UUID PRIMARY KEY,
    ipa_id VARCHAR(100) UNIQUE NOT NULL,
    title TEXT NOT NULL,
    title_ja TEXT,
    description TEXT,
    category VARCHAR(100), -- 'security_alert', 'vulnerability_note', 'technical_watch'
    severity VARCHAR(20), -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    source_url TEXT NOT NULL,
    related_cves TEXT[], -- array of related CVE IDs
    published_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ipa_announcements_published ON ipa_announcements(published_at DESC);
CREATE INDEX idx_ipa_announcements_category ON ipa_announcements(category);
CREATE INDEX idx_ipa_announcements_severity ON ipa_announcements(severity);

-- IPA sync settings per tenant
CREATE TABLE ipa_sync_settings (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    notify_on_new BOOLEAN NOT NULL DEFAULT true,
    notify_severity TEXT[] DEFAULT ARRAY['CRITICAL', 'HIGH'],
    last_sync_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

CREATE INDEX idx_ipa_sync_settings_tenant ON ipa_sync_settings(tenant_id);

-- Mapping between IPA announcements and vulnerabilities
CREATE TABLE ipa_vulnerability_mapping (
    id UUID PRIMARY KEY,
    ipa_announcement_id UUID NOT NULL REFERENCES ipa_announcements(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(ipa_announcement_id, cve_id)
);

CREATE INDEX idx_ipa_vuln_mapping_cve ON ipa_vulnerability_mapping(cve_id);

-- Enable RLS
ALTER TABLE ipa_sync_settings ENABLE ROW LEVEL SECURITY;

-- RLS policy
CREATE POLICY "ipa_sync_settings_tenant_isolation" ON ipa_sync_settings
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
