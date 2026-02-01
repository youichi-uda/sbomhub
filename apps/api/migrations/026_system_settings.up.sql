-- System settings table for storing global configuration
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(key);

-- Insert default CVE sync setting
INSERT INTO system_settings (key, value, description)
VALUES ('cve_sync_last_run', NOW()::text, 'Last time CVE sync job ran')
ON CONFLICT (key) DO NOTHING;
