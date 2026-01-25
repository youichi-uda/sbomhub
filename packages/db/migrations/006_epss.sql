-- 006_epss.sql
-- Add EPSS (Exploit Prediction Scoring System) scores to vulnerabilities

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_score DECIMAL(5,4);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_percentile DECIMAL(5,4);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_epss ON vulnerabilities(epss_score DESC NULLS LAST);
