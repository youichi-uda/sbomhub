-- License policies table
CREATE TABLE license_policies (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    license_id VARCHAR(100) NOT NULL,
    license_name VARCHAR(255) NOT NULL,
    policy_type VARCHAR(20) NOT NULL CHECK (policy_type IN ('allowed', 'denied', 'review')),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for efficient queries
CREATE INDEX idx_license_policies_project_id ON license_policies(project_id);
CREATE INDEX idx_license_policies_license_id ON license_policies(license_id);
CREATE INDEX idx_license_policies_policy_type ON license_policies(policy_type);

-- Unique constraint to prevent duplicate policies for same project/license combination
CREATE UNIQUE INDEX idx_license_policies_unique ON license_policies(project_id, license_id);
