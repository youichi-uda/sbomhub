-- GitHub integration tables
CREATE TABLE github_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Encrypted access token (PAT or OAuth token)
    access_token_encrypted TEXT NOT NULL,
    token_type VARCHAR(20) DEFAULT 'pat',  -- 'pat' or 'oauth'
    
    -- Token metadata
    username VARCHAR(255),
    scopes TEXT[],
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(tenant_id)
);

CREATE TABLE github_repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES github_connections(id) ON DELETE CASCADE,
    
    repo_full_name VARCHAR(255) NOT NULL,  -- 'owner/repo'
    branch VARCHAR(255) DEFAULT 'main',
    webhook_secret VARCHAR(255) NOT NULL,
    webhook_id BIGINT,  -- GitHub webhook ID for management
    
    auto_scan BOOLEAN DEFAULT true,
    
    last_scan_at TIMESTAMP WITH TIME ZONE,
    last_commit_sha VARCHAR(40),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(tenant_id, repo_full_name)
);

-- Index for efficient queries
CREATE INDEX idx_github_connections_tenant_id ON github_connections(tenant_id);
CREATE INDEX idx_github_repositories_tenant_id ON github_repositories(tenant_id);
CREATE INDEX idx_github_repositories_project_id ON github_repositories(project_id);
CREATE INDEX idx_github_repositories_repo_name ON github_repositories(repo_full_name);
