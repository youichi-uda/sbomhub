-- Issue tracker integration tables

-- Issue tracker connections (Jira, Backlog)
CREATE TABLE issue_tracker_connections (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tracker_type VARCHAR(20) NOT NULL, -- 'jira', 'backlog'
    name VARCHAR(255) NOT NULL,
    base_url TEXT NOT NULL,
    auth_type VARCHAR(20) NOT NULL DEFAULT 'api_token', -- 'api_token', 'oauth'
    auth_email VARCHAR(255), -- for Jira API token auth
    auth_token_encrypted TEXT NOT NULL,
    default_project_key VARCHAR(100),
    default_issue_type VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, tracker_type, name)
);

CREATE INDEX idx_issue_tracker_connections_tenant ON issue_tracker_connections(tenant_id);
CREATE INDEX idx_issue_tracker_connections_type ON issue_tracker_connections(tracker_type);

-- Vulnerability tickets
CREATE TABLE vulnerability_tickets (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES issue_tracker_connections(id) ON DELETE CASCADE,
    external_ticket_id VARCHAR(100) NOT NULL,
    external_ticket_key VARCHAR(100), -- e.g., PROJ-123
    external_ticket_url TEXT NOT NULL,
    local_status VARCHAR(50) NOT NULL DEFAULT 'open', -- 'open', 'in_progress', 'resolved', 'closed'
    external_status VARCHAR(100),
    priority VARCHAR(50),
    assignee VARCHAR(255),
    summary TEXT,
    last_synced_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(vulnerability_id, connection_id)
);

CREATE INDEX idx_vulnerability_tickets_tenant ON vulnerability_tickets(tenant_id);
CREATE INDEX idx_vulnerability_tickets_vulnerability ON vulnerability_tickets(vulnerability_id);
CREATE INDEX idx_vulnerability_tickets_project ON vulnerability_tickets(project_id);
CREATE INDEX idx_vulnerability_tickets_connection ON vulnerability_tickets(connection_id);
CREATE INDEX idx_vulnerability_tickets_status ON vulnerability_tickets(local_status);
CREATE INDEX idx_vulnerability_tickets_external ON vulnerability_tickets(external_ticket_id);

-- Enable RLS
ALTER TABLE issue_tracker_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_tickets ENABLE ROW LEVEL SECURITY;

-- RLS policies
CREATE POLICY "issue_tracker_connections_tenant_isolation" ON issue_tracker_connections
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY "vulnerability_tickets_tenant_isolation" ON vulnerability_tickets
    FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
