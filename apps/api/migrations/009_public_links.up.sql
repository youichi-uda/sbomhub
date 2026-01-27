-- ============================================
-- SBOMHub Public Links Migration
-- ============================================

CREATE TABLE public_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    sbom_id UUID REFERENCES sboms(id) ON DELETE SET NULL,

    token VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,

    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT true,

    allowed_downloads INTEGER,
    password_hash VARCHAR(255),

    view_count INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_public_links_token ON public_links(token);
CREATE INDEX idx_public_links_tenant ON public_links(tenant_id);
CREATE INDEX idx_public_links_project ON public_links(project_id);

CREATE TABLE public_link_access_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    public_link_id UUID NOT NULL REFERENCES public_links(id) ON DELETE CASCADE,
    action VARCHAR(20) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_public_link_access_logs_link ON public_link_access_logs(public_link_id);
CREATE INDEX idx_public_link_access_logs_created ON public_link_access_logs(created_at);

-- Enable RLS
ALTER TABLE public_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public_link_access_logs ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY tenant_isolation_public_links ON public_links
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_public_link_access_logs ON public_link_access_logs
    USING (public_link_id IN (
        SELECT id FROM public_links
        WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
    ));
