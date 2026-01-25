CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    format VARCHAR(50) NOT NULL,
    version VARCHAR(50),
    raw_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE components (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    name VARCHAR(500) NOT NULL,
    version VARCHAR(200),
    type VARCHAR(100),
    purl VARCHAR(1000),
    license VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    published_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE component_vulnerabilities (
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (component_id, vulnerability_id)
);

CREATE INDEX idx_sboms_project_id ON sboms(project_id);
CREATE INDEX idx_components_sbom_id ON components(sbom_id);
CREATE INDEX idx_components_purl ON components(purl);
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
