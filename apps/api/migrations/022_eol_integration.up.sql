-- EOL (End of Life) integration using endoflife.date API
-- https://endoflife.date/api

-- EOL products table (cached from endoflife.date)
CREATE TABLE eol_products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,          -- Product identifier (e.g., "python", "nodejs")
    title VARCHAR(255) NOT NULL,                 -- Human-readable name (e.g., "Python", "Node.js")
    category VARCHAR(100),                       -- Category (e.g., "programming-language", "database")
    link VARCHAR(500),                           -- Link to product page
    total_cycles INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_eol_products_name ON eol_products(name);
CREATE INDEX idx_eol_products_category ON eol_products(category);

-- EOL product cycles table (version lifecycle information)
CREATE TABLE eol_product_cycles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES eol_products(id) ON DELETE CASCADE,
    cycle VARCHAR(100) NOT NULL,                 -- Version cycle (e.g., "3.11", "18")
    release_date DATE,                           -- Release date
    eol_date DATE,                               -- End of Life date (can be NULL if ongoing)
    eos_date DATE,                               -- End of Support date (security fixes end)
    latest_version VARCHAR(100),                 -- Latest version in this cycle
    is_lts BOOLEAN DEFAULT false,                -- Long Term Support
    is_eol BOOLEAN DEFAULT false,                -- End of Life reached
    discontinued BOOLEAN DEFAULT false,          -- Completely discontinued
    link VARCHAR(500),                           -- Link to release notes
    support_end_date DATE,                       -- When active support ends
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (product_id, cycle)
);

CREATE INDEX idx_eol_cycles_product ON eol_product_cycles(product_id);
CREATE INDEX idx_eol_cycles_eol_date ON eol_product_cycles(eol_date);
CREATE INDEX idx_eol_cycles_eos_date ON eol_product_cycles(eos_date);
CREATE INDEX idx_eol_cycles_is_eol ON eol_product_cycles(is_eol) WHERE is_eol = true;

-- Component to product mapping table (for automatic matching)
CREATE TABLE eol_component_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES eol_products(id) ON DELETE CASCADE,
    component_pattern VARCHAR(255) NOT NULL,     -- Regex or exact match pattern
    component_type VARCHAR(100),                 -- Package type (e.g., "npm", "pypi", "maven")
    purl_type VARCHAR(100),                      -- PURL type (e.g., "npm", "pypi", "maven")
    priority INTEGER DEFAULT 0,                  -- Higher = more specific match
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (product_id, component_pattern, component_type)
);

CREATE INDEX idx_eol_mappings_pattern ON eol_component_mappings(component_pattern);
CREATE INDEX idx_eol_mappings_type ON eol_component_mappings(component_type);
CREATE INDEX idx_eol_mappings_purl ON eol_component_mappings(purl_type);

-- EOL sync settings (global, not per-tenant)
CREATE TABLE eol_sync_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enabled BOOLEAN NOT NULL DEFAULT true,
    sync_interval_hours INTEGER NOT NULL DEFAULT 24,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    total_products INTEGER NOT NULL DEFAULT 0,
    total_cycles INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Insert default settings
INSERT INTO eol_sync_settings (enabled, sync_interval_hours)
VALUES (true, 24);

-- EOL sync logs
CREATE TABLE eol_sync_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL DEFAULT 'running',  -- 'running', 'success', 'failed'
    products_synced INTEGER NOT NULL DEFAULT 0,
    cycles_synced INTEGER NOT NULL DEFAULT 0,
    components_updated INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);

CREATE INDEX idx_eol_sync_logs_started ON eol_sync_logs(started_at DESC);

-- Add EOL fields to components table
ALTER TABLE components ADD COLUMN IF NOT EXISTS eol_status VARCHAR(20) DEFAULT 'unknown';
ALTER TABLE components ADD COLUMN IF NOT EXISTS eol_product_id UUID REFERENCES eol_products(id);
ALTER TABLE components ADD COLUMN IF NOT EXISTS eol_cycle_id UUID REFERENCES eol_product_cycles(id);
ALTER TABLE components ADD COLUMN IF NOT EXISTS eol_date DATE;
ALTER TABLE components ADD COLUMN IF NOT EXISTS eos_date DATE;
ALTER TABLE components ADD COLUMN IF NOT EXISTS eol_checked_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX idx_components_eol_status ON components(eol_status);
CREATE INDEX idx_components_eol_product ON components(eol_product_id);
CREATE INDEX idx_components_eol_date ON components(eol_date);

-- Pre-populate common component to product mappings
INSERT INTO eol_products (name, title, category) VALUES
    ('python', 'Python', 'programming-language'),
    ('nodejs', 'Node.js', 'runtime'),
    ('go', 'Go', 'programming-language'),
    ('ruby', 'Ruby', 'programming-language'),
    ('php', 'PHP', 'programming-language'),
    ('java', 'Java', 'runtime'),
    ('dotnet', '.NET', 'framework'),
    ('django', 'Django', 'framework'),
    ('rails', 'Ruby on Rails', 'framework'),
    ('spring-framework', 'Spring Framework', 'framework'),
    ('react', 'React', 'library'),
    ('angular', 'Angular', 'framework'),
    ('vue', 'Vue.js', 'framework'),
    ('postgresql', 'PostgreSQL', 'database'),
    ('mysql', 'MySQL', 'database'),
    ('mariadb', 'MariaDB', 'database'),
    ('mongodb', 'MongoDB', 'database'),
    ('redis', 'Redis', 'database'),
    ('elasticsearch', 'Elasticsearch', 'database'),
    ('nginx', 'nginx', 'server'),
    ('apache', 'Apache HTTP Server', 'server'),
    ('kubernetes', 'Kubernetes', 'container'),
    ('docker-engine', 'Docker Engine', 'container'),
    ('ubuntu', 'Ubuntu', 'os'),
    ('debian', 'Debian', 'os'),
    ('centos', 'CentOS', 'os'),
    ('rhel', 'Red Hat Enterprise Linux', 'os'),
    ('amazon-linux', 'Amazon Linux', 'os'),
    ('alpine', 'Alpine Linux', 'os'),
    ('express', 'Express.js', 'framework'),
    ('flask', 'Flask', 'framework'),
    ('fastapi', 'FastAPI', 'framework'),
    ('laravel', 'Laravel', 'framework'),
    ('symfony', 'Symfony', 'framework'),
    ('jquery', 'jQuery', 'library'),
    ('bootstrap', 'Bootstrap', 'library'),
    ('lodash', 'Lodash', 'library'),
    ('webpack', 'webpack', 'tool'),
    ('typescript', 'TypeScript', 'language'),
    ('terraform', 'Terraform', 'tool'),
    ('ansible', 'Ansible', 'tool')
ON CONFLICT (name) DO NOTHING;

-- Insert component mappings for common packages
INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'python', 'runtime', 'pypi', 100 FROM eol_products WHERE name = 'python'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'node', 'runtime', 'npm', 100 FROM eol_products WHERE name = 'nodejs'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'django', 'library', 'pypi', 90 FROM eol_products WHERE name = 'django'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'rails', 'library', 'gem', 90 FROM eol_products WHERE name = 'rails'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'react', 'library', 'npm', 80 FROM eol_products WHERE name = 'react'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, '@angular/core', 'library', 'npm', 80 FROM eol_products WHERE name = 'angular'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'vue', 'library', 'npm', 80 FROM eol_products WHERE name = 'vue'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'express', 'library', 'npm', 70 FROM eol_products WHERE name = 'express'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'flask', 'library', 'pypi', 70 FROM eol_products WHERE name = 'flask'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'fastapi', 'library', 'pypi', 70 FROM eol_products WHERE name = 'fastapi'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'laravel', 'library', 'composer', 70 FROM eol_products WHERE name = 'laravel'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'spring-boot', 'library', 'maven', 70 FROM eol_products WHERE name = 'spring-framework'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'spring-core', 'library', 'maven', 70 FROM eol_products WHERE name = 'spring-framework'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'jquery', 'library', 'npm', 60 FROM eol_products WHERE name = 'jquery'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'bootstrap', 'library', 'npm', 60 FROM eol_products WHERE name = 'bootstrap'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'lodash', 'library', 'npm', 60 FROM eol_products WHERE name = 'lodash'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'typescript', 'library', 'npm', 80 FROM eol_products WHERE name = 'typescript'
ON CONFLICT DO NOTHING;

INSERT INTO eol_component_mappings (product_id, component_pattern, component_type, purl_type, priority)
SELECT id, 'webpack', 'library', 'npm', 60 FROM eol_products WHERE name = 'webpack'
ON CONFLICT DO NOTHING;
