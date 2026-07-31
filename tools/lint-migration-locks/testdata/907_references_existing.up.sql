-- The new table is invisible to other sessions, but the inline
-- REFERENCES takes SHARE ROW EXCLUSIVE on the pre-existing parent.
CREATE TABLE sample_children (
    id        UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);
