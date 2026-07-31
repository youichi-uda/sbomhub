-- Everything here targets a relation this file creates, so the ACCESS
-- EXCLUSIVE locks have no other session to block. No budget required.
CREATE TABLE sample_widgets (
    id   UUID PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE INDEX idx_sample_widgets_name ON sample_widgets(name);

ALTER TABLE sample_widgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE sample_widgets FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_sample_widgets ON sample_widgets
    FOR ALL USING (true);

ALTER TABLE sample_widgets ADD COLUMN note TEXT;

DROP INDEX idx_sample_widgets_name;
