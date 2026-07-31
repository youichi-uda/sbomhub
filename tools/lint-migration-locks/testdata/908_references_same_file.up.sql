-- Both sides of the FK are created here, so nothing pre-existing is
-- locked and no budget is required.
CREATE TABLE sample_parents (
    id UUID PRIMARY KEY
);

CREATE TABLE sample_kids (
    id        UUID PRIMARY KEY,
    parent_id UUID NOT NULL REFERENCES sample_parents(id)
);
