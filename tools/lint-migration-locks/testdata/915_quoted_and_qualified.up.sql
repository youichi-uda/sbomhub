-- Schema-qualified and double-quoted identifiers must resolve to the
-- same relation as their bare spelling.
CREATE TABLE public."sample_quoted" (
    id UUID PRIMARY KEY
);

ALTER TABLE public."sample_quoted" ADD COLUMN extra TEXT;
