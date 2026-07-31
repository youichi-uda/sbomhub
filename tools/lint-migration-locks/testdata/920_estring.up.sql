-- With standard_conforming_strings = on (the PostgreSQL 15 default) a
-- backslash is literal in a plain string but an escape in an E-string.
-- Measured: SELECT E'foo\'; SELECT harmless' returns ONE value,
-- `foo'; SELECT harmless` — the semicolon is inside the literal.
SELECT E'foo\'; SELECT harmless' AS estr;
ALTER TABLE components ADD COLUMN estring_probe INTEGER;
