-- A DO block whose body contains semicolons, `--` comments and quoted
-- text that includes SQL keywords. It must lex as ONE statement and must
-- not be mistaken for DDL.
DO $$
DECLARE
    n INTEGER;
BEGIN
    SELECT COUNT(*) INTO n
    FROM projects p   -- inline comment; with a semicolon
    WHERE p.tenant_id IS NULL;

    IF n > 0 THEN
        RAISE EXCEPTION 'fixture 912: % rows; run ALTER TABLE projects '
            'ADD COLUMN by hand; then retry', n;
    END IF;
END $$;
