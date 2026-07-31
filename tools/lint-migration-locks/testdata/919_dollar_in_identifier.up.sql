-- `begin$$` is one identifier, not the start of a dollar-quoted body.
-- PostgreSQL 15.18 executes all three statements below; a lexer that
-- opens a dollar quote at the first `$` swallows the ALTER TABLE.
SELECT 1 AS begin$$;
ALTER TABLE components ADD COLUMN dollar_probe INTEGER;
SELECT 2 AS end$$;
