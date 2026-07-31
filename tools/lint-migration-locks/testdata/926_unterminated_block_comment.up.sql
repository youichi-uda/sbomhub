-- An unterminated block comment swallows the rest of the file. Rather
-- than silently certifying whatever survived, the lint reports it.
/* this comment is never closed
ALTER TABLE components ADD COLUMN swallowed INTEGER;
