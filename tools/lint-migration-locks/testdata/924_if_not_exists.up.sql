-- `CREATE TABLE IF NOT EXISTS` proves nothing: if the relation already
-- exists the statement is a no-op and everything after it contends with
-- live traffic. The same-file exemption must not be granted here.
CREATE TABLE IF NOT EXISTS maybe_existing (id UUID PRIMARY KEY);

ALTER TABLE maybe_existing ADD COLUMN extra TEXT;
