-- CREATE INDEX CONCURRENTLY cannot run inside the runner's per-file
-- transaction; a budget does not make it legal.
SET LOCAL lock_timeout = '5s';

CREATE INDEX CONCURRENTLY idx_components_name ON components(name);
