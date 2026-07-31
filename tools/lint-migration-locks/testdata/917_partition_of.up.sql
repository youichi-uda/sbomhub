-- `CREATE TABLE … PARTITION OF parent` takes ACCESS EXCLUSIVE on the
-- PARENT, which is pre-existing. The new partition itself is invisible to
-- other sessions, so a naive "CREATE TABLE is always safe" rule misses it.
--
-- Measured on PostgreSQL 15.18: pg_locks on the parent -> AccessExclusiveLock
CREATE TABLE components_2026 PARTITION OF components
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
