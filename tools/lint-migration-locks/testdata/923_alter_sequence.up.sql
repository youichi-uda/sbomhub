-- Measured on PostgreSQL 15.18: ALTER SEQUENCE takes
-- ShareRowExclusiveLock (plus RowExclusiveLock) on the sequence.
ALTER SEQUENCE component_id_seq RESTART WITH 10;
