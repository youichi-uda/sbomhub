-- Measured on PostgreSQL 15.18:
--   REINDEX SCHEMA / DATABASE / SYSTEM cannot run inside a transaction
--   block, while REINDEX INDEX / TABLE can.
SET LOCAL lock_timeout = '5s';

REINDEX SCHEMA public;
