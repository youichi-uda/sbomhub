-- ============================================
-- Reverse of 051_ticket_external_project_key.up.sql.
--
-- Drops the per-ticket external_project_key column added by 051.
-- vulnerability_tickets reverts to the pre-051 shape from migration 015
-- (repository known only via the connection default / the ticket URL).
-- The COMMENT ON COLUMN is dropped together with the column itself.
-- ============================================

ALTER TABLE vulnerability_tickets
    DROP COLUMN IF EXISTS external_project_key;
