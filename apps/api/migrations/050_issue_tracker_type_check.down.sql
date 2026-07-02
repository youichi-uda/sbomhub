-- ============================================
-- Reverse of 050_issue_tracker_type_check.up.sql.
--
-- Drops the tracker_type CHECK registry constraint added by 050.
-- issue_tracker_connections.tracker_type reverts to the pre-050
-- unconstrained VARCHAR(20) shape from migration 015 (comment-only
-- registry). The COMMENT ON CONSTRAINT is dropped together with the
-- constraint itself.
-- ============================================

ALTER TABLE issue_tracker_connections
    DROP CONSTRAINT IF EXISTS issue_tracker_connections_tracker_type_check;
