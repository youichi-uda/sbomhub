-- ============================================
-- Reverse of 054_cra_reports_awareness_time.up.sql.
--
-- Drops the operator-attested awareness_time column added by 054.
-- cra_reports reverts to the pre-054 shape (awareness instant flows only
-- into the rendered template prose, never persisted). The read-time
-- deadline / on-time computation that reads this column simply has no
-- source once it is gone. The COMMENT ON COLUMN is dropped together with
-- the column itself. RLS is untouched (054 did not declare it).
-- ============================================

ALTER TABLE cra_reports
    DROP COLUMN IF EXISTS awareness_time;
