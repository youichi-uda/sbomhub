-- ============================================
-- Reverse of 055_vulnerabilities_epss.up.sql (M36-A / #154 / F432).
--
-- Drops the EPSS index and the three EPSS columns added by 055,
-- reverting vulnerabilities to its pre-055 shape. Fully round-trippable:
-- the columns carry only externally-sourced FIRST.org data (no backfill,
-- no derived state), so dropping them loses nothing that cannot be
-- re-synced. The COMMENT ON COLUMN annotations are dropped together with
-- their columns. RLS is untouched (vulnerabilities is a global, non-tenant
-- structural exemption; 055 declared no RLS). Index dropped first, then
-- the columns, mirroring the 020_kev_integration down order.
-- ============================================

DROP INDEX IF EXISTS idx_vulnerabilities_epss;

ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_score;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_percentile;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_updated_at;
