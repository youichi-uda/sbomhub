-- ============================================
-- Rollback of 072: drop the JVNDB RSS tables.
--
-- What is lost: every stored JVNDB advisory, its CVE mapping and the feed
-- state. Nothing else references these tables, and no other table changes.
-- Re-applying 072 starts empty; the next sync fetches the recent feed again
-- and, when SBOMHUB_JVNDB_RSS_BACKFILL_FROM is set, re-runs the backfill.
--
-- Roll the binary back with the schema: this release reads jvndb_* on every
-- project vulnerability list, which fails while the tables are missing.
--
-- LOCK BUDGET: DROP TABLE takes ACCESS EXCLUSIVE on the dropped tables, which
-- the vulnerability list reads. Bounded wait, same rationale as 063.
-- ============================================

SET LOCAL lock_timeout = '5s';

DROP TABLE IF EXISTS jvndb_advisory_cves;
DROP TABLE IF EXISTS jvndb_advisories;
DROP TABLE IF EXISTS jvndb_feed_state;
