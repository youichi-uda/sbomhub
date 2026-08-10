-- ============================================
-- Rollback of 066: drop vulnerabilities.source_modified_at.
--
-- What is lost, and what that costs:
--   The column is the ONLY record of how old the upstream record behind a
--   row's metadata is. Dropping it discards that for every row, and the
--   value cannot be reconstructed — re-applying 066 starts every row at NULL
--   again (066 performs no backfill, in either direction).
--
--   The older binary this rollback exists for refreshes catalogue metadata
--   with an unguarded UPDATE, so while 066 is rolled back a replayed OLDER
--   NVD record downgrades a row's severity again — the exact defect 066 was
--   added to arbitrate. Nothing here can prevent that; it is a property of
--   the older binary, so treat it as an accepted cost of the rollback rather
--   than an oversight. If the rollback is expected to last, disable the
--   cve_sync scheduler job while it does.
--
-- RLS: untouched. `vulnerabilities` is the global, non-tenant CVE catalogue
--   (structural exemption; 066 declared no RLS).
--
-- LOCK BUDGET: see 063. `DROP COLUMN` does not rewrite the table (the column
--   is marked dropped and the space is reclaimed lazily), but it takes ACCESS
--   EXCLUSIVE on `vulnerabilities` and holds it until COMMIT, so acquiring it
--   can queue behind a live reader and every waiter queues behind us. Same
--   bounded-wait rationale as the up file.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS source_modified_at;
