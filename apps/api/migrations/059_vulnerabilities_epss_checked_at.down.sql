-- ============================================
-- Reverse of 059_vulnerabilities_epss_checked_at.up.sql (M46 Codex final
-- round, Low #2).
--
-- Drops epss_checked_at and restores migration 055's original COMMENT text
-- on epss_updated_at verbatim, reverting vulnerabilities to its post-055
-- shape. Fully round-trippable: epss_checked_at carries only a derived
-- freshness timestamp (no backfill, no state any other column depends on),
-- so dropping it loses nothing that the next epss_sync cannot re-establish.
-- The COMMENT ON COLUMN annotation is dropped together with its column.
--
-- ROLLBACK SEQUENCING -- read before running this down:
--   This migration is NOT safe to apply under an application build that
--   expects 059. Three statements in repository/vulnerability.go name
--   epss_checked_at directly -- UpdateEPSSScores writes it, and GetByID /
--   GetByCVE both SELECT it -- so once the column is dropped, every EPSS
--   sync write and every single-vulnerability read fails with
--   `column "epss_checked_at" does not exist` (i.e. 500s on the
--   vulnerability detail path, not merely a lost freshness signal). Roll the
--   API binary back to a pre-059 build FIRST, then run this down. The
--   reverse order (down first) takes the detail endpoints out of service
--   until the binary follows.
--
--   The writer's OTHER 059 behaviour -- epss_updated_at moving only when a
--   score is actually written -- needs no rollback: it is exactly what
--   migration 055's COMMENT (restored below) already specified.
--
-- RLS is untouched (vulnerabilities is a global, non-tenant structural
-- exemption; 059 declared no RLS).
-- ============================================

ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_checked_at;

COMMENT ON COLUMN vulnerabilities.epss_updated_at IS
    'M36-A / F432 (#154): timestamp of the last successful EPSS sync for this CVE (TIMESTAMPTZ). Global non-tenant attribute. NULL until the scheduled epss_sync (M36-B) writes a score. Promoted verbatim from orphan packages/db 006_epss.sql.';
