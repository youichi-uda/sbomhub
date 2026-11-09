-- ============================================
-- Rollback of 069: drop vulnerabilities.cvss_version (and its CHECK, which
-- goes with the column).
--
-- Data: the recorded versions are lost. cvss_score and severity are kept and
-- stay as the M67 rule derived them; an older binary simply stops recording
-- which version they came from. The M67 binary needs the column (every
-- catalogue write names it), so roll the binary back first.
--
-- LOCK BUDGET: same as the up file. DROP COLUMN is metadata-only but takes
--   ACCESS EXCLUSIVE.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS cvss_version;
