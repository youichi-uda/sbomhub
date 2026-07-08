-- ============================================
-- Reverse of 056_advisory_excerpts_source_osv.up.sql
-- (M43 Wave 3 / issue #169 / F467).
--
-- Restores the 3-value source registry from migration 033. Any 'osv'
-- rows written by the CVE sync scheduler MUST be deleted before the
-- 3-value CHECK returns, otherwise the down migration would either fail
-- validation or (with NOT VALID) leave rows behind that violate the
-- restored registry on their next UPDATE. The rows are safe to drop:
-- they carry only externally-sourced OSV / Go-vulndb data that the
-- scheduler re-fetches and re-upserts on its next sync tick after a
-- re-apply of 056 (idempotent on the (tenant_id, cve_id, source) key).
--
-- Why RLS is toggled around the DELETE:
--   advisory_excerpts is ENABLE + FORCE ROW LEVEL SECURITY (033) and the
--   migration runs under the NOBYPASSRLS sbomhub_migrator role with no
--   app.current_tenant_id GUC set. Under the 033 policy a bare DELETE
--   would silently match ZERO rows (the missing_ok GUC read yields NULL,
--   so the USING predicate is never true) — the down would "succeed"
--   while leaving every 'osv' row in place. Disabling RLS for the DELETE
--   makes the cleanup real; ENABLE + FORCE are re-asserted immediately
--   after, restoring the exact 033 state. golang-migrate runs this file
--   inside a single transaction and the ALTERs hold an ACCESS EXCLUSIVE
--   lock, so there is no concurrent window where tenant rows are
--   readable without RLS.
--
-- Why the restored CHECK is NOT VALID (050 / 045 precedent):
--   Same NOBYPASSRLS validation-scan hazard as the up migration. The
--   skipped validation is vacuous: the DELETE above removed every 'osv'
--   row, and all remaining rows predate 056 (or were written under its
--   CHECK) with source in {nvd, ghsa, jvn}.
-- ============================================

ALTER TABLE advisory_excerpts DISABLE ROW LEVEL SECURITY;

DELETE FROM advisory_excerpts WHERE source = 'osv';

ALTER TABLE advisory_excerpts ENABLE ROW LEVEL SECURITY;
ALTER TABLE advisory_excerpts FORCE  ROW LEVEL SECURITY;

ALTER TABLE advisory_excerpts
    DROP CONSTRAINT IF EXISTS advisory_excerpts_source_check;

ALTER TABLE advisory_excerpts
    ADD CONSTRAINT advisory_excerpts_source_check
    CHECK (source IN ('nvd', 'ghsa', 'jvn'))
    NOT VALID;

COMMENT ON CONSTRAINT advisory_excerpts_source_check ON advisory_excerpts IS
    'Restored by 056 down: 033-era closed source registry (nvd, ghsa, jvn). NOT VALID (050 precedent): existing rows are not re-validated at apply time; the 056 down DELETE already removed every osv row.';
