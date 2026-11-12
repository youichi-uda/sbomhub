-- ============================================
-- Record WHICH CVSS version a stored score was taken from (M67).
--
-- The problem:
--   NVD publishes several CVSS assessments per CVE (v2, v3.0, v3.1, v4.0, each
--   possibly from several sources), and `vulnerabilities` stores one score and
--   one severity. Until M67 the writers disagreed on which version wins: the
--   daily CVE sync (scheduler/cve_sync.go, shared by the M58 monthly
--   re-read) took v4.0 first, the NVD scanner / search (service/nvd.go) v3.x
--   first. A CVE carrying both was therefore stored at whichever score the
--   last writer chose — on the recorded M60 fixtures (live NVD, 2026-11-08)
--   CVE-2026-34479 is v3.1 Primary 7.5 HIGH beside a v4.0 Secondary 6.9
--   MEDIUM, and its severity flipped between the two. Nothing on the row said
--   which scale the number was on.
--
--   M67 settles the rule in one function (internal/cvss.Select): v3.1 > v3.0
--   > v4.0 > v2, NVD's Primary over a Secondary within a version. This column
--   records the version of the assessment the row's cvss_score and severity
--   were derived from.
--
-- Semantics and who writes it:
--   '3.1' / '3.0' / '4.0' / '2.0'. NULL means one of:
--     - unscored (no usable CVSS assessment; cvss_score is NULL too);
--     - the feed's version label was not recognised (JVN only);
--     - the row was written before this migration.
--   Written by repository.VulnerabilityRepository.Create (NVD and JVN
--   scanners, NVD search), UpdateMetadata (CVE sync refresh and the M58
--   catalogue re-read) and the CVE sync's INSERT.
--
--   The third NULL case is load-bearing. UpdateMetadata refuses a record
--   whose upstream lastModified is not newer than the stored
--   source_modified_at, so on its own it would never re-derive a row the old
--   sync already dated: the M58 re-read offers exactly that timestamp again.
--   A DATED row (source_modified_at set) with NULL cvss_version is
--   recognisably pre-069: every writer that dates a row from here on (the CVE
--   sync, the catalogue re-read) records the version of any assessment it
--   writes. UpdateMetadata re-derives such a row ONCE at an equal timestamp
--   when the record carries an assessment AND was read from NVD itself — not
--   from a mirror set with SBOMHUB_NVD_URL, which could serve a stale body
--   under an unchanged timestamp; see the guard's comment.
--   Rows without a version are also created after 069 by the scanner
--   from a CPE-path cache hit (that cache does not carry the version yet), but
--   scanner rows are UNDATED, so the ordinary "stored NULL timestamp is
--   writable" rule refreshes them and the exception is never what reaches
--   them.
--
-- Mixed binaries (Codex M67 R1, High):
--   A pre-069 binary running against this schema refreshes cvss_score /
--   severity under ITS rule (v4.0 first) and leaves cvss_version as it was, so
--   a version a new binary recorded can end up beside a score it no longer
--   describes; at that same lastModified the new binary then refuses the
--   record. Stop every pre-069 API process before (or while) this migration is
--   applied — the docker compose upgrade does. If one kept running, run once
--   after it has stopped:
--       UPDATE vulnerabilities SET cvss_version = NULL
--       WHERE cvss_version IS NOT NULL AND source = 'NVD';
--   which returns every NVD-sourced scored row to the re-derivable state; the
--   next CVE sync / catalogue re-read re-derives each from NVD's record. It is
--   limited to source = 'NVD' because every NVD refresh writes that source,
--   and a JVN-only row (JVNDB id) can never be re-derived from NVD.
--
-- Mirrors (Codex M67 R6, High):
--   With SBOMHUB_NVD_URL pointing at a mirror the equal-timestamp
--   re-derivation is off, so pre-069 rows keep the old rule until NVD modifies
--   each CVE. To converge them anyway, once the mirror is known to be complete
--   and current, run:
--       UPDATE vulnerabilities SET source_modified_at = NULL
--       WHERE cvss_version IS NULL AND source = 'NVD'
--         AND source_modified_at IS NOT NULL;
--   which makes each row writable once by the next dated record (the guard's
--   documented operator escape hatch), from whichever source the sync reads.
--
-- No backfill:
--   The version of a legacy score was never captured, and inferring it from
--   the number is impossible (v3.1 7.5 and v4.0 7.5 are both possible).
--   Legacy rows converge through the CVE sync (CVEs NVD modifies) and the
--   monthly catalogue re-read (all others); there is no one-shot NVD backfill.
--
-- The CHECK is added NOT VALID and deliberately not validated: the column is
--   created in this same statement, so every existing row holds NULL, which
--   the constraint admits. VALIDATE would scan the whole table under the
--   ACCESS EXCLUSIVE lock this file already holds (the 064 / 065 lesson) to
--   prove what the DDL already guarantees. New and updated rows are checked.
--
-- RLS: untouched. `vulnerabilities` is the global, non-tenant CVE catalogue —
--   a recorded structural exemption in tools/lint-migration-rls (063).
--
-- LOCK BUDGET: same as 066. A nullable ADD COLUMN with no DEFAULT rewrites
--   nothing (PostgreSQL 11+) and a NOT VALID CHECK scans nothing, but the
--   statement takes ACCESS EXCLUSIVE on `vulnerabilities`, so ACQUIRING it
--   can queue behind a live reader with every later request queued behind
--   it. lock_timeout bounds that acquisition; the runner's per-file
--   transaction rolls the DDL and the schema_migrations row back together.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS cvss_version VARCHAR(3),
    ADD CONSTRAINT vulnerabilities_cvss_version_check
    CHECK (cvss_version IS NULL OR cvss_version IN ('2.0', '3.0', '3.1', '4.0'))
    NOT VALID;

COMMENT ON COLUMN vulnerabilities.cvss_version IS
    'M67: the CVSS version (''3.1'', ''3.0'', ''4.0'', ''2.0'') of the assessment cvss_score and severity were derived from, chosen by internal/cvss.Select: v3.1 > v3.0 > v4.0 > v2, NVD Primary over Secondary within a version. Global non-tenant attribute. NULL: unscored, an unrecognised feed version (JVN), a scanner row created from a CPE-path cache hit (undated, refreshed by the next CVE sync), or written before 069. A dated row with NULL cvss_version is pre-069 and is re-derived once by repository.UpdateMetadata at an equal upstream timestamp when the record carries an assessment and was read from NVD itself (not a mirror), so the CVE sync and the monthly catalogue re-read converge it without a backfill.';
