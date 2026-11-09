-- ============================================
-- M70: distro-aware matching. Widen component_vulnerabilities.match_method
-- with three distro labels and store the distro data's evidence with each
-- such link.
--
-- New match_method values (the vocabulary of 067 plus three):
--   'distro_affected' the distro (OSV distro ecosystem: Debian / Ubuntu /
--                     AlmaLinux / Rocky Linux) has released a fix for this
--                     CVE in the installed release and the installed
--                     version is below it, by the distro's own version
--                     ordering (dpkg / rpm).
--   'distro_unfixed'  the distro lists the installed release as affected
--                     with no fix released.
--   'distro_fixed'    the distro's data says the installed version already
--                     contains the fix. The link is KEPT for a human to
--                     review; nothing is marked not_affected automatically.
--   Only the distro step of a scan writes them (service/distro_scan.go), by
--   relabelling an existing link; the vocabulary is mirrored in Go by
--   model.MatchMethod (IsValid / Rank / FindingRank). The lists must move
--   together.
--
-- component_vulnerabilities.match_evidence (JSONB, NULL = no evidence):
--   written together with a distro label: the data source and record ids,
--   the release ecosystem ("Debian:11"), the package name, the installed and
--   the fixed version, and the basis ('release' or, for an end-of-life
--   Debian release the data no longer lists, 'later_releases'), plus
--   prior_method (the method before the first distro label). On a link
--   without a distro label it may hold only the distro data's watermark
--   (source_id, data_modified) of the last check; the API shows evidence only
--   for distro labels. component_vulnerabilities has no tenant_id and no
--   RLS policy of its own (001; 063 lists its inbound FKs): every reader and
--   writer reaches it through components, which FORCE row-level security
--   (007 / 023), and the distro step's relabel additionally requires its
--   component to be visible under the tenant GUC. A new column changes
--   none of that, so no RLS statement is needed here.
--
-- The CHECK is replaced and re-added NOT VALID: every existing row was
-- written under 067's narrower CHECK (or predates it with NULL), so it
-- satisfies the wider predicate by construction; NOT VALID only skips the
-- verification scan that would otherwise run while ACCESS EXCLUSIVE is held.
-- New and updated rows are checked.
--
-- No backfill: links get a distro label when a scan of their SBOM runs the
-- distro step.
--
-- LOCK BUDGET: see 063. ADD COLUMN (nullable, no DEFAULT) rewrites nothing;
-- DROP / ADD CONSTRAINT ... NOT VALID scan nothing. All three take ACCESS
-- EXCLUSIVE on component_vulnerabilities until COMMIT, so acquiring it can
-- queue behind a live reader (a scan's write phase, the vulnerability list)
-- with every later request queued behind it; lock_timeout bounds that wait
-- and the runner's per-file transaction rolls everything back together.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE component_vulnerabilities ADD COLUMN IF NOT EXISTS match_evidence JSONB;

ALTER TABLE component_vulnerabilities DROP CONSTRAINT IF EXISTS component_vulnerabilities_match_method_check;

ALTER TABLE component_vulnerabilities
    ADD CONSTRAINT component_vulnerabilities_match_method_check
    CHECK (match_method IS NULL OR match_method IN (
        'nvd_cpe', 'nvd_cpe_distro', 'nvd_cpe_unverified', 'nvd_keyword', 'jvn_keyword', 'cve_sync_keyword',
        'distro_affected', 'distro_unfixed', 'distro_fixed'
    )) NOT VALID;
