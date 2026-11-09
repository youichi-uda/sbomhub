-- ============================================
-- Rollback of 070: drop component_vulnerabilities.match_evidence and narrow
-- the match_method CHECK back to 067's vocabulary.
--
-- What is lost: every distro label and its evidence. A link carrying one is
-- set back to NULL ("unknown", which the API reports as such) rather than to
-- a guessed NVD label: the method the link had before the distro step
-- relabelled it is not recorded. The links themselves are untouched, and the
-- next scan of their SBOM labels them again.
--
-- THE BINARY MUST BE ROLLED BACK WITH THE SCHEMA: the M70 code writes the
-- distro labels and match_evidence and fails loudly against a schema without
-- them.
--
-- LOCK BUDGET: see 063. The UPDATE locks only the relabelled rows;
-- DROP CONSTRAINT / ADD CONSTRAINT ... NOT VALID / DROP COLUMN take ACCESS
-- EXCLUSIVE. statement_timeout bounds the UPDATE, whose size is the number of
-- distro-labelled links.
-- ============================================

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '300s';

UPDATE component_vulnerabilities
   SET match_method = NULL
 WHERE match_method IN ('distro_affected', 'distro_unfixed', 'distro_fixed');

ALTER TABLE component_vulnerabilities DROP CONSTRAINT IF EXISTS component_vulnerabilities_match_method_check;

ALTER TABLE component_vulnerabilities
    ADD CONSTRAINT component_vulnerabilities_match_method_check
    CHECK (match_method IS NULL OR match_method IN (
        'nvd_cpe', 'nvd_cpe_distro', 'nvd_cpe_unverified', 'nvd_keyword', 'jvn_keyword', 'cve_sync_keyword'
    )) NOT VALID;

ALTER TABLE component_vulnerabilities DROP COLUMN IF EXISTS match_evidence;
