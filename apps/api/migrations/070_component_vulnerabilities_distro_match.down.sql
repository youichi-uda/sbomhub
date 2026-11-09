-- ============================================
-- Rollback of 070: drop component_vulnerabilities.match_evidence and narrow
-- the match_method CHECK back to 067's vocabulary.
--
-- What is lost: every distro label and its evidence. A link carrying one goes
-- back to the method it had before the distro step (evidence prior_method,
-- when it is one of 067's methods), else to NULL ("unknown", which the API
-- reports as such). The links themselves are untouched, and the next scan
-- of their SBOM labels them again (Codex M70 R13 Medium-7).
--
-- THE BINARY MUST BE ROLLED BACK WITH THE SCHEMA: the M70 code writes the
-- distro labels and match_evidence and fails loudly against a schema without
-- them.
--
-- LOCK BUDGET: see 063. The whole file holds ACCESS EXCLUSIVE on
-- component_vulnerabilities from its first statement. statement_timeout
-- bounds the UPDATE, whose size is the number of distro-labelled links.
-- ============================================

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '300s';

-- ACCESS EXCLUSIVE first (Codex M70 R2 Medium-5): a still-running M70 binary
-- could otherwise relabel a row between the UPDATE and the narrowed CHECK,
-- which NOT VALID would not catch.
LOCK TABLE component_vulnerabilities IN ACCESS EXCLUSIVE MODE;

UPDATE component_vulnerabilities
   SET match_method = CASE WHEN match_evidence->>'prior_method' IN (
                               'nvd_cpe', 'nvd_cpe_distro', 'nvd_cpe_unverified', 'nvd_keyword', 'jvn_keyword', 'cve_sync_keyword')
                           THEN match_evidence->>'prior_method' END
 WHERE match_method IN ('distro_affected', 'distro_unfixed', 'distro_fixed');

ALTER TABLE component_vulnerabilities DROP CONSTRAINT IF EXISTS component_vulnerabilities_match_method_check;

ALTER TABLE component_vulnerabilities
    ADD CONSTRAINT component_vulnerabilities_match_method_check
    CHECK (match_method IS NULL OR match_method IN (
        'nvd_cpe', 'nvd_cpe_distro', 'nvd_cpe_unverified', 'nvd_keyword', 'jvn_keyword', 'cve_sync_keyword'
    )) NOT VALID;

ALTER TABLE component_vulnerabilities DROP COLUMN IF EXISTS match_evidence;
