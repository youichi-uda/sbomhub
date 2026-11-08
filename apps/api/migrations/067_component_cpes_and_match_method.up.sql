-- ============================================
-- M60: keep the SBOM's CPE names on each component, and record HOW each
-- component -> vulnerability link was made.
--
-- components.cpes (TEXT[], NULL = the SBOM declared none):
--   Before M60 the importers dropped every CPE the SBOM carried (CycloneDX
--   `cpe` / Syft's `syft:cpe23` properties, SPDX 2 `cpe23Type` externalRefs,
--   SPDX 3 `cpe23` external identifiers). The NVD scanner now matches on
--   them, so they have to survive the import. Order is meaningful — Syft
--   lists its candidates in its own preference order and the scanner tries
--   them first to last — which is why this is an array and not a child table.
--   `components` is tenant-scoped and already carries the full RLS triple
--   (007 / 023); a new column inherits the table's policy, so no RLS
--   statement is needed here.
--
-- component_vulnerabilities.match_method (NULL = made before M60, unknown):
--   'nvd_cpe'          NVD CPE match, verified against the CVE's NVD
--                      configurations (vulnerable=true, same part:vendor:
--                      product, component version inside the range).
--   'nvd_cpe_distro'   same, for a distro package (deb/rpm/apk): matched on
--                      the UPSTREAM version, so distro backports are NOT
--                      taken into account.
--   'nvd_keyword'      NVD keywordSearch on "<name> <version>" (no usable
--                      CPE on the component).
--   'jvn_keyword'      MyJVN keyword search on the component name.
--   'cve_sync_keyword' CVE-sync daily linker: product names from the CVE's
--                      CPE criteria matched against component names.
--   The vocabulary is enforced by the CHECK below AND in Go
--   (model.MatchMethod*). The two lists must move together.
--
-- No backfill, deliberately: there is no source for how a pre-M60 link was
-- made. NULL is reported through the API as confidence "unknown", never as
-- either "high" or "low". A link is relabelled when a later scan reproduces
-- it with a stronger method.
--
-- The CHECK is added NOT VALID: the column is created in this same file, so
-- every existing row holds NULL and passes the predicate by construction;
-- NOT VALID only skips the full-table verification scan that would otherwise
-- run while ACCESS EXCLUSIVE is held. New and updated rows are checked.
--
-- LOCK BUDGET: see 063. Both ADD COLUMNs (nullable, no DEFAULT) rewrite
-- nothing but take ACCESS EXCLUSIVE on their table until COMMIT.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE components ADD COLUMN IF NOT EXISTS cpes TEXT[];

ALTER TABLE component_vulnerabilities ADD COLUMN IF NOT EXISTS match_method VARCHAR(32);

ALTER TABLE component_vulnerabilities
    ADD CONSTRAINT component_vulnerabilities_match_method_check
    CHECK (match_method IS NULL OR match_method IN (
        'nvd_cpe', 'nvd_cpe_distro', 'nvd_keyword', 'jvn_keyword', 'cve_sync_keyword'
    )) NOT VALID;
