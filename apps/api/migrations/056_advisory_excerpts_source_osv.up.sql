-- ============================================
-- advisory_excerpts.source registry: add 'osv'
-- (M43 Wave 3 / issue #169 / F467).
--
-- Scope:
--   Migration 033 pinned advisory_excerpts.source to the three feeds the
--   M1 advisory parser shipped with ('nvd', 'ghsa', 'jvn') and predicted
--   this exact extension in its header: "Adding a new source (e.g. 'osv',
--   'redhat') is a one-line ALTER ... DROP CONSTRAINT / ADD CONSTRAINT,
--   not a full enum migration." M43 Wave 3 cashes that in: the CVE sync
--   scheduler (internal/scheduler/cve_sync.go, syncOSVVulnFuncs) now
--   persists OSV / Go-vulndb structured vulnerable symbols
--   (affected[].ecosystem_specific.imports[].symbols) as
--   source = 'osv' rows, filling vuln_funcs with wire-safe
--   "Pkg.Func" / "Pkg.Type.Method" selectors for the M43 Wave 1
--   GET /reachability/targets enrichment. Until now the only vuln_funcs
--   producer was the NVD prose heuristic (backtick-anchored regex), so
--   production vuln_funcs were almost always empty.
--
-- Constraint name:
--   033 declared the CHECK inline on the source column, so PostgreSQL
--   auto-named it advisory_excerpts_source_check (<table>_<column>_check).
--   DROP CONSTRAINT IF EXISTS keeps the swap idempotent-ish for
--   environments where the constraint was already adjusted out of band.
--
-- Why NOT VALID (050 / 045 precedent):
--   advisory_excerpts has been ENABLE + FORCE ROW LEVEL SECURITY since 033
--   and `migrate up` runs under the NOBYPASSRLS sbomhub_migrator role with
--   no app.current_tenant_id GUC set. A validated ADD CONSTRAINT performs
--   a full-table validation scan under that role — the failure class that
--   forced NOT VALID onto the 045 composite FKs and the 050 tracker_type
--   CHECK. NOT VALID skips only the existing-row validation; PostgreSQL
--   still enforces the CHECK on every new INSERT / UPDATE immediately.
--   The skipped validation is provably vacuous here anyway: every
--   pre-056 row already passed the stricter 3-value CHECK, and
--   {nvd, ghsa, jvn} is a subset of the new registry.
--
-- RLS:
--   Untouched. Swapping a CHECK constraint changes neither the table's
--   ENABLE/FORCE state nor the tenant_isolation_advisory_excerpts policy,
--   and the lint-migration-rls directory aggregation still sees 033's
--   full RLS triple.
-- ============================================

ALTER TABLE advisory_excerpts
    DROP CONSTRAINT IF EXISTS advisory_excerpts_source_check;

ALTER TABLE advisory_excerpts
    ADD CONSTRAINT advisory_excerpts_source_check
    CHECK (source IN ('nvd', 'ghsa', 'jvn', 'osv'))
    NOT VALID;

COMMENT ON CONSTRAINT advisory_excerpts_source_check ON advisory_excerpts IS
    'M43 Wave 3 / F467 (#169): closed source registry (nvd, ghsa, jvn, osv). osv rows carry Go vulndb structured vulnerable symbols (ecosystem_specific.imports[].symbols) written by the CVE sync scheduler; vuln_funcs holds wire-safe Pkg.Func / Pkg.Type.Method selectors for the reachability targets endpoint. NOT VALID: existing rows are not re-validated at apply time (FORCE RLS + NOBYPASSRLS migrator, 050 precedent); validation is vacuous because every pre-056 row passed the stricter 3-value CHECK.';
