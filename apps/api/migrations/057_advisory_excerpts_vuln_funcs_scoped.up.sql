-- ============================================
-- advisory_excerpts.vuln_funcs_scoped: module-scoped symbol lists
-- (M43 Phase D round 8 / R8f).
--
-- Scope:
--   The M43 Wave 3 OSV pass (migration 056) stores the Go vulndb
--   structured vulnerable symbols as ONE flat vuln_funcs union per
--   (tenant, cve, 'osv') row. GET /reachability/targets then attached
--   that CVE-level union to EVERY component target of the CVE — so when
--   one CVE spans several Go modules (multiple affected[] entries in the
--   OSV record), component A's worklist row carried component B's
--   symbols, and a project call into B's package could flip A to a false
--   `reachable` verdict (M43 Phase D round 8 Medium finding:
--   over-report). This column adds the module attribution the serving
--   edge needs to hand each target row only its own module's symbols:
--
--     [{"module": "<Go module path>", "vuln_funcs": ["Pkg.Func", ...]}, ...]
--
--   module is the OSV affected[].package.name the symbols were declared
--   under (already validated against imports[].path by the scheduler's
--   osvImportPathWithinModule, M43 Phase D R2 finding 4); Go vulndb's
--   synthetic "stdlib" / "toolchain" modules are stored verbatim. The
--   flat vuln_funcs column is UNCHANGED and keeps feeding the triage
--   prompt / grounding readers; rows written before this migration keep
--   the column's '[]' default and are served unscoped (legacy
--   behaviour). The wire contract (targets[].vuln_funcs flat string
--   array) does not change — scoping happens server-side per target row.
--
-- Why plain ADD COLUMN (no NOT VALID discussion, unlike 050/056):
--   This is a nullable-free column addition with a constant DEFAULT —
--   PostgreSQL (11+) stores the default in the catalog without rewriting
--   or scanning the table, so the FORCE-RLS + NOBYPASSRLS-migrator
--   failure class that pushed 045/050/056 to NOT VALID does not arise:
--   no existing row is read or validated at apply time.
--
-- RLS:
--   Untouched. Adding a column changes neither the table's ENABLE/FORCE
--   state nor the tenant_isolation_advisory_excerpts policy, and the
--   lint-migration-rls directory aggregation still sees 033's full RLS
--   triple.
-- ============================================

ALTER TABLE advisory_excerpts
    ADD COLUMN vuln_funcs_scoped JSONB NOT NULL DEFAULT '[]'::JSONB;

COMMENT ON COLUMN advisory_excerpts.vuln_funcs_scoped IS
    'M43 Phase D round 8 (R8f): module-scoped advisory symbol lists, shape [{"module": "<Go module path>", "vuln_funcs": ["Pkg.Func", ...]}, ...]. Written by the CVE sync scheduler''s OSV pass alongside the flat vuln_funcs union; module is the OSV affected[].package.name ("stdlib"/"toolchain" verbatim for Go vulndb''s synthetic modules). GET /reachability/targets serves a target row only the entries whose module matches the component''s purl-derived Go module, plus the unscoped (prose-source / legacy) union — preventing one CVE''s multi-module symbols from cross-contaminating sibling components. ''[]'' means "no module attribution known" (pre-057 rows, nvd/ghsa/jvn prose rows, tombstones): such rows serve their flat vuln_funcs unscoped.';
