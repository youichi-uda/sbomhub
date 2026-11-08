-- ============================================
-- Rollback of 067: drop components.cpes and component_vulnerabilities.
-- match_method (and its CHECK).
--
-- What is lost: the stored CPE names (re-uploading the SBOM restores them)
-- and every link's match method (not recoverable; re-applying 067 starts
-- every link at NULL = "unknown"). The links themselves are untouched.
--
-- THE BINARY MUST BE ROLLED BACK WITH THE SCHEMA: the M60 code writes both
-- columns and fails loudly against a schema without them.
--
-- LOCK BUDGET: see 063 (DROP COLUMN / DROP CONSTRAINT take ACCESS EXCLUSIVE).
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE component_vulnerabilities DROP CONSTRAINT IF EXISTS component_vulnerabilities_match_method_check;

ALTER TABLE component_vulnerabilities DROP COLUMN IF EXISTS match_method;

ALTER TABLE components DROP COLUMN IF EXISTS cpes;
