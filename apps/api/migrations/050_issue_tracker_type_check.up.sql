-- ============================================
-- tracker_type CHECK registry for issue_tracker_connections
-- (M24-2 / issue #126 / F357).
--
-- Scope:
--   Migration 015 created issue_tracker_connections.tracker_type as
--   VARCHAR(20) with only a prose comment ("-- 'jira', 'backlog'") as the
--   value registry — nothing DB-side rejects a typo'd or unknown
--   tracker_type written past the application layer. This migration closes
--   the registry with a named CHECK constraint.
--
-- Why 'github' is in the allow-list already:
--   M24 adds a GitHub issue-tracker connection type (issue #125). Shipping
--   the DB registry with all three values in this one migration closes it in
--   a single step; the alternative (2-value CHECK now, DROP + re-ADD when the
--   GitHub tracker lands) would churn a constraint on a FORCE RLS table twice
--   for zero data-integrity gain — migrations are immutable once shipped, so
--   the re-ADD would need yet another migration. 'github' rows cannot appear
--   before the feature ships: the application-side tracker registry gates
--   what actually gets written; the CHECK is the schema-layer backstop.
--
-- Why NOT VALID (045 precedent):
--   issue_tracker_connections has been FORCE RLS since migration 023, and
--   the 015 policy "issue_tracker_connections_tenant_isolation" — which 023
--   did NOT drop; 023 added the second policy
--   tenant_isolation_issue_tracker_connections alongside it — calls
--   current_setting('app.current_tenant_id') WITHOUT missing_ok = true.
--   A validated ADD CONSTRAINT performs a full-table validation scan; under
--   the NOBYPASSRLS sbomhub_migrator role with no app.current_tenant_id GUC
--   set (the normal `migrate up` condition) that scan can raise
--   "unrecognized configuration parameter" — the same failure class that
--   forced NOT VALID on the 045 composite FKs. NOT VALID skips only the
--   existing-row validation; PostgreSQL still enforces the CHECK on every
--   new INSERT / UPDATE immediately.
--
--   Independently, NOT VALID keeps `migrate up` from bricking legacy
--   deployments: tracker_type was never DB-enforced before this migration,
--   so a hypothetical pre-existing out-of-registry row (unlikely — the app
--   layer has only ever written 'jira' / 'backlog') must not abort the whole
--   migration chain at apply time. Operators may run
--   ALTER TABLE ... VALIDATE CONSTRAINT ... later under a session with the
--   GUC set / RLS lifted, following the shape of the 045 runbook
--   (docker/scripts/validate-deferred-constraints.sh,
--   docs/operations/validate-deferred-constraints.md).
-- ============================================

ALTER TABLE issue_tracker_connections
    ADD CONSTRAINT issue_tracker_connections_tracker_type_check
    CHECK (tracker_type IN ('jira', 'backlog', 'github'))
    NOT VALID;

COMMENT ON CONSTRAINT issue_tracker_connections_tracker_type_check ON issue_tracker_connections IS
    'M24-2 / F357 (#126): closed tracker_type registry (jira, backlog, github). github is pre-registered ahead of the M24 GitHub tracker (#125) so the registry is closed in one migration. NOT VALID: existing rows are not validated at apply time (FORCE RLS + missing_ok-less 015 policy would break the migrator validation scan — see the 050 header); new writes are enforced immediately.';
