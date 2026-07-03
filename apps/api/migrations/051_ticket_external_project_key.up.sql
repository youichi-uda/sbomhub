-- ============================================
-- Per-ticket external project key for vulnerability_tickets
-- (M25-A / issue #128 / F366).
--
-- Scope:
--   Migration 015 created vulnerability_tickets without a per-ticket
--   project/repository column: the ticket row persists only the external
--   ticket id/key/url. For Jira/Backlog that is sufficient (issue keys such
--   as PROJ-123 are instance-scoped), but GitHub issue numbers are
--   repository-scoped, which forced F361 (M24) to reject per-ticket
--   repository overrides at creation time — SyncTicket had no way to know
--   which repository a ticket's issue number belongs to other than the
--   connection's single DefaultProjectKey. This migration adds the missing
--   column so createGitHubTicket can persist the repository each ticket was
--   actually created in, unlocking per-ticket repository overrides while
--   SyncTicket polls the persisted repository instead of guessing.
--
-- Column shape:
--   VARCHAR(200), nullable, no default. 200 comfortably bounds both the
--   GitHub "owner/repo" shape (GitHub caps owner at 39 and repo at 100
--   characters) and Jira/Backlog project keys (issue_tracker_connections.
--   default_project_key is VARCHAR(100)); the column is written by the
--   application only, and the GitHub client validates the owner/repo shape
--   before any value reaches an INSERT.
--
-- Why existing rows are NOT backfilled:
--   A backfill UPDATE would scan/write every vulnerability_tickets row.
--   The table has been FORCE RLS since migration 023, and the 015 policy
--   "vulnerability_tickets_tenant_isolation" calls
--   current_setting('app.current_tenant_id') WITHOUT missing_ok = true, so
--   under the NOBYPASSRLS sbomhub_migrator role with no tenant GUC set (the
--   normal `migrate up` condition) a whole-table UPDATE can raise
--   "unrecognized configuration parameter" — the failure class recorded in
--   the 045 header (which had to temporarily lift RLS to backfill, an
--   escalation this migration deliberately avoids for a nice-to-have
--   denormalisation). Legacy NULL rows lose nothing: the service falls back
--   to deriving the repository from the persisted issue html_url
--   (githubRepoFromIssueURL), the exact pre-F366 sync path, so old tickets
--   keep syncing unchanged. New tickets get the column populated at INSERT
--   time by the application.
--
-- NULL vs '' contract (service side):
--   The repository layer COALESCEs NULL to '' when scanning; the service
--   treats an empty ExternalProjectKey as "legacy row — resolve the
--   repository from the ticket URL".
-- ============================================

ALTER TABLE vulnerability_tickets
    ADD COLUMN external_project_key VARCHAR(200);

COMMENT ON COLUMN vulnerability_tickets.external_project_key IS
    'M25-A / F366 (#128): project/repository the external ticket was created in (GitHub "owner/repo"; enables per-ticket repository overrides). NULL for rows created before migration 051 — deliberately not backfilled (FORCE RLS + missing_ok-less 015 policy would break a migrator whole-table UPDATE, see the 051 header); the service falls back to the repository derived from external_ticket_url for those rows.';
