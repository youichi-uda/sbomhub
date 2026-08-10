-- ============================================
-- Record WHEN the upstream feed last modified the CVE record we stored, so a
-- metadata refresh can refuse to move the catalogue backwards (M55).
--
-- The problem this column exists to solve:
--   `vulnerabilities` is the global CVE catalogue. Its description / severity
--   / cvss_score are refreshed by the daily CVE-sync job
--   (scheduler/cve_sync.go), which replays whatever NVD returns for the
--   `lastModStartDate` window. Nothing in that UPDATE compared the incoming
--   record's age against the stored one, so replaying an OLDER NVD record
--   over a NEWER one silently downgraded the row. Measured 2026-08-11 on
--   PostgreSQL 15: a row holding CRITICAL / 9.8 written from an NVD record
--   whose lastModified was 2026-07-01 was overwritten with LOW / 2.0 by a
--   record whose lastModified was 2026-01-01, and the vulnerability page then
--   served LOW.
--
--   That is not a hypothetical ordering: the NVD 2.0 feed is paged and the
--   job replays a time WINDOW, so a re-run after a clock skew, a retried
--   window, or a mirror serving a cached page all deliver an older record
--   after a newer one has already landed. `updated_at` cannot arbitrate it —
--   it records when WE wrote the row, not how old the upstream record is, so
--   the stale write always looks like the most recent one.
--
-- Why a new column instead of reusing updated_at:
--   The two answer different questions and both are needed. `updated_at` is
--   our write clock (and is published through the JSON API as
--   model.Vulnerability.UpdatedAt); redefining it as "upstream modification
--   time" would silently change the meaning of a shipped field, the failure
--   mode migration 059 declined for epss_updated_at. This column is purely
--   ADDITIVE and is not published through the API — it exists to arbitrate
--   writes.
--
-- Semantics and who writes it:
--   Written by repository.VulnerabilityRepository.UpdateMetadata and by the
--   CVE-sync job's INSERT path, both of which carry NVD's `lastModified`.
--   NULL means "we have never recorded an upstream modification time for this
--   row" — every row written before this migration, plus every row the
--   per-component scanners (service/nvd.go, service/jvn.go) create, since
--   those paths do not carry the field. NULL is therefore NOT "very old": it
--   is "unknown", and UpdateMetadata treats it as writable so a legacy row
--   can be refreshed exactly once and thereafter arbitrated normally.
--
-- No backfill:
--   There is no source for a historical value — the upstream lastModified of
--   the record a legacy row was written from was never captured. Backfilling
--   `updated_at` into it would assert a freshness we cannot support and would
--   let a genuinely newer NVD record be refused as stale. Legacy rows are
--   reconciled on their next successful refresh.
--
-- RLS: untouched. `vulnerabilities` is the global, non-tenant CVE catalogue —
--   a recorded structural exemption in tools/lint-migration-rls (migration 063
--   removed its vestigial tenant_id). This migration declares no RLS.
--
-- LOCK BUDGET: see 063. `ADD COLUMN` of a nullable column with no DEFAULT
--   rewrites nothing (PostgreSQL 11+), but it still takes ACCESS EXCLUSIVE on
--   `vulnerabilities` and holds it until COMMIT, so ACQUIRING it can queue
--   behind a live reader — and every waiter queues behind us. A bounded wait
--   turns an indefinite stall into a retry: the runner's transaction rolls
--   back the DDL and the schema_migrations row together. lock_timeout bounds
--   ACQUISITION of each statement's locks, not how long they are then held.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS source_modified_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN vulnerabilities.source_modified_at IS
    'M55: the UPSTREAM feed timestamp of the record this row''s metadata was last written from -- NVD `lastModified` for the CVE-sync job (TIMESTAMPTZ). Global non-tenant attribute. Distinct from updated_at, which is OUR write clock and is published through the JSON API; this column is internal and exists to arbitrate writes. Read and written by repository.UpdateMetadata, which refuses a metadata write whose upstream record is OLDER than the one already stored, so replaying a stale NVD page cannot downgrade a severity. NULL means "unknown", not "old": rows predating this migration and rows created by the per-component scanners (service/nvd.go, service/jvn.go) carry NULL and are writable once, after which they are arbitrated normally. No backfill is performed -- the upstream timestamp of a legacy row was never captured, and asserting one would let a genuinely newer record be refused as stale.';
