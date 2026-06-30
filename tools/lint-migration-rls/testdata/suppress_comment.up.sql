-- ============================================
-- Suppression fixture: tenant_* table created WITHOUT RLS but with an
-- explicit `-- lint:no-rls-required: <reason>` marker.
--
-- The lint must accept this as a clean (suppressed) entry. The reason is
-- echoed back in --verbose mode for the audit log.
--
-- Use case in production: a global cache / mirror table that happens to
-- carry a `tenant_*` prefix for naming consistency but is intentionally
-- not tenant-scoped. The marker forces a human to justify the exception
-- in the migration itself so a future reviewer can see WHY there is no
-- RLS without spelunking through PR history.
-- ============================================

-- lint:no-rls-required: shared global cache mirroring upstream advisory data; tenant_id stored for join convenience only and not used for filtering.

CREATE TABLE IF NOT EXISTS tenant_suppress_example (
    advisory_id TEXT PRIMARY KEY,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
