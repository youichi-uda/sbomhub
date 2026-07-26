-- ============================================
-- M46 Codex round B-1 (High-1 / High-2):
-- public_links.is_active / view_count / download_count -> NOT NULL
-- ============================================
--
-- WHY (High-1, authorization fail-open):
--   `is_active` has carried a DDL DEFAULT true since 009 but was never
--   NOT NULL. A row with is_active = NULL (out-of-band SQL, a restore
--   from a partial dump, an operator UPDATE that forgot the column) is
--   neither active nor inactive at the SQL layer, and the M46 wave-2
--   read applied the DDL default at read time — COALESCE(is_active,
--   true) — which resolved the ambiguity in the ATTACKER's favour: the
--   anonymous /api/v1/public/:token flow saw an ACTIVE link and served
--   the project name, SBOM and component list to anyone holding the
--   token. Authorization state must fail CLOSED, so the repository now
--   reads COALESCE(is_active, false) on every path, and this migration
--   removes the anomaly at its source.
--
-- WHY (High-2, download cap never consumed):
--   `download_count` was likewise nullable with DEFAULT 0. The read side
--   COALESCEd it to 0 but the write side did `download_count =
--   download_count + 1`, and NULL + 1 = NULL in SQL — the counter never
--   moved. A link with allowed_downloads = 1 and download_count = NULL
--   therefore passed `0 < 1` on EVERY request: unlimited anonymous
--   downloads. The repository now COALESCEs the increment and folds the
--   cap check into one conditional UPDATE (TryConsumeDownload, which
--   also closes the check-then-act race); NOT NULL here means the
--   arithmetic can never see a NULL again. `view_count` is included for
--   uniformity — the same NULL + 1 = NULL freeze applies to it (a
--   cosmetic counter, not an authorization control).
--
-- SAFETY OF THE BACKFILL:
--   - is_active NULL -> false. This is the fail-closed direction and it
--     matches the new read semantics exactly, so the migration cannot
--     change the answer the application already gives post-fix. It CAN
--     deactivate a link that a pre-fix deployment was (wrongly) serving;
--     that is the intended security outcome and the operator can
--     re-activate deliberately through the dashboard.
--   - view_count / download_count NULL -> 0, i.e. the DDL default and
--     the value both the pre-fix and post-fix reads already reported.
--   Measured on the dev DB 2026-07-26: 42 public_links rows, 0 NULL in
--   all three columns — the backfill is a no-op there and exists for
--   long-lived self-host installs.
--
-- The DEFAULTs from 009 are intentionally kept: every INSERT in
-- repository/public_link.go binds all three columns explicitly, and the
-- defaults keep hand-written operator INSERTs working.

UPDATE public_links SET is_active      = false WHERE is_active      IS NULL;
UPDATE public_links SET view_count     = 0     WHERE view_count     IS NULL;
UPDATE public_links SET download_count = 0     WHERE download_count IS NULL;

ALTER TABLE public_links ALTER COLUMN is_active      SET NOT NULL;
ALTER TABLE public_links ALTER COLUMN view_count     SET NOT NULL;
ALTER TABLE public_links ALTER COLUMN download_count SET NOT NULL;

COMMENT ON COLUMN public_links.is_active IS
    'Authorization state for the anonymous share flow. NOT NULL since '
    'migration 058 (M46 B-1 High-1): a NULL was resolved to "active" by '
    'the read-time COALESCE and let token holders read revoked shares.';
COMMENT ON COLUMN public_links.download_count IS
    'Downloads consumed against allowed_downloads. NOT NULL since '
    'migration 058 (M46 B-1 High-2): NULL + 1 = NULL froze the counter '
    'and made the per-link cap unenforceable.';
