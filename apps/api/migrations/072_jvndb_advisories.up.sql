-- ============================================
-- 072: JVN iPedia (JVNDB) advisories from the JVNDB RSS feeds, as
-- SUPPLEMENTARY information on CVEs the catalogue already holds.
--
-- Why: JPCERT/CC suspended JVN iPedia and MyJVN on 2026-10-22 with no
-- resumption date (https://jvn.jp/nav/info2026102281.html); the MyJVN API
-- answers 404. The JVNDBRSS data feeds (https://jvndb.jvn.jp/ja/feed/) are
-- still published. Each RSS item carries the JVNDB id, a Japanese title, the
-- dates and its references (CVE ids among them), but only product-level CPEs
-- with NO version ranges, so it cannot decide whether a component is
-- affected. SBOMHub therefore never creates or removes a finding from it: the
-- RSS data is attached, by CVE id, to vulnerabilities NVD already supplied
-- (repository.AttachJVNDB), and it is never reported as a JVN check
-- (scan-status `checked_sources` is untouched).
--
-- Tables (all GLOBAL, like `vulnerabilities`, `kev_catalog`, `eol_*`: no
-- tenant_id, no RLS -- the rows are public upstream data shared by every
-- tenant, written only by the background sync and read by every tenant's
-- vulnerability list):
--
--   jvndb_advisories      one row per JVNDB id. The canonical advisory URL is
--                         derived from the id at read time
--                         (https://jvndb.jvn.jp/ja/contents/<year>/<id>.html),
--                         never taken from the feed, so a mirror cannot plant
--                         a link. The description is NOT stored: only what the
--                         UI shows (id, title, dates).
--   jvndb_advisory_cves   the CVE ids an advisory references
--                         (sec:references source="CVE"), upper-case.
--   jvndb_feed_state      one row per feed ('recent', 'year:<YYYY>'): the
--                         conditional-GET validators and the URL they belong
--                         to (sent only to that URL), when it was last tried
--                         and last succeeded, and whether a year feed's
--                         backfill finished. The claim on last_attempt_at is
--                         what keeps several API replicas from fetching the
--                         same feed in the same interval.
--
-- LOCK BUDGET: only new tables are created; REFERENCES points at a table this
--   file creates. Nothing here can queue behind live traffic, but the budget
--   is declared first anyway per the directory convention.
-- ============================================

SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS jvndb_advisories (
    jvndb_id      VARCHAR(32) PRIMARY KEY
                  CHECK (jvndb_id ~ '^JVNDB-[0-9]{4}-[0-9]{6,12}$'),
    title         TEXT NOT NULL
                  CHECK (char_length(title) BETWEEN 1 AND 1000),
    published_at  TIMESTAMP WITH TIME ZONE,
    modified_at   TIMESTAMP WITH TIME ZONE,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE jvndb_advisories IS
    '072: JVN iPedia advisories read from the JVNDB RSS feeds. Global (no tenant_id, no RLS). Supplementary only: never creates findings, never counts as a JVN check.';
COMMENT ON COLUMN jvndb_advisories.modified_at IS
    '072: dcterms:modified of the item this row was last written from. An item whose modified time is OLDER than the stored one is ignored, so a stale year feed cannot overwrite what the recent feed wrote.';

CREATE TABLE IF NOT EXISTS jvndb_advisory_cves (
    jvndb_id  VARCHAR(32) NOT NULL REFERENCES jvndb_advisories(jvndb_id) ON DELETE CASCADE,
    cve_id    VARCHAR(50) NOT NULL
              CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
    PRIMARY KEY (jvndb_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_jvndb_advisory_cves_cve ON jvndb_advisory_cves(cve_id);

CREATE TABLE IF NOT EXISTS jvndb_feed_state (
    feed              VARCHAR(32) PRIMARY KEY
                      CHECK (feed = 'recent' OR feed ~ '^year:[0-9]{4}$'),
    source_url        TEXT,
    etag              TEXT,
    last_modified     TEXT,
    last_attempt_at   TIMESTAMP WITH TIME ZONE,
    last_success_at   TIMESTAMP WITH TIME ZONE,
    last_status       VARCHAR(20) NOT NULL DEFAULT 'never'
                      CHECK (last_status IN ('never', 'running', 'success', 'not_modified', 'failed', 'partial')),
    last_error        TEXT,
    items_seen        INTEGER NOT NULL DEFAULT 0,
    items_written     INTEGER NOT NULL DEFAULT 0,
    items_rejected    INTEGER NOT NULL DEFAULT 0,
    completed         BOOLEAN NOT NULL DEFAULT false,
    gap_detected_at   TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE jvndb_feed_state IS
    '072: per-feed sync state of the JVNDB RSS ingestion (recent feed and per-year backfill feeds). last_error holds a generic message only.';
