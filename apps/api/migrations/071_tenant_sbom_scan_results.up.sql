-- ============================================
-- 071: the last terminal scan result of each SBOM, kept in PostgreSQL.
--
-- scan-status (GET /api/v1/projects/:id/sboms/:sbom_id/scan-status) reads a
-- status kept in Redis for about an hour after the scan's last write (M72,
-- UPGRADE §25.3); after that it answered "unknown" for every SBOM that was
-- not scanned recently. This table keeps, per SBOM, the LAST terminal result
-- a scan group reached (service/scan_result_store.go), and scan-status
-- answers from it, marked `source: "recorded"` with `last_scan_at`, when
-- the live status holds no entry for the SBOM.
--
-- One row per SBOM (sbom_id is the primary key):
--   status / error / reasons / checked_sources / skipped_sources /
--   scan_run / finished_at / vuln_total
--                    the last terminal result: written by the API process
--                    whose finish (or a later re-check) found the scan group
--                    terminal. status is NULL until a terminal result was
--                    recorded. checked_sources NULL = the scan did not report
--                    its coverage (unknown, never "none"). finished_at is
--                    when the terminal state was published (Redis's clock
--                    with the shared store, the API process's without); a
--                    write never replaces a row whose finished_at is newer.
--                    vuln_total is the number of findings linked to the
--                    SBOM when the result was recorded (informational).
--   result_born / result_ver
--                    the Redis key incarnation and write counter of the
--                    recorded state (this API process's entry revision
--                    without Redis): order two results published in the same
--                    millisecond.
--   open_runs        JSON object {"<run generation>": {"s": <start, epoch
--                    ms>, "q": <rev of the open>}}: runs whose start this
--                    version recorded and whose finish it has not. A run
--                    still open makes readers answer "unknown" (it may be
--                    running while the live status lost it); one older than
--                    the longest possible scan that is later than the
--                    recorded result reads as interrupted.
--   last_started_at / last_open_seq / last_open_unacked
--                    the latest start recorded, the rev of the latest open
--                    and whether its run's Begin had not yet reached the
--                    shared status ("u" of open_runs); result_seq the rev of
--                    the recorded result. A start later than the result that
--                    closed without one makes readers answer "unknown".
--   rev              bumped on every write: the row's write sequence, and the
--                    version scan-status compares between its two reads.
--
-- Older replicas (rolling upgrade) write nothing here; their scans leave the
-- previous row in place (its last_scan_at says when it was recorded).
--
-- Tenancy: tenant_id NOT NULL, ENABLE + FORCE RLS with WITH CHECK, as every
-- tenant table. Every reader and writer binds app.current_tenant_id. The
-- single-column FK cannot say that the SBOM is the row's tenant's (sboms has
-- no UNIQUE (id, tenant_id), see 053), so a trigger checks it: under the
-- writer's tenant GUC another tenant's SBOM is invisible (sboms FORCEs RLS),
-- and a row naming it is refused. Without it a tenant could occupy another
-- tenant's SBOM's row (its primary key) and keep that SBOM from ever being
-- recorded.
-- Foreign keys: sbom_id -> sboms(id) ON DELETE CASCADE (a deleted SBOM, its
-- project or its tenant takes its row along); tenant_id -> tenants(id) ON
-- DELETE CASCADE.
--
-- LOCK BUDGET: CREATE TABLE ... REFERENCES takes SHARE ROW EXCLUSIVE on
-- sboms and tenants, which queues behind a live writer (an upload) with
-- every later request queued behind it; lock_timeout bounds that wait and
-- the runner's per-file transaction rolls everything back together.
-- ============================================

SET LOCAL lock_timeout = '5s';

CREATE TABLE tenant_sbom_scan_results (
    sbom_id UUID PRIMARY KEY REFERENCES sboms(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    status VARCHAR(16) CHECK (status IS NULL OR status IN ('completed', 'failed')),
    error TEXT NOT NULL DEFAULT '',
    reasons TEXT[] NOT NULL DEFAULT '{}',
    checked_sources TEXT[],
    skipped_sources TEXT[] NOT NULL DEFAULT '{}',
    scan_run VARCHAR(64),
    finished_at TIMESTAMPTZ,
    vuln_total INTEGER,

    result_born BIGINT,
    result_ver BIGINT,
    result_seq BIGINT,

    open_runs JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_started_at TIMESTAMPTZ,
    last_open_seq BIGINT,
    last_open_unacked BOOLEAN NOT NULL DEFAULT FALSE,

    rev BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenant_sbom_scan_results_tenant
    ON tenant_sbom_scan_results (tenant_id);

ALTER TABLE tenant_sbom_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_sbom_scan_results FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_sbom_scan_results ON tenant_sbom_scan_results
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE FUNCTION tenant_sbom_scan_results_sbom_tenant() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sboms WHERE id = NEW.sbom_id AND tenant_id = NEW.tenant_id) THEN
        RAISE EXCEPTION 'tenant_sbom_scan_results: sbom % is not an SBOM of tenant %', NEW.sbom_id, NEW.tenant_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER tenant_sbom_scan_results_sbom_tenant
    BEFORE INSERT OR UPDATE OF sbom_id, tenant_id ON tenant_sbom_scan_results
    FOR EACH ROW EXECUTE FUNCTION tenant_sbom_scan_results_sbom_tenant();

COMMENT ON TABLE tenant_sbom_scan_results IS
    'The last terminal vulnerability-scan result per SBOM (and the runs '
    'started but not yet finished), recorded by the API so scan-status can '
    'answer after the shared Redis status expired (source "recorded").';
