-- ============================================
-- EPSS (Exploit Prediction Scoring System) columns on vulnerabilities
-- (M36-A / issue #154 / F432).
--
-- Scope:
--   EPSS is FIRST.org's daily-updated exploitation-probability signal
--   ([0,1] score + percentile per CVE). SBOMHub shipped EPSS scoring in
--   Phase 1, BUT the column that stores it was never part of the
--   canonical apps/api migration chain: it lived only in the orphan
--   packages/db/migrations/006_epss.sql, which is a SEPARATE, out-of-band
--   directory that a stock apps/api migrate run never applies. This
--   migration PROMOTES that orphan into the canonical chain verbatim so a
--   from-scratch deploy has the column.
--
-- Why this matters (the latent-correctness split M35 recon surfaced):
--   Two families of code already reference these columns, and until this
--   migration they were latently split on a from-scratch (canonical-only)
--   database:
--     (a) The EPSS sync WRITER (service/epss.go SyncScores ->
--         repository/vulnerability.go UpdateEPSSScores) issues
--         UPDATE vulnerabilities SET epss_score/epss_percentile/
--         epss_updated_at, and the real-column READERS (repository/ssvc.go,
--         repository/kev.go, repository/vulnerability.go, and
--         scheduler/vulnerability_scan.go) SELECT v.epss_score. On a
--         canonical-only DB these were latently broken -- they only worked
--         if 006_epss had been applied out of band.
--     (b) repository/impact.go, repository/dashboard.go and
--         repository/search.go DEFENSIVELY selected a fixed 0::numeric
--         sentinel instead of the column, so they kept working but could
--         never surface a real score.
--   Adding the column here reconciles the split: the readers/writer in (a)
--   become valid on every deploy, and the sentinels in (b) are flipped in
--   the same milestone to read the real column NULL-safely
--   (COALESCE(epss_score, 0)) so an un-synced row still reads 0.
--
-- Column shape (mirrors orphan 006_epss.sql EXACTLY, for schema convergence
-- with any instance that already applied 006 out of band):
--   epss_score       DECIMAL(5,4)              -- probability in [0,1], 4dp
--   epss_percentile  DECIMAL(5,4)              -- percentile in [0,1], 4dp
--   epss_updated_at  TIMESTAMP WITH TIME ZONE  -- last successful sync
--   All three are NULLABLE with no default: a fresh row has no EPSS until
--   the scheduled epss_sync (M36-B) populates it. Readers COALESCE the NULL
--   to 0, which reproduces the pre-migration sentinel-0 semantics exactly
--   (and keeps the web >0 EPSS-badge suppression, F391, unchanged).
--   Precision is DECIMAL(5,4): FIRST.org publishes 5dp, truncated to 4dp
--   here to stay identical to 006 (full-fidelity DECIMAL(6,5) is a later
--   consideration). The partial index orders NULLS LAST so un-synced rows
--   sink beneath scored ones in "highest EPSS first" queries.
--
-- RLS:
--   vulnerabilities is a GLOBAL, non-tenant table: 001_init declares no
--   tenant_id, it is a shared NVD/JVN/EPSS cache identical for every
--   tenant, and it is a recorded structural exemption in the
--   lint-migration-rls tool (no ENABLE/FORCE/POLICY). Adding non-tenant
--   columns via ALTER TABLE ... ADD COLUMN touches neither the table's RLS
--   state nor any policy, exactly as migration 020 added the KEV columns
--   here without any RLS statements. The lint-migration-rls gate is a
--   no-op for this migration (no tenant_id declared or ALTER-promoted).
-- ============================================

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_score DECIMAL(5,4);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_percentile DECIMAL(5,4);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_epss ON vulnerabilities(epss_score DESC NULLS LAST);

COMMENT ON COLUMN vulnerabilities.epss_score IS
    'M36-A / F432 (#154): FIRST.org EPSS exploitation probability in [0,1] (DECIMAL(5,4), 4dp). Global non-tenant attribute of a CVE. NULL until the scheduled epss_sync (M36-B) populates it; readers COALESCE(epss_score, 0) so an un-synced row reads 0 (matching the pre-055 0::numeric sentinel and the web >0 EPSS-badge suppression, F391). Promoted verbatim from orphan packages/db 006_epss.sql.';
COMMENT ON COLUMN vulnerabilities.epss_percentile IS
    'M36-A / F432 (#154): FIRST.org EPSS percentile rank in [0,1] (DECIMAL(5,4), 4dp). Global non-tenant attribute of a CVE. NULL until the scheduled epss_sync (M36-B) populates it; readers COALESCE(epss_percentile, 0) so an un-synced row reads 0. Promoted verbatim from orphan packages/db 006_epss.sql.';
COMMENT ON COLUMN vulnerabilities.epss_updated_at IS
    'M36-A / F432 (#154): timestamp of the last successful EPSS sync for this CVE (TIMESTAMPTZ). Global non-tenant attribute. NULL until the scheduled epss_sync (M36-B) writes a score. Promoted verbatim from orphan packages/db 006_epss.sql.';
