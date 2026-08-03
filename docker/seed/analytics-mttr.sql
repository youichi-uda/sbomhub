-- SBOMHub - analytics MTTR / SLO / compliance fixture (M49 render gate)
--
-- PURPOSE
--   docker/seed/web-e2e.sql leaves the analytics surface completely
--   unmeasured: it seeds zero rows in vulnerability_resolution_events and
--   zero rows in compliance_snapshots, so /analytics answers null for every
--   MTTR / SLO / compliance ratio at every period. That is exactly "state A"
--   (a tenant that has never remediated anything) and it is what M49
--   (fdaebe4) has to render as 未計測 / "Not measured" instead of
--   "0.0 時間" / "100.0%".
--
--   This file adds the COMPLEMENTARY rows so the same tenant also has a
--   "state B" — measured — view, WITHOUT disturbing state A:
--
--     * two vulnerability_resolution_events resolved 60 days ago. They are
--       INSIDE a 90-day window and OUTSIDE a 30-day one, so
--         - 30d (the page default) stays fully unmeasured  = state A
--         - 90d shows real numbers                          = state B
--       That split is the 209b55e regression in fixture form: pre-fix the
--       headline average MTTR came from GetQuickStats' hard-coded "last 30
--       days" while the MTTR panel below it was period-scoped, so a 90-day
--       view printed real per-severity numbers under a headline that said
--       "not measured" and a tooltip that claimed nothing had been resolved
--       in the selected period.
--
--     * two tenant-level compliance_snapshots, one WITH a checklist
--       (max_score 10) and one WITHOUT (max_score 0). The max_score 0 row is
--       the M49 "0 / 0 is the absence of an assessment, not a score of zero"
--       case, and 209b55e replaced its hard-coded em dash with the localised
--       未計測 / "Not measured" label. Having both rows on one screen is what
--       makes the assertion meaningful: a measured 80% and an unmeasured row
--       must not render the same way.
--
-- MEASURED VALUES (deliberate, the specs assert them)
--   CRITICAL  detected -62d, resolved -60d  =  48 h  vs target   24 h -> LATE
--             -> MTTR "2 日" / "2 days", SLO achievement 0.0%  (a REAL zero)
--   HIGH      detected -60d 12h, resolved -60d = 12 h vs target 168 h -> OK
--             -> MTTR "12.0 時間" / "12.0 hours", SLO achievement 100.0%
--   MEDIUM / LOW  no events -> unmeasured -> 未計測 / "Not measured"
--   headline  count-weighted mean (48 + 12) / 2 = 30 h -> "1 日 6 時間"
--   headline  overall SLO = 1 on-target / 2 resolved = 50.0%
--
--   The CRITICAL row exists to prove the UI distinguishes a MEASURED 0.0%
--   from an UNMEASURED one: both used to be a bare 0-sentinel, and a gate
--   that only ever sees "not measured" cannot catch a regression that
--   replaces every number with the label.
--
-- ORDERING / SAFETY
--   * Load AFTER docker/seed/web-e2e.sql — every row here FK-references the
--     tenant / project / vulnerability UUIDs that file pins.
--   * Same "load before the web container / any authenticated request"
--     ordering rule as web-e2e.sql (see apps/web/e2e/README.md): the API's
--     GetOrCreateDefault mints a random-UUID tenant otherwise.
--   * Idempotent — every INSERT carries ON CONFLICT (id) DO NOTHING. The
--     PK is the arbiter deliberately: compliance_snapshots' UNIQUE
--     (tenant_id, project_id, snapshot_date) treats NULLs as DISTINCT in
--     PostgreSQL 15, so a project_id IS NULL row would re-insert forever
--     if that constraint were used as the conflict target.
--   * Timestamps are relative to load time (NOW() / CURRENT_DATE), and only
--     the DIFFERENCE between detected_at and resolved_at is asserted, so the
--     measured values above are stable no matter when the seed runs.
--   * Appends only. It does not modify any row web-e2e.sql inserts, so the
--     26 existing specs see exactly the DB they saw before.
--   * DO NOT load against a production database (same warning as
--     web-e2e.sql).

-- ---------------------------------------------------------------------------
-- 1. Resolution events (drive MTTR + SLO achievement)
-- ---------------------------------------------------------------------------
-- vulnerability_resolution_events.severity is its own column, independent of
-- the referenced vulnerabilities row; the CVEs below are picked so the two
-- agree anyway (CVE-2021-44228 = CRITICAL, CVE-2020-8203 = HIGH).

INSERT INTO vulnerability_resolution_events (
    id, tenant_id, vulnerability_id, project_id, cve_id, severity,
    detected_at, resolved_at, resolution_type, resolution_notes,
    created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-0000000000a1'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000040'::uuid,  -- CVE-2021-44228
    '00000000-0000-0000-0000-000000000010'::uuid,  -- M10-3 Seed Project
    'CVE-2021-44228',
    'CRITICAL',
    NOW() - INTERVAL '62 days',
    NOW() - INTERVAL '60 days',                    -- 48 h, target 24 h -> late
    'fixed',
    'M49 analytics fixture: 48h remediation, misses the 24h CRITICAL SLO',
    NOW(), NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO vulnerability_resolution_events (
    id, tenant_id, vulnerability_id, project_id, cve_id, severity,
    detected_at, resolved_at, resolution_type, resolution_notes,
    created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-0000000000a2'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000043'::uuid,  -- CVE-2020-8203
    '00000000-0000-0000-0000-000000000010'::uuid,
    'CVE-2020-8203',
    'HIGH',
    NOW() - INTERVAL '60 days' - INTERVAL '12 hours',
    NOW() - INTERVAL '60 days',                    -- 12 h, target 168 h -> ok
    'fixed',
    'M49 analytics fixture: 12h remediation, inside the 168h HIGH SLO',
    NOW(), NOW()
) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Compliance snapshots (drive the compliance trend rows + headline tile)
-- ---------------------------------------------------------------------------
-- GetComplianceTrend filters on project_id IS NULL (tenant-level snapshots),
-- and GetQuickStats reads the LATEST such row for the headline. The newer row
-- is deliberately the max_score 0 one so BOTH the per-row label and the
-- headline exercise the not-measured branch, while the older row keeps a real
-- 80% on screen for contrast.

INSERT INTO compliance_snapshots (
    id, tenant_id, project_id, snapshot_date,
    overall_score, max_score,
    sbom_generation_score, vulnerability_management_score, license_management_score,
    created_at
) VALUES (
    '00000000-0000-0000-0000-0000000000b1'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    NULL,
    CURRENT_DATE - 20,
    8, 10,          -- 80% — a real measurement
    3, 3, 2,
    NOW()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO compliance_snapshots (
    id, tenant_id, project_id, snapshot_date,
    overall_score, max_score,
    sbom_generation_score, vulnerability_management_score, license_management_score,
    created_at
) VALUES (
    '00000000-0000-0000-0000-0000000000b2'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    NULL,
    CURRENT_DATE - 5,
    0, 0,           -- no checklist configured — NOT a score of zero
    0, 0, 0,
    NOW()
) ON CONFLICT (id) DO NOTHING;
