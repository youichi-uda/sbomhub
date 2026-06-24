-- ============================================
-- Advisory excerpts (M1 Wave M1-2, AI VEX MVP foundation)
--
-- Source of truth: sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §8.5
-- Issue: youichi-uda/sbomhub#23 (M1 Wave M1-2 schema half; the parser
-- itself lands as #24 under internal/service/advisory/).
--
-- Purpose:
--   The advisory parser (NVD / GHSA / JVN) extracts a small, structured
--   shape -- vulnerable functions, affected file paths, required runtime
--   config, required environment values, and the raw excerpt the
--   judgement was made from -- and persists one row per
--   (tenant, cve, source) tuple here. The triage LLM call (#28 / M1-4)
--   then loads these rows as context and references them by id from
--   vex_drafts (#27 / M1-5) as the "evidence pointer" the design doc
--   requires ("evidence なしの出力は保存しない").
--
-- Tenancy:
--   Even though advisory text itself is public, the *parsed* excerpts
--   are tenant-scoped so that:
--     1. Each tenant's parser version / heuristic tuning is independent
--        and reproducible.
--     2. A tenant editing or annotating an excerpt (planned for M2)
--        does not leak across organisations.
--     3. The cleanup story is simple: ON DELETE CASCADE from tenants
--        reaps everything the tenant ever derived.
--   tenant_id is therefore NOT NULL + RLS-enforced from day one.
--
-- RLS model:
--   * ENABLE + FORCE ROW LEVEL SECURITY (matches the post-023 hardened
--     pattern used by 032_llm_calls). FORCE keeps migrator/owner
--     connections from bypassing the policy during ad-hoc maintenance.
--   * Single tenant_isolation_advisory_excerpts policy with USING +
--     WITH CHECK both bound to
--     `current_setting('app.current_tenant_id', true)::UUID`.
--     The `true` second arg (missing_ok) makes the GUC return '' when
--     unset; the cast to UUID then fails the predicate, so
--     unauthenticated paths get zero rows / rejected INSERTs rather than
--     a SQL error.
--
-- Indexes:
--   * Unique (tenant_id, cve_id, source) -- enables upsert-by-source
--     ("we re-pulled GHSA for this CVE, replace the GHSA row but leave
--     NVD alone") and stops duplicate rows accumulating from re-runs.
--   * idx_advisory_excerpts_cve (tenant_id, cve_id) -- supports the
--     dominant lookup "give me every excerpt we have for CVE X" that
--     the triage prompt builder issues.
--   * idx_advisory_excerpts_fetched (tenant_id, fetched_at DESC) --
--     supports staleness sweeps and "what advisories did we ingest
--     recently" analytics.
--
-- Storage shape decisions:
--   * source VARCHAR(20) with a CHECK constraint pinning it to the
--     three currently-supported advisory feeds. Adding a new source
--     (e.g. 'osv', 'redhat') is a one-line ALTER ... DROP CONSTRAINT /
--     ADD CONSTRAINT, not a full enum migration.
--   * cve_id VARCHAR(30) matches the convention from llm_calls
--     (triage_target_cve) and is long enough for CVE-YYYY-NNNNNNN +
--     a couple of vendor-prefixed advisory ids that occasionally show
--     up in JVN feeds. ※要確認: do we want to also key by GHSA-id /
--     JVN-id for advisories without a CVE allocation? Today we drop
--     those at parser time; M2 may need to revisit.
--   * vuln_funcs / affected_paths / required_config / required_env are
--     JSONB rather than TEXT[] so the parser can record more than just
--     a name (e.g. `{"name": "html.Parse", "package": "html/template",
--     "since": "1.20"}`) without a schema change. Defaulted to '[]'::JSONB
--     so callers that only fill a subset do not have to deal with NULL.
--   * raw_excerpt TEXT is the verbatim slice the parser hashed for
--     evidence; nullable so a parser that only succeeded at the
--     structured fields (no raw fallback) can still write a row.
-- ============================================

CREATE TABLE advisory_excerpts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenancy. NOT NULL so RLS WITH CHECK has something to compare,
    -- ON DELETE CASCADE so tenant teardown reaps the rows.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Advisory identifier. CVE-YYYY-NNNN(NNN) is the canonical form;
    -- VARCHAR(30) leaves headroom for vendor-prefixed ids.
    cve_id VARCHAR(30) NOT NULL,

    -- Feed of origin. Currently NVD / GHSA / JVN per AC; constrained
    -- with a CHECK so a typo at the parser layer surfaces immediately
    -- instead of polluting the table with 'Ghsa' / 'NVD ' variants.
    source VARCHAR(20) NOT NULL
        CHECK (source IN ('nvd', 'ghsa', 'jvn')),

    -- Structured parser output. JSONB array shape, defaulted to []
    -- so a partial parse still writes a syntactically valid row.
    vuln_funcs      JSONB NOT NULL DEFAULT '[]'::JSONB,
    affected_paths  JSONB NOT NULL DEFAULT '[]'::JSONB,
    required_config JSONB NOT NULL DEFAULT '[]'::JSONB,
    required_env    JSONB NOT NULL DEFAULT '[]'::JSONB,

    -- The verbatim slice of advisory text the parser based the
    -- structured fields on. Used as both human-debugging context and
    -- as LLM-context fallback when the heuristics extract nothing.
    raw_excerpt TEXT,

    -- When the upstream advisory was fetched. Nullable so callers that
    -- only have parser-side timestamps (e.g. replay of an offline
    -- fixture) can still insert.
    fetched_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One row per (tenant, cve, source). Upserts target this constraint.
    CONSTRAINT advisory_excerpts_tenant_cve_source_uniq
        UNIQUE (tenant_id, cve_id, source)
);

-- "Give me every excerpt for this CVE" -- the dominant triage-prompt
-- builder lookup.
CREATE INDEX idx_advisory_excerpts_cve
    ON advisory_excerpts (tenant_id, cve_id);

-- Staleness sweeps + recent-ingestion analytics.
CREATE INDEX idx_advisory_excerpts_fetched
    ON advisory_excerpts (tenant_id, fetched_at DESC);

-- RLS: tenant_isolation. Same shape as 032_llm_calls: FORCE + WITH CHECK
-- + missing_ok GUC read, so an unauthenticated session degrades to zero
-- rows instead of crashing, and a foreign-tenant INSERT is rejected at
-- write time rather than merely hidden at read time.
ALTER TABLE advisory_excerpts ENABLE ROW LEVEL SECURITY;
ALTER TABLE advisory_excerpts FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_advisory_excerpts ON advisory_excerpts
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON TABLE advisory_excerpts IS
    'Parsed advisory excerpts (PRODUCT_REBOOT_PLAN.md §8.5, issue #23). '
    'One row per (tenant_id, cve_id, source); referenced by vex_drafts '
    'as the evidence pointer required by the "no AI output without '
    'evidence" rule. RLS is ENABLE + FORCE with WITH CHECK so '
    'foreign-tenant INSERTs are rejected and migrator/owner connections '
    'do not bypass tenant scope.';
