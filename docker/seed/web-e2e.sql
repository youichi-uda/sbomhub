-- SBOMHub - Web e2e (Playwright) populated DB seed — M10-3 #71
--
-- This file is loaded by .github/workflows/web-e2e.yml right after the
-- migrator has finished applying apps/api/migrations/. It populates the
-- minimum row set that the 26 specs under apps/web/e2e/*.spec.ts need
-- in order to render their target pages before the spec's own setup
-- code (most specs self-seed a fresh project via POST /api/v1/projects
-- in beforeAll, but several render dashboards / lists that look empty
-- without at least one persisted row).
--
-- Design notes
-- ------------
--   1. We intentionally PRE-CREATE the self-hosted default tenant with
--      a deterministic UUID so the seed-and-test flow is reproducible
--      (otherwise the API's GetOrCreateDefault() generates a random
--      UUID on first request and FK-references below have no anchor).
--      The clerk_org_id='self-hosted' + slug='default' combination is
--      what the API's repository.TenantRepository.GetOrCreateDefault
--      and UserRepository.GetOrCreateDefault look up by — when those
--      rows already exist, the API uses them verbatim instead of
--      creating new ones (apps/api/internal/repository/tenant.go:201,
--      apps/api/internal/repository/user.go:180).
--
--   2. All UUIDs / passwords here are HARDCODED constants because the
--      tenant is non-production (see CLAUDE.md M0-M9 §"Constraints"
--      under M10-3 brief). They MUST NEVER appear in a production
--      deployment. The workflow runs this file against an ephemeral
--      docker compose postgres volume that is torn down at the end of
--      the job (`docker compose down -v`).
--
--   3. The file is idempotent: every INSERT is wrapped with ON
--      CONFLICT DO NOTHING so re-running the seed against a partially
--      populated DB is safe. This matters in the local repro recipe
--      (apps/web/e2e/README.md) where developers re-run the seed
--      across multiple Playwright sessions without dropping volumes.
--
--   4. Evidence JSON columns (vex_drafts.evidence, cra_reports.evidence,
--      meti_assessments.evidence) carry a check constraint requiring
--      jsonb_array_length(...) > 0 (or >= 0 for METI) — the seed
--      includes a single citation object per row to satisfy the
--      "no AI output without evidence" invariant
--      (apps/api/migrations/035_vex_drafts.up.sql header comment).
--
--   5. RLS — FORCE ROW LEVEL SECURITY is enabled on most tables (see
--      migrations 007, 023, 030, 040, 042, 043). The `sbomhub`
--      superuser-equivalent role created by docker-compose.yml's
--      POSTGRES_USER carries `rolbypassrls=t`, so this script is meant
--      to be loaded as the `sbomhub` role (NOT sbomhub_app /
--      sbomhub_migrator, which both honour RLS). The workflow uses
--      `docker compose exec -T postgres psql -U sbomhub` to enforce
--      this — running it via the app role would require a SET LOCAL
--      app.current_tenant_id ahead of every INSERT, which we avoid.

BEGIN;

-- ---------------------------------------------------------------------
-- 1. Default tenant + user (self-hosted bootstrap)
-- ---------------------------------------------------------------------
INSERT INTO tenants (id, clerk_org_id, name, slug, plan, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001'::uuid,
    'self-hosted',
    'Default Organization',
    'default',
    'enterprise',
    NOW(),
    NOW()
)
ON CONFLICT (clerk_org_id) DO NOTHING;

-- avatar_url is TEXT NULL in the schema, but the API repository scans
-- into a plain Go `string` field (model/user.go). NULL Scan into a
-- string fails — so the seed forces an empty string to match the
-- shape the API's GetOrCreateDefault() writes.
INSERT INTO users (id, clerk_user_id, email, name, avatar_url, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000002'::uuid,
    'self-hosted',
    'admin@localhost',
    'Administrator',
    '',
    NOW(),
    NOW()
)
ON CONFLICT (clerk_user_id) DO NOTHING;

INSERT INTO tenant_users (tenant_id, user_id, role, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000002'::uuid,
    'owner',
    NOW()
)
ON CONFLICT (tenant_id, user_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 2. Seed project + SBOM + component
-- ---------------------------------------------------------------------
-- Project the dashboard/projects/sbom/vex/etc specs can render against
-- before their beforeAll creates their own. Several specs filter by
-- "M10-3" in their navigation flow assertions; the marker name keeps
-- the seed row distinguishable from spec-created projects.
INSERT INTO projects (id, tenant_id, name, description, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000010'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'M10-3 Seed Project',
    'Seed project for web e2e CI gate (M10-3 #71).',
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000020'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    'cyclonedx',
    '1.4',
    jsonb_build_object(
        'bomFormat', 'CycloneDX',
        'specVersion', '1.4',
        'version', 1,
        'components', jsonb_build_array(
            jsonb_build_object(
                'type', 'library',
                'name', 'log4j-core',
                'version', '2.14.0',
                'purl', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0',
                'licenses', jsonb_build_array(jsonb_build_object('license', jsonb_build_object('id', 'Apache-2.0')))
            )
        )
    ),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000030'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000020'::uuid,
    'log4j-core',
    '2.14.0',
    'library',
    'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0',
    'Apache-2.0',
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 2b. Second SBOM (newer version) + 3 components for diff / licenses
-- ---------------------------------------------------------------------
-- A second SBOM on the same project so:
--   * the sbom-diff page has two SBOMs to diff against (already covered
--     by M11-1's per-test self-seeding, but a seeded pair lets cross-
--     tenant flows render against a non-empty diff history),
--   * the licenses spec finds at least one MIT-allow / GPL-3-deny
--     policy violation (matched by license_id below),
--   * Hosted vuln search returns updated component versions when the
--     `log4j-core` row appears at both 2.14.0 (vulnerable) and 2.17.0
--     (fixed) — M11-2 #77 follow-up to M10-3's minimum seed.
INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000021'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    'cyclonedx',
    '1.4',
    jsonb_build_object(
        'bomFormat', 'CycloneDX',
        'specVersion', '1.4',
        'version', 2,
        'components', jsonb_build_array(
            jsonb_build_object(
                'type', 'library',
                'name', 'log4j-core',
                'version', '2.17.0',
                'purl', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0',
                'licenses', jsonb_build_array(jsonb_build_object('license', jsonb_build_object('id', 'Apache-2.0')))
            ),
            jsonb_build_object(
                'type', 'library',
                'name', 'lodash',
                'version', '4.17.21',
                'purl', 'pkg:npm/lodash@4.17.21',
                'licenses', jsonb_build_array(jsonb_build_object('license', jsonb_build_object('id', 'MIT')))
            ),
            jsonb_build_object(
                'type', 'library',
                'name', 'gpl-test-component',
                'version', '1.0.0',
                'purl', 'pkg:generic/gpl-test-component@1.0.0',
                'licenses', jsonb_build_array(jsonb_build_object('license', jsonb_build_object('id', 'GPL-3.0-only')))
            )
        )
    ),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- log4j-core 2.17.0 — patched version, no CVE link.
INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000031'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000021'::uuid,
    'log4j-core',
    '2.17.0',
    'library',
    'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0',
    'Apache-2.0',
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- MIT-licensed component (lodash) — allowed by license_policies.
INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000032'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000021'::uuid,
    'lodash',
    '4.17.21',
    'library',
    'pkg:npm/lodash@4.17.21',
    'MIT',
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- GPL-3-licensed component — denied by license_policies (drives the
-- license-violations rendering path below).
INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000033'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000021'::uuid,
    'gpl-test-component',
    '1.0.0',
    'library',
    'pkg:generic/gpl-test-component@1.0.0',
    'GPL-3.0-only',
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 3. Vulnerability + component-vulnerability link
-- ---------------------------------------------------------------------
-- The vulnerabilities table is tenant-soft (tenant_id ON DELETE SET
-- NULL) so the seed pins one CVE row that the vex_draft / cra_report
-- below FK-reference. cve_id is UNIQUE so the ON CONFLICT clause keys
-- on that column.
INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, tenant_id, in_kev, published_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000040'::uuid,
    'CVE-2021-44228',
    'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
    'CRITICAL',
    10.0,
    'NVD',
    '00000000-0000-0000-0000-000000000001'::uuid,
    TRUE,
    '2021-12-10T00:00:00Z',
    NOW()
)
ON CONFLICT (cve_id) DO NOTHING;

INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
VALUES (
    '00000000-0000-0000-0000-000000000030'::uuid,
    '00000000-0000-0000-0000-000000000040'::uuid,
    NOW()
)
ON CONFLICT (component_id, vulnerability_id) DO NOTHING;

-- Additional CVEs so cross-tenant CVE search (e2e/search.spec.ts) and
-- the vulnerabilities list (e2e/vulnerabilities.spec.ts) return more
-- than a single Log4Shell row.
INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, tenant_id, in_kev, published_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000041'::uuid,
    'CVE-2021-45046',
    'Apache Log4j2 Thread Context Map lookup pattern allows attackers with control over Thread Context Map (MDC) input data to craft malicious input data using a JNDI lookup pattern.',
    'CRITICAL',
    9.0,
    'NVD',
    '00000000-0000-0000-0000-000000000001'::uuid,
    TRUE,
    '2021-12-14T00:00:00Z',
    NOW()
)
ON CONFLICT (cve_id) DO NOTHING;

INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, tenant_id, in_kev, published_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000042'::uuid,
    'CVE-2021-23337',
    'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.',
    'HIGH',
    7.2,
    'NVD',
    '00000000-0000-0000-0000-000000000001'::uuid,
    FALSE,
    '2021-02-15T00:00:00Z',
    NOW()
)
ON CONFLICT (cve_id) DO NOTHING;

INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, tenant_id, in_kev, published_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000043'::uuid,
    'CVE-2020-8203',
    'Prototype pollution in lodash before 4.17.20 via _.zipObjectDeep allows a malicious user to modify object prototype properties.',
    'HIGH',
    7.4,
    'NVD',
    '00000000-0000-0000-0000-000000000001'::uuid,
    FALSE,
    '2020-07-15T00:00:00Z',
    NOW()
)
ON CONFLICT (cve_id) DO NOTHING;

-- Match the additional CVEs to the components already present:
--   * log4j-core 2.14.0 (component …030) ← CVE-2021-45046
--   * lodash 4.17.21 (component …032) ← CVE-2021-23337 + CVE-2020-8203
--     (kept here as fixed-version components so the vulnerabilities
--     list still has rows to render; the API surfaces all component-
--     linked CVEs irrespective of "fixed-by" comparisons today).
INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
VALUES (
    '00000000-0000-0000-0000-000000000030'::uuid,
    '00000000-0000-0000-0000-000000000041'::uuid,
    NOW()
)
ON CONFLICT (component_id, vulnerability_id) DO NOTHING;

INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
VALUES (
    '00000000-0000-0000-0000-000000000032'::uuid,
    '00000000-0000-0000-0000-000000000042'::uuid,
    NOW()
)
ON CONFLICT (component_id, vulnerability_id) DO NOTHING;

INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
VALUES (
    '00000000-0000-0000-0000-000000000032'::uuid,
    '00000000-0000-0000-0000-000000000043'::uuid,
    NOW()
)
ON CONFLICT (component_id, vulnerability_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 3b. License policies (M11-2 #77)
-- ---------------------------------------------------------------------
-- One allow rule (MIT) + one deny rule (GPL-3-only) so the licenses
-- spec can render the policies list and exercise the violations API
-- against the seeded components above. Per project_id + tenant_id, RLS
-- and the (project_id, license_id) UNIQUE constraint both apply.
INSERT INTO license_policies (
    id, project_id, tenant_id, license_id, license_name, policy_type, reason, created_at, updated_at
)
VALUES (
    '00000000-0000-0000-0000-0000000000a0'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'MIT',
    'MIT License',
    'allowed',
    'Seed allow-rule: MIT is approved for commercial use (M11-2 #77).',
    NOW(),
    NOW()
)
ON CONFLICT (project_id, license_id) DO NOTHING;

INSERT INTO license_policies (
    id, project_id, tenant_id, license_id, license_name, policy_type, reason, created_at, updated_at
)
VALUES (
    '00000000-0000-0000-0000-0000000000a1'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'GPL-3.0-only',
    'GNU GPL v3.0',
    'denied',
    'Seed deny-rule: GPL-3.0 copyleft incompatible with proprietary release (M11-2 #77).',
    NOW(),
    NOW()
)
ON CONFLICT (project_id, license_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 3c. API key fixture (M11-2 #77)
-- ---------------------------------------------------------------------
-- A single tenant-scoped key so /settings/apikeys (and any per-project
-- /apikeys list) renders at least one row. The hash is a SYNTHETIC
-- sha256 placeholder — `sha256('m11-2-seed-key-do-not-use-in-prod')` —
-- which DOES NOT correspond to any real key value. The plaintext key
-- is intentionally not stored anywhere; the row exists only so the UI
-- list path renders without depending on a successful POST in the
-- spec's beforeAll.
--
-- DO NOT replace this with a hash of a real key in any production
-- deployment — this file is ephemeral CI seed only and must never be
-- loaded against a production database (see header §2 / CLAUDE.md M0
-- "Trust Rescue" §Constraints).
INSERT INTO api_keys (
    id, project_id, tenant_id, name, key_hash, key_prefix, permissions, created_at
)
VALUES (
    '00000000-0000-0000-0000-0000000000b0'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'M11-2 Seed Key (do not use in production)',
    'm11-2-seed-synthetic-not-a-real-hash-00000000000000000000000000',
    'sbh_seed',
    'write',
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 4. AI VEX draft (M1) — 1 pending row so /triage renders the list
-- ---------------------------------------------------------------------
-- vex_drafts.evidence has CHECK (jsonb_array_length(evidence) > 0),
-- so we attach a single citation object. provider/model are pinned
-- to "seed" to mark the row as non-LLM-generated for any spec that
-- filters real provider drafts.
INSERT INTO vex_drafts (
    id, tenant_id, project_id, sbom_id, component_id, vulnerability_id, cve_id,
    state, justification, detail, confidence, provider, model,
    evidence, decision, created_by, created_at, updated_at
)
VALUES (
    '00000000-0000-0000-0000-000000000050'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    '00000000-0000-0000-0000-000000000020'::uuid,
    '00000000-0000-0000-0000-000000000030'::uuid,
    '00000000-0000-0000-0000-000000000040'::uuid,
    'CVE-2021-44228',
    'not_affected',
    'vulnerable_code_not_in_execute_path',
    'Seed VEX draft for M10-3 e2e gate. JNDI lookup path is not reachable in the bundled configuration.',
    0.80,
    'seed',
    'm10-3-fixture',
    jsonb_build_array(
        jsonb_build_object('kind', 'seed_fixture', 'ref', 'M10-3 #71 docker/seed/web-e2e.sql')
    ),
    'pending',
    '00000000-0000-0000-0000-000000000002'::uuid,
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 5. AI CRA report draft (M2) — early_warning + detailed_notification
-- ---------------------------------------------------------------------
-- cra_reports has the same evidence + decision pattern. We seed both a
-- "draft" and a separate "approved" row so the cra-reports.spec can
-- exercise the state filter without depending on the live LLM runner.
INSERT INTO cra_reports (
    id, tenant_id, project_id, vulnerability_id, cve_id,
    report_type, lang, state, draft_text,
    provider, model, evidence, decision,
    source_vex_draft_id, created_by, created_at, updated_at
)
VALUES (
    '00000000-0000-0000-0000-000000000060'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    '00000000-0000-0000-0000-000000000040'::uuid,
    'CVE-2021-44228',
    'early_warning',
    'ja',
    'draft',
    '【24時間早期警告 ドラフト (M10-3 seed)】CVE-2021-44228 (Log4Shell) を検知。影響範囲を調査中。',
    'seed',
    'm10-3-fixture',
    jsonb_build_array(
        jsonb_build_object('kind', 'seed_fixture', 'ref', 'M10-3 #71 docker/seed/web-e2e.sql')
    ),
    'pending',
    '00000000-0000-0000-0000-000000000050'::uuid,
    '00000000-0000-0000-0000-000000000002'::uuid,
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 6. METI self-assessment row (M3) — 1 needs_review criterion
-- ---------------------------------------------------------------------
-- meti_assessments.evidence accepts jsonb_array_length >= 0 (empty arrays
-- are legal — see migration 039 comment). The seed pins one row in the
-- "sbom_creation" phase so meti-assessment.spec.ts has at least one
-- assessment to render before its own POST /refresh kicks in.
-- M11-2 #77: criterion_id pinned to the catalog-correct
-- "meti.env_setup.01" form so the criterion-card.tsx title resolves
-- to the seeded en/ja string instead of falling back to the raw id.
-- override_status stays NULL so the override-form spec finds a
-- non-overridden row to interact with.
--
-- The row's id moved from ...070 → ...071 in M11-2 to avoid PK
-- conflicts when re-loading on top of an M10-3-shaped DB (the
-- legacy seed used id=...070 / criterion_id='sbom-1'). The UNIQUE
-- (tenant_id, project_id, criterion_id) ON CONFLICT clause still
-- protects against accidental duplicates within a single load.
INSERT INTO meti_assessments (
    id, tenant_id, project_id,
    criterion_id, criterion_phase, status, evidence,
    evaluator_version, evaluated_at, created_at, updated_at
)
VALUES (
    '00000000-0000-0000-0000-000000000071'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    'meti.env_setup.01',
    'env_setup',
    'needs_review',
    jsonb_build_array(
        jsonb_build_object('kind', 'seed_fixture', 'ref', 'M11-2 #77 docker/seed/web-e2e.sql')
    ),
    'seed-1',
    NOW(),
    NOW(),
    NOW()
)
ON CONFLICT (tenant_id, project_id, criterion_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 7. Audit log seed row
-- ---------------------------------------------------------------------
-- audit_logs has FORCE RLS but is loaded by the BYPASSRLS sbomhub
-- superuser. A single seed action row keeps audit.spec.ts renderable
-- before its own beforeAll-created project triggers further entries.
INSERT INTO audit_logs (id, tenant_id, user_id, action, resource_type, resource_id, details, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000080'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000002'::uuid,
    'seed.bootstrap',
    'project',
    '00000000-0000-0000-0000-000000000010'::uuid,
    jsonb_build_object('source', 'M10-3 #71 docker/seed/web-e2e.sql', 'note', 'web e2e CI gate fixture'),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

COMMIT;
