-- ============================================
-- RLS ENABLE + FORCE + policy on three previously-unguarded tenant-
-- scoped tables (M5 Wave M5-1 / issue #50, RLS uniformity sweep).
--
-- Source of truth:
--   * sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md §9.1
--   * sbomhub-internal/planning/M5_AGENT_PROMPT_TEMPLATE.md §1.A §2 M5-1
--   * GitHub issue #50 (M5 Wave M5-1: RLS uniformity sweep)
--
-- Why these tables need RLS (the P0 leak class M5-1 closes):
--   `github_connections`, `github_repositories`, and
--   `ssvc_assessment_history` all carry tenant-scoped data but shipped
--   without RLS in their original migrations (011 and 021). A
--   sbomhub_app session that knows or guesses another tenant's
--   github_connection UUID / repo full_name / assessment UUID can
--   read or mutate cross-tenant rows through any code path that does
--   not enforce `WHERE tenant_id = $N` at the application layer.
--
--   The current repository / handler layer for github_* does not exist
--   yet (audited 2026-06-27: no Go code references github_connections
--   or github_repositories outside this migration set), but the tables
--   were seeded with hard FKs to projects + tenants in migration 011
--   and are expected to be filled by future GitHub integration work.
--   Closing the RLS gap NOW means the future repository can rely on
--   the policy and does not need to re-discover the F73 / F74 lessons.
--
--   `ssvc_assessment_history` IS exercised by the M2 SSVC repository
--   (internal/repository/ssvc.go CreateAssessmentHistory +
--   GetAssessmentHistory), and the assessment_id-only WHERE clause
--   currently relies on the parent `ssvc_assessments` policy to fail
--   closed for cross-tenant access. That works for SELECT (the JOIN
--   to ssvc_assessments would filter), but `GetAssessmentHistory`
--   queries `ssvc_assessment_history` directly by `assessment_id`
--   without joining the parent. A tenant-A session that learns a
--   tenant-B `assessment_id` (e.g. from an exported VEX bundle that
--   leaks the UUID) can read tenant-B's prior parameter changes and
--   the user UUID that made each change. That is the cross-tenant
--   audit-trail leak this migration closes.
--
-- Why a separate migration (not amending 011 / 021):
--   Same precedent as 023 / 037 / 040 / 042. Operators already past
--   011 / 021 must pick up the RLS state transition through the
--   normal migrate-up sequence; rewriting the original migrations
--   would silently skip those installs.
--
-- Tables covered:
--   1. github_connections      -- has tenant_id column, no policy yet.
--   2. github_repositories     -- has tenant_id + project_id columns,
--                                 no policy yet (composite FK added
--                                 in 044, see header there).
--   3. ssvc_assessment_history -- NO tenant_id column. Policy uses an
--                                 EXISTS-subquery to ssvc_assessments
--                                 to derive tenancy from the parent
--                                 row.
--
-- ssvc_assessment_history policy shape rationale:
--   The straightforward fix would be to ALTER TABLE ADD COLUMN
--   tenant_id UUID and backfill from ssvc_assessments. That requires:
--     * a schema migration that holds an ACCESS EXCLUSIVE lock long
--       enough to add the column + NOT NULL constraint + FK,
--     * an update to the Go model + every CreateAssessmentHistory
--       caller to thread the tenant_id,
--     * an update to GetAssessmentHistory's SELECT list and Scan.
--   None of those are conceptually hard, but they cross the
--   "apps/api/internal/repository/*" + model code surface that
--   M5-1 is supposed to leave alone (the M5-1 scope is RLS, not
--   schema redesign). Instead we use a subquery policy:
--
--     USING (EXISTS (
--       SELECT 1 FROM ssvc_assessments a
--       WHERE a.id = ssvc_assessment_history.assessment_id
--         AND a.tenant_id = current_setting('app.current_tenant_id', true)::UUID
--     ))
--
--   The subquery itself is subject to the parent's RLS (FORCE + policy
--   from migration 042), so it can only see the caller's own
--   ssvc_assessments rows. If the assessment_id belongs to another
--   tenant, the subquery returns no rows, EXISTS is false, and the
--   history row is invisible / write-rejected. Net effect: same
--   guarantee as a tenant_id column, no schema churn.
--
--   Performance note: the subquery hits an index lookup on
--   ssvc_assessments(id) (PRIMARY KEY) plus the tenant_id predicate.
--   For typical history-list pages this is a few hundred rows max;
--   not worth optimising further until the audit-trail UI ships.
--
-- RLS model (matches M4 / post-040 hardened convention):
--   * ENABLE ROW LEVEL SECURITY
--   * FORCE  ROW LEVEL SECURITY (so the sbomhub_migrator role is
--     also subject to the policy)
--   * Single tenant_isolation_<table> policy with FOR ALL, USING +
--     WITH CHECK, both with `, true` so an unset GUC fails closed.
-- ============================================

-- ---------- migration 011 / GitHub integration ----------

ALTER TABLE github_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE github_connections FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_github_connections ON github_connections
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_github_connections ON github_connections IS
    'M5 Wave M5-1 / issue #50: tenant isolation on GitHub PAT / OAuth '
    'credentials. Cross-tenant disclosure here would expose '
    'access_token_encrypted (the encrypted PAT used to clone tenant repos). '
    'See migrations/043_rls_enable_github_ssvc_history.up.sql header.';


ALTER TABLE github_repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE github_repositories FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_github_repositories ON github_repositories
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

COMMENT ON POLICY tenant_isolation_github_repositories ON github_repositories IS
    'M5 Wave M5-1 / issue #50: tenant isolation on per-repo webhook + last-'
    'commit metadata. Cross-tenant disclosure here would expose '
    'webhook_secret (HMAC verification key) and last_commit_sha (private '
    'tenant codebase state). See migrations/043_rls_enable_github_ssvc_history.up.sql header.';


-- ---------- migration 021 / SSVC ----------
--
-- Note ordering: this policy DEPENDS on the parent
-- ssvc_assessments policy being correct. Migration 042 already
-- harmonised ssvc_assessments to FORCE + explicit WITH CHECK; this
-- migration follows 042, so the subquery here is guaranteed to be
-- subject to the same tenant guard.

ALTER TABLE ssvc_assessment_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssvc_assessment_history FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ssvc_assessment_history ON ssvc_assessment_history
    FOR ALL
    USING (
        EXISTS (
            SELECT 1
            FROM ssvc_assessments a
            WHERE a.id = ssvc_assessment_history.assessment_id
              AND a.tenant_id = current_setting('app.current_tenant_id', true)::UUID
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM ssvc_assessments a
            WHERE a.id = ssvc_assessment_history.assessment_id
              AND a.tenant_id = current_setting('app.current_tenant_id', true)::UUID
        )
    );

COMMENT ON POLICY tenant_isolation_ssvc_assessment_history ON ssvc_assessment_history IS
    'M5 Wave M5-1 / issue #50: tenant isolation derived from the parent '
    'ssvc_assessments row (no tenant_id column on history). Cross-tenant '
    'disclosure here would expose the audit trail of SSVC parameter '
    'changes (prev_/new_ exploitation / automatable / safety_impact / '
    'decision + changed_by user UUID). The EXISTS subquery is itself '
    'subject to ssvc_assessments RLS (FORCE + tenant_isolation from '
    'migration 042), so it can only resolve to the caller''s own tenant. '
    'See migrations/043_rls_enable_github_ssvc_history.up.sql header.';
