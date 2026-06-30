-- ============================================
-- Negative fixture (F195 / M13 Phase D round 3): two tenant-scoped
-- tables in a single migration with an UNSCOPED suppression marker.
--
-- An unscoped `-- lint:no-rls-required: <reason>` marker cannot
-- disambiguate which of the file's tenant-scoped tables is being
-- exempted. Pre-F195 the lint silently treated such a marker as
-- file-wide, defeating the gate; F195 hardens audit() to reject the
-- ambiguous use with a dedicated error pointing the operator at the
-- table-scoped form.
--
-- The lint must FAIL on this fixture, surface the ambiguous-marker
-- error (NOT the generic missing-RLS triple), and recommend the
-- `lint:no-rls-required(<table>):` form as the fix.
-- ============================================

-- lint:no-rls-required: legacy mirror data; tenant_id is informational only

CREATE TABLE tenant_amb_a (
    tenant_id  UUID PRIMARY KEY,
    payload    TEXT NOT NULL
);

CREATE TABLE tenant_amb_b (
    tenant_id  UUID PRIMARY KEY,
    cached_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
