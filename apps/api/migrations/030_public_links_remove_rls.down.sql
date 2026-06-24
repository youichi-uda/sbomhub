-- ============================================
-- Restore RLS on public_links + public_link_access_logs
-- (rollback of codex-r5 P1 #19 follow-up)
--
-- WARNING: This revives the chicken-and-egg between the anonymous
-- /api/v1/public/:token token lookup and tenant context. Under
-- `sbomhub_app` (NOBYPASSRLS) every public share link will return 0
-- rows again. Only roll back if you have switched the runtime role
-- back to a BYPASSRLS / superuser one, OR if you no longer expose
-- the public-share feature.
-- ============================================

-- Reset table comments to their pre-030 state (no explicit COMMENT
-- existed before migration 030; NULL clears the comment).
COMMENT ON TABLE public_links IS NULL;
COMMENT ON TABLE public_link_access_logs IS NULL;

-- Re-enable RLS to match the migration 009 state. Migration 023 did not
-- add FORCE on these tables, so we do not re-add it here either.
ALTER TABLE public_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public_link_access_logs ENABLE ROW LEVEL SECURITY;

-- Recreate the original policies from migration 009.
CREATE POLICY tenant_isolation_public_links ON public_links
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_public_link_access_logs ON public_link_access_logs
    USING (public_link_id IN (
        SELECT id FROM public_links
        WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
    ));
