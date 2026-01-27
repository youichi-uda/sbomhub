DROP POLICY IF EXISTS tenant_isolation_public_link_access_logs ON public_link_access_logs;
DROP POLICY IF EXISTS tenant_isolation_public_links ON public_links;

ALTER TABLE public_link_access_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE public_links DISABLE ROW LEVEL SECURITY;

DROP TABLE IF EXISTS public_link_access_logs;
DROP TABLE IF EXISTS public_links;
