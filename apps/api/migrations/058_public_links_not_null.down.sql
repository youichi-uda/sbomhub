-- Reverse of 058_public_links_not_null.up.sql.
--
-- Drops the NOT NULL constraints, restoring the pre-058 (009) column
-- shape: nullable with a DEFAULT. The backfill (NULL -> false / 0) is
-- deliberately NOT reversed — the original NULLs are not recoverable and
-- re-introducing them would re-open the High-1 fail-open window. This
-- follows the same "backfill is one-way" precedent as
-- 027_sbom_tenant_id_not_null.down.sql.
--
-- The 009 DEFAULTs were never dropped by the up migration, so nothing
-- has to be re-added here.

ALTER TABLE public_links ALTER COLUMN is_active      DROP NOT NULL;
ALTER TABLE public_links ALTER COLUMN view_count     DROP NOT NULL;
ALTER TABLE public_links ALTER COLUMN download_count DROP NOT NULL;

COMMENT ON COLUMN public_links.is_active IS NULL;
COMMENT ON COLUMN public_links.download_count IS NULL;
