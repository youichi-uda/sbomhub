-- Rollback: Revert API keys back to project-level only

-- Remove comments
COMMENT ON COLUMN api_keys.project_id IS NULL;
COMMENT ON COLUMN api_keys.tenant_id IS NULL;

-- Make tenant_id nullable again
ALTER TABLE api_keys ALTER COLUMN tenant_id DROP NOT NULL;

-- Make project_id required again (this will fail if there are tenant-level keys)
-- You may need to delete tenant-level keys first: DELETE FROM api_keys WHERE project_id IS NULL;
ALTER TABLE api_keys ALTER COLUMN project_id SET NOT NULL;
