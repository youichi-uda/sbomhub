-- Migration: Move API keys from project-level to tenant-level
-- This allows API keys to work across all projects in a tenant

-- Step 1: Update existing api_keys to set tenant_id from their project's tenant_id
UPDATE api_keys ak
SET tenant_id = p.tenant_id
FROM projects p
WHERE ak.project_id = p.id
  AND ak.tenant_id IS NULL
  AND p.tenant_id IS NOT NULL;

-- Step 2: Make project_id nullable (new API keys won't need it)
ALTER TABLE api_keys ALTER COLUMN project_id DROP NOT NULL;

-- Step 3: Add NOT NULL constraint to tenant_id (after data migration)
-- First, delete any orphaned api_keys that couldn't get a tenant_id
DELETE FROM api_keys WHERE tenant_id IS NULL;

-- Now make tenant_id required
ALTER TABLE api_keys ALTER COLUMN tenant_id SET NOT NULL;

-- Step 4: Add a comment explaining the change
COMMENT ON COLUMN api_keys.project_id IS 'Deprecated: Legacy project-level API keys. NULL for tenant-level keys.';
COMMENT ON COLUMN api_keys.tenant_id IS 'Required: The tenant this API key belongs to. Grants access to all projects in the tenant.';
