-- Rollback EOL integration

-- Remove EOL columns from components table
ALTER TABLE components DROP COLUMN IF EXISTS eol_checked_at;
ALTER TABLE components DROP COLUMN IF EXISTS eos_date;
ALTER TABLE components DROP COLUMN IF EXISTS eol_date;
ALTER TABLE components DROP COLUMN IF EXISTS eol_cycle_id;
ALTER TABLE components DROP COLUMN IF EXISTS eol_product_id;
ALTER TABLE components DROP COLUMN IF EXISTS eol_status;

-- Drop indexes
DROP INDEX IF EXISTS idx_components_eol_date;
DROP INDEX IF EXISTS idx_components_eol_product;
DROP INDEX IF EXISTS idx_components_eol_status;

-- Drop tables in reverse order of creation (due to foreign key constraints)
DROP TABLE IF EXISTS eol_sync_logs;
DROP TABLE IF EXISTS eol_sync_settings;
DROP TABLE IF EXISTS eol_component_mappings;
DROP TABLE IF EXISTS eol_product_cycles;
DROP TABLE IF EXISTS eol_products;
