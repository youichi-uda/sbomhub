-- A DO body is procedural code, not a read path. Measured on PostgreSQL
-- 15.18: this takes AccessExclusiveLock on components, with no EXECUTE
-- anywhere in the body.
DO $$
BEGIN
    ALTER TABLE components ADD COLUMN do_static_probe INTEGER;
END $$;
