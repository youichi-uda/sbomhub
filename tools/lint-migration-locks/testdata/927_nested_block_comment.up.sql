-- PostgreSQL block comments nest. Measured on 15.18:
--   SELECT 1 /* outer /* nested */ still outer */ AS nested_ok;  -> 1
/* outer /* nested */ still outer */
ALTER TABLE components ADD COLUMN nested_probe INTEGER;
