-- A DO block that issues dynamic SQL. The lint cannot see what it does,
-- so it is charged the strongest lock and the file needs a budget.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE projects ADD COLUMN dynamic_col TEXT';
END $$;
