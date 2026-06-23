-- ============================================
-- Roll back NOT NULL on sboms / components.tenant_id
--
-- NOTE: the backfill UPDATEs in the .up are NOT reversed here. They simply
-- copied tenant_id from a parent row into the child row; even if we wanted to
-- restore the prior NULL state we could not distinguish a backfilled row from
-- a row that was inserted with tenant_id set legitimately. Leave the data and
-- only drop the constraint.
-- ============================================

ALTER TABLE sboms ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE components ALTER COLUMN tenant_id DROP NOT NULL;
