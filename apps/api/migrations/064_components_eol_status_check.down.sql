-- ============================================
-- Reverse of 064_components_eol_status_check.up.sql (M50 follow-up).
--
-- Drops the CHECK, restoring components.eol_status to an unconstrained
-- nullable varchar. No data changes: the constraint only ever rejected writes,
-- it never rewrote a row, so there is nothing to restore.
--
-- Runs after 065's down (the runner rolls back in descending version order),
-- by which point the constraint is already back to NOT VALID. DROP CONSTRAINT
-- removes it in either state, so this file is correct whether or not 065 ever
-- ran.
--
-- What rolling back re-opens: the '' / NULL collision described in the up
-- migration. model.Component types EOLStatus as a plain string, so a row
-- written with an empty status reads back identically to a row that was never
-- assessed, with no error anywhere. The Go-side allowlist in
-- repository/eol.go (validEOLStatuses / ErrInvalidEOLStatus) still holds after
-- this down, so the repository path stays closed — what is lost is coverage of
-- writers that bypass it (operator SQL, a future second writer).
--
-- ROLLBACK SEQUENCING: no ordering constraint against the API binary. Dropping
-- a CHECK only ever widens what is accepted, so no deployed build can fail
-- because of it — unlike 062, whose down had to precede the API rollback.
--
-- LOCK BUDGET: `DROP CONSTRAINT` takes ACCESS EXCLUSIVE (catalogue-only, no
-- table scan), so it can still queue behind a live reader. Bounded for the
-- same reason as the up migration.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE components
    DROP CONSTRAINT IF EXISTS components_eol_status_check;
