-- ============================================
-- Reverse of 065_components_eol_status_validate.up.sql.
--
-- PostgreSQL has no "un-validate" statement: convalidated can be cleared only
-- by dropping the constraint and re-adding it NOT VALID. That is what this
-- does, restoring exactly the state 064 leaves behind (constraint present,
-- enforced for new rows, unproven for old ones) so that `down 1` from a fully
-- migrated database lands on 064's post-state rather than on something new.
--
-- The drop-and-readd is NOT a no-op in lock terms even though it looks like
-- one: DROP CONSTRAINT and ADD CONSTRAINT ... NOT VALID both take ACCESS
-- EXCLUSIVE. Both are catalogue-only — no table scan — so the lock is brief,
-- but it is still exclusive, hence the budget below.
--
-- No data changes. The constraint never rewrote a row; rolling back its
-- validated status changes only what PostgreSQL believes it has proven about
-- existing rows. New writes stay constrained until 064's down removes the
-- constraint entirely.
--
-- The constraint definition below MUST stay character-identical to 064's. If
-- they drift, `down 1` followed by `up` silently changes the enforced set.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE components
    DROP CONSTRAINT IF EXISTS components_eol_status_check;

ALTER TABLE components
    ADD CONSTRAINT components_eol_status_check
    CHECK (eol_status IS NULL OR eol_status IN ('unknown', 'active', 'eol', 'eos'))
    NOT VALID;
