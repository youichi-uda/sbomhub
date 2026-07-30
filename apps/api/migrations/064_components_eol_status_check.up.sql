-- ============================================
-- Constrain components.eol_status to the four statuses the product defines
-- (M50 follow-up, Codex round 2 #1).
--
-- What this closes:
--   `eol_status` is a nullable varchar with DDL default 'unknown' and, until
--   now, no constraint. The only writer is
--   EOLRepository.UpdateComponentEOLStatus, which bound the caller's
--   model.EOLStatus straight into the UPDATE. That type is a string type, so
--   its zero value is "" — and "" is not just "some other string", it is the
--   value that COLLIDES with SQL NULL on read: model.Component types
--   EOLStatus as a plain string, so GetComponentsWithEOL maps both NULL and ''
--   to "". A row written with '' becomes indistinguishable from a row that was
--   never assessed.
--
--   Round 1 of the review called that collision "unreachable by data".
--   Round 2 disproved it by writing '' through the repository path in a
--   rolled-back UPDATE. Nothing shipped wrong — every live caller passes one
--   of the four model.EOLStatus* constants — but "no caller does this today"
--   is not a constraint, and this table has no RLS-style backstop that would
--   catch it later.
--
-- Belt and braces, matching how this repository treats authorisation input:
--   belt   — repository/eol.go validates against validEOLStatuses and returns
--            ErrInvalidEOLStatus before issuing the UPDATE. This is the half
--            that produces a message naming the field.
--   braces — this CHECK. It also covers writers that bypass the repository
--            (operator SQL, a future second writer, a migration).
--
--   The two lists must stay in step. Adding a status to the Go allowlist
--   without amending this constraint moves the failure from a clear
--   application error to a constraint violation at write time.
--
-- NULL is still allowed:
--   The column is nullable and 063-era rows may hold NULL. This migration is
--   about excluding meaningless values, not about making the column
--   mandatory; `eol_status IS NULL` short-circuits the IN test.
--
-- Existing data:
--   Verified on the dev DB before writing this (2026-07-30): 2 rows, both
--   'unknown', zero NULL, zero empty-string, zero out-of-set values. A
--   production instance carrying a value outside the set will fail at
--   VALIDATE CONSTRAINT below, loudly, with the offending row reported by
--   PostgreSQL — the same "abort rather than silently coerce" posture
--   migration 027 takes for orphaned tenant_id rows. To find such rows before
--   upgrading:
--
--     SELECT id, eol_status FROM components
--      WHERE eol_status IS NOT NULL
--        AND eol_status NOT IN ('unknown','active','eol','eos');
--
--   Remediation is to set them to 'unknown' (the DDL default, meaning "not
--   determined") and re-run the EOL sweep, which recomputes the real status.
--
-- Why NOT VALID then VALIDATE, rather than one ALTER:
--   A plain `ADD CONSTRAINT ... CHECK` holds ACCESS EXCLUSIVE on `components`
--   for the whole verification scan, blocking every reader and writer for the
--   duration. `components` is the largest tenant table in this schema.
--   Splitting it takes ACCESS EXCLUSIVE only for the catalogue update (the
--   NOT VALID step, metadata-only) and then verifies under SHARE UPDATE
--   EXCLUSIVE, which does NOT conflict with reads or ordinary writes.
--
--   The trade: between the two statements the constraint is enforced for NEW
--   rows but not yet proven for old ones. Both run inside the runner's single
--   transaction, so that window does not outlive the migration.
--
-- LOCK BUDGET: see 063 for the reasoning. The NOT VALID step still needs
--   ACCESS EXCLUSIVE briefly, so it can queue behind a live reader; a bounded
--   wait turns an indefinite stall into a retry. 063 was the first migration
--   in this directory to set one; the other 62 still inherit lock_timeout = 0,
--   which remains a repo-wide gap.
-- ============================================

SET LOCAL lock_timeout = '5s';

ALTER TABLE components
    ADD CONSTRAINT components_eol_status_check
    CHECK (eol_status IS NULL OR eol_status IN ('unknown', 'active', 'eol', 'eos'))
    NOT VALID;

ALTER TABLE components
    VALIDATE CONSTRAINT components_eol_status_check;
