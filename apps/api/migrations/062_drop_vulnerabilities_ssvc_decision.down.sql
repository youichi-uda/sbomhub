-- ============================================
-- Reverse of 062_drop_vulnerabilities_ssvc_decision.up.sql (M47 W4).
--
-- Restores the COLUMN AND INDEX exactly as migration 021 declared them
-- (nullable `ssvc_decision` + the partial index on non-NULL values). The
-- `ssvc_decision` ENUM type is never dropped by 062, so it is still present
-- and this re-add needs no CREATE TYPE.
--
-- DATA IS NOT RESTORED, and cannot be. 062 discards the column's contents on
-- purpose: every value it held was a per-(tenant, project) SSVC decision
-- written to the shared, tenant-less `vulnerabilities` row, i.e. the arbitrary
-- winner of a cross-tenant race. There is no correct single value to put back
-- on a globally-shared row, which is the finding 062 fixes.
--
-- No assessment data was lost in either direction: the authoritative record is
-- the ssvc_assessments row keyed by (tenant_id, project_id, vulnerability_id),
-- which 062 does not touch.
--
-- ROLLBACK SEQUENCING -- read before running this down:
--   Apply THIS MIGRATION FIRST, then roll the API back. This is the mirror of
--   062 up's DEPLOY SEQUENCING: the schema step and the binary step bracket
--   each other in opposite orders.
--
--   Why this order: a post-M47-W4 binary never touches the column, so it
--   tolerates the column being present. A pre-M47-W4 binary REQUIRES it — it
--   ends both SSVC assess paths with
--   `UPDATE vulnerabilities SET ssvc_decision = $1 ... WHERE id = $2`. Roll
--   the API back while the column is still dropped and every
--   POST .../vulnerabilities/:vuln_id/ssvc, plus every .../ssvc/auto-assess
--   that actually reaches the write, answers 500 with
--   `column "ssvc_decision" does not exist`. (Auto-assess returns the stored
--   row early when a MANUAL assessment already exists, so that case is
--   unaffected.) Restoring the column first leaves no window in which any
--   deployed binary is broken.
--
--   No API build has ever READ this column (it was write-only from migration
--   021 until M47 W4 removed the writer), so no read path is affected in
--   either direction.
--
--   Note what rolling back COSTS: a pre-M47-W4 binary resumes WRITING the
--   column via SSVCRepository.UpdateVulnerabilitySSVCDecision, which
--   reinstates the cross-tenant last-write-wins behaviour 062 removed. This
--   down is a security regression, not merely a structural one, and it is the
--   reason to prefer rolling forward.
-- ============================================

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_decision ssvc_decision;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_ssvc_decision
    ON vulnerabilities(ssvc_decision) WHERE ssvc_decision IS NOT NULL;
