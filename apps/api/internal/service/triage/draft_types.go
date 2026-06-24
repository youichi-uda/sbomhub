package triage

// This file used to declare a local VexDraft type used by the runner
// while agent A's vex_drafts repository was in flight (parallel-agent
// boundary on Wave M1-5 / issue #30).
//
// Agent A's PR (commit ac8883b) landed `repository.VEXDraft` /
// `repository.VEXDraftsRepository` / `repository.VEXDraftListFilter`
// / `repository.VEXDraftDecisionUpdate`. The runner now uses those
// types directly through the VexDraftStore interface declared in
// runner.go, so this file no longer carries a local VexDraft type --
// it is kept as a breadcrumb so the orchestrator can see at a glance
// that the parallel-agent reconciliation has been done.
//
// Differences vs the original Wave M1-5 prompt assumption:
//
//   - Type name:        VEXDraft (caps) not VexDraft.
//   - Constructor:      NewVEXDraftsRepository not NewVexDraftsRepository.
//   - ComponentID:      required uuid.UUID (not optional *uuid.UUID).
//                       runner.RunInput keeps ComponentID *uuid.UUID for
//                       UI flexibility; the runner deref-checks before
//                       calling Insert.
//   - Confidence:       *float64 (pointer, nullable). The runner only
//                       persists a non-nil pointer.
//   - ConfidenceThreshold / ClampedToUnderInvestigation: NOT columns in
//                       agent A's schema; these are kept only in the
//                       audit_logs Details map (see runner.writeAudit)
//                       and on the in-memory RunResult.
//   - Edit decision:    A's UpdateDecision overwrites state /
//                       justification / detail in place via COALESCE,
//                       rather than carrying edited_* sidecar columns.
//                       The runner.UpdateDecision adapter maps to that.
//   - UpdateDecision return: A's method returns only `error`, not the
//                       updated draft. The runner's UpdateDecision
//                       follows that and re-Gets the row when callers
//                       need the post-update view.

// Decision string constants for the vex_drafts lifecycle. These are
// the same strings agent A's UpdateDecision validates (`approved` /
// `edited` / `rejected`); `pending` is the initial state set by
// VEXDraftsRepository.Insert when a fresh row is written.
//
// Plain string typed (not a sum type) so they can be passed straight
// to repository.VEXDraftDecisionUpdate.Decision and through the JSON
// request bodies without an extra conversion step.
const (
	DecisionPending  = "pending"
	DecisionApproved = "approved"
	DecisionEdited   = "edited"
	DecisionRejected = "rejected"
)
