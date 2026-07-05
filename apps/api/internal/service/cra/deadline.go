package cra

// deadline.go (M34-A / F423, issue #148) — CRA Article 14 reporting
// deadline computation.
//
// CRA Art.14 starts its reporting clock at the instant a manufacturer
// becomes AWARE of an actively exploited vulnerability (persisted on
// cra_reports.awareness_time, migration 054). From that instant:
//
//   - the early_warning report is due within 24h (Art.14(2)(a));
//   - the detailed_notification report is due within 72h (Art.14(2)(b));
//   - the final_report has no fixed clock ("as soon as practicable"
//     after remediation, Art.14(2)(c)) — it is never judged here.
//
// This file is PURE: it takes the raw awareness instant, the earliest
// actual submission time, and a caller-injected `now`, and returns the
// deadline + a status. It has NO DB / HTTP / LLM dependency (only the
// time package) so it is trivially table-testable; the handler (Wave B)
// injects time.Now().UTC() and the batched earliest-submission times.
//
// Derived-state discipline (migration 053 / 054 rationale): NOTHING here
// is persisted. deadline_at and the status are recomputed on every read
// from the two sources of truth (awareness_time + submitted_at) so a
// corrected awareness instant or report type can never leave a stale
// stored deadline behind.

import "time"

// DeadlineStatus is the read-time judgement of a CRA report against its
// Art.14 reporting window. Five values, mutually exclusive.
type DeadlineStatus string

const (
	// DeadlineNotApplicable — no clock to judge: the report is a
	// final_report (no fixed Art.14 window) OR its awareness instant is
	// nil (forward-looking only; legacy rows drafted before migration
	// 054 stay here).
	DeadlineNotApplicable DeadlineStatus = "not_applicable"

	// DeadlinePending — not yet submitted and the deadline is still in
	// the future (now < deadline). Remaining carries now→deadline.
	DeadlinePending DeadlineStatus = "pending"

	// DeadlineOverdue — not yet submitted and the deadline has passed
	// (now >= deadline).
	DeadlineOverdue DeadlineStatus = "overdue"

	// DeadlineOnTime — submitted on or before the deadline
	// (earliest submitted_at <= deadline).
	DeadlineOnTime DeadlineStatus = "on_time"

	// DeadlineLate — submitted after the deadline
	// (earliest submitted_at > deadline).
	DeadlineLate DeadlineStatus = "late"
)

// DeadlineResult is the outcome of ComputeDeadline.
type DeadlineResult struct {
	// Status is the mutually-exclusive judgement.
	Status DeadlineStatus

	// DeadlineAt is awareness_time + the report-type window. nil for
	// not_applicable (there is no window to compute); non-nil for every
	// other status.
	DeadlineAt *time.Time

	// Remaining is the now→deadline duration and is set ONLY for
	// pending. It is nil for every other status (a negative "time since
	// deadline" is deliberately not surfaced here — overdue already says
	// that qualitatively).
	Remaining *time.Duration
}

// ComputeDeadline judges one CRA report against its Art.14 reporting
// window. Pure function; the caller injects `now` (production passes
// time.Now().UTC()).
//
//   - reportType          — the report's milestone; only early_warning
//     (24h) and detailed_notification (72h) carry a window. final_report
//     is always not_applicable.
//   - awareness           — the operator-attested awareness instant
//     (cra_reports.awareness_time); nil ⇒ not_applicable.
//   - earliestSubmittedAt — the earliest cra_submissions.submitted_at
//     for this report (MIN); nil ⇒ not submitted yet.
//   - now                 — the clock the pending/overdue split uses.
//
// Judgement:
//
//	final_report OR awareness == nil          → not_applicable
//	deadline = awareness + window(reportType)
//	submitted (earliestSubmittedAt != nil):
//	    submitted <= deadline                 → on_time   (boundary: == is on_time)
//	    submitted >  deadline                 → late
//	not submitted:
//	    now <  deadline                       → pending   (Remaining = deadline - now)
//	    now >= deadline                       → overdue
func ComputeDeadline(reportType ReportType, awareness *time.Time, earliestSubmittedAt *time.Time, now time.Time) DeadlineResult {
	// No clock: final_report has no fixed Art.14 window, and a nil
	// awareness instant means no clock could ever have started.
	if reportType == ReportTypeFinalReport || awareness == nil {
		return DeadlineResult{Status: DeadlineNotApplicable}
	}

	window, ok := deadlineWindow(reportType)
	if !ok {
		// Drift guard: a report type with no defined reporting window
		// (should never reach here for a registered type) is judged
		// not_applicable rather than assuming a default deadline.
		return DeadlineResult{Status: DeadlineNotApplicable}
	}

	deadlineAt := awareness.Add(window)

	if earliestSubmittedAt != nil {
		// Submitted: on time when filed on or before the deadline
		// (boundary filedAt == deadline is on_time), otherwise late.
		status := DeadlineOnTime
		if earliestSubmittedAt.After(deadlineAt) {
			status = DeadlineLate
		}
		return DeadlineResult{Status: status, DeadlineAt: &deadlineAt}
	}

	// Not yet submitted: pending while the deadline is in the future,
	// overdue once it has passed (boundary now == deadline is overdue).
	if now.Before(deadlineAt) {
		remaining := deadlineAt.Sub(now)
		return DeadlineResult{Status: DeadlinePending, DeadlineAt: &deadlineAt, Remaining: &remaining}
	}
	return DeadlineResult{Status: DeadlineOverdue, DeadlineAt: &deadlineAt}
}

// deadlineWindow maps a windowed CRA report type to its Art.14
// reporting window. Switches on the typed ReportType consts (never a
// bare wire literal) so the F341 registry parity contract stays the
// single source of the wire values. final_report is deliberately absent
// (it has no fixed clock and is handled as not_applicable before this is
// called); a report type not listed here returns ok == false.
func deadlineWindow(reportType ReportType) (time.Duration, bool) {
	switch reportType {
	case ReportTypeEarlyWarning:
		return 24 * time.Hour, true
	case ReportTypeDetailedNotification:
		return 72 * time.Hour, true
	default:
		return 0, false
	}
}
