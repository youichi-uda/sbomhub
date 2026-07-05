package cra

// deadline_test.go (M34-A / F423) — table-driven coverage for the pure
// CRA Art.14 deadline computation in deadline.go. Every DeadlineStatus
// value is exercised across the windowed report types (early_warning
// 24h, detailed_notification 72h), plus final_report and the
// awareness-nil case (both not_applicable), plus the two on-time /
// overdue boundaries where the submission / clock lands exactly on the
// deadline.

import (
	"testing"
	"time"
)

func tp(t time.Time) *time.Time { return &t }

func TestComputeDeadline_Table(t *testing.T) {
	// Reference instants. awareness at 2026-06-24T00:00:00Z gives an
	// early_warning deadline of 06-25T00:00:00Z (+24h) and a
	// detailed_notification deadline of 06-27T00:00:00Z (+72h).
	awareness := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	ewDeadline := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC) // +24h
	dnDeadline := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) // +72h

	twelveH := 12 * time.Hour
	fortyEightH := 48 * time.Hour

	cases := []struct {
		name           string
		reportType     ReportType
		awareness      *time.Time
		submitted      *time.Time
		now            time.Time
		wantStatus     DeadlineStatus
		wantDeadlineAt *time.Time
		wantRemaining  *time.Duration
	}{
		// ---- early_warning (24h) ----
		{
			name:           "early_warning/pending",
			reportType:     ReportTypeEarlyWarning,
			awareness:      &awareness,
			submitted:      nil,
			now:            time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC), // 12h before deadline
			wantStatus:     DeadlinePending,
			wantDeadlineAt: tp(ewDeadline),
			wantRemaining:  &twelveH,
		},
		{
			name:           "early_warning/overdue",
			reportType:     ReportTypeEarlyWarning,
			awareness:      &awareness,
			submitted:      nil,
			now:            time.Date(2026, 6, 25, 6, 0, 0, 0, time.UTC), // past deadline
			wantStatus:     DeadlineOverdue,
			wantDeadlineAt: tp(ewDeadline),
		},
		{
			name:           "early_warning/overdue_boundary_now_eq_deadline",
			reportType:     ReportTypeEarlyWarning,
			awareness:      &awareness,
			submitted:      nil,
			now:            ewDeadline, // now == deadline → overdue (not pending)
			wantStatus:     DeadlineOverdue,
			wantDeadlineAt: tp(ewDeadline),
		},
		{
			name:           "early_warning/on_time",
			reportType:     ReportTypeEarlyWarning,
			awareness:      &awareness,
			submitted:      tp(time.Date(2026, 6, 24, 20, 0, 0, 0, time.UTC)), // before deadline
			now:            time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineOnTime,
			wantDeadlineAt: tp(ewDeadline),
		},
		{
			name:           "early_warning/on_time_boundary_filed_eq_deadline",
			reportType:     ReportTypeEarlyWarning,
			awareness:      &awareness,
			submitted:      tp(ewDeadline), // filedAt == deadline → on_time
			now:            time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineOnTime,
			wantDeadlineAt: tp(ewDeadline),
		},
		{
			name:           "early_warning/late",
			reportType:     ReportTypeEarlyWarning,
			awareness:      &awareness,
			submitted:      tp(time.Date(2026, 6, 25, 1, 0, 0, 0, time.UTC)), // 1h past deadline
			now:            time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineLate,
			wantDeadlineAt: tp(ewDeadline),
		},

		// ---- detailed_notification (72h) ----
		{
			name:           "detailed_notification/pending",
			reportType:     ReportTypeDetailedNotification,
			awareness:      &awareness,
			submitted:      nil,
			now:            time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC), // 48h before deadline
			wantStatus:     DeadlinePending,
			wantDeadlineAt: tp(dnDeadline),
			wantRemaining:  &fortyEightH,
		},
		{
			name:           "detailed_notification/overdue",
			reportType:     ReportTypeDetailedNotification,
			awareness:      &awareness,
			submitted:      nil,
			now:            time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineOverdue,
			wantDeadlineAt: tp(dnDeadline),
		},
		{
			name:           "detailed_notification/on_time",
			reportType:     ReportTypeDetailedNotification,
			awareness:      &awareness,
			submitted:      tp(time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)),
			now:            time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineOnTime,
			wantDeadlineAt: tp(dnDeadline),
		},
		{
			name:           "detailed_notification/on_time_boundary_filed_eq_deadline",
			reportType:     ReportTypeDetailedNotification,
			awareness:      &awareness,
			submitted:      tp(dnDeadline),
			now:            time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineOnTime,
			wantDeadlineAt: tp(dnDeadline),
		},
		{
			name:           "detailed_notification/late",
			reportType:     ReportTypeDetailedNotification,
			awareness:      &awareness,
			submitted:      tp(time.Date(2026, 6, 27, 0, 0, 1, 0, time.UTC)), // 1s past deadline
			now:            time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineLate,
			wantDeadlineAt: tp(dnDeadline),
		},

		// ---- final_report: no clock, always not_applicable ----
		{
			name:           "final_report/not_applicable_submitted",
			reportType:     ReportTypeFinalReport,
			awareness:      &awareness,
			submitted:      tp(time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)),
			now:            time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineNotApplicable,
			wantDeadlineAt: nil,
		},
		{
			name:           "final_report/not_applicable_unsubmitted",
			reportType:     ReportTypeFinalReport,
			awareness:      &awareness,
			submitted:      nil,
			now:            time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineNotApplicable,
			wantDeadlineAt: nil,
		},

		// ---- awareness nil: no clock could start, not_applicable ----
		{
			name:           "early_warning/awareness_nil_not_applicable",
			reportType:     ReportTypeEarlyWarning,
			awareness:      nil,
			submitted:      nil,
			now:            time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineNotApplicable,
			wantDeadlineAt: nil,
		},
		{
			name:           "detailed_notification/awareness_nil_not_applicable",
			reportType:     ReportTypeDetailedNotification,
			awareness:      nil,
			submitted:      tp(time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)),
			now:            time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineNotApplicable,
			wantDeadlineAt: nil,
		},
		{
			name:           "final_report/awareness_nil_not_applicable",
			reportType:     ReportTypeFinalReport,
			awareness:      nil,
			submitted:      nil,
			now:            time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC),
			wantStatus:     DeadlineNotApplicable,
			wantDeadlineAt: nil,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeDeadline(tc.reportType, tc.awareness, tc.submitted, tc.now)

			if got.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", got.Status, tc.wantStatus)
			}

			switch {
			case tc.wantDeadlineAt == nil && got.DeadlineAt != nil:
				t.Errorf("DeadlineAt = %v, want nil", got.DeadlineAt)
			case tc.wantDeadlineAt != nil && got.DeadlineAt == nil:
				t.Errorf("DeadlineAt = nil, want %v", tc.wantDeadlineAt)
			case tc.wantDeadlineAt != nil && got.DeadlineAt != nil && !got.DeadlineAt.Equal(*tc.wantDeadlineAt):
				t.Errorf("DeadlineAt = %v, want %v", got.DeadlineAt, tc.wantDeadlineAt)
			}

			switch {
			case tc.wantRemaining == nil && got.Remaining != nil:
				t.Errorf("Remaining = %v, want nil", got.Remaining)
			case tc.wantRemaining != nil && got.Remaining == nil:
				t.Errorf("Remaining = nil, want %v", tc.wantRemaining)
			case tc.wantRemaining != nil && got.Remaining != nil && *got.Remaining != *tc.wantRemaining:
				t.Errorf("Remaining = %v, want %v", *got.Remaining, *tc.wantRemaining)
			}
		})
	}
}

// TestComputeDeadline_StatusValues pins the five wire string values the
// handler (Wave B) serialises and the web (Wave C) / CLI (Wave D)
// clients read. A rename here would silently break the cross-surface
// contract frozen in the M34 API pin.
func TestComputeDeadline_StatusValues(t *testing.T) {
	pairs := map[DeadlineStatus]string{
		DeadlineNotApplicable: "not_applicable",
		DeadlinePending:       "pending",
		DeadlineOverdue:       "overdue",
		DeadlineOnTime:        "on_time",
		DeadlineLate:          "late",
	}
	for got, want := range pairs {
		if string(got) != want {
			t.Errorf("status const = %q, want wire value %q", string(got), want)
		}
	}
}
