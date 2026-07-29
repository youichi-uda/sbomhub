package service

import (
	"testing"
	"time"
)

// TestWeeklyScanDay_NullMeansTheSharedDefault pins the single source of
// truth for "scan_settings.schedule_day is NULL".
//
// M49: the column is DDL-nullable with no default, and before this change
// two readers disagreed about the NULL — this package defaulted to Monday
// while scheduler.updateNextScan read sql.NullInt64.Int64 without checking
// .Valid and got 0 (Sunday). The constant below is what both now use.
func TestWeeklyScanDay_NullMeansTheSharedDefault(t *testing.T) {
	if got := WeeklyScanDay(nil); got != DefaultWeeklyScanDay {
		t.Errorf("WeeklyScanDay(nil) = %d, want %d (DefaultWeeklyScanDay)", got, DefaultWeeklyScanDay)
	}
	if DefaultWeeklyScanDay != int(time.Monday) {
		t.Errorf("DefaultWeeklyScanDay = %d, want %d (Monday) — the writer-side next_scan_at "+
			"values already persisted and the settings UI's `schedule_day ?? 1` both assume Monday",
			DefaultWeeklyScanDay, int(time.Monday))
	}
}

// TestWeeklyScanDay_StoredValuesAreHonoured guards the other direction: 0 is
// a legal stored value (Update validates 0..6), so resolving NULL must not
// swallow an explicitly chosen Sunday.
func TestWeeklyScanDay_StoredValuesAreHonoured(t *testing.T) {
	for day := 0; day <= 6; day++ {
		d := day
		if got := WeeklyScanDay(&d); got != day {
			t.Errorf("WeeklyScanDay(&%d) = %d, want %d", day, got, day)
		}
	}
}

// TestWeeklyScanDay_OutOfRangeFallsBackToDefault covers rows that predate
// (or bypass) the 0..6 API validation: scan_settings carries no CHECK
// constraint on schedule_day, so a 7 or a -1 can physically exist. Feeding
// one straight into the modulo arithmetic would silently schedule a
// different weekday than any UI could ever display.
func TestWeeklyScanDay_OutOfRangeFallsBackToDefault(t *testing.T) {
	for _, day := range []int{-1, 7, 99} {
		d := day
		if got := WeeklyScanDay(&d); got != DefaultWeeklyScanDay {
			t.Errorf("WeeklyScanDay(&%d) = %d, want %d (out-of-range is not a choice)",
				day, got, DefaultWeeklyScanDay)
		}
	}
}

// TestNextWeeklyScan_TargetsTheResolvedWeekday walks a full week of "now"
// values so the assertion cannot pass by accident of today's weekday.
func TestNextWeeklyScan_TargetsTheResolvedWeekday(t *testing.T) {
	// 2026-07-27 is a Monday; +i covers every weekday.
	base := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	if base.Weekday() != time.Monday {
		t.Fatalf("fixture drift: %s is %v, expected Monday", base.Format("2006-01-02"), base.Weekday())
	}

	for i := 0; i < 7; i++ {
		now := base.AddDate(0, 0, i)

		got := NextWeeklyScan(now, 6, nil)
		if got.Weekday() != time.Weekday(DefaultWeeklyScanDay) {
			t.Errorf("now=%v: NextWeeklyScan(nil day).Weekday() = %v, want %v",
				now.Weekday(), got.Weekday(), time.Weekday(DefaultWeeklyScanDay))
		}
		if got.Hour() != 6 || got.Minute() != 0 || got.Second() != 0 {
			t.Errorf("now=%v: NextWeeklyScan(hour 6) = %s, want 06:00:00", now.Weekday(), got.Format(time.RFC3339))
		}
		if !got.After(now) {
			t.Errorf("now=%s: next weekly scan %s is not in the future",
				now.Format(time.RFC3339), got.Format(time.RFC3339))
		}
		if d := got.Sub(now); d > 7*24*time.Hour {
			t.Errorf("now=%s: next weekly scan is %v away, want <= 7d", now.Format(time.RFC3339), d)
		}

		for day := 0; day <= 6; day++ {
			d := day
			g := NextWeeklyScan(now, 6, &d)
			if g.Weekday() != time.Weekday(day) {
				t.Errorf("now=%v day=%d: weekday = %v, want %v", now.Weekday(), day, g.Weekday(), time.Weekday(day))
			}
		}
	}
}

// TestNextWeeklyScan_SameDayAfterHourRollsAWeek pins the boundary the
// scheduler depends on: finishing a scan at/after the scheduled hour on the
// target weekday must schedule the NEXT week, not "today, already past".
func TestNextWeeklyScan_SameDayAfterHourRollsAWeek(t *testing.T) {
	monday := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC) // Monday 09:00
	day := int(time.Monday)

	after := NextWeeklyScan(monday, 6, &day) // hour already passed
	if want := monday.AddDate(0, 0, 7); after.Day() != want.Day() || after.Month() != want.Month() {
		t.Errorf("after-hour: next = %s, want %s", after.Format("2006-01-02"), want.Format("2006-01-02"))
	}

	before := NextWeeklyScan(monday, 18, &day) // hour still ahead today
	if before.Day() != monday.Day() {
		t.Errorf("before-hour: next = %s, want the same day %s",
			before.Format("2006-01-02 15:04"), monday.Format("2006-01-02"))
	}
}

// TestCalculateNextScan_WeeklyDelegatesToTheSharedHelper keeps the writer
// wired to the shared helper: if calculateNextScan ever grows its own copy
// of the weekday arithmetic again, this fails.
func TestCalculateNextScan_WeeklyDelegatesToTheSharedHelper(t *testing.T) {
	// calculateNextScan reads time.Now() internally, so the expected value has
	// to be bracketed rather than computed from a second, later Now(): if the
	// two calls straddle the target weekday's scheduled hour, one answers
	// "today" and the other "next week" and the test flakes (Codex round 1,
	// Low-5). Accepting either bracket instant keeps the delegation assertion
	// exact without a clock injection point.
	before := time.Now()
	got := calculateNextScan("weekly", 6, nil)
	after := time.Now()

	if !got.Equal(NextWeeklyScan(before, 6, nil)) && !got.Equal(NextWeeklyScan(after, 6, nil)) {
		t.Errorf("calculateNextScan(weekly, nil day) = %s, want %s (shared helper)",
			got.Format(time.RFC3339), NextWeeklyScan(before, 6, nil).Format(time.RFC3339))
	}
}
