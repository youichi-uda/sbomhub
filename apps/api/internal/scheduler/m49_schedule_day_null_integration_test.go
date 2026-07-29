//go:build integration

// Package scheduler — M49: scan_settings.schedule_day NULL must not read as
// "Sunday".
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M49ScheduleDay' ./internal/scheduler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// The bug this pins down. scan_settings.schedule_day is DDL-nullable with
// NO default (measured 2026-07-30 on the dev DB: 31 rows, 31 of them NULL),
// so "the operator never picked a weekday" is a NULL, not a number. Two
// readers disagreed about what that NULL means:
//
//   - service.calculateNextScan reads the column as *int and defaults a nil
//     to 1 (Monday) — and it is the WRITER, so the next_scan_at persisted by
//     a settings update is a Monday;
//   - scheduler.updateNextScan scanned into sql.NullInt64 and used
//     int(scheduleDay.Int64) WITHOUT checking .Valid, so a NULL became 0 =
//     Sunday.
//
// Net effect pre-fix: the moment the scheduler ran a weekly tenant's scan it
// rewrote next_scan_at one day earlier than the value the settings page had
// shown, and every subsequent scan drifted onto Sunday. Post-fix both
// readers go through service.NextWeeklyScan / service.DefaultWeeklyScanDay.
package scheduler

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/service"
)

// readNextScanAt reads scan_settings.next_scan_at for tenant as the tenant
// (the table is FORCE RLS post-048).
func readNextScanAt(t *testing.T, migDB *sql.DB, tenant uuid.UUID) time.Time {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenant.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	var nextScanAt sql.NullTime
	if err := tx.QueryRow(
		`SELECT next_scan_at FROM scan_settings WHERE tenant_id = $1`, tenant,
	).Scan(&nextScanAt); err != nil {
		t.Fatalf("read back scan_settings: %v", err)
	}
	if !nextScanAt.Valid {
		t.Fatalf("next_scan_at is NULL after updateNextScan")
	}
	return nextScanAt.Time.Local()
}

// TestM49ScheduleDay_WeeklyNullDayIsMonday_RealPG is the red-first
// regression: a weekly tenant with schedule_day NULL must be rescheduled
// onto the SAME weekday the writer (service.calculateNextScan) picks for a
// nil day. Pre-fix updateNextScan produced a Sunday.
func TestM49ScheduleDay_WeeklyNullDayIsMonday_RealPG(t *testing.T) {
	appURL, migURL := schedIntEnv(t)

	migDB := schedOpenOrSkip(t, migURL)
	if !schedSchemaReady(t, migDB) {
		return
	}
	appDB := schedOpenOrSkip(t, appURL)

	tenant := seedWave3Tenant(t, migDB, "m49-weekly-null-day")
	execWave3AsTenant(t, migDB, tenant, `
		INSERT INTO scan_settings (tenant_id, enabled, schedule_type, schedule_hour, schedule_day, next_scan_at)
		VALUES ($1, true, 'weekly', 6, NULL, NULL)
	`, tenant)

	if err := j49(appDB).updateNextScan(context.Background(), tenant); err != nil {
		t.Fatalf("updateNextScan (weekly, NULL schedule_day): %v", err)
	}
	got := readNextScanAt(t, migDB, tenant)

	wantDay := time.Weekday(service.DefaultWeeklyScanDay)
	if got.Weekday() != wantDay {
		t.Errorf("next_scan_at weekday = %v (%s), want %v — a NULL schedule_day was read as "+
			"day %d instead of the shared default (0-sentinel: sql.NullInt64.Int64 without .Valid)",
			got.Weekday(), got.Format(time.RFC3339), wantDay, int(got.Weekday()))
	}
	if got.Hour() != 6 {
		t.Errorf("next_scan_at hour = %d, want 6", got.Hour())
	}
	if !got.After(time.Now()) {
		t.Errorf("next_scan_at = %s is not in the future", got.Format(time.RFC3339))
	}

	// Cross-check against the WRITER: the two must agree on the weekday for
	// the same (nil day, hour) input — that agreement is the whole point of
	// the shared helper.
	writer := service.NextWeeklyScan(time.Now(), 6, nil)
	if writer.Weekday() != got.Weekday() {
		t.Errorf("scheduler weekday %v != service (writer) weekday %v — the two readers of "+
			"scan_settings.schedule_day disagree about what NULL means",
			got.Weekday(), writer.Weekday())
	}
}

// TestM49ScheduleDay_WeeklyExplicitSundayIsHonoured_RealPG guards the other
// direction: 0 is a LEGAL stored value (Update validates 0..6), so the fix
// must not turn an explicitly chosen Sunday into the Monday default.
func TestM49ScheduleDay_WeeklyExplicitSundayIsHonoured_RealPG(t *testing.T) {
	appURL, migURL := schedIntEnv(t)

	migDB := schedOpenOrSkip(t, migURL)
	if !schedSchemaReady(t, migDB) {
		return
	}
	appDB := schedOpenOrSkip(t, appURL)

	tenant := seedWave3Tenant(t, migDB, "m49-weekly-sunday")
	execWave3AsTenant(t, migDB, tenant, `
		INSERT INTO scan_settings (tenant_id, enabled, schedule_type, schedule_hour, schedule_day, next_scan_at)
		VALUES ($1, true, 'weekly', 3, 0, NULL)
	`, tenant)

	if err := j49(appDB).updateNextScan(context.Background(), tenant); err != nil {
		t.Fatalf("updateNextScan (weekly, schedule_day=0): %v", err)
	}
	got := readNextScanAt(t, migDB, tenant)
	if got.Weekday() != time.Sunday {
		t.Errorf("next_scan_at weekday = %v, want Sunday — an explicitly stored 0 must be honoured, "+
			"not replaced by the NULL default", got.Weekday())
	}
	if got.Hour() != 3 {
		t.Errorf("next_scan_at hour = %d, want 3", got.Hour())
	}
}

// TestM49ScheduleDay_WeeklyExplicitSaturdayIsHonoured_RealPG pins a
// non-boundary explicit value so the test set cannot pass by hard-coding
// either end of the range.
func TestM49ScheduleDay_WeeklyExplicitSaturdayIsHonoured_RealPG(t *testing.T) {
	appURL, migURL := schedIntEnv(t)

	migDB := schedOpenOrSkip(t, migURL)
	if !schedSchemaReady(t, migDB) {
		return
	}
	appDB := schedOpenOrSkip(t, appURL)

	tenant := seedWave3Tenant(t, migDB, "m49-weekly-saturday")
	execWave3AsTenant(t, migDB, tenant, `
		INSERT INTO scan_settings (tenant_id, enabled, schedule_type, schedule_hour, schedule_day, next_scan_at)
		VALUES ($1, true, 'weekly', 22, 6, NULL)
	`, tenant)

	if err := j49(appDB).updateNextScan(context.Background(), tenant); err != nil {
		t.Fatalf("updateNextScan (weekly, schedule_day=6): %v", err)
	}
	got := readNextScanAt(t, migDB, tenant)
	if got.Weekday() != time.Saturday {
		t.Errorf("next_scan_at weekday = %v, want Saturday", got.Weekday())
	}
}

func j49(appDB *sql.DB) *VulnerabilityScanJob { return &VulnerabilityScanJob{db: appDB} }
