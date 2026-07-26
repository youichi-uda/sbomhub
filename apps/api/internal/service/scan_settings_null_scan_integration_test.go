//go:build integration

// Package service — M46 Track A wave 3 nullable-column scan regression
// tests for ScanSettingsService (scan_settings / scan_logs reads).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'Wave3' ./internal/service
//
// scan_settings.enabled / schedule_type / schedule_hour / notify_* /
// created_at / updated_at and scan_logs.projects_scanned /
// new_vulnerabilities / created_at are all DDL-nullable with defaults; the
// service scanned them into bare bool / string / int / time.Time. A NULL
// row made Get error (500 on the settings page) and made GetLogs silently
// DROP the row (`continue` on scan error — the partial-result bug class).
// Fix: COALESCE(col, <DDL default>) at read time (0 NULL rows measured on
// the dev DB, 2026-07-26) and scan errors returned, not swallowed.
package service

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
)

// wave3SvcEnv returns the (app, migrator) URLs or skips. Duplicated from
// repository.llmCallsTestEnv because service cannot import repository's
// test helpers (different package).
func wave3SvcEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("scan_settings integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

func wave3SvcOpenOrSkip(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open failed (%v) - skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("DB unreachable (%v) - skipping", err)
	}
	// C27: Close via t.Cleanup so row cleanups registered later run first.
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// wave3SvcSeedTenant seeds a marker-prefixed tenant (C27 run-id marker via
// this package's c27Org) with an error-visible DELETE cleanup; CASCADE
// reaps scan_settings / scan_logs.
func wave3SvcSeedTenant(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	org := c27Org("wave3-" + label + "-" + id.String())
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, org, "wave3 "+label, org,
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, id); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s (%s): %v", id, org, err)
		}
	})
	return id
}

// wave3SvcExecAsTenant runs one statement inside a tenant-GUC tx (FORCE RLS
// tables need the GUC even under the migrator role, which is NOBYPASSRLS).
func wave3SvcExecAsTenant(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, query string, args ...any) {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin tenant tx (%s): %v", tenantID, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL (%s): %v", tenantID, err)
	}
	if _, err := tx.Exec(query, args...); err != nil {
		t.Fatalf("exec as tenant %s: %v\nquery: %s", tenantID, err, query)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tenant tx (%s): %v", tenantID, err)
	}
	committed = true
}

// wave3SvcReadAsTenant opens an app-role tx pinned to the tenant GUC,
// attaches it to ctx via database.WithTx (the production TenantTx shape the
// service's database.Querier routing expects), runs fn, rolls back.
func wave3SvcReadAsTenant(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, fn func(ctx context.Context)) {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin read tx (%s): %v", tenantID, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL (%s): %v", tenantID, err)
	}
	fn(database.WithTx(context.Background(), tx))
}

// TestWave3ScanSettingsGet_NullColumns_RealPG seeds an all-NULL
// scan_settings row (every defaulted column forced NULL) plus a
// fully-populated row under a second tenant, and asserts Get returns the
// DDL defaults for the NULL row and an exact round-trip (column-order pin)
// for the populated one. Pre-fix the NULL row errors with
// `converting NULL to bool is unsupported`.
func TestWave3ScanSettingsGet_NullColumns_RealPG(t *testing.T) {
	appURL, migURL := wave3SvcEnv(t)
	migDB := wave3SvcOpenOrSkip(t, migURL)
	appDB := wave3SvcOpenOrSkip(t, appURL)

	nullTenant := wave3SvcSeedTenant(t, migDB, "get-null")
	popTenant := wave3SvcSeedTenant(t, migDB, "get-pop")

	nullID := uuid.New()
	popID := uuid.New()
	wave3SvcExecAsTenant(t, migDB, nullTenant, `
		INSERT INTO scan_settings (id, tenant_id, enabled, schedule_type, schedule_hour, schedule_day,
			notify_critical, notify_high, notify_medium, notify_low, created_at, updated_at)
		VALUES ($1, $2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
	`, nullID, nullTenant)
	popCreatedAt := time.Date(2026, 7, 6, 7, 8, 9, 0, time.UTC)
	popUpdatedAt := time.Date(2026, 7, 7, 10, 11, 12, 0, time.UTC)
	wave3SvcExecAsTenant(t, migDB, popTenant, `
		INSERT INTO scan_settings (id, tenant_id, enabled, schedule_type, schedule_hour, schedule_day,
			notify_critical, notify_high, notify_medium, notify_low, created_at, updated_at)
		VALUES ($1, $2, false, 'weekly', 22, 3, false, false, true, true, $3, $4)
	`, popID, popTenant, popCreatedAt, popUpdatedAt)

	svc := NewScanSettingsService(appDB)

	wave3SvcReadAsTenant(t, appDB, nullTenant, func(ctx context.Context) {
		s, err := svc.Get(ctx, nullTenant)
		if err != nil {
			t.Errorf("Get on an all-NULL scan_settings row must not fail, got: %v", err)
			return
		}
		// DDL defaults: enabled=true, schedule 'daily'/6, notify
		// true/true/false/false, timestamps read-time NOW().
		if !s.Enabled || s.ScheduleType != "daily" || s.ScheduleHour != 6 {
			t.Errorf("Get(null): enabled=%v type=%q hour=%d, want true/daily/6 (DDL defaults)",
				s.Enabled, s.ScheduleType, s.ScheduleHour)
		}
		if !s.NotifyCritical || !s.NotifyHigh || s.NotifyMedium || s.NotifyLow {
			t.Errorf("Get(null): notify=%v/%v/%v/%v, want true/true/false/false (DDL defaults)",
				s.NotifyCritical, s.NotifyHigh, s.NotifyMedium, s.NotifyLow)
		}
		if s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() {
			t.Errorf("Get(null): CreatedAt/UpdatedAt zero, want read-time defaults")
		}
		if s.ScheduleDay != nil {
			t.Errorf("Get(null): ScheduleDay = %v, want nil", *s.ScheduleDay)
		}
	})

	wave3SvcReadAsTenant(t, appDB, popTenant, func(ctx context.Context) {
		s, err := svc.Get(ctx, popTenant)
		if err != nil {
			t.Errorf("Get (populated row): %v", err)
			return
		}
		if s.Enabled || s.ScheduleType != "weekly" || s.ScheduleHour != 22 ||
			s.ScheduleDay == nil || *s.ScheduleDay != 3 {
			t.Errorf("Get(pop): enabled=%v type=%q hour=%d day=%v round-trip mismatch",
				s.Enabled, s.ScheduleType, s.ScheduleHour, s.ScheduleDay)
		}
		if s.NotifyCritical || s.NotifyHigh || !s.NotifyMedium || !s.NotifyLow {
			t.Errorf("Get(pop): notify=%v/%v/%v/%v, want false/false/true/true (COALESCE must not flatten real values)",
				s.NotifyCritical, s.NotifyHigh, s.NotifyMedium, s.NotifyLow)
		}
		if !s.CreatedAt.UTC().Equal(popCreatedAt) || !s.UpdatedAt.UTC().Equal(popUpdatedAt) {
			t.Errorf("Get(pop): CreatedAt/UpdatedAt = %v/%v, want %v/%v",
				s.CreatedAt, s.UpdatedAt, popCreatedAt, popUpdatedAt)
		}
	})
}

// TestWave3ScanSettingsGetLogs_NullCounts_RealPG seeds one scan_logs row
// with NULL projects_scanned / new_vulnerabilities / created_at and one
// fully-populated row, and asserts BOTH come back. Pre-fix the NULL row's
// scan error hit `continue` and the row silently vanished from the log
// listing (partial results reported as complete).
func TestWave3ScanSettingsGetLogs_NullCounts_RealPG(t *testing.T) {
	appURL, migURL := wave3SvcEnv(t)
	migDB := wave3SvcOpenOrSkip(t, migURL)
	appDB := wave3SvcOpenOrSkip(t, appURL)

	tenant := wave3SvcSeedTenant(t, migDB, "logs")

	nullLogID := uuid.New()
	popLogID := uuid.New()
	wave3SvcExecAsTenant(t, migDB, tenant, `
		INSERT INTO scan_logs (id, tenant_id, started_at, completed_at, status,
			projects_scanned, new_vulnerabilities, error_message, created_at)
		VALUES ($1, $2, NOW() - INTERVAL '2 hours', NULL, 'running', NULL, NULL, NULL, NULL)
	`, nullLogID, tenant)
	popStartedAt := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	popCompletedAt := time.Date(2026, 7, 8, 1, 12, 3, 0, time.UTC)
	popCreatedAt := time.Date(2026, 7, 8, 1, 2, 4, 0, time.UTC)
	wave3SvcExecAsTenant(t, migDB, tenant, `
		INSERT INTO scan_logs (id, tenant_id, started_at, completed_at, status,
			projects_scanned, new_vulnerabilities, error_message, created_at)
		VALUES ($1, $2, $3, $4, 'completed', 7, 3, 'pop error', $5)
	`, popLogID, tenant, popStartedAt, popCompletedAt, popCreatedAt)

	svc := NewScanSettingsService(appDB)

	wave3SvcReadAsTenant(t, appDB, tenant, func(ctx context.Context) {
		logs, err := svc.GetLogs(ctx, tenant, 10)
		if err != nil {
			t.Errorf("GetLogs with a NULL-count row must not fail, got: %v", err)
			return
		}
		if len(logs) != 2 {
			t.Errorf("GetLogs returned %d rows, want 2 (pre-fix the NULL row was silently dropped)", len(logs))
			return
		}
		var sawNull, sawPop bool
		for i := range logs {
			switch logs[i].ID {
			case nullLogID:
				sawNull = true
				if logs[i].ProjectsScanned != 0 || logs[i].NewVulnerabilities != 0 {
					t.Errorf("GetLogs(null): counts = %d/%d, want 0/0 (DDL defaults)",
						logs[i].ProjectsScanned, logs[i].NewVulnerabilities)
				}
				if logs[i].CreatedAt.IsZero() {
					t.Errorf("GetLogs(null): CreatedAt zero, want read-time default")
				}
				if logs[i].CompletedAt != nil || logs[i].ErrorMessage != nil {
					t.Errorf("GetLogs(null): CompletedAt/ErrorMessage = %v/%v, want nil/nil",
						logs[i].CompletedAt, logs[i].ErrorMessage)
				}
				if logs[i].Status != "running" {
					t.Errorf("GetLogs(null): Status = %q, want running", logs[i].Status)
				}
			case popLogID:
				sawPop = true
				if logs[i].ProjectsScanned != 7 || logs[i].NewVulnerabilities != 3 ||
					logs[i].Status != "completed" {
					t.Errorf("GetLogs(pop): round-trip mismatch: %+v", logs[i])
				}
				if logs[i].ErrorMessage == nil || *logs[i].ErrorMessage != "pop error" {
					t.Errorf("GetLogs(pop): ErrorMessage = %v, want pop error", logs[i].ErrorMessage)
				}
				if logs[i].CompletedAt == nil || !logs[i].CompletedAt.UTC().Equal(popCompletedAt) {
					t.Errorf("GetLogs(pop): CompletedAt = %v, want %v", logs[i].CompletedAt, popCompletedAt)
				}
				if !logs[i].StartedAt.UTC().Equal(popStartedAt) {
					t.Errorf("GetLogs(pop): StartedAt = %v, want %v", logs[i].StartedAt, popStartedAt)
				}
				if !logs[i].CreatedAt.UTC().Equal(popCreatedAt) {
					t.Errorf("GetLogs(pop): CreatedAt = %v, want %v", logs[i].CreatedAt, popCreatedAt)
				}
			}
		}
		if !sawNull || !sawPop {
			t.Errorf("GetLogs missing seeded rows (null=%v pop=%v)", sawNull, sawPop)
		}
	})
}
