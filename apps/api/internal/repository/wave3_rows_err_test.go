// Package repository — M46 Track A wave 3 rows.Err() regression tests.
//
// Every list-shaped read below used to end its rows.Next() loop without
// checking rows.Err(), so a mid-iteration failure (connection reset,
// statement timeout, tx abort) silently truncated the result set and
// presented the partial slice as the complete answer. sqlmock's RowError
// reproduces exactly that: one good row, then the driver fails — the
// repository must surface the error and return no partial data.
package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

var errWave3Boom = errors.New("wave3: connection reset mid-iteration")

// TestWave3RowsErr_PartialResultsNotReturned drives each fixed read against
// a result set that yields one good row and then breaks. Pre-fix these
// calls returned (1 row, nil error); post-fix they must return the
// iteration error and zero rows.
func TestWave3RowsErr_PartialResultsNotReturned(t *testing.T) {
	now := time.Now()
	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New()

	// mkRows builds a two-row result where the second row poisons the
	// iteration. The second row's values are never scanned — rows.Next()
	// returns false and rows.Err() carries errWave3Boom.
	mkRows := func(cols []string, good []driverValues) *sqlmock.Rows {
		r := sqlmock.NewRows(cols)
		for _, g := range good {
			r.AddRow(g...)
		}
		r.AddRow(good[len(good)-1]...)
		r.RowError(len(good), errWave3Boom)
		return r
	}

	auditCols := []string{"id", "tenant_id", "user_id", "action", "resource_type", "resource_id", "details", "ip_address", "user_agent", "created_at"}
	auditRow := driverValues{id1.String(), nil, nil, "a", "r", nil, []byte(`{}`), nil, "ua", now}

	reportSettingsCols := []string{"id", "tenant_id", "enabled", "report_type", "schedule_type", "schedule_day", "schedule_hour", "format", "email_enabled", "email_recipients", "include_sections", "created_at", "updated_at"}
	reportSettingsRow := driverValues{id1.String(), id2.String(), true, "monthly", "weekly", 1, 6, "pdf", false, []byte("{}"), []byte("{}"), now, now}

	licenseCols := []string{"id", "project_id", "license_id", "license_name", "policy_type", "reason", "created_at", "updated_at"}
	licenseRow := driverValues{id1.String(), id2.String(), "MIT", "MIT License", "allowed", "", now, now}

	apikeyCols := []string{"id", "tenant_id", "project_id", "name", "key_hash", "key_prefix", "permissions", "last_used_at", "expires_at", "created_at"}
	apikeyRow := driverValues{id1.String(), id2.String(), nil, "n", "h", "p", "read", nil, nil, now}

	cases := []struct {
		name  string
		setup func(m sqlmock.Sqlmock)
		call  func(db *sql.DB) (int, error)
	}{
		{
			name: "audit List",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(auditCols, []driverValues{auditRow}))
			},
			call: func(db *sql.DB) (int, error) {
				logs, err := NewAuditRepository(db).List(context.Background(), id2, 10, 0)
				return len(logs), err
			},
		},
		{
			name: "audit ListByUser",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(auditCols, []driverValues{auditRow}))
			},
			call: func(db *sql.DB) (int, error) {
				logs, err := NewAuditRepository(db).ListByUser(context.Background(), id2, id3, 10, 0)
				return len(logs), err
			},
		},
		{
			name: "audit ListByResource",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(auditCols, []driverValues{auditRow}))
			},
			call: func(db *sql.DB) (int, error) {
				logs, err := NewAuditRepository(db).ListByResource(context.Background(), id2, "r", id3, 10, 0)
				return len(logs), err
			},
		},
		{
			name: "audit ListWithFilter",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT COUNT").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(auditCols, []driverValues{auditRow}))
			},
			call: func(db *sql.DB) (int, error) {
				logs, _, err := NewAuditRepository(db).ListWithFilter(context.Background(), id2, AuditFilter{Limit: 10})
				return len(logs), err
			},
		},
		{
			name: "audit GetActionCounts",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"action", "count"}, []driverValues{{"a", 1}}))
			},
			call: func(db *sql.DB) (int, error) {
				counts, err := NewAuditRepository(db).GetActionCounts(context.Background(), id2, now.Add(-time.Hour), now)
				return len(counts), err
			},
		},
		{
			name: "audit GetDailyActionCounts",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"date", "action", "count"}, []driverValues{{now, "a", 1}}))
			},
			call: func(db *sql.DB) (int, error) {
				res, err := NewAuditRepository(db).GetDailyActionCounts(context.Background(), id2, 7)
				return len(res), err
			},
		},
		{
			name: "analytics GetMTTR",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"severity", "mttr_hours", "count", "target_hours"},
						[]driverValues{{"CRITICAL", 1.5, 2, 24}}))
			},
			call: func(db *sql.DB) (int, error) {
				res, err := NewAnalyticsRepository(db).GetMTTR(context.Background(), id2, now.Add(-time.Hour), now)
				return len(res), err
			},
		},
		{
			name: "analytics GetVulnerabilityTrend",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"date", "critical", "high", "medium", "low", "total", "resolved"},
						[]driverValues{{"2026-07-01", 1, 2, 3, 4, 10, 5}}))
			},
			call: func(db *sql.DB) (int, error) {
				// A mid-iteration break must surface as an error — NOT
				// silently reroute into the calculate-fallback (which would
				// issue a second query the mock does not expect).
				res, err := NewAnalyticsRepository(db).GetVulnerabilityTrend(context.Background(), id2, 7)
				return len(res), err
			},
		},
		{
			name: "analytics calculateVulnerabilityTrend",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"date", "critical", "high", "medium", "low", "total", "resolved"},
						[]driverValues{{"2026-07-01", 1, 2, 3, 4, 10, 5}}))
			},
			call: func(db *sql.DB) (int, error) {
				res, err := NewAnalyticsRepository(db).calculateVulnerabilityTrend(context.Background(), id2, 7)
				return len(res), err
			},
		},
		{
			name: "analytics GetSLOAchievement",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"severity", "total_count", "on_target_count", "achievement_pct", "target_hours", "avg_mttr"},
						[]driverValues{{"HIGH", 1, 1, 100.0, 24, 1.0}}))
			},
			call: func(db *sql.DB) (int, error) {
				res, err := NewAnalyticsRepository(db).GetSLOAchievement(context.Background(), id2, now.Add(-time.Hour), now)
				return len(res), err
			},
		},
		{
			name: "analytics GetComplianceTrend",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"date", "score", "max_score", "percentage", "sbom", "vuln", "lic"},
						[]driverValues{{"2026-07-01", 80, 100, 80.0, 30, 40, 10}}))
			},
			call: func(db *sql.DB) (int, error) {
				res, err := NewAnalyticsRepository(db).GetComplianceTrend(context.Background(), id2, 7)
				return len(res), err
			},
		},
		{
			name: "analytics GetSLOTargets",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"id", "tenant_id", "severity", "target_hours", "created_at", "updated_at"},
						[]driverValues{{id1.String(), nil, "CRITICAL", 24, now, now}}))
			},
			call: func(db *sql.DB) (int, error) {
				res, err := NewAnalyticsRepository(db).GetSLOTargets(context.Background(), id2)
				return len(res), err
			},
		},
		{
			name: "apikey ListByTenant",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(apikeyCols, []driverValues{apikeyRow}))
			},
			call: func(db *sql.DB) (int, error) {
				keys, err := NewAPIKeyRepository(db).ListByTenant(context.Background(), id2)
				return len(keys), err
			},
		},
		{
			name: "apikey ListByProject",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(apikeyCols, []driverValues{apikeyRow}))
			},
			call: func(db *sql.DB) (int, error) {
				keys, err := NewAPIKeyRepository(db).ListByProject(context.Background(), id2, id3)
				return len(keys), err
			},
		},
		{
			name: "license ListByProject",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(licenseCols, []driverValues{licenseRow}))
			},
			call: func(db *sql.DB) (int, error) {
				policies, err := NewLicensePolicyRepository(db).ListByProject(context.Background(), id2)
				return len(policies), err
			},
		},
		{
			name: "license GetPoliciesForLicenses",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(licenseCols, []driverValues{licenseRow}))
			},
			call: func(db *sql.DB) (int, error) {
				policies, err := NewLicensePolicyRepository(db).GetPoliciesForLicenses(context.Background(), id2, []string{"MIT"})
				return len(policies), err
			},
		},
		{
			name: "project ListByTenant",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"id", "name", "description", "created_at", "updated_at"},
						[]driverValues{{id1.String(), "n", "d", now, now}}))
			},
			call: func(db *sql.DB) (int, error) {
				projects, err := NewProjectRepository(db).ListByTenant(context.Background(), id2)
				return len(projects), err
			},
		},
		{
			name: "report GetAllSettings",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(reportSettingsCols, []driverValues{reportSettingsRow}))
			},
			call: func(db *sql.DB) (int, error) {
				settings, err := NewReportRepository(db).GetAllSettings(context.Background(), id2)
				return len(settings), err
			},
		},
		{
			name: "report GetEnabledSettings",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(reportSettingsCols, []driverValues{reportSettingsRow}))
			},
			call: func(db *sql.DB) (int, error) {
				settings, err := NewReportRepository(db).GetEnabledSettings(context.Background())
				return len(settings), err
			},
		},
		{
			name: "report ListReports",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT COUNT").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(
					[]string{"id", "tenant_id", "settings_id", "report_type", "format", "title", "period_start", "period_end", "file_path", "file_size", "status", "error_message", "generated_by", "email_sent_at", "email_recipients", "created_at", "completed_at"},
					[]driverValues{{id1.String(), id2.String(), nil, "monthly", "pdf", "t", now, now, "", 0, "done", "", nil, nil, []byte("{}"), now, nil}}))
			},
			call: func(db *sql.DB) (int, error) {
				reports, _, err := NewReportRepository(db).ListReports(context.Background(), id2, 10, 0)
				return len(reports), err
			},
		},
		{
			name: "sbom ListByProject",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(
					mkRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"},
						[]driverValues{{id1.String(), id2.String(), "cyclonedx", "1.0", []byte("{}"), now}}))
			},
			call: func(db *sql.DB) (int, error) {
				sboms, err := NewSbomRepository(db).ListByProject(context.Background(), id2)
				return len(sboms), err
			},
		},
		{
			name: "subscription GetEvents",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(
					[]string{"id", "subscription_id", "tenant_id", "event_type", "ls_event_id", "previous_status", "new_status", "previous_plan", "new_plan", "metadata", "created_at"},
					[]driverValues{{id1.String(), id2.String(), id3.String(), "t", "", "", "", "", "", []byte("{}"), now}}))
			},
			call: func(db *sql.DB) (int, error) {
				events, err := NewSubscriptionRepository(db).GetEvents(context.Background(), id3, 10)
				return len(events), err
			},
		},
		{
			name: "subscription GetUsage",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(
					[]string{"id", "tenant_id", "metric", "quantity", "period_start", "period_end", "created_at"},
					[]driverValues{{id1.String(), id2.String(), "m", 1, now, now, now}}))
			},
			call: func(db *sql.DB) (int, error) {
				records, err := NewSubscriptionRepository(db).GetUsage(context.Background(), id2, "m", now.Add(-time.Hour), now)
				return len(records), err
			},
		},
		{
			name: "user GetTenantUsers",
			setup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT").WillReturnRows(mkRows(
					[]string{"id", "clerk_user_id", "email", "name", "avatar_url", "created_at", "updated_at", "role"},
					[]driverValues{{id1.String(), "c", "e", "n", "a", now, now, "member"}}))
			},
			call: func(db *sql.DB) (int, error) {
				users, err := NewUserRepository(db).GetTenantUsers(context.Background(), id2)
				return len(users), err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			tc.setup(mock)
			n, err := tc.call(db)
			if err == nil {
				t.Fatalf("%s: mid-iteration failure returned nil error (partial results presented as complete)", tc.name)
			}
			if !errors.Is(err, errWave3Boom) {
				t.Errorf("%s: error = %v, want errWave3Boom via rows.Err()", tc.name, err)
			}
			if n != 0 {
				t.Errorf("%s: returned %d rows alongside the error, want 0 (no partial results)", tc.name, n)
			}
		})
	}
}

// driverValues is a positional row for sqlmock.Rows.AddRow.
type driverValues = []driver.Value
