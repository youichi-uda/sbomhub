//go:build integration

// Package service — M49: the analytics summary a fresh tenant sees must not
// claim a 0-hour MTTR and 100% SLO achievement.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M49MTTR' ./internal/service
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// This is the END of the chain the repository tests start
// (internal/repository/m49_mttr_unmeasured_integration_test.go). Even with
// the repository reads fixed, AnalyticsService substitutes
// getDefaultMTTR() / getDefaultSLOAchievement() whenever the repository
// returns no rows — and those defaults hard-coded MTTRHours: 0, OnTarget:
// true, AchievementPct: 100.0. A tenant that has never resolved anything
// therefore still got a full green dashboard. The service arm is the one an
// operator actually sees, because "no resolution events at all" is the
// normal state of every new installation.
package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// TestM49MTTR_GetSummary_FreshTenantReportsUnmeasured drives the real
// AnalyticsService against a tenant with zero resolution events — the state
// of every fresh install — and asserts the summary withholds MTTR, the
// on-target verdict and the SLO achievement rather than manufacturing the
// best possible values.
func TestM49MTTR_GetSummary_FreshTenantReportsUnmeasured(t *testing.T) {
	appURL, migURL := wave3SvcEnv(t)

	migDB := wave3SvcOpenOrSkip(t, migURL)
	appDB := wave3SvcOpenOrSkip(t, appURL)

	tenant := wave3SvcSeedTenant(t, migDB, "m49-mttr-summary")

	svc := NewAnalyticsService(repository.NewAnalyticsRepository(appDB), nil)

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin tenant tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	ctx := database.WithTx(context.Background(), tx)

	summary, err := svc.GetSummary(ctx, tenant, 30)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}

	if len(summary.MTTR) == 0 {
		t.Fatalf("GetSummary returned no MTTR rows at all")
	}
	for _, m := range summary.MTTR {
		if m.Count != 0 {
			t.Errorf("%s: count = %d, want 0 for a fresh tenant", m.Severity, m.Count)
			continue
		}
		switch v := any(m.MTTRHours).(type) {
		case *float64:
			if v != nil {
				t.Errorf("%s: mttr_hours = %v with 0 resolved vulnerabilities, want nil", m.Severity, *v)
			}
		case float64:
			t.Errorf("%s: mttr_hours is a bare float64 (%v) — a fresh tenant is shown the BEST "+
				"possible remediation time", m.Severity, v)
		}
		switch v := any(m.OnTarget).(type) {
		case *bool:
			if v != nil {
				t.Errorf("%s: on_target = %v with 0 resolved vulnerabilities, want nil", m.Severity, *v)
			}
		case bool:
			t.Errorf("%s: on_target is a bare bool (%v) — a fresh tenant is certified as meeting "+
				"every SLO before remediating anything", m.Severity, v)
		}
	}

	for _, s := range summary.SLOAchievement {
		if s.TotalCount != 0 {
			continue
		}
		switch v := any(s.AchievementPct).(type) {
		case *float64:
			if v != nil {
				t.Errorf("%s: achievement_pct = %v with 0 resolved vulnerabilities, want nil", s.Severity, *v)
			}
		case float64:
			t.Errorf("%s: achievement_pct is a bare float64 (%v) — unmeasured SLO reads as achieved",
				s.Severity, v)
		}
		switch v := any(s.AverageMTTR).(type) {
		case *float64:
			if v != nil {
				t.Errorf("%s: average_mttr_hours = %v with 0 resolved vulnerabilities, want nil", s.Severity, *v)
			}
		case float64:
			t.Errorf("%s: average_mttr_hours is a bare float64 (%v)", s.Severity, v)
		}
	}

	switch v := any(summary.Summary.AverageMTTRHours).(type) {
	case *float64:
		if v != nil {
			t.Errorf("summary.average_mttr_hours = %v with 0 resolved vulnerabilities, want nil", *v)
		}
	case float64:
		t.Errorf("summary.average_mttr_hours is a bare float64 (%v) — the dashboard headline tile "+
			"reports a measurement that does not exist", v)
	}
	switch v := any(summary.Summary.OverallSLOAchievementPct).(type) {
	case *float64:
		if v != nil {
			t.Errorf("summary.overall_slo_achievement_pct = %v with nothing measured, want nil", *v)
		}
	case float64:
		t.Errorf("summary.overall_slo_achievement_pct is a bare float64 (%v) — the dashboard headline "+
			"tile certifies an SLO nobody has measured", v)
	}
}

// seedM49ReportEvents inserts one resolved vulnerability_resolution_event at
// `resolvedDaysAgo` days ago that took `hours` to remediate, plus the
// slo_targets row its severity needs. Returns nothing — the caller reads the
// aggregates back through the report gathering path.
func seedM49ReportEvents(t *testing.T, migDB *sql.DB, tenant uuid.UUID, severity string,
	resolvedDaysAgo, hours int) {
	t.Helper()

	projectID := uuid.New()
	vulnID := uuid.New()
	// vulnerabilities is a GLOBAL table (no tenant CASCADE) — reap explicitly
	// (C27), registered before the INSERT so a later t.Fatal cannot strand it.
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID); err != nil {
			t.Errorf("C27 cleanup: delete vulnerability %s: %v", vulnID, err)
		}
	})
	if _, err := migDB.Exec(
		`INSERT INTO vulnerabilities (id, cve_id) VALUES ($1, $2)`,
		vulnID, "CVE-M49-RPT-"+vulnID.String()[:8]); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	// projects / slo_targets / vulnerability_resolution_events are FORCE RLS:
	// even the migrator role needs the tenant GUC pinned inside the tx.
	wave3SvcExecAsTenant(t, migDB, tenant,
		`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm49-report-project')`,
		projectID, tenant)
	wave3SvcExecAsTenant(t, migDB, tenant,
		`INSERT INTO slo_targets (id, tenant_id, severity, target_hours) VALUES ($1, $2, $3, 24)`,
		uuid.New(), tenant, severity)
	wave3SvcExecAsTenant(t, migDB, tenant, `
		INSERT INTO vulnerability_resolution_events
			(id, tenant_id, vulnerability_id, project_id, cve_id, severity, detected_at, resolved_at)
		VALUES ($1, $2, $3, $4, 'CVE-M49-RPT', $5,
		        NOW() - ($6 || ' days')::interval - ($7 || ' hours')::interval,
		        NOW() - ($6 || ' days')::interval)
	`, uuid.New(), tenant, vulnID, projectID, severity, resolvedDaysAgo, hours)
}

// TestM49MTTR_GatherReportData_UsesTheReportPeriodNotLast30Days pins the two
// Codex round-1 High findings on the report gathering path:
//
//	High-1 — SLOAchievementPct was copied from AnalyticsQuickStats, a field
//	         GetQuickStats never populates, so EVERY report printed the zero
//	         value regardless of the tenant's actual record.
//	High-2 — AverageMTTRHours / ResolvedInPeriod came from GetQuickStats,
//	         whose queries are hard-coded to the last 30 days, while the
//	         report covers an arbitrary [start, end]. A 90-day report whose
//	         remediations all landed 31-90 days ago reported none of them.
//
// The fixture resolves a single CRITICAL 60 days ago in 48h (target 24h →
// off target). A 90-day window must therefore see 1 resolution, ~48h MTTR
// and 0% achievement; a 30-day window must see nothing measured at all.
func TestM49MTTR_GatherReportData_UsesTheReportPeriodNotLast30Days(t *testing.T) {
	appURL, migURL := wave3SvcEnv(t)

	migDB := wave3SvcOpenOrSkip(t, migURL)
	appDB := wave3SvcOpenOrSkip(t, appURL)

	tenant := wave3SvcSeedTenant(t, migDB, "m49-report-period")
	seedM49ReportEvents(t, migDB, tenant, "CRITICAL", 60, 48)

	svc := NewReportService(nil, nil, repository.NewAnalyticsRepository(appDB), nil, nil, nil, t.TempDir())

	gather := func(days int) *model.ReportSummary {
		t.Helper()
		tx, err := appDB.Begin()
		if err != nil {
			t.Fatalf("begin tenant tx: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		ctx := database.WithTx(context.Background(), tx)
		end := time.Now()
		data := svc.gatherReportData(ctx, tenant, end.AddDate(0, 0, -days), end)
		return &data.Summary
	}

	wide := gather(90)
	if wide.ResolvedInPeriod != 1 {
		t.Errorf("90d report resolved_in_period = %d, want 1 (a 60-day-old remediation is inside the window)",
			wide.ResolvedInPeriod)
	}
	if wide.AverageMTTRHours == nil {
		t.Errorf("90d report average_mttr_hours = nil, want ~48 — GetQuickStats' hard-coded 30-day " +
			"window hid a remediation the report period covers")
	} else if *wide.AverageMTTRHours < 47 || *wide.AverageMTTRHours > 49 {
		t.Errorf("90d report average_mttr_hours = %v, want ~48", *wide.AverageMTTRHours)
	}
	if wide.SLOAchievementPct == nil {
		t.Errorf("90d report slo_achievement_pct = nil, want 0 — the field was never populated from " +
			"GetQuickStats, so every report printed the zero value")
	} else if *wide.SLOAchievementPct != 0 {
		t.Errorf("90d report slo_achievement_pct = %v, want 0 (48h missed a 24h target)", *wide.SLOAchievementPct)
	}

	narrow := gather(30)
	if narrow.ResolvedInPeriod != 0 {
		t.Errorf("30d report resolved_in_period = %d, want 0", narrow.ResolvedInPeriod)
	}
	if narrow.AverageMTTRHours != nil {
		t.Errorf("30d report average_mttr_hours = %v, want nil (nothing resolved in that window)",
			*narrow.AverageMTTRHours)
	}
	if narrow.SLOAchievementPct != nil {
		t.Errorf("30d report slo_achievement_pct = %v, want nil (nothing resolved in that window)",
			*narrow.SLOAchievementPct)
	}
}

// TestM49MTTR_GetSummary_PartiallyMeasuredKeepsEverySeverity pins Codex round
// 4, Medium-1 end to end: GetMTTR only emits severities that produced a
// remediation, so a tenant with one resolved HIGH used to get a one-row MTTR
// panel and its unremediated CRITICAL silently vanished — partial data
// presented as the whole picture. Every severity with an SLO target must now
// appear, with the unremediated ones marked unmeasured rather than dropped or
// shown as a 0-hour, on-target success.
func TestM49MTTR_GetSummary_PartiallyMeasuredKeepsEverySeverity(t *testing.T) {
	appURL, migURL := wave3SvcEnv(t)

	migDB := wave3SvcOpenOrSkip(t, migURL)
	appDB := wave3SvcOpenOrSkip(t, appURL)

	tenant := wave3SvcSeedTenant(t, migDB, "m49-mttr-partial")
	// One HIGH resolved 5 days ago in 6h (inside the 24h target seeded here).
	seedM49ReportEvents(t, migDB, tenant, "HIGH", 5, 6)

	svc := NewAnalyticsService(repository.NewAnalyticsRepository(appDB), nil)

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin tenant tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}

	summary, err := svc.GetSummary(database.WithTx(context.Background(), tx), tenant, 30)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}

	bySev := map[string]model.MTTRResult{}
	for _, m := range summary.MTTR {
		bySev[m.Severity] = m
	}
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if _, ok := bySev[sev]; !ok {
			t.Errorf("MTTR panel is missing %s — a severity with an SLO target but no remediation "+
				"must be listed as unmeasured, not dropped (got %+v)", sev, summary.MTTR)
		}
	}
	if high, ok := bySev["HIGH"]; ok {
		if high.MTTRHours == nil || *high.MTTRHours < 5.5 || *high.MTTRHours > 6.5 {
			t.Errorf("HIGH mttr_hours = %v, want ~6", high.MTTRHours)
		}
		if high.OnTarget == nil || !*high.OnTarget {
			t.Errorf("HIGH on_target = %v, want a present true (6h <= 24h)", high.OnTarget)
		}
	}
	if crit, ok := bySev["CRITICAL"]; ok {
		if crit.MTTRHours != nil {
			t.Errorf("CRITICAL mttr_hours = %v with no remediation, want nil", *crit.MTTRHours)
		}
		if crit.OnTarget != nil {
			t.Errorf("CRITICAL on_target = %v with no remediation, want nil", *crit.OnTarget)
		}
		if crit.TargetHours <= 0 {
			t.Errorf("CRITICAL target_hours = %d, want the configured/global target", crit.TargetHours)
		}
	}
}
