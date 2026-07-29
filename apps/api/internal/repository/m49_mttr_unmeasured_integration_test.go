//go:build integration

// Package repository — M49: "no vulnerability has ever been resolved" is
// NOT an MTTR of 0.0 hours, and it is NOT 100% SLO achievement.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M49MTTR' ./internal/repository
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// The bug this pins down. Three reads manufactured a 0 out of "nothing was
// measured":
//
//	analytics.go:54   COALESCE(AVG(m.hours), 0)  as mttr_hours
//	analytics.go:248  COALESCE(r.avg_mttr, 0)    as avg_mttr
//	analytics.go:352  COALESCE(AVG(...), 0)      → AnalyticsQuickStats.AverageMTTRHours
//
// plus the achievement_pct CASE, which answered a literal 100.0 for a
// severity with zero resolved rows. MTTR is a metric where LOW IS GOOD, so
// unlike the CVSS/EPSS sentinels this one does not merely lose information
// — it reports the BEST POSSIBLE value. The blast radius is worst one line
// later, at analytics.go:82:
//
//	m.OnTarget = m.MTTRHours <= float64(m.TargetHours)
//
// 0 <= any target, so a severity nobody has ever remediated was flagged
// "on target" with a green check in the analytics dashboard and a "100.0%"
// SLO line in the executive PDF handed to an auditor.
//
// Post-fix every one of those is a *float64 / *bool: nil = not measured,
// non-nil = a real measurement (including a genuine near-zero MTTR, which a
// fast-moving team can legitimately produce).
//
// SCOPE. These tests drive the three REPOSITORY reads against a real
// Postgres and assert on the returned model structs. They stop at the model
// boundary — the service-level defaults, the JSON shape and the TSX render
// sites are covered by internal/service/analytics_test.go,
// internal/service/report_mttr_test.go and the frontend typecheck.
//
// The MTTR assertions are written against `any` so this file compiles on
// both the pre-fix (bare float64/bool) and post-fix (pointer) shapes; on the
// pre-fix shape the value branch fails with the sentinel diagnosis instead
// of a compile error masking the red run.
package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
)

// assertMTTRUnmeasured fails unless v is the "never measured" representation.
func assertMTTRUnmeasured(t *testing.T, where string, v any) {
	t.Helper()
	switch got := v.(type) {
	case *float64:
		if got != nil {
			t.Errorf("%s: unmeasured MTTR = %v, want nil (no resolved vulnerability is NOT a 0-hour remediation)", where, *got)
		}
	case float64:
		t.Errorf("%s: MTTR is a bare float64 (%v): 'nothing resolved' is reported as the BEST "+
			"possible remediation time and passes every SLO target", where, got)
	default:
		t.Errorf("%s: unexpected MTTR type %T", where, v)
	}
}

// assertMTTRMeasured fails unless v is a present value within tolerance.
func assertMTTRMeasured(t *testing.T, where string, v any, want, tolerance float64) {
	t.Helper()
	switch got := v.(type) {
	case *float64:
		if got == nil {
			t.Errorf("%s: measured MTTR = nil, want ~%v", where, want)
		} else if *got < want-tolerance || *got > want+tolerance {
			t.Errorf("%s: measured MTTR = %v, want ~%v (±%v)", where, *got, want, tolerance)
		}
	case float64:
		if got < want-tolerance || got > want+tolerance {
			t.Errorf("%s: measured MTTR = %v, want ~%v (±%v)", where, got, want, tolerance)
		}
	default:
		t.Errorf("%s: unexpected MTTR type %T", where, v)
	}
}

// assertOnTargetUnknown fails unless the on-target verdict is withheld.
func assertOnTargetUnknown(t *testing.T, where string, v any) {
	t.Helper()
	switch got := v.(type) {
	case *bool:
		if got != nil {
			t.Errorf("%s: on_target = %v for an unmeasured severity, want nil (no data is not a pass)", where, *got)
		}
	case bool:
		if got {
			t.Errorf("%s: on_target is a bare bool and reads TRUE for a severity with zero resolved "+
				"vulnerabilities — 0 <= target always holds, so 'never remediated' renders as 'meeting SLO'", where)
		} else {
			t.Errorf("%s: on_target is a bare bool (%v): 'unknown' cannot be represented", where, got)
		}
	default:
		t.Errorf("%s: unexpected on_target type %T", where, v)
	}
}

// assertPctUnmeasured fails unless an achievement percentage is withheld.
func assertPctUnmeasured(t *testing.T, where string, v any) {
	t.Helper()
	switch got := v.(type) {
	case *float64:
		if got != nil {
			t.Errorf("%s: achievement_pct = %v with zero resolved rows, want nil", where, *got)
		}
	case float64:
		t.Errorf("%s: achievement_pct is a bare float64 (%v): a severity nobody has remediated "+
			"is reported as a measured SLO achievement", where, got)
	default:
		t.Errorf("%s: unexpected achievement_pct type %T", where, v)
	}
}

// assertPctMeasured fails unless the percentage is present and equal to want.
func assertPctMeasured(t *testing.T, where string, v any, want float64) {
	t.Helper()
	switch got := v.(type) {
	case *float64:
		if got == nil {
			t.Errorf("%s: achievement_pct = nil, want %v", where, want)
		} else if *got != want {
			t.Errorf("%s: achievement_pct = %v, want %v", where, *got, want)
		}
	case float64:
		if got != want {
			t.Errorf("%s: achievement_pct = %v, want %v", where, got, want)
		}
	default:
		t.Errorf("%s: unexpected achievement_pct type %T", where, v)
	}
}

// m49MTTRSeed is a tenant with SLO targets for CRITICAL and HIGH, where
// only HIGH has ever been resolved. CRITICAL is the "not measured" arm.
type m49MTTRSeed struct {
	tenant    uuid.UUID
	projectID uuid.UUID
	vulnID    uuid.UUID
}

// seedM49MTTRTenant creates the tenant + SLO targets and (optionally) one
// resolved HIGH event 10h after detection against a 24h target.
func seedM49MTTRTenant(t *testing.T, migDB *sql.DB, label string, withResolvedHigh bool) m49MTTRSeed {
	t.Helper()

	tenant := seedIntegrationTenant(t, migDB, label)
	s := m49MTTRSeed{tenant: tenant, projectID: uuid.New(), vulnID: uuid.New()}

	registerCleanupExec(t, migDB, "m49 "+label+" vulnerability",
		`DELETE FROM vulnerabilities WHERE id = $1`, s.vulnID)

	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm49-mttr-project')
	`, s.projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id) VALUES ($1, $2)
	`, s.vulnID, "CVE-M49-MTTR-"+tenant.String()[:8]); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	for _, sev := range []string{"CRITICAL", "HIGH"} {
		if err := execAsTenant(t, migDB, tenant, `
			INSERT INTO slo_targets (id, tenant_id, severity, target_hours) VALUES ($1, $2, $3, 24)
		`, uuid.New(), tenant, sev); err != nil {
			t.Fatalf("seed slo_target %s: %v", sev, err)
		}
	}

	if withResolvedHigh {
		// Resolved 10h after detection: inside the 24h target.
		if err := execAsTenant(t, migDB, tenant, `
			INSERT INTO vulnerability_resolution_events
				(id, tenant_id, vulnerability_id, project_id, cve_id, severity, detected_at, resolved_at)
			VALUES ($1, $2, $3, $4, 'CVE-M49-MTTR', 'HIGH',
			        NOW() - INTERVAL '12 hours', NOW() - INTERVAL '2 hours')
		`, uuid.New(), tenant, s.vulnID, s.projectID); err != nil {
			t.Fatalf("seed resolution event: %v", err)
		}
		// A GENUINE zero-hour remediation (detected and resolved in the same
		// instant — a pre-merged fix landing with the advisory). This is the
		// value the sentinel is indistinguishable from, so it must survive the
		// COALESCE removal as a PRESENT 0.0, not become nil. MEDIUM gets no
		// PER-TENANT slo_targets row, so it also exercises the global
		// (tenant_id IS NULL) target the `slo` CTE falls back to.
		if err := execAsTenant(t, migDB, tenant, `
			INSERT INTO vulnerability_resolution_events
				(id, tenant_id, vulnerability_id, project_id, cve_id, severity, detected_at, resolved_at)
			SELECT $1, $2, $3, $4, 'CVE-M49-MTTR', 'MEDIUM', ts, ts
			FROM (SELECT NOW() - INTERVAL '5 hours' AS ts) x
		`, uuid.New(), tenant, s.vulnID, s.projectID); err != nil {
			t.Fatalf("seed zero-duration resolution event: %v", err)
		}
	}
	// An OPEN (never resolved) CRITICAL: the severity has vulnerabilities,
	// they have simply never been remediated. This is precisely the state
	// the sentinel rendered as "MTTR 0.0h, on target".
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO vulnerability_resolution_events
			(id, tenant_id, vulnerability_id, project_id, cve_id, severity, detected_at, resolved_at)
		VALUES ($1, $2, $3, $4, 'CVE-M49-MTTR', 'CRITICAL', NOW() - INTERVAL '400 hours', NULL)
	`, uuid.New(), tenant, s.vulnID, s.projectID); err != nil {
		t.Fatalf("seed open critical event: %v", err)
	}

	return s
}

// TestM49MTTR_GetMTTR_UnresolvedSeverityIsNotAZeroHourRemediation drives
// AnalyticsRepository.GetMTTR. HIGH has one 10h remediation; CRITICAL has an
// open vulnerability and no remediation at all.
func TestM49MTTR_GetMTTR_UnresolvedSeverityIsNotAZeroHourRemediation(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "vulnerability_resolution_events") {
		return
	}
	appDB := openIntegrationDB(t, appURL)

	s := seedM49MTTRTenant(t, migDB, "m49-mttr-getmttr", true)
	repo := NewAnalyticsRepository(appDB)

	readAsTenantTx(t, appDB, s.tenant, func(ctx context.Context) {
		results, err := repo.GetMTTR(ctx, s.tenant, time.Now().Add(-30*24*time.Hour), time.Now())
		if err != nil {
			t.Fatalf("GetMTTR: %v", err)
		}
		bySev := map[string]model.MTTRResult{}
		for _, m := range results {
			bySev[m.Severity] = m
		}

		// M49: exactly one row per severity. A tenant SLO override used to
		// coexist with the global (tenant_id IS NULL) default in the `slo`
		// CTE, fanning every resolved row across both and listing the
		// severity twice with doubled counts. HIGH and CRITICAL both carry a
		// tenant override here, so this is the shape that regressed.
		if len(results) != len(bySev) {
			t.Errorf("GetMTTR returned %d rows for %d distinct severities — the slo CTE is "+
				"duplicating tenant-override severities against the global default: %+v",
				len(results), len(bySev), results)
		}

		high, ok := bySev["HIGH"]
		if !ok {
			t.Fatalf("GetMTTR missing HIGH row (got %+v)", results)
		}
		assertMTTRMeasured(t, "GetMTTR HIGH", high.MTTRHours, 10, 0.5)
		if high.Count != 1 {
			t.Errorf("GetMTTR HIGH count = %d, want 1", high.Count)
		}
		// PRECEDENCE (Codex round 2, Low): the tenant's own 24h target must
		// win over the global (tenant_id IS NULL) 168h HIGH default. Without
		// this assertion a DISTINCT ON ... ORDER BY ... NULLS FIRST regression
		// would silently pick the global row and still look on-target.
		if high.TargetHours != 24 {
			t.Errorf("GetMTTR HIGH target_hours = %d, want 24 — the tenant override must win over "+
				"the global slo_targets default (168)", high.TargetHours)
		}
		switch v := any(high.OnTarget).(type) {
		case *bool:
			if v == nil || !*v {
				t.Errorf("GetMTTR HIGH on_target = %v, want a present true (10h <= 24h target)", v)
			}
		case bool:
			if !v {
				t.Errorf("GetMTTR HIGH on_target = false, want true (10h <= 24h target)")
			}
		}

		// A GENUINE 0-hour remediation must stay a MEASUREMENT. This is the
		// assertion that gives the COALESCE(AVG(...), 0) removal teeth in the
		// other direction: nil and 0.0 are now different answers, and the real
		// 0.0 must not be swept into "not measured".
		med, ok := bySev["MEDIUM"]
		if !ok {
			t.Fatalf("GetMTTR missing MEDIUM row (got %+v)", results)
		}
		assertMTTRMeasured(t, "GetMTTR MEDIUM (real 0h)", med.MTTRHours, 0, 0.01)
		switch v := any(med.MTTRHours).(type) {
		case *float64:
			if v == nil {
				t.Errorf("GetMTTR MEDIUM: a real 0-hour remediation came back nil — 0 and " +
					"'not measured' must remain distinguishable in BOTH directions")
			}
		}
		// 720 is the seeded GLOBAL (tenant_id IS NULL) MEDIUM target; the
		// point of the assertion is that the tenant-less fallback resolves at
		// all, not the specific number.
		if med.TargetHours <= 0 {
			t.Errorf("GetMTTR MEDIUM target_hours = %d, want the global slo_targets fallback (>0)",
				med.TargetHours)
		}

		// SCOPE NOTE. CRITICAL has an OPEN vulnerability and no remediation,
		// so GetMTTR's mttr_data CTE — which selects only rows with
		// resolved_at IS NOT NULL — produces no group for it and the severity
		// is ABSENT from this REPOSITORY result. That absence used to reach
		// the dashboard as a silently shortened list (Codex round 4,
		// Medium-1); it is now filled in one layer up by
		// AnalyticsService.mergeUnmeasuredMTTR, which adds an UNMEASURED row
		// for every severity with an SLO target. The assertion below pins the
		// repository contract so the two layers cannot both stop doing it.
		//
		// Consequence for this test (Codex round 2, Low, acknowledged and NOT
		// papered over): because detected_at is NOT NULL, AVG(m.hours) over a
		// returned group can never be SQL NULL, so removing the
		// COALESCE(AVG(...), 0) at the GetMTTR site is unreachable-by-schema
		// defence in depth and NO test in this repository can turn it red on
		// its own. Constructing a red case would require ALTERing the column
		// to nullable, which these tests are not permitted to do. The
		// user-visible GetMTTR sentinel lives in the SERVICE defaults and IS
		// pinned, by internal/service/m49_mttr_unmeasured_integration_test.go
		// (red run observed: mttr_hours 0 / on_target true for all four
		// severities on a fresh tenant).
		if crit, ok := bySev["CRITICAL"]; ok {
			t.Errorf("GetMTTR unexpectedly returned a CRITICAL row (%+v) — if the query changed to "+
				"emit unremediated severities, it must report them as unmeasured, not as 0h/on-target", crit)
			assertMTTRUnmeasured(t, "GetMTTR CRITICAL", crit.MTTRHours)
			assertOnTargetUnknown(t, "GetMTTR CRITICAL", crit.OnTarget)
		}
	})
}

// TestM49MTTR_GetSLOAchievement_NoResolvedRowsWithholdsPctAndMTTR drives the
// LEFT JOIN arm: CRITICAL has an SLO target but nothing resolved, so
// avg_mttr is SQL NULL and achievement_pct has nothing to compute from.
func TestM49MTTR_GetSLOAchievement_NoResolvedRowsWithholdsPctAndMTTR(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "vulnerability_resolution_events") {
		return
	}
	appDB := openIntegrationDB(t, appURL)

	s := seedM49MTTRTenant(t, migDB, "m49-mttr-slo", true)
	repo := NewAnalyticsRepository(appDB)

	readAsTenantTx(t, appDB, s.tenant, func(ctx context.Context) {
		results, err := repo.GetSLOAchievement(ctx, s.tenant, time.Now().Add(-30*24*time.Hour), time.Now())
		if err != nil {
			t.Fatalf("GetSLOAchievement: %v", err)
		}
		bySev := map[string]model.SLOAchievement{}
		for _, a := range results {
			bySev[a.Severity] = a
		}

		crit, ok := bySev["CRITICAL"]
		if !ok {
			t.Fatalf("GetSLOAchievement missing CRITICAL row (got %+v)", results)
		}
		if crit.TotalCount != 0 || crit.OnTargetCount != 0 {
			t.Errorf("GetSLOAchievement CRITICAL counts = %d/%d, want 0/0", crit.OnTargetCount, crit.TotalCount)
		}
		assertPctUnmeasured(t, "GetSLOAchievement CRITICAL", crit.AchievementPct)
		assertMTTRUnmeasured(t, "GetSLOAchievement CRITICAL avg", crit.AverageMTTR)

		high, ok := bySev["HIGH"]
		if !ok {
			t.Fatalf("GetSLOAchievement missing HIGH row (got %+v)", results)
		}
		if high.TotalCount != 1 || high.OnTargetCount != 1 {
			t.Errorf("GetSLOAchievement HIGH counts = %d/%d, want 1/1", high.OnTargetCount, high.TotalCount)
		}
		assertPctMeasured(t, "GetSLOAchievement HIGH", high.AchievementPct, 100.0)
		assertMTTRMeasured(t, "GetSLOAchievement HIGH avg", high.AverageMTTR, 10, 0.5)
	})
}

// TestM49MTTR_GetQuickStats_NoResolutionsWithholdsAverage drives the
// dashboard's headline "average MTTR" tile and, through
// ReportService.gatherExecutiveData, the executive PDF/Excel summary line.
func TestM49MTTR_GetQuickStats_NoResolutionsWithholdsAverage(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "vulnerability_resolution_events") {
		return
	}
	appDB := openIntegrationDB(t, appURL)

	// No resolved event at all — only the open CRITICAL.
	none := seedM49MTTRTenant(t, migDB, "m49-mttr-qs-none", false)
	// One resolved HIGH, ~10h.
	some := seedM49MTTRTenant(t, migDB, "m49-mttr-qs-some", true)
	repo := NewAnalyticsRepository(appDB)

	readAsTenantTx(t, appDB, none.tenant, func(ctx context.Context) {
		stats, err := repo.GetQuickStats(ctx, none.tenant)
		if err != nil {
			t.Fatalf("GetQuickStats(none): %v", err)
		}
		if stats.ResolvedLast30Days != 0 {
			t.Errorf("GetQuickStats(none) resolved = %d, want 0", stats.ResolvedLast30Days)
		}
		if stats.TotalOpenVulnerabilities != 1 {
			t.Errorf("GetQuickStats(none) open = %d, want 1", stats.TotalOpenVulnerabilities)
		}
		assertMTTRUnmeasured(t, "GetQuickStats(none)", stats.AverageMTTRHours)
	})

	readAsTenantTx(t, appDB, some.tenant, func(ctx context.Context) {
		stats, err := repo.GetQuickStats(ctx, some.tenant)
		if err != nil {
			t.Fatalf("GetQuickStats(some): %v", err)
		}
		// Two resolutions in the fixture: HIGH at ~10h and the genuine 0h
		// MEDIUM, so the tenant-wide mean is ~5h. The 0h row participating in
		// the mean (rather than being dropped as "unmeasured") is itself part
		// of what this pins.
		if stats.ResolvedLast30Days != 2 {
			t.Errorf("GetQuickStats(some) resolved = %d, want 2", stats.ResolvedLast30Days)
		}
		assertMTTRMeasured(t, "GetQuickStats(some)", stats.AverageMTTRHours, 5, 0.5)
	})
}
