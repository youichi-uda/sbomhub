package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestGetDefaultMTTR(t *testing.T) {
	// analyticsRepo is nil, so getDefaultSLOAchievement falls back to the
	// product defaults — the shape this test has always covered.
	s := &AnalyticsService{}
	mttr := unmeasuredMTTRFor(s.getDefaultSLOAchievement(context.Background(), uuid.Nil))

	if len(mttr) != 4 {
		t.Fatalf("getDefaultMTTR() returned %d items, want 4", len(mttr))
	}

	// Check severities
	expectedSeverities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for i, expected := range expectedSeverities {
		if mttr[i].Severity != expected {
			t.Errorf("mttr[%d].Severity = %q, want %q", i, mttr[i].Severity, expected)
		}
	}

	// Check target hours (based on SLO)
	expectedTargets := []int{24, 168, 720, 2160}
	for i, expected := range expectedTargets {
		if int(mttr[i].TargetHours) != expected {
			t.Errorf("mttr[%d].TargetHours = %v, want %d", i, mttr[i].TargetHours, expected)
		}
	}

	// M49 (inverted from the pre-fix contract): with no data there is no
	// measurement and no verdict. This test used to assert OnTarget == true
	// and MTTRHours == 0 for every severity — i.e. it PINNED the sentinel:
	// a fresh installation was certified as meeting every SLO with a 0-hour
	// remediation time before resolving a single vulnerability.
	for i, m := range mttr {
		if m.Count != 0 {
			t.Errorf("mttr[%d].Count = %d, want 0", i, m.Count)
		}
		if m.MTTRHours != nil {
			t.Errorf("mttr[%d].MTTRHours = %v, want nil (no resolved vulnerability is not a 0-hour remediation)",
				i, *m.MTTRHours)
		}
		if m.OnTarget != nil {
			t.Errorf("mttr[%d].OnTarget = %v, want nil (no data is not a pass)", i, *m.OnTarget)
		}
	}
}

func TestGetDefaultSLOAchievement(t *testing.T) {
	s := &AnalyticsService{}
	slo := s.getDefaultSLOAchievement(context.Background(), uuid.Nil)

	if len(slo) != 4 {
		t.Fatalf("getDefaultSLOAchievement() returned %d items, want 4", len(slo))
	}

	// Check severities
	expectedSeverities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for i, expected := range expectedSeverities {
		if slo[i].Severity != expected {
			t.Errorf("slo[%d].Severity = %q, want %q", i, slo[i].Severity, expected)
		}
	}

	// Check target hours
	expectedTargets := []int{24, 168, 720, 2160}
	for i, expected := range expectedTargets {
		if slo[i].TargetHours != expected {
			t.Errorf("slo[%d].TargetHours = %d, want %d", i, slo[i].TargetHours, expected)
		}
	}

	// M49 (inverted from the pre-fix contract): the counts really are 0, but
	// the RATIO and the average have no sample to be computed from. This
	// test used to assert AchievementPct == 100.0 — pinning the claim that
	// a severity nobody has remediated is in perfect SLO compliance.
	for i, s := range slo {
		if s.TotalCount != 0 {
			t.Errorf("slo[%d].TotalCount = %d, want 0", i, s.TotalCount)
		}
		if s.OnTargetCount != 0 {
			t.Errorf("slo[%d].OnTargetCount = %d, want 0", i, s.OnTargetCount)
		}
		if s.AchievementPct != nil {
			t.Errorf("slo[%d].AchievementPct = %v, want nil (an empty denominator is not 100%%)",
				i, *s.AchievementPct)
		}
		if s.AverageMTTR != nil {
			t.Errorf("slo[%d].AverageMTTR = %v, want nil", i, *s.AverageMTTR)
		}
	}
}

func TestSLOTargetValidation(t *testing.T) {
	// Test severity validation via map lookup pattern
	validSeverities := map[string]bool{
		"CRITICAL": true,
		"HIGH":     true,
		"MEDIUM":   true,
		"LOW":      true,
	}

	// Valid severities
	validCases := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, sev := range validCases {
		if !validSeverities[sev] {
			t.Errorf("severity %q should be valid", sev)
		}
	}

	// Invalid severities
	invalidCases := []string{"", "critical", "UNKNOWN", "EXTREME", "none"}
	for _, sev := range invalidCases {
		if validSeverities[sev] {
			t.Errorf("severity %q should be invalid", sev)
		}
	}
}

func TestTargetHoursValidation(t *testing.T) {
	// Test that target hours must be positive
	tests := []struct {
		hours int
		valid bool
	}{
		{24, true},
		{168, true},
		{1, true},
		{0, false},
		{-1, false},
		{-100, false},
	}

	for _, tt := range tests {
		isValid := tt.hours > 0
		if isValid != tt.valid {
			t.Errorf("targetHours %d validation = %v, want %v", tt.hours, isValid, tt.valid)
		}
	}
}

func TestDefaultDaysPeriod(t *testing.T) {
	// Test that days <= 0 defaults to 30
	tests := []struct {
		input    int
		expected int
	}{
		{30, 30},
		{7, 7},
		{90, 90},
		{0, 30},    // Should default
		{-1, 30},   // Should default
		{-100, 30}, // Should default
	}

	for _, tt := range tests {
		days := tt.input
		if days <= 0 {
			days = 30
		}
		if days != tt.expected {
			t.Errorf("days normalization: input %d, got %d, want %d", tt.input, days, tt.expected)
		}
	}
}

func TestMTTRTargetHoursMapping(t *testing.T) {
	// Verify MTTR target hours match SLO standards
	// CRITICAL: 24h (1 day)
	// HIGH: 168h (7 days)
	// MEDIUM: 720h (30 days)
	// LOW: 2160h (90 days)

	expected := map[string]int{
		"CRITICAL": 24,
		"HIGH":     168,
		"MEDIUM":   720,
		"LOW":      2160,
	}

	s := &AnalyticsService{}
	mttr := unmeasuredMTTRFor(s.getDefaultSLOAchievement(context.Background(), uuid.Nil))

	for _, m := range mttr {
		expectedHours, ok := expected[m.Severity]
		if !ok {
			t.Errorf("unexpected severity: %s", m.Severity)
			continue
		}
		if int(m.TargetHours) != expectedHours {
			t.Errorf("MTTR target for %s = %v hours, want %d", m.Severity, m.TargetHours, expectedHours)
		}
	}
}

func TestSLOTargetHoursMapping(t *testing.T) {
	// Verify SLO target hours are consistent
	expected := map[string]int{
		"CRITICAL": 24,
		"HIGH":     168,
		"MEDIUM":   720,
		"LOW":      2160,
	}

	s := &AnalyticsService{}
	slo := s.getDefaultSLOAchievement(context.Background(), uuid.Nil)

	for _, item := range slo {
		expectedHours, ok := expected[item.Severity]
		if !ok {
			t.Errorf("unexpected severity: %s", item.Severity)
			continue
		}
		if item.TargetHours != expectedHours {
			t.Errorf("SLO target for %s = %d hours, want %d", item.Severity, item.TargetHours, expectedHours)
		}
	}
}

// TestOverallSLOAchievementCalculation exercises the REAL aggregation
// (overallSLOAchievement) instead of re-implementing the loop inline, which
// is how the previous version of this test managed to stay green while the
// production code averaged in invented 100.0 values (M49).
func TestOverallSLOAchievementCalculation(t *testing.T) {
	f := func(v float64) *float64 { return &v }

	tests := []struct {
		name     string
		rows     []model.SLOAchievement
		expected *float64
	}{
		{
			name: "all on target",
			rows: []model.SLOAchievement{
				{TotalCount: 4, OnTargetCount: 4, AchievementPct: f(100)},
				{TotalCount: 6, OnTargetCount: 6, AchievementPct: f(100)},
			},
			expected: f(100.0),
		},
		{
			name: "none on target",
			rows: []model.SLOAchievement{
				{TotalCount: 3, OnTargetCount: 0, AchievementPct: f(0)},
			},
			expected: f(0.0),
		},
		{
			name: "half on target",
			rows: []model.SLOAchievement{
				{TotalCount: 2, OnTargetCount: 1, AchievementPct: f(50)},
				{TotalCount: 2, OnTargetCount: 1, AchievementPct: f(50)},
			},
			expected: f(50.0),
		},
		// M49 (Codex round 2, High): the aggregate is POPULATION-weighted.
		// An unweighted mean of the per-severity percentages answers 50% for
		// the row set below, when only 1 of 101 resolutions actually met its
		// target. The caption the operator reads ("the proportion of
		// vulnerabilities resolved within the SLO target time") promises the
		// weighted number.
		{
			name: "one tiny perfect severity does not outweigh a large failing one",
			rows: []model.SLOAchievement{
				{TotalCount: 1, OnTargetCount: 1, AchievementPct: f(100)},
				{TotalCount: 100, OnTargetCount: 0, AchievementPct: f(0)},
			},
			expected: f(100.0 / 101.0),
		},
		// Unmeasured severities are EXCLUDED, not counted as 100. Pre-M49
		// "one late CRITICAL, nothing else measured" reported 75% overall —
		// three quarters of the contributions were manufactured.
		{
			name: "one measured, three unmeasured",
			rows: []model.SLOAchievement{
				{TotalCount: 2, OnTargetCount: 0, AchievementPct: f(0)},
				{TotalCount: 0, OnTargetCount: 0, AchievementPct: nil},
				{TotalCount: 0, OnTargetCount: 0, AchievementPct: nil},
				{TotalCount: 0, OnTargetCount: 0, AchievementPct: nil},
			},
			expected: f(0.0),
		},
		{
			name: "nothing measured",
			rows: []model.SLOAchievement{
				{TotalCount: 0, OnTargetCount: 0, AchievementPct: nil},
				{TotalCount: 0, OnTargetCount: 0, AchievementPct: nil},
			},
			expected: nil,
		},
		{name: "empty list", rows: nil, expected: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := overallSLOAchievement(tt.rows)
			switch {
			case tt.expected == nil && got != nil:
				t.Errorf("overall SLO = %v, want nil (nothing measured)", *got)
			case tt.expected != nil && got == nil:
				t.Errorf("overall SLO = nil, want %v", *tt.expected)
			case tt.expected != nil && got != nil:
				if diff := *got - *tt.expected; diff > 1e-9 || diff < -1e-9 {
					t.Errorf("overall SLO = %v, want %v", *got, *tt.expected)
				}
			}
		})
	}
}

// TestAggregatePeriodMTTR pins the report-window aggregation: the mean is
// COUNT-weighted and is withheld (nil) when the window resolved nothing,
// while the total count is always a real count (M49).
func TestAggregatePeriodMTTR(t *testing.T) {
	f := func(v float64) *float64 { return &v }

	tests := []struct {
		name        string
		rows        []model.MTTRResult
		wantCount   int
		wantAverage *float64
	}{
		{"empty", nil, 0, nil},
		{
			name:        "single severity",
			rows:        []model.MTTRResult{{Count: 3, MTTRHours: f(12)}},
			wantCount:   3,
			wantAverage: f(12),
		},
		{
			// Count-weighted, not mean-of-means: the unweighted mean would be
			// 55h, which lets one slow LOW dominate 99 prompt CRITICALs.
			name: "count weighted across severities",
			rows: []model.MTTRResult{
				{Count: 99, MTTRHours: f(10)},
				{Count: 1, MTTRHours: f(100)},
			},
			wantCount:   100,
			wantAverage: f((99*10 + 100) / 100.0),
		},
		{
			// A row with a count but no measurement cannot happen today
			// (GetMTTR derives both from the same group), but the aggregate
			// must not silently treat it as 0 hours if it ever does.
			name: "unmeasured rows are excluded from the mean but counted",
			rows: []model.MTTRResult{
				{Count: 2, MTTRHours: nil},
				{Count: 2, MTTRHours: f(20)},
			},
			wantCount:   4,
			wantAverage: f(20),
		},
		{
			name:        "all unmeasured",
			rows:        []model.MTTRResult{{Count: 0, MTTRHours: nil}, {Count: 0, MTTRHours: nil}},
			wantCount:   0,
			wantAverage: nil,
		},
		{
			// A genuine 0-hour remediation is a MEASUREMENT and must survive.
			name:        "real zero stays measured",
			rows:        []model.MTTRResult{{Count: 1, MTTRHours: f(0)}},
			wantCount:   1,
			wantAverage: f(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, avg := aggregatePeriodMTTR(tt.rows)
			if count != tt.wantCount {
				t.Errorf("resolved count = %d, want %d", count, tt.wantCount)
			}
			switch {
			case tt.wantAverage == nil && avg != nil:
				t.Errorf("average = %v, want nil (nothing measured is not a 0-hour remediation)", *avg)
			case tt.wantAverage != nil && avg == nil:
				t.Errorf("average = nil, want %v", *tt.wantAverage)
			case tt.wantAverage != nil && avg != nil:
				if diff := *avg - *tt.wantAverage; diff > 1e-9 || diff < -1e-9 {
					t.Errorf("average = %v, want %v", *avg, *tt.wantAverage)
				}
			}
		})
	}
}

// TestUnmeasuredMTTRFor_InheritsConfiguredTargets pins Codex round 3, Low:
// the MTTR placeholder rows must carry the tenant's REAL SLO targets, not a
// second hard-coded copy of the product defaults. Pre-fix a tenant that had
// set CRITICAL to 12h saw "target 24h" in the MTTR panel and "target 12h" in
// the SLO panel until its first remediation.
func TestUnmeasuredMTTRFor_InheritsConfiguredTargets(t *testing.T) {
	slo := []model.SLOAchievement{
		{Severity: "CRITICAL", TargetHours: 12},
		{Severity: "HIGH", TargetHours: 72},
	}

	got := unmeasuredMTTRFor(slo)
	if len(got) != 2 {
		t.Fatalf("unmeasuredMTTRFor returned %d rows, want 2", len(got))
	}
	for i, want := range slo {
		if got[i].Severity != want.Severity || got[i].TargetHours != want.TargetHours {
			t.Errorf("row %d = (%s, %dh), want (%s, %dh) — the MTTR panel must not disagree with "+
				"the SLO panel about the tenant's configured target",
				i, got[i].Severity, got[i].TargetHours, want.Severity, want.TargetHours)
		}
		if got[i].MTTRHours != nil || got[i].OnTarget != nil || got[i].Count != 0 {
			t.Errorf("row %d claims a measurement: %+v", i, got[i])
		}
	}

	// Severity reading order must hold even when NOTHING was measured — that
	// path is built from GetSLOTargets, whose SQL order is lexical
	// (CRITICAL, HIGH, LOW, MEDIUM), not severity rank (Codex round 5, Low).
	lexical := mergeUnmeasuredMTTR(nil, []model.SLOAchievement{
		{Severity: "CRITICAL", TargetHours: 24},
		{Severity: "HIGH", TargetHours: 168},
		{Severity: "LOW", TargetHours: 2160},
		{Severity: "MEDIUM", TargetHours: 720},
	})
	for i, want := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if lexical[i].Severity != want {
			t.Errorf("all-unmeasured row %d = %q, want %q (severity rank order, not lexical)",
				i, lexical[i].Severity, want)
		}
	}

	// Empty input (slo_targets unreadable) falls back to the product defaults
	// rather than to zero-valued targets, which would make every row look
	// "over target" the moment a measurement arrived.
	fallback := unmeasuredMTTRFor(nil)
	if len(fallback) != len(fallbackSLOTargetHours) {
		t.Fatalf("fallback returned %d rows, want %d", len(fallback), len(fallbackSLOTargetHours))
	}
	for i, d := range fallbackSLOTargetHours {
		if fallback[i].Severity != d.Severity || fallback[i].TargetHours != d.TargetHours {
			t.Errorf("fallback row %d = (%s, %dh), want (%s, %dh)",
				i, fallback[i].Severity, fallback[i].TargetHours, d.Severity, d.TargetHours)
		}
	}
}

// TestMergeUnmeasuredMTTR_KeepsUnremediatedSeveritiesVisible pins Codex round
// 4, Medium-1: GetMTTR only returns severities that produced a remediation,
// so a tenant with one resolved HIGH and an unremediated CRITICAL used to see
// a single-row MTTR panel — its worst severity silently dropped, partial data
// presented as complete.
func TestMergeUnmeasuredMTTR_KeepsUnremediatedSeveritiesVisible(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	b := func(v bool) *bool { return &v }

	measured := []model.MTTRResult{
		{Severity: "HIGH", MTTRHours: f(10), Count: 1, TargetHours: 24, OnTarget: b(true)},
	}
	slo := []model.SLOAchievement{
		{Severity: "CRITICAL", TargetHours: 12},
		{Severity: "HIGH", TargetHours: 24},
		{Severity: "LOW", TargetHours: 2160},
	}

	got := mergeUnmeasuredMTTR(measured, slo)
	if len(got) != 3 {
		t.Fatalf("merged rows = %d (%+v), want 3", len(got), got)
	}
	// Severity reading order must survive the merge.
	for i, want := range []string{"CRITICAL", "HIGH", "LOW"} {
		if got[i].Severity != want {
			t.Errorf("row %d severity = %q, want %q", i, got[i].Severity, want)
		}
	}
	if got[0].MTTRHours != nil || got[0].OnTarget != nil || got[0].Count != 0 {
		t.Errorf("CRITICAL placeholder claims a measurement: %+v", got[0])
	}
	if got[0].TargetHours != 12 {
		t.Errorf("CRITICAL placeholder target = %d, want the tenant's 12", got[0].TargetHours)
	}
	if got[1].MTTRHours == nil || *got[1].MTTRHours != 10 || got[1].OnTarget == nil || !*got[1].OnTarget {
		t.Errorf("measured HIGH row was altered by the merge: %+v", got[1])
	}
	// The caller's slice must not be mutated.
	if len(measured) != 1 {
		t.Errorf("mergeUnmeasuredMTTR mutated the input slice (len %d)", len(measured))
	}

	// A severity that GetMTTR measured but slo_targets does not list must
	// survive too (severity values are not constrained by a FK).
	orphan := mergeUnmeasuredMTTR(
		[]model.MTTRResult{{Severity: "UNKNOWN", MTTRHours: f(1), Count: 1, TargetHours: 168, OnTarget: b(true)}},
		[]model.SLOAchievement{{Severity: "CRITICAL", TargetHours: 24}},
	)
	if len(orphan) != 2 || orphan[0].Severity != "CRITICAL" || orphan[1].Severity != "UNKNOWN" {
		t.Errorf("orphan-severity merge = %+v, want [CRITICAL(unmeasured), UNKNOWN(measured)]", orphan)
	}
}
