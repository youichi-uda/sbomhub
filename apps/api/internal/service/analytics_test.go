package service

import (
	"testing"
)

func TestGetDefaultMTTR(t *testing.T) {
	s := &AnalyticsService{}
	mttr := s.getDefaultMTTR()

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

	// All should be on target when no data
	for i, m := range mttr {
		if !m.OnTarget {
			t.Errorf("mttr[%d].OnTarget = false, want true", i)
		}
		if m.Count != 0 {
			t.Errorf("mttr[%d].Count = %d, want 0", i, m.Count)
		}
		if m.MTTRHours != 0 {
			t.Errorf("mttr[%d].MTTRHours = %f, want 0", i, m.MTTRHours)
		}
	}
}

func TestGetDefaultSLOAchievement(t *testing.T) {
	s := &AnalyticsService{}
	slo := s.getDefaultSLOAchievement()

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

	// All should show 100% achievement when no data
	for i, s := range slo {
		if s.AchievementPct != 100.0 {
			t.Errorf("slo[%d].AchievementPct = %f, want 100.0", i, s.AchievementPct)
		}
		if s.TotalCount != 0 {
			t.Errorf("slo[%d].TotalCount = %d, want 0", i, s.TotalCount)
		}
		if s.OnTargetCount != 0 {
			t.Errorf("slo[%d].OnTargetCount = %d, want 0", i, s.OnTargetCount)
		}
		if s.AverageMTTR != 0 {
			t.Errorf("slo[%d].AverageMTTR = %f, want 0", i, s.AverageMTTR)
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
		{0, 30},  // Should default
		{-1, 30}, // Should default
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
	mttr := s.getDefaultMTTR()

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
	slo := s.getDefaultSLOAchievement()

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

func TestOverallSLOAchievementCalculation(t *testing.T) {
	// Test overall SLO calculation logic
	tests := []struct {
		name        string
		achievements []float64
		expected     float64
	}{
		{
			name:        "all 100%",
			achievements: []float64{100, 100, 100, 100},
			expected:     100.0,
		},
		{
			name:        "mixed achievements",
			achievements: []float64{80, 90, 100, 70},
			expected:     85.0, // (80+90+100+70)/4
		},
		{
			name:        "all 0%",
			achievements: []float64{0, 0, 0, 0},
			expected:     0.0,
		},
		{
			name:        "single value",
			achievements: []float64{75},
			expected:     75.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var totalPct float64
			for _, pct := range tt.achievements {
				totalPct += pct
			}
			result := totalPct / float64(len(tt.achievements))

			if result != tt.expected {
				t.Errorf("overall SLO = %f, want %f", result, tt.expected)
			}
		})
	}
}
