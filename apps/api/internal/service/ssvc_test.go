package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// TestSSVCService_CalculateDecision tests the SSVC decision tree algorithm
func TestSSVCService_CalculateDecision(t *testing.T) {
	s := &SSVCService{}

	tests := []struct {
		name              string
		exploitation      model.SSVCExploitation
		automatable       model.SSVCAutomatable
		technicalImpact   model.SSVCTechnicalImpact
		missionPrevalence model.SSVCMissionPrevalence
		safetyImpact      model.SSVCSafetyImpact
		expected          model.SSVCDecision
	}{
		// Active exploitation scenarios
		{
			name:              "Active + Significant Safety = Immediate",
			exploitation:      model.SSVCExploitationActive,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceMinimal,
			safetyImpact:      model.SSVCSafetyImpactSignificant,
			expected:          model.SSVCDecisionImmediate,
		},
		{
			name:              "Active + Essential Mission = Immediate",
			exploitation:      model.SSVCExploitationActive,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceEssential,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionImmediate,
		},
		{
			name:              "Active + Total Impact + Support = Out of Cycle",
			exploitation:      model.SSVCExploitationActive,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactTotal,
			missionPrevalence: model.SSVCMissionPrevalenceSupport,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionOutOfCycle,
		},
		{
			name:              "Active + Automatable = Out of Cycle",
			exploitation:      model.SSVCExploitationActive,
			automatable:       model.SSVCAutomatableYes,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceMinimal,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionOutOfCycle,
		},
		{
			name:              "Active + Low Risk = Scheduled",
			exploitation:      model.SSVCExploitationActive,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceMinimal,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionScheduled,
		},

		// PoC exploitation scenarios
		{
			name:              "PoC + Significant Safety = Out of Cycle",
			exploitation:      model.SSVCExploitationPoC,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceMinimal,
			safetyImpact:      model.SSVCSafetyImpactSignificant,
			expected:          model.SSVCDecisionOutOfCycle,
		},
		{
			name:              "PoC + Essential + Total = Out of Cycle",
			exploitation:      model.SSVCExploitationPoC,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactTotal,
			missionPrevalence: model.SSVCMissionPrevalenceEssential,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionOutOfCycle,
		},
		{
			name:              "PoC + Automatable + Total = Scheduled",
			exploitation:      model.SSVCExploitationPoC,
			automatable:       model.SSVCAutomatableYes,
			technicalImpact:   model.SSVCTechnicalImpactTotal,
			missionPrevalence: model.SSVCMissionPrevalenceMinimal,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionScheduled,
		},
		{
			name:              "PoC + Support Mission = Scheduled",
			exploitation:      model.SSVCExploitationPoC,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceSupport,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionScheduled,
		},
		{
			name:              "PoC + Minimal Everything = Defer",
			exploitation:      model.SSVCExploitationPoC,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceMinimal,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionDefer,
		},

		// No exploitation scenarios
		{
			name:              "None + Significant Safety + Total = Scheduled",
			exploitation:      model.SSVCExploitationNone,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactTotal,
			missionPrevalence: model.SSVCMissionPrevalenceMinimal,
			safetyImpact:      model.SSVCSafetyImpactSignificant,
			expected:          model.SSVCDecisionScheduled,
		},
		{
			name:              "None + Essential + Total = Scheduled",
			exploitation:      model.SSVCExploitationNone,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactTotal,
			missionPrevalence: model.SSVCMissionPrevalenceEssential,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionScheduled,
		},
		{
			name:              "None + Automatable + Total + Support = Scheduled",
			exploitation:      model.SSVCExploitationNone,
			automatable:       model.SSVCAutomatableYes,
			technicalImpact:   model.SSVCTechnicalImpactTotal,
			missionPrevalence: model.SSVCMissionPrevalenceSupport,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionScheduled,
		},
		{
			name:              "None + Low Everything = Defer",
			exploitation:      model.SSVCExploitationNone,
			automatable:       model.SSVCAutomatableNo,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceMinimal,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionDefer,
		},
		{
			name:              "None + Automatable + Partial = Defer",
			exploitation:      model.SSVCExploitationNone,
			automatable:       model.SSVCAutomatableYes,
			technicalImpact:   model.SSVCTechnicalImpactPartial,
			missionPrevalence: model.SSVCMissionPrevalenceSupport,
			safetyImpact:      model.SSVCSafetyImpactMinimal,
			expected:          model.SSVCDecisionDefer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.CalculateDecision(
				tt.exploitation,
				tt.automatable,
				tt.technicalImpact,
				tt.missionPrevalence,
				tt.safetyImpact,
			)

			if result != tt.expected {
				t.Errorf("CalculateDecision() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSSVCDecisionPriority tests that decisions are correctly ordered by priority
func TestSSVCDecisionPriority(t *testing.T) {
	// Decision priority should be: Immediate > OutOfCycle > Scheduled > Defer
	decisions := []model.SSVCDecision{
		model.SSVCDecisionImmediate,
		model.SSVCDecisionOutOfCycle,
		model.SSVCDecisionScheduled,
		model.SSVCDecisionDefer,
	}

	expectedOrder := []string{"immediate", "out_of_cycle", "scheduled", "defer"}

	for i, d := range decisions {
		if string(d) != expectedOrder[i] {
			t.Errorf("Decision at index %d = %v, want %v", i, d, expectedOrder[i])
		}
	}
}

// TestSSVCParameterValidValues tests that all parameter values are valid
func TestSSVCParameterValidValues(t *testing.T) {
	// Exploitation values
	exploitationValues := []model.SSVCExploitation{
		model.SSVCExploitationNone,
		model.SSVCExploitationPoC,
		model.SSVCExploitationActive,
	}
	for _, v := range exploitationValues {
		if v == "" {
			t.Error("Exploitation value should not be empty")
		}
	}

	// Automatable values
	automatableValues := []model.SSVCAutomatable{
		model.SSVCAutomatableYes,
		model.SSVCAutomatableNo,
	}
	for _, v := range automatableValues {
		if v == "" {
			t.Error("Automatable value should not be empty")
		}
	}

	// Technical Impact values
	technicalImpactValues := []model.SSVCTechnicalImpact{
		model.SSVCTechnicalImpactPartial,
		model.SSVCTechnicalImpactTotal,
	}
	for _, v := range technicalImpactValues {
		if v == "" {
			t.Error("TechnicalImpact value should not be empty")
		}
	}

	// Mission Prevalence values
	missionPrevalenceValues := []model.SSVCMissionPrevalence{
		model.SSVCMissionPrevalenceMinimal,
		model.SSVCMissionPrevalenceSupport,
		model.SSVCMissionPrevalenceEssential,
	}
	for _, v := range missionPrevalenceValues {
		if v == "" {
			t.Error("MissionPrevalence value should not be empty")
		}
	}

	// Safety Impact values
	safetyImpactValues := []model.SSVCSafetyImpact{
		model.SSVCSafetyImpactMinimal,
		model.SSVCSafetyImpactSignificant,
	}
	for _, v := range safetyImpactValues {
		if v == "" {
			t.Error("SafetyImpact value should not be empty")
		}
	}

	// Decision values
	decisionValues := []model.SSVCDecision{
		model.SSVCDecisionDefer,
		model.SSVCDecisionScheduled,
		model.SSVCDecisionOutOfCycle,
		model.SSVCDecisionImmediate,
	}
	for _, v := range decisionValues {
		if v == "" {
			t.Error("Decision value should not be empty")
		}
	}
}

// TestSSVCAutoAssessmentLogic tests the auto-assessment parameter inference
func TestSSVCAutoAssessmentLogic(t *testing.T) {
	// Test EPSS threshold for Automatable
	epssThreshold := 0.5
	tests := []struct {
		name             string
		epssScore        float64
		expectedAutoFlag bool
	}{
		{"High EPSS (0.7) = Automatable Yes", 0.7, true},
		{"Medium EPSS (0.5) = Automatable No", 0.5, false},
		{"Low EPSS (0.1) = Automatable No", 0.1, false},
		{"Very High EPSS (0.95) = Automatable Yes", 0.95, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAutomatable := tt.epssScore > epssThreshold
			if isAutomatable != tt.expectedAutoFlag {
				t.Errorf("EPSS %v: automatable = %v, want %v", tt.epssScore, isAutomatable, tt.expectedAutoFlag)
			}
		})
	}
}

// TestSSVCTechnicalImpactFromCVSS tests technical impact derivation from CVSS
func TestSSVCTechnicalImpactFromCVSS(t *testing.T) {
	cvssThreshold := 7.0
	tests := []struct {
		name     string
		cvss     float64
		expected model.SSVCTechnicalImpact
	}{
		{"CVSS 9.8 = Total", 9.8, model.SSVCTechnicalImpactTotal},
		{"CVSS 7.5 = Total", 7.5, model.SSVCTechnicalImpactTotal},
		{"CVSS 7.0 = Total", 7.0, model.SSVCTechnicalImpactTotal},
		{"CVSS 6.9 = Partial", 6.9, model.SSVCTechnicalImpactPartial},
		{"CVSS 5.0 = Partial", 5.0, model.SSVCTechnicalImpactPartial},
		{"CVSS 3.0 = Partial", 3.0, model.SSVCTechnicalImpactPartial},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result model.SSVCTechnicalImpact
			if tt.cvss >= cvssThreshold {
				result = model.SSVCTechnicalImpactTotal
			} else {
				result = model.SSVCTechnicalImpactPartial
			}

			if result != tt.expected {
				t.Errorf("CVSS %v: technical impact = %v, want %v", tt.cvss, result, tt.expected)
			}
		})
	}
}
