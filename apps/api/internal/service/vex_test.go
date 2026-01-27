package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestIsValidStatus(t *testing.T) {
	tests := []struct {
		name   string
		status model.VEXStatus
		valid  bool
	}{
		{"not_affected is valid", model.VEXStatusNotAffected, true},
		{"affected is valid", model.VEXStatusAffected, true},
		{"fixed is valid", model.VEXStatusFixed, true},
		{"under_investigation is valid", model.VEXStatusUnderInvestigation, true},
		{"empty is invalid", model.VEXStatus(""), false},
		{"unknown is invalid", model.VEXStatus("unknown"), false},
		{"random is invalid", model.VEXStatus("random_status"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidStatus(tt.status)
			if result != tt.valid {
				t.Errorf("isValidStatus(%s) = %v, want %v", tt.status, result, tt.valid)
			}
		})
	}
}

func TestMapStatusToCycloneDX(t *testing.T) {
	tests := []struct {
		status   model.VEXStatus
		expected string
	}{
		{model.VEXStatusNotAffected, "not_affected"},
		{model.VEXStatusAffected, "exploitable"},
		{model.VEXStatusFixed, "resolved"},
		{model.VEXStatusUnderInvestigation, "in_triage"},
		{model.VEXStatus("unknown"), "in_triage"}, // default
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := mapStatusToCycloneDX(tt.status)
			if result != tt.expected {
				t.Errorf("mapStatusToCycloneDX(%s) = %s, want %s", tt.status, result, tt.expected)
			}
		})
	}
}

func TestMapJustificationToCycloneDX(t *testing.T) {
	tests := []struct {
		justification model.VEXJustification
		expected      string
	}{
		{model.VEXJustificationComponentNotPresent, "component_not_present"},
		{model.VEXJustificationVulnerableCodeNotPresent, "vulnerable_code_not_present"},
		{model.VEXJustificationVulnerableCodeNotInExecutePath, "vulnerable_code_not_in_execute_path"},
		{model.VEXJustificationVulnerableCodeCannotBeControlled, "vulnerable_code_cannot_be_controlled_by_adversary"},
		{model.VEXJustificationInlineMitigationsAlreadyExist, "inline_mitigations_already_exist"},
		{model.VEXJustification("unknown"), ""},   // default empty
		{model.VEXJustification(""), ""},          // empty
	}

	for _, tt := range tests {
		t.Run(string(tt.justification), func(t *testing.T) {
			result := mapJustificationToCycloneDX(tt.justification)
			if result != tt.expected {
				t.Errorf("mapJustificationToCycloneDX(%s) = %s, want %s", tt.justification, result, tt.expected)
			}
		})
	}
}
