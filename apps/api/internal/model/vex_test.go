package model

import (
	"testing"

	"github.com/google/uuid"
)

func TestVEXStatus_Constants(t *testing.T) {
	tests := []struct {
		status   VEXStatus
		expected string
	}{
		{VEXStatusNotAffected, "not_affected"},
		{VEXStatusAffected, "affected"},
		{VEXStatusFixed, "fixed"},
		{VEXStatusUnderInvestigation, "under_investigation"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.expected {
			t.Errorf("VEXStatus %s should be %s", tt.status, tt.expected)
		}
	}
}

func TestVEXJustification_Constants(t *testing.T) {
	tests := []struct {
		justification VEXJustification
		expected      string
	}{
		{VEXJustificationComponentNotPresent, "component_not_present"},
		{VEXJustificationVulnerableCodeNotPresent, "vulnerable_code_not_present"},
		{VEXJustificationVulnerableCodeNotInExecutePath, "vulnerable_code_not_in_execute_path"},
		{VEXJustificationVulnerableCodeCannotBeControlled, "vulnerable_code_cannot_be_controlled_by_adversary"},
		{VEXJustificationInlineMitigationsAlreadyExist, "inline_mitigations_already_exist"},
	}

	for _, tt := range tests {
		if string(tt.justification) != tt.expected {
			t.Errorf("VEXJustification %s should be %s", tt.justification, tt.expected)
		}
	}
}

func TestVEXStatement_Fields(t *testing.T) {
	id := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	compID := uuid.New()

	stmt := VEXStatement{
		ID:              id,
		ProjectID:       projectID,
		VulnerabilityID: vulnID,
		ComponentID:     &compID,
		Status:          VEXStatusNotAffected,
		Justification:   VEXJustificationComponentNotPresent,
		ActionStatement: "Update to version 2.0",
		ImpactStatement: "Low impact",
		CreatedBy:       "user@example.com",
	}

	if stmt.ID != id {
		t.Error("ID mismatch")
	}
	if stmt.ProjectID != projectID {
		t.Error("ProjectID mismatch")
	}
	if stmt.VulnerabilityID != vulnID {
		t.Error("VulnerabilityID mismatch")
	}
	if *stmt.ComponentID != compID {
		t.Error("ComponentID mismatch")
	}
	if stmt.Status != VEXStatusNotAffected {
		t.Error("Status mismatch")
	}
	if stmt.Justification != VEXJustificationComponentNotPresent {
		t.Error("Justification mismatch")
	}
}

func TestVEXStatement_NilComponentID(t *testing.T) {
	stmt := VEXStatement{
		ID:        uuid.New(),
		ProjectID: uuid.New(),
		Status:    VEXStatusAffected,
		// ComponentID is nil
	}

	if stmt.ComponentID != nil {
		t.Error("ComponentID should be nil")
	}
}

func TestVEXStatementWithDetails(t *testing.T) {
	compName := "lodash"
	compVersion := "4.17.20"
	
	stmt := VEXStatementWithDetails{
		VEXStatement: VEXStatement{
			ID:        uuid.New(),
			ProjectID: uuid.New(),
			Status:    VEXStatusFixed,
		},
		VulnerabilityCVEID:    "CVE-2021-44228",
		VulnerabilitySeverity: "CRITICAL",
		ComponentName:         &compName,
		ComponentVersion:      &compVersion,
	}

	if stmt.VulnerabilityCVEID != "CVE-2021-44228" {
		t.Error("VulnerabilityCVEID mismatch")
	}
	if stmt.VulnerabilitySeverity != "CRITICAL" {
		t.Error("VulnerabilitySeverity mismatch")
	}
	if *stmt.ComponentName != "lodash" {
		t.Error("ComponentName mismatch")
	}
	if *stmt.ComponentVersion != "4.17.20" {
		t.Error("ComponentVersion mismatch")
	}
}
