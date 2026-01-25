package model

import (
	"time"

	"github.com/google/uuid"
)

// VEX status values per CycloneDX VEX specification
type VEXStatus string

const (
	VEXStatusNotAffected       VEXStatus = "not_affected"
	VEXStatusAffected          VEXStatus = "affected"
	VEXStatusFixed             VEXStatus = "fixed"
	VEXStatusUnderInvestigation VEXStatus = "under_investigation"
)

// VEX justification values for not_affected status
type VEXJustification string

const (
	VEXJustificationComponentNotPresent              VEXJustification = "component_not_present"
	VEXJustificationVulnerableCodeNotPresent         VEXJustification = "vulnerable_code_not_present"
	VEXJustificationVulnerableCodeNotInExecutePath   VEXJustification = "vulnerable_code_not_in_execute_path"
	VEXJustificationVulnerableCodeCannotBeControlled VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"
	VEXJustificationInlineMitigationsAlreadyExist    VEXJustification = "inline_mitigations_already_exist"
)

// VEXStatement represents a VEX statement about a vulnerability's status
type VEXStatement struct {
	ID              uuid.UUID        `json:"id" db:"id"`
	ProjectID       uuid.UUID        `json:"project_id" db:"project_id"`
	VulnerabilityID uuid.UUID        `json:"vulnerability_id" db:"vulnerability_id"`
	ComponentID     *uuid.UUID       `json:"component_id,omitempty" db:"component_id"`
	Status          VEXStatus        `json:"status" db:"status"`
	Justification   VEXJustification `json:"justification,omitempty" db:"justification"`
	ActionStatement string           `json:"action_statement,omitempty" db:"action_statement"`
	ImpactStatement string           `json:"impact_statement,omitempty" db:"impact_statement"`
	CreatedBy       string           `json:"created_by" db:"created_by"`
	CreatedAt       time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at" db:"updated_at"`
}

// VEXStatementWithDetails includes vulnerability and component info for display
type VEXStatementWithDetails struct {
	VEXStatement
	VulnerabilityCVEID   string  `json:"vulnerability_cve_id"`
	VulnerabilitySeverity string `json:"vulnerability_severity"`
	ComponentName        *string `json:"component_name,omitempty"`
	ComponentVersion     *string `json:"component_version,omitempty"`
}
