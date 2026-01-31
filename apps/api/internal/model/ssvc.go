package model

import (
	"time"

	"github.com/google/uuid"
)

// SSVC Parameter Types

type SSVCExploitation string

const (
	SSVCExploitationNone   SSVCExploitation = "none"
	SSVCExploitationPoC    SSVCExploitation = "poc"
	SSVCExploitationActive SSVCExploitation = "active"
)

type SSVCAutomatable string

const (
	SSVCAutomatableYes SSVCAutomatable = "yes"
	SSVCAutomatableNo  SSVCAutomatable = "no"
)

type SSVCTechnicalImpact string

const (
	SSVCTechnicalImpactPartial SSVCTechnicalImpact = "partial"
	SSVCTechnicalImpactTotal   SSVCTechnicalImpact = "total"
)

type SSVCMissionPrevalence string

const (
	SSVCMissionPrevalenceMinimal   SSVCMissionPrevalence = "minimal"
	SSVCMissionPrevalenceSupport   SSVCMissionPrevalence = "support"
	SSVCMissionPrevalenceEssential SSVCMissionPrevalence = "essential"
)

type SSVCSafetyImpact string

const (
	SSVCSafetyImpactMinimal     SSVCSafetyImpact = "minimal"
	SSVCSafetyImpactSignificant SSVCSafetyImpact = "significant"
)

type SSVCDecision string

const (
	SSVCDecisionDefer      SSVCDecision = "defer"
	SSVCDecisionScheduled  SSVCDecision = "scheduled"
	SSVCDecisionOutOfCycle SSVCDecision = "out_of_cycle"
	SSVCDecisionImmediate  SSVCDecision = "immediate"
)

// SSVCProjectDefaults represents project-level SSVC default settings
type SSVCProjectDefaults struct {
	ID                   uuid.UUID             `json:"id" db:"id"`
	ProjectID            uuid.UUID             `json:"project_id" db:"project_id"`
	TenantID             uuid.UUID             `json:"tenant_id" db:"tenant_id"`
	MissionPrevalence    SSVCMissionPrevalence `json:"mission_prevalence" db:"mission_prevalence"`
	SafetyImpact         SSVCSafetyImpact      `json:"safety_impact" db:"safety_impact"`
	SystemExposure       string                `json:"system_exposure" db:"system_exposure"` // internet, internal, airgap
	AutoAssessEnabled    bool                  `json:"auto_assess_enabled" db:"auto_assess_enabled"`
	AutoAssessExploitation bool                `json:"auto_assess_exploitation" db:"auto_assess_exploitation"`
	AutoAssessAutomatable  bool                `json:"auto_assess_automatable" db:"auto_assess_automatable"`
	CreatedAt            time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time             `json:"updated_at" db:"updated_at"`
}

// SSVCAssessment represents a SSVC assessment for a vulnerability in a project
type SSVCAssessment struct {
	ID                uuid.UUID             `json:"id" db:"id"`
	ProjectID         uuid.UUID             `json:"project_id" db:"project_id"`
	TenantID          uuid.UUID             `json:"tenant_id" db:"tenant_id"`
	VulnerabilityID   uuid.UUID             `json:"vulnerability_id" db:"vulnerability_id"`
	CVEID             string                `json:"cve_id" db:"cve_id"`
	Exploitation      SSVCExploitation      `json:"exploitation" db:"exploitation"`
	Automatable       SSVCAutomatable       `json:"automatable" db:"automatable"`
	TechnicalImpact   SSVCTechnicalImpact   `json:"technical_impact" db:"technical_impact"`
	MissionPrevalence SSVCMissionPrevalence `json:"mission_prevalence" db:"mission_prevalence"`
	SafetyImpact      SSVCSafetyImpact      `json:"safety_impact" db:"safety_impact"`
	Decision          SSVCDecision          `json:"decision" db:"decision"`
	ExploitationAuto  bool                  `json:"exploitation_auto" db:"exploitation_auto"`
	AutomatableAuto   bool                  `json:"automatable_auto" db:"automatable_auto"`
	AssessedBy        *uuid.UUID            `json:"assessed_by,omitempty" db:"assessed_by"`
	AssessedAt        time.Time             `json:"assessed_at" db:"assessed_at"`
	Notes             string                `json:"notes,omitempty" db:"notes"`
	CreatedAt         time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at" db:"updated_at"`
}

// SSVCAssessmentHistory represents a history entry for assessment changes
type SSVCAssessmentHistory struct {
	ID                   uuid.UUID             `json:"id" db:"id"`
	AssessmentID         uuid.UUID             `json:"assessment_id" db:"assessment_id"`
	PrevExploitation     *SSVCExploitation     `json:"prev_exploitation,omitempty" db:"prev_exploitation"`
	PrevAutomatable      *SSVCAutomatable      `json:"prev_automatable,omitempty" db:"prev_automatable"`
	PrevTechnicalImpact  *SSVCTechnicalImpact  `json:"prev_technical_impact,omitempty" db:"prev_technical_impact"`
	PrevMissionPrevalence *SSVCMissionPrevalence `json:"prev_mission_prevalence,omitempty" db:"prev_mission_prevalence"`
	PrevSafetyImpact     *SSVCSafetyImpact     `json:"prev_safety_impact,omitempty" db:"prev_safety_impact"`
	PrevDecision         *SSVCDecision         `json:"prev_decision,omitempty" db:"prev_decision"`
	NewExploitation      SSVCExploitation      `json:"new_exploitation" db:"new_exploitation"`
	NewAutomatable       SSVCAutomatable       `json:"new_automatable" db:"new_automatable"`
	NewTechnicalImpact   SSVCTechnicalImpact   `json:"new_technical_impact" db:"new_technical_impact"`
	NewMissionPrevalence SSVCMissionPrevalence `json:"new_mission_prevalence" db:"new_mission_prevalence"`
	NewSafetyImpact      SSVCSafetyImpact      `json:"new_safety_impact" db:"new_safety_impact"`
	NewDecision          SSVCDecision          `json:"new_decision" db:"new_decision"`
	ChangedBy            *uuid.UUID            `json:"changed_by,omitempty" db:"changed_by"`
	ChangedAt            time.Time             `json:"changed_at" db:"changed_at"`
	ChangeReason         string                `json:"change_reason,omitempty" db:"change_reason"`
}

// SSVCAssessmentInput represents input for creating/updating an assessment
type SSVCAssessmentInput struct {
	Exploitation      SSVCExploitation      `json:"exploitation"`
	Automatable       SSVCAutomatable       `json:"automatable"`
	TechnicalImpact   SSVCTechnicalImpact   `json:"technical_impact"`
	MissionPrevalence SSVCMissionPrevalence `json:"mission_prevalence"`
	SafetyImpact      SSVCSafetyImpact      `json:"safety_impact"`
	Notes             string                `json:"notes,omitempty"`
}

// SSVCSummary represents a summary of SSVC assessments for a project
type SSVCSummary struct {
	ProjectID      uuid.UUID `json:"project_id"`
	TotalAssessed  int       `json:"total_assessed"`
	Immediate      int       `json:"immediate"`
	OutOfCycle     int       `json:"out_of_cycle"`
	Scheduled      int       `json:"scheduled"`
	Defer          int       `json:"defer"`
	Unassessed     int       `json:"unassessed"`
}

// SSVCAssessmentWithVuln represents an assessment with vulnerability details
type SSVCAssessmentWithVuln struct {
	SSVCAssessment
	VulnerabilitySeverity  string   `json:"vulnerability_severity"`
	VulnerabilityCVSSScore float64  `json:"vulnerability_cvss_score"`
	VulnerabilityInKEV     bool     `json:"vulnerability_in_kev"`
	VulnerabilityEPSSScore *float64 `json:"vulnerability_epss_score,omitempty"`
}
