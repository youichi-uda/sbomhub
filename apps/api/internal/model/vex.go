package model

import (
	"time"

	"github.com/google/uuid"
)

// VEX status values per CycloneDX VEX specification
type VEXStatus string

const (
	VEXStatusNotAffected        VEXStatus = "not_affected"
	VEXStatusAffected           VEXStatus = "affected"
	VEXStatusFixed              VEXStatus = "fixed"
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
	TenantID        uuid.UUID        `json:"tenant_id" db:"tenant_id"`
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
	VulnerabilityCVEID    string  `json:"vulnerability_cve_id"`
	VulnerabilitySeverity string  `json:"vulnerability_severity"`
	ComponentName         *string `json:"component_name,omitempty"`
	ComponentVersion      *string `json:"component_version,omitempty"`
}

// VEX suggestion match types (M26-A / F375, issue #130).
//
// A cross-project VEX suggestion is classified by how strongly the
// source (an approved vex_statement from another project of the same
// tenant) matches the target project's affected component:
//
//   - VEXMatchTypePurl: the source statement is component-specific
//     (vex_statements.component_id is non-NULL) and the source
//     component's purl equals the target component's purl. This is the
//     precise match — same package coordinate, same vulnerability.
//   - VEXMatchTypeVulnerabilityOnly: the source statement is
//     component-agnostic (component_id IS NULL), so it matches on the
//     vulnerability alone. Surfaced as a coarser match so a reviewer
//     knows the source judgement was project-wide, not tied to this
//     exact package coordinate.
const (
	VEXMatchTypePurl              = "purl"
	VEXMatchTypeVulnerabilityOnly = "vulnerability_only"
)

// VEXSuggestionCandidate is a raw row returned by
// VEXRepository.ListCrossProjectVEXCandidates. It is the DB-access DTO
// that VEXService.GetSuggestions filters (self-project + already-triaged
// exclusion) and maps into VEXSuggestion. Keeping the exclusion logic in
// Go (rather than a SQL WHERE) keeps it unit-testable without a live DB
// (see assembleSuggestions + its test), while the SQL owns the tenant
// boundary + the purl/vulnerability match join.
type VEXSuggestionCandidate struct {
	VulnerabilityID   uuid.UUID
	CVEID             string
	TargetComponentID uuid.UUID
	ComponentName     string
	ComponentVersion  string
	ComponentPurl     string

	SourceProjectID   uuid.UUID
	SourceProjectName string
	// SourceComponentID is nil when the source statement is
	// component-agnostic → drives match_type = vulnerability_only.
	SourceComponentID *uuid.UUID
	StatementID       uuid.UUID
	Status            string
	Justification     string
	ImpactStatement   string
	ActionStatement   string
	CreatedAt         time.Time

	// TargetAlreadyTriaged is true when the target project already holds
	// a vex_statement covering (vulnerability_id, this component) — either
	// component-specific for this component, or a project-wide (NULL
	// component) statement for the vulnerability. Such candidates are
	// dropped to avoid re-surfacing an already-triaged decision.
	TargetAlreadyTriaged bool
}

// VEXSuggestion is one cross-project VEX reuse suggestion returned by
// GET /api/v1/projects/:id/vex/suggestions (read-only Phase 1). It tells
// a reviewer "another project in your tenant already judged this
// vulnerability/component — here is that judgement and where it came
// from". No apply action is offered in Phase 1.
type VEXSuggestion struct {
	VulnerabilityID uuid.UUID              `json:"vulnerability_id"`
	CVEID           string                 `json:"cve_id"`
	Component       VEXSuggestionComponent `json:"component"`
	MatchType       string                 `json:"match_type"`
	Source          VEXSuggestionSource    `json:"source"`
}

// VEXSuggestionComponent is the target project's affected component the
// suggestion applies to.
//
// ComponentID is the target project's components.id (M26-D / F377, issue
// #131). It is what makes a suggestion uniquely addressable: a single
// vulnerability_only source statement (source component_id NULL) fans out
// across every target component the vulnerability touches, and two distinct
// target component rows can carry the identical (name, version, purl) triple,
// so the previous {statement_id, vulnerability_id} pair was NOT a unique key
// for the web list (duplicate React keys). Emitting the concrete target
// component id lets the client key each row uniquely. NOTE: this only fixes
// key uniqueness — collapsing / de-duplicating the vulnerability_only fan-out
// itself (N target components ⇒ N suggestions from one source) is deferred to
// M27 Phase 2 grouping, per the M26 kickoff N-growth note.
type VEXSuggestionComponent struct {
	ComponentID uuid.UUID `json:"component_id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Purl        string    `json:"purl"`
}

// VEXSuggestionSource is the provenance of the reused judgement: which
// other project it came from and the approved statement's fields. Enough
// context for a reviewer to decide whether to trust the reuse.
//
// justification / impact_statement / action_statement are omitempty (F378,
// issue #131). vex_statements.justification (migration 003) is nullable and
// is only required for status=not_affected, so a source statement with
// status=affected/fixed/under_investigation legitimately carries none of the
// three; the aggregation query COALESCEs each to "". The TS contract types
// these as OPTIONAL — crucially justification is `VEXJustification?`, an enum
// union of which "" is not a member — so emitting "" would put a non-member
// value on the wire. omitempty drops the empty value instead, keeping the
// Go↔TS shape aligned (absent ⇒ TS undefined). status is intentionally NOT
// omitempty: it is NOT NULL in the schema and always present. The web
// component already falsy-guards all three fields, so display is unaffected.
type VEXSuggestionSource struct {
	ProjectID       uuid.UUID `json:"project_id"`
	ProjectName     string    `json:"project_name"`
	StatementID     uuid.UUID `json:"statement_id"`
	Status          string    `json:"status"`
	Justification   string    `json:"justification,omitempty"`
	ImpactStatement string    `json:"impact_statement,omitempty"`
	ActionStatement string    `json:"action_statement,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}
