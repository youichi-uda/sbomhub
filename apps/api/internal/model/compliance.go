package model

import "github.com/google/uuid"

// ComplianceResult represents the overall compliance check result
type ComplianceResult struct {
	ProjectID  uuid.UUID            `json:"project_id"`
	Score      int                  `json:"score"`
	MaxScore   int                  `json:"max_score"`
	Categories []ComplianceCategory `json:"categories"`
}

// ComplianceCategory represents a category of compliance checks
type ComplianceCategory struct {
	Name     string            `json:"name"`
	Label    string            `json:"label"`
	Score    int               `json:"score"`
	MaxScore int               `json:"max_score"`
	Checks   []ComplianceCheck `json:"checks"`
}

// ComplianceCheck represents a single compliance check
type ComplianceCheck struct {
	ID      string  `json:"id"`
	Label   string  `json:"label"`
	Passed  bool    `json:"passed"`
	Details *string `json:"details,omitempty"`
}

// ComplianceCategoryName represents category names
type ComplianceCategoryName string

const (
	ComplianceCategorySBOM          ComplianceCategoryName = "sbom_generation"
	ComplianceCategoryVulnerability ComplianceCategoryName = "vulnerability_management"
	ComplianceCategoryLicense       ComplianceCategoryName = "license_management"
)
