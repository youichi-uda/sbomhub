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
	ComplianceCategorySBOM            ComplianceCategoryName = "sbom_generation"
	ComplianceCategoryVulnerability   ComplianceCategoryName = "vulnerability_management"
	ComplianceCategoryLicense         ComplianceCategoryName = "license_management"
	ComplianceCategoryMinimumElements ComplianceCategoryName = "minimum_elements"
)

// MinimumElementsCoverage represents coverage stats for METI minimum elements
type MinimumElementsCoverage struct {
	TotalComponents int                   `json:"total_components"`
	Elements        []MinimumElementStats `json:"elements"`
	OverallScore    int                   `json:"overall_score"` // 0-100
}

// MinimumElementStats represents statistics for a single minimum element
type MinimumElementStats struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	LabelJa    string `json:"label_ja"`
	Count      int    `json:"count"`      // Number of components with this element
	Percentage int    `json:"percentage"` // 0-100
}
