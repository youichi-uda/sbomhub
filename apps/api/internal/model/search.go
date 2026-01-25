package model

import "github.com/google/uuid"

// CVESearchResult represents the result of a CVE search
type CVESearchResult struct {
	CVEID              string               `json:"cve_id"`
	Description        string               `json:"description"`
	CVSSScore          float64              `json:"cvss_score"`
	EPSSScore          float64              `json:"epss_score"`
	Severity           string               `json:"severity"`
	AffectedProjects   []AffectedProject    `json:"affected_projects"`
	UnaffectedProjects []UnaffectedProject  `json:"unaffected_projects"`
}

// AffectedProject represents a project affected by a CVE
type AffectedProject struct {
	ProjectID          uuid.UUID           `json:"project_id"`
	ProjectName        string              `json:"project_name"`
	AffectedComponents []AffectedComponent `json:"affected_components"`
}

// AffectedComponent represents a component affected by a CVE
type AffectedComponent struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	FixedVersion string    `json:"fixed_version,omitempty"`
}

// UnaffectedProject represents a project not affected by a CVE
type UnaffectedProject struct {
	ProjectID   uuid.UUID `json:"project_id"`
	ProjectName string    `json:"project_name"`
}

// ComponentSearchQuery represents a component search query
type ComponentSearchQuery struct {
	Name              string `json:"name"`
	VersionConstraint string `json:"version_constraint,omitempty"`
}

// ComponentSearchResult represents the result of a component search
type ComponentSearchResult struct {
	Query   ComponentSearchQuery      `json:"query"`
	Matches []ComponentSearchMatch    `json:"matches"`
}

// ComponentSearchMatch represents a matching component
type ComponentSearchMatch struct {
	ProjectID       uuid.UUID       `json:"project_id"`
	ProjectName     string          `json:"project_name"`
	Component       ComponentInfo   `json:"component"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// ComponentInfo represents basic component information
type ComponentInfo struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	License string    `json:"license,omitempty"`
}
