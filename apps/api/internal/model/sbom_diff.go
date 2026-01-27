package model

type SbomDiffSummary struct {
	AddedCount              int `json:"added_count"`
	RemovedCount            int `json:"removed_count"`
	UpdatedCount            int `json:"updated_count"`
	NewVulnerabilitiesCount int `json:"new_vulnerabilities_count"`
}

type SbomDiffComponent struct {
	Name           string           `json:"name"`
	Version        string           `json:"version"`
	License        string           `json:"license,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type SbomDiffUpdated struct {
	Name                string   `json:"name"`
	OldVersion          string   `json:"old_version"`
	NewVersion          string   `json:"new_version"`
	VulnerabilitiesFixed []string `json:"vulnerabilities_fixed,omitempty"`
}

type SbomDiffVulnerability struct {
	CVEID     string `json:"cve_id"`
	Severity  string `json:"severity"`
	Component string `json:"component"`
	Version   string `json:"version"`
}

type SbomDiffResponse struct {
	Summary           SbomDiffSummary          `json:"summary"`
	Added             []SbomDiffComponent      `json:"added"`
	Removed           []SbomDiffComponent      `json:"removed"`
	Updated           []SbomDiffUpdated        `json:"updated"`
	NewVulnerabilities []SbomDiffVulnerability `json:"new_vulnerabilities"`
}
