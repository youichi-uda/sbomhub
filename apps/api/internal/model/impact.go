package model

import "github.com/google/uuid"

// CVEImpact is the cross-project blast-radius view for a single CVE within one
// tenant (M28-A / F388, issue #134). It answers "how far does this
// vulnerability reach across our projects": how many of the tenant's projects
// carry it, which projects, and the affected components per project, alongside
// the vulnerability's severity / CVSS / EPSS / KEV metadata.
//
// It is a read-only aggregation over the existing search / vulnerability tables
// — no new table, no new audit action. Tenant isolation is structural: RLS is
// the authoritative boundary (the braces) and every tenant-scoped join also
// carries an explicit tenant_id predicate (the belt). project_id is crossed
// deliberately; tenant_id never is.
type CVEImpact struct {
	CVEID     string  `json:"cve_id"`
	Severity  string  `json:"severity"`
	CVSSScore float64 `json:"cvss_score"`
	EPSSScore float64 `json:"epss_score"`
	InKEV     bool    `json:"in_kev"`
	// AffectedProjectCount is len(AffectedProjects); emitted explicitly so the
	// web summary can render "N of M projects affected" without walking the
	// list.
	AffectedProjectCount int `json:"affected_project_count"`
	// TotalProjectCount is the tenant's total project count (the denominator
	// M in "N of M"). Counts only this tenant's projects.
	TotalProjectCount int             `json:"total_project_count"`
	AffectedProjects  []ImpactProject `json:"affected_projects"`
}

// ImpactProject is one project reached by the CVE, with the components in it
// that carry the vulnerability.
type ImpactProject struct {
	ProjectID          uuid.UUID         `json:"project_id"`
	ProjectName        string            `json:"project_name"`
	AffectedComponents []ImpactComponent `json:"affected_components"`
	// ComponentCount is len(AffectedComponents), emitted for the same reason
	// as AffectedProjectCount.
	ComponentCount int `json:"component_count"`
}

// ImpactComponent is a single affected component coordinate.
type ImpactComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
}

// CVEImpactMeta carries the vulnerability-level metadata resolved from the
// global vulnerabilities cache (cve_id UNIQUE, RLS-exempt). A nil *CVEImpactMeta
// means the CVE is unknown, which the handler answers as 404 — distinct from a
// known CVE that simply affects no project (a valid 200 with an empty list).
type CVEImpactMeta struct {
	VulnerabilityID uuid.UUID
	Severity        string
	CVSSScore       float64
	EPSSScore       float64
	InKEV           bool
}
