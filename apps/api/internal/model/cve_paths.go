package model

import "github.com/google/uuid"

// CVEPathsResponse is the cross-project transitive dependency-path view for a
// single CVE within one tenant (M30-A / F402, issue #138). It is the
// on-demand fusion of M28's blast radius (which projects / components a CVE
// reaches) with M29's reverse reachability (how each vulnerable component is
// pulled in): for every affected project it carries, per affected component,
// the root → … → component entry paths computed against that project's LATEST
// SBOM.
//
// It is a superset of CVEImpact — the same cve_id / severity / cvss / epss /
// kev metadata and the same affected_project_count / total_project_count
// counters — grafted with M29's per-component path chains. Like CVEImpact it
// is a read-only aggregation with no new table and no new audit action; the
// per-SBOM traversal is computed on demand (no migration / ingest change /
// backfill in M30-lite). epss_score stays a fixed 0 until 006_epss lands,
// exactly as CVEImpact.
//
// Tenant isolation is structural and identical to CVEImpact: RLS is the
// authoritative boundary (braces) and every tenant-scoped join also carries
// an explicit tenant_id predicate (belt). project_id is crossed deliberately;
// tenant_id never is.
type CVEPathsResponse struct {
	CVEID     string  `json:"cve_id"`
	Severity  string  `json:"severity"`
	CVSSScore float64 `json:"cvss_score"`
	EPSSScore float64 `json:"epss_score"`
	InKEV     bool    `json:"in_kev"`
	// AffectedProjectCount is len(AffectedProjects); mirrors CVEImpact.
	AffectedProjectCount int `json:"affected_project_count"`
	// TotalProjectCount is the tenant's total project count (the "N of M"
	// denominator). Counts only this tenant's projects.
	TotalProjectCount int                    `json:"total_project_count"`
	AffectedProjects  []AffectedProjectPaths `json:"affected_projects"`
}

// AffectedProjectPaths is one project reached by the CVE, with per-component
// entry paths computed against the project's latest SBOM.
//
//   - SbomID / Format identify the SBOM actually traversed (the latest).
//   - Degraded is a PROJECT-level flag: the latest SBOM is SPDX / unknown /
//     unparseable, so it carries no dependency edges and no paths can be
//     computed (the frontend renders "dependency edges unavailable").
type AffectedProjectPaths struct {
	ProjectID          uuid.UUID                `json:"project_id"`
	ProjectName        string                   `json:"project_name"`
	SbomID             uuid.UUID                `json:"sbom_id"`
	Format             string                   `json:"format"`
	Degraded           bool                     `json:"degraded"`
	ComponentCount     int                      `json:"component_count"`
	AffectedComponents []AffectedComponentPaths `json:"affected_components"`
}

// AffectedComponentPaths is a single affected component coordinate plus its
// reverse-reachability answer against the project's latest SBOM.
//
//   - InGraph is a COMPONENT-level flag: the component's (version-stripped)
//     match key exists in the latest SBOM's dependency graph. It is false
//     when the component is affected only in an OLDER snapshot and absent
//     from the latest — a genuine "not in your current SBOM" answer, with
//     empty paths (not an error).
//   - IsDirect / Truncated / PathCount / Paths mirror M29's PathsResponse.
//     Truncated propagates the M29 path-cap / step-budget hit (silent
//     truncation is forbidden). PathCount == len(Paths) (paths RETURNED).
type AffectedComponentPaths struct {
	Name      string       `json:"name"`
	Version   string       `json:"version"`
	Purl      string       `json:"purl"`
	InGraph   bool         `json:"in_graph"`
	IsDirect  bool         `json:"is_direct"`
	Truncated bool         `json:"truncated"`
	PathCount int          `json:"path_count"`
	Paths     [][]PathNode `json:"paths"`
}

// PathNode is one node in a root → … → component entry path. It mirrors the
// diff package's GraphNode shape (id = version-stripped match key, plus the
// real name / version / type) but lives in model so CVEPathsResponse has no
// import dependency on the diff package (which itself imports model — a model
// → diff import would be a cycle). The service maps each diff.GraphNode into
// a PathNode when assembling the response.
type PathNode struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// CVEAffectedProject is the tenant-scoped resolution DTO returned by
// SearchRepository.AggregateCVEAffectedComponents: one project reached by the
// CVE and the affected components in it (name / version / purl / type — the
// four fields the diff match key needs). It is the internal input the paths
// service groups and traverses; it is NOT serialised (no JSON tags) — the
// wire shape is AffectedProjectPaths above.
type CVEAffectedProject struct {
	ProjectID   uuid.UUID
	ProjectName string
	Components  []Component
}
