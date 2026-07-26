package repository

import (
	"context"
	"database/sql"
	"strings"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type SearchRepository struct {
	db *sql.DB
}

func NewSearchRepository(db *sql.DB) *SearchRepository {
	return &SearchRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
// Every search query below joins projects/sboms/components, all of which
// enforce RLS — without the tenant GUC set by TenantTx, results collapse to
// zero rows for callers using the sbomhub_app role (codex-r1 Finding 2).
func (r *SearchRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// SearchByCVE searches for all projects affected by a specific CVE
func (r *SearchRepository) SearchByCVE(ctx context.Context, cveID string) (*model.CVESearchResult, error) {
	// First, get the vulnerability info.
	// M36-A / F432: epss_score is now in the canonical migration chain
	// (055_vulnerabilities_epss), so this reads the real column instead of the
	// old 0::numeric sentinel. COALESCE(epss_score, 0) keeps it NULL-safe (the
	// column stays NULL until the scheduled epss_sync populates it, and scanning
	// a SQL NULL into the bare float64 CVESearchResult.EPSSScore would error);
	// the COALESCE holds the SAME 5th position in the positional SELECT, so the
	// Scan target order below is unchanged.
	// M46 B2: description/severity are DDL-nullable and COALESCE'd to ''
	// (NVD "Awaiting Analysis" rows are real); cvss_score scans into the
	// *float64 CVESearchResult.CVSSScore — no 0-sentinel, un-scored stays
	// nil (CVSS 0.0 is a real "None" score).
	vulnQuery := `
		SELECT id, cve_id, COALESCE(description, ''), cvss_score, COALESCE(epss_score, 0), COALESCE(severity, '')
		FROM vulnerabilities
		WHERE cve_id = $1
		LIMIT 1
	`
	var vulnID uuid.UUID
	var result model.CVESearchResult
	err := r.q(ctx).QueryRowContext(ctx, vulnQuery, cveID).Scan(
		&vulnID,
		&result.CVEID,
		&result.Description,
		&result.CVSSScore,
		&result.EPSSScore,
		&result.Severity,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Get affected projects and components
	// M46 B2: c.version is DDL-nullable — COALESCE'd to ''.
	affectedQuery := `
		SELECT
			p.id as project_id,
			p.name as project_name,
			c.id as component_id,
			c.name as component_name,
			COALESCE(c.version, '') as component_version
		FROM projects p
		INNER JOIN sboms s ON p.id = s.project_id
		INNER JOIN components c ON s.id = c.sbom_id
		INNER JOIN component_vulnerabilities cv ON c.id = cv.component_id
		WHERE cv.vulnerability_id = $1
		ORDER BY p.name, c.name
	`

	rows, err := r.q(ctx).QueryContext(ctx, affectedQuery, vulnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	projectMap := make(map[uuid.UUID]*model.AffectedProject)
	for rows.Next() {
		var projectID uuid.UUID
		var projectName string
		var comp model.AffectedComponent

		if err := rows.Scan(&projectID, &projectName, &comp.ID, &comp.Name, &comp.Version); err != nil {
			return nil, err
		}

		if _, exists := projectMap[projectID]; !exists {
			projectMap[projectID] = &model.AffectedProject{
				ProjectID:          projectID,
				ProjectName:        projectName,
				AffectedComponents: []model.AffectedComponent{},
			}
		}
		projectMap[projectID].AffectedComponents = append(projectMap[projectID].AffectedComponents, comp)
	}

	result.AffectedProjects = make([]model.AffectedProject, 0, len(projectMap))
	for _, project := range projectMap {
		result.AffectedProjects = append(result.AffectedProjects, *project)
	}

	// Get unaffected projects
	unaffectedQuery := `
		SELECT p.id, p.name
		FROM projects p
		WHERE p.id NOT IN (
			SELECT DISTINCT s.project_id
			FROM sboms s
			INNER JOIN components c ON s.id = c.sbom_id
			INNER JOIN component_vulnerabilities cv ON c.id = cv.component_id
			WHERE cv.vulnerability_id = $1
		)
		ORDER BY p.name
	`

	unaffectedRows, err := r.q(ctx).QueryContext(ctx, unaffectedQuery, vulnID)
	if err != nil {
		return nil, err
	}
	defer unaffectedRows.Close()

	result.UnaffectedProjects = []model.UnaffectedProject{}
	for unaffectedRows.Next() {
		var project model.UnaffectedProject
		if err := unaffectedRows.Scan(&project.ProjectID, &project.ProjectName); err != nil {
			return nil, err
		}
		result.UnaffectedProjects = append(result.UnaffectedProjects, project)
	}

	return &result, nil
}

// SearchByComponent searches for components by name and optional version constraint
func (r *SearchRepository) SearchByComponent(ctx context.Context, name string, versionConstraint string) (*model.ComponentSearchResult, error) {
	result := &model.ComponentSearchResult{
		Query: model.ComponentSearchQuery{
			Name:              name,
			VersionConstraint: versionConstraint,
		},
		Matches: []model.ComponentSearchMatch{},
	}

	// Search for components by name (case-insensitive partial match)
	// M46 B2: c.version is DDL-nullable — COALESCE'd to '' like license.
	query := `
		SELECT
			p.id as project_id,
			p.name as project_name,
			c.id as component_id,
			c.name as component_name,
			COALESCE(c.version, '') as component_version,
			COALESCE(c.license, '') as license
		FROM components c
		INNER JOIN sboms s ON c.sbom_id = s.id
		INNER JOIN projects p ON s.project_id = p.id
		WHERE LOWER(c.name) LIKE LOWER($1)
		ORDER BY p.name, c.name, c.version
	`

	searchPattern := "%" + name + "%"
	rows, err := r.q(ctx).QueryContext(ctx, query, searchPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// M46 B2: materialize the matches BEFORE fetching their
	// vulnerabilities. Under the request's TenantTx everything shares one
	// connection, and lib/pq cannot run getComponentVulnerabilities while
	// this result set is still open — the nested query de-syncs the
	// protocol ("pq: unexpected Parse response 'D'") and poisons the tx.
	// (Previously masked: a NULL component version aborted the scan first.)
	for rows.Next() {
		var match model.ComponentSearchMatch
		if err := rows.Scan(
			&match.ProjectID,
			&match.ProjectName,
			&match.Component.ID,
			&match.Component.Name,
			&match.Component.Version,
			&match.Component.License,
		); err != nil {
			return nil, err
		}

		// Apply version constraint if specified
		if versionConstraint != "" && !matchesVersionConstraint(match.Component.Version, versionConstraint) {
			continue
		}

		result.Matches = append(result.Matches, match)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	// Get vulnerabilities for each match now that the connection is free.
	for i := range result.Matches {
		vulns, err := r.getComponentVulnerabilities(ctx, result.Matches[i].Component.ID)
		if err != nil {
			return nil, err
		}
		result.Matches[i].Vulnerabilities = vulns
	}

	return result, nil
}

func (r *SearchRepository) getComponentVulnerabilities(ctx context.Context, componentID uuid.UUID) ([]model.Vulnerability, error) {
	// M36-A / F432: epss_score/epss_percentile are now in the canonical migration
	// chain (055_vulnerabilities_epss), so this reads the real columns instead of
	// the old 0::numeric sentinels. COALESCE(v.epss_score, 0) /
	// COALESCE(v.epss_percentile, 0) keep it NULL-safe (both columns stay NULL
	// until the scheduled epss_sync populates them, and scanning a SQL NULL into
	// the bare float64 locals below would error). They hold the SAME 6th/7th
	// positions in the positional SELECT, so the Scan target order is unchanged;
	// the `> 0` guard below still leaves the model pointers nil for an un-synced
	// (COALESCE-0) row, preserving the web >0 EPSS-badge suppression (F391).
	// M46 B2: description/severity COALESCE'd to '', source to 'NVD'
	// (this repo's existing convention); cvss_score/published_at/
	// updated_at scan into the model's pointer fields. NULLS LAST keeps
	// un-scored rows at the tail (Postgres defaults DESC to NULLS FIRST).
	query := `
		SELECT v.id, v.cve_id, COALESCE(v.description, ''), COALESCE(v.severity, ''), v.cvss_score,
		       COALESCE(v.epss_score, 0), COALESCE(v.epss_percentile, 0),
		       COALESCE(v.source, 'NVD'), v.published_at, v.updated_at
		FROM vulnerabilities v
		INNER JOIN component_vulnerabilities cv ON v.id = cv.vulnerability_id
		WHERE cv.component_id = $1
		ORDER BY v.cvss_score DESC NULLS LAST
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, componentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		var epssScore, epssPercentile float64
		if err := rows.Scan(
			&v.ID, &v.CVEID, &v.Description, &v.Severity, &v.CVSSScore,
			&epssScore, &epssPercentile,
			&v.Source, &v.PublishedAt, &v.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if epssScore > 0 {
			v.EPSSScore = &epssScore
		}
		if epssPercentile > 0 {
			v.EPSSPercentile = &epssPercentile
		}
		vulns = append(vulns, v)
	}

	if vulns == nil {
		vulns = []model.Vulnerability{}
	}
	return vulns, rows.Err()
}

// matchesVersionConstraint checks if a version matches a simple constraint
// Supports: <X.Y.Z, >X.Y.Z, =X.Y.Z, <=X.Y.Z, >=X.Y.Z
func matchesVersionConstraint(version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return true
	}

	var op string
	var targetVersion string

	if strings.HasPrefix(constraint, "<=") {
		op = "<="
		targetVersion = strings.TrimPrefix(constraint, "<=")
	} else if strings.HasPrefix(constraint, ">=") {
		op = ">="
		targetVersion = strings.TrimPrefix(constraint, ">=")
	} else if strings.HasPrefix(constraint, "<") {
		op = "<"
		targetVersion = strings.TrimPrefix(constraint, "<")
	} else if strings.HasPrefix(constraint, ">") {
		op = ">"
		targetVersion = strings.TrimPrefix(constraint, ">")
	} else if strings.HasPrefix(constraint, "=") {
		op = "="
		targetVersion = strings.TrimPrefix(constraint, "=")
	} else {
		// Default to exact match
		op = "="
		targetVersion = constraint
	}

	targetVersion = strings.TrimSpace(targetVersion)
	cmp := compareVersions(version, targetVersion)

	switch op {
	case "<":
		return cmp < 0
	case ">":
		return cmp > 0
	case "<=":
		return cmp <= 0
	case ">=":
		return cmp >= 0
	case "=":
		return cmp == 0
	}
	return false
}

// compareVersions compares two semver-like version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 string
		if i < len(parts1) {
			p1 = parts1[i]
		} else {
			p1 = "0"
		}
		if i < len(parts2) {
			p2 = parts2[i]
		} else {
			p2 = "0"
		}

		// Extract numeric prefix
		n1 := extractNumeric(p1)
		n2 := extractNumeric(p2)

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}

func extractNumeric(s string) int {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}
