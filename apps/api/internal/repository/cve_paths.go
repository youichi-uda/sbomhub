package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// cvePathsRow is one (project, component) tuple returned by the affected
// resolution before grouping. Kept unexported so the pure grouping step
// (groupCVEAffectedRows) is unit-testable without a database.
type cvePathsRow struct {
	ProjectID   uuid.UUID
	ProjectName string
	Component   model.Component
}

// AggregateCVEAffectedComponents returns every project of tenantID whose
// components carry the vulnerability vulnID, grouped per project, with each
// affected component's name / version / purl / type — the resolution the
// M30-A cross-project transitive-path view (F402, issue #138) traverses.
//
// It is the paths-view sibling of AggregateCVEImpact (M28-A / F388): SAME
// tenant boundary (belt + braces), SAME multi-snapshot DISTINCT dedup, but it
// additionally selects c.type (the diff match key falls back to name|type
// when purl is absent) and returns the richer model.Component so the caller
// can compute each component's graph node key. AggregateCVEImpact is left
// UNCHANGED — this is a new query, not a mutation of the M28 one.
//
// Tenant isolation is double-guarded exactly as AggregateCVEImpact:
//   - braces: projects / sboms / components are FORCE ROW LEVEL SECURITY, so
//     the caller MUST run inside a TenantTx (SET LOCAL app.current_tenant_id)
//     — the authoritative boundary that hides a foreign tenant's rows
//     regardless of the WHERE clause.
//   - belt: every tenant-scoped join carries an explicit tenant_id = $1, so
//     the boundary survives even if RLS were disabled (defence in depth).
//     project_id is crossed; tenant_id never is. component_vulnerabilities has
//     no tenant_id column (a global join table); its rows are constrained
//     transitively via the tenant-pinned components it joins to.
//
// Multi-snapshot dedup (F390 parity): a project can hold several SBOM
// snapshots; the SELECT DISTINCT on the logical component identity (project,
// name, version, purl, type) collapses the duplicate rows a shared component
// produces across snapshots so component_count is not inflated. The affected
// set spans ALL snapshots (matching AggregateCVEImpact / SearchByCVE); the
// paths are later traversed against only the LATEST SBOM, so a component
// affected only in an older snapshot still appears here but resolves to
// in_graph=false with empty paths (the honest current-exposure semantics).
func (r *SearchRepository) AggregateCVEAffectedComponents(ctx context.Context, tenantID, vulnID uuid.UUID) ([]model.CVEAffectedProject, error) {
	const query = `
		SELECT DISTINCT
			p.id                    AS project_id,
			p.name                  AS project_name,
			c.name                  AS component_name,
			COALESCE(c.version, '') AS component_version,
			COALESCE(c.purl, '')    AS component_purl,
			COALESCE(c.type, '')    AS component_type
		FROM projects p
		INNER JOIN sboms s
			ON s.project_id = p.id
		   AND s.tenant_id = $1
		INNER JOIN components c
			ON c.sbom_id = s.id
		   AND c.tenant_id = $1
		INNER JOIN component_vulnerabilities cv
			ON cv.component_id = c.id
		WHERE cv.vulnerability_id = $2
		  AND p.tenant_id = $1
		ORDER BY p.name, c.name, COALESCE(c.version, '')
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, vulnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scanned := make([]cvePathsRow, 0)
	for rows.Next() {
		var row cvePathsRow
		if err := rows.Scan(
			&row.ProjectID,
			&row.ProjectName,
			&row.Component.Name,
			&row.Component.Version,
			&row.Component.Purl,
			&row.Component.Type,
		); err != nil {
			return nil, err
		}
		scanned = append(scanned, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groupCVEAffectedRows(scanned), nil
}

// groupCVEAffectedRows folds the flat (project, component) rows into one
// CVEAffectedProject per project, preserving the query's first-seen order
// (ORDER BY p.name). Pure and side-effect-free so the rollup is unit-testable
// without a live database.
func groupCVEAffectedRows(rows []cvePathsRow) []model.CVEAffectedProject {
	order := make([]uuid.UUID, 0)
	byID := make(map[uuid.UUID]*model.CVEAffectedProject)
	for _, row := range rows {
		proj, ok := byID[row.ProjectID]
		if !ok {
			proj = &model.CVEAffectedProject{
				ProjectID:   row.ProjectID,
				ProjectName: row.ProjectName,
				Components:  make([]model.Component, 0),
			}
			byID[row.ProjectID] = proj
			order = append(order, row.ProjectID)
		}
		proj.Components = append(proj.Components, row.Component)
	}

	out := make([]model.CVEAffectedProject, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}
