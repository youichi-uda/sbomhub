package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ListCrossProjectVEXCandidates returns approved VEX statements from OTHER
// projects of the SAME tenant that match a vulnerability affecting the
// target project's components (M26-A / F375, issue #130).
//
// This is the cross-project sibling of ComponentRepository.ListIDsByVulnerability
// (component.go): that method fans a single vulnerability across the
// components of ONE project (JOIN sboms WHERE tenant_id AND project_id);
// this method deliberately drops the source-side project_id constraint so
// a judgement made in project A can be surfaced to project B — but it keeps
// the tenant_id constraint on every join so the horizon stays inside a
// single tenant.
//
// Tenant isolation, structurally (belt AND braces):
//   - braces: every tenant-scoped table on the read path (components,
//     sboms, vex_statements, projects) is under FORCE ROW LEVEL SECURITY
//     with a tenant_isolation_* policy (migrations 023 / 027). Callers MUST
//     invoke this from inside a TenantTx so SET LOCAL app.current_tenant_id
//     is bound; the policy then makes a foreign tenant's rows invisible
//     regardless of the WHERE clause. This is the authoritative boundary.
//   - belt: every join also carries an explicit `... .tenant_id = $1`
//     predicate. project_id is crossed on the source side; tenant_id never
//     is. component_vulnerabilities has no tenant_id column (it is a global
//     join table), so its rows are constrained transitively via the
//     tenant-scoped components / sboms it joins to.
//
// The method does NOT apply the self-project or already-triaged exclusion
// as a WHERE filter — instead it emits the source project_id and a
// target_already_triaged flag so VEXService.assembleSuggestions can apply
// those business rules in unit-testable Go. Self-project statements are
// therefore intentionally returned here and dropped one layer up.
func (r *VEXRepository) ListCrossProjectVEXCandidates(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.VEXSuggestionCandidate, error) {
	const query = `
		SELECT
			ta.vulnerability_id,
			v.cve_id,
			ta.component_id,
			ta.component_name,
			ta.component_version,
			ta.component_purl,
			vs.project_id                     AS source_project_id,
			sp.name                           AS source_project_name,
			vs.component_id                   AS source_component_id,
			vs.id                             AS statement_id,
			vs.status,
			COALESCE(vs.justification, '')    AS justification,
			COALESCE(vs.impact_statement, '') AS impact_statement,
			COALESCE(vs.action_statement, '') AS action_statement,
			vs.created_at,
			EXISTS (
				SELECT 1
				FROM vex_statements ex
				WHERE ex.tenant_id = $1
				  AND ex.project_id = $2
				  AND ex.vulnerability_id = ta.vulnerability_id
				  AND (ex.component_id = ta.component_id OR ex.component_id IS NULL)
			) AS target_already_triaged
		FROM (
			SELECT DISTINCT
				cv.vulnerability_id,
				c.id                    AS component_id,
				c.name                  AS component_name,
				COALESCE(c.version, '') AS component_version,
				COALESCE(c.purl, '')    AS component_purl
			FROM component_vulnerabilities cv
			JOIN components c ON c.id = cv.component_id
			JOIN sboms s ON s.id = c.sbom_id
			WHERE s.tenant_id = $1 AND s.project_id = $2
		) ta
		JOIN vulnerabilities v ON v.id = ta.vulnerability_id
		JOIN vex_statements vs
			ON vs.vulnerability_id = ta.vulnerability_id
		   AND vs.tenant_id = $1
		LEFT JOIN components sc
			ON sc.id = vs.component_id
		   AND sc.tenant_id = $1
		JOIN projects sp
			ON sp.id = vs.project_id
		   AND sp.tenant_id = $1
		WHERE (
			-- purl match: source is component-specific and its component's
			-- purl equals the target component's purl. Empty purls never
			-- match (a component with no coordinate must not collapse onto
			-- every other coordinate-less component).
			(vs.component_id IS NOT NULL AND sc.purl IS NOT NULL AND sc.purl <> '' AND sc.purl = ta.component_purl)
			OR
			-- vulnerability_only match: source is component-agnostic.
			(vs.component_id IS NULL)
		)
		ORDER BY v.cve_id, ta.component_name, ta.component_version, vs.created_at DESC, vs.id
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.VEXSuggestionCandidate, 0)
	for rows.Next() {
		var c model.VEXSuggestionCandidate
		if err := rows.Scan(
			&c.VulnerabilityID,
			&c.CVEID,
			&c.TargetComponentID,
			&c.ComponentName,
			&c.ComponentVersion,
			&c.ComponentPurl,
			&c.SourceProjectID,
			&c.SourceProjectName,
			&c.SourceComponentID,
			&c.StatementID,
			&c.Status,
			&c.Justification,
			&c.ImpactStatement,
			&c.ActionStatement,
			&c.CreatedAt,
			&c.TargetAlreadyTriaged,
		); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
