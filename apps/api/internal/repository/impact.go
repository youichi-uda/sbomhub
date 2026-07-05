package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// GetVulnerabilityImpactMeta resolves the vulnerability-level metadata used by
// the cross-project blast-radius view (M28-A / F388, issue #134): severity,
// CVSS, EPSS and the KEV flag, plus the internal id used to fan the
// aggregation.
//
// The vulnerabilities table is a global NVD/JVN cache — cve_id is UNIQUE and
// the table is RLS-exempt (no FORCE ROW LEVEL SECURITY) — so this query is
// intentionally NOT tenant-scoped: a CVE's severity/CVSS/KEV is identical for
// every tenant. It returns (nil, nil) when the CVE is unknown so the caller can
// answer 404, keeping "unknown CVE" distinct from "known CVE, zero affected
// projects" (a valid 200 with an empty list).
//
// EPSS note (M36-A / F432): epss_score is now part of the canonical apps/api
// migration chain (055_vulnerabilities_epss promotes the orphan packages/db
// 006_epss.sql), so — exactly like SearchByCVE and
// DashboardRepository.GetTopRisksByTenant — this reads the real column instead
// of the old fixed 0::numeric sentinel. It reads it NULL-safely with
// COALESCE(epss_score, 0): the column is nullable and stays NULL until the
// scheduled epss_sync (M36-B) populates it, and scanning a SQL NULL into the
// bare float64 CVEImpactMeta.EPSSScore would error (there is no ErrNoRows
// fallback for a KNOWN CVE, so it would 500). COALESCE reproduces the old
// sentinel-0 exactly for an un-synced row, and the web blast-radius summary
// still treats epss_score = 0 as "n/a" and suppresses the EPSS badge (F391) so
// a KEV/critical CVE never shows a misleading "EPSS 0.0%".
//
// Nullable-metadata note (F394): vulnerabilities.severity (VARCHAR(20)) and
// cvss_score (DECIMAL(3,1)) are both NULLABLE — 001_init declares neither NOT
// NULL, and real NVD/JVN rows do arrive with a missing CVSS (e.g. a CVE awaiting
// analysis). Scanning a SQL NULL straight into a Go string / float64 fails, so
// without a guard a KNOWN CVE with null metadata would error and 500 — worse, it
// would never reach the sql.ErrNoRows path, collapsing the "unknown CVE -> 404"
// vs "known CVE, null meta" distinction. We COALESCE at the query: severity
// defaults to 'UNKNOWN' (UPPERCASE, matching the dashboard's CRITICAL/HIGH/...
// convention and rendering as a graceful gray badge in the web SeverityBadge,
// which lowercases and falls back to gray for unknown keys) and cvss_score to 0.
// in_kev is BOOLEAN NOT NULL DEFAULT false (migration 020) so it needs no guard.
func (r *SearchRepository) GetVulnerabilityImpactMeta(ctx context.Context, cveID string) (*model.CVEImpactMeta, error) {
	const query = `
		SELECT
			id,
			COALESCE(severity, 'UNKNOWN') AS severity,
			COALESCE(cvss_score, 0)       AS cvss_score,
			COALESCE(epss_score, 0)       AS epss_score,
			in_kev
		FROM vulnerabilities
		WHERE cve_id = $1
		LIMIT 1
	`
	var m model.CVEImpactMeta
	err := r.q(ctx).QueryRowContext(ctx, query, cveID).Scan(
		&m.VulnerabilityID, &m.Severity, &m.CVSSScore, &m.EPSSScore, &m.InKEV,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// impactRow is one (project, component) tuple returned by the aggregation
// before grouping. Kept unexported so the pure grouping step (groupImpactRows)
// is unit-testable without a database.
type impactRow struct {
	ProjectID   uuid.UUID
	ProjectName string
	Component   model.ImpactComponent
}

// AggregateCVEImpact returns every project of tenantID whose components carry
// the vulnerability vulnID, with those components (name/version/purl) grouped
// per project — the cross-project blast radius (M28-A / F388, issue #134).
//
// This is the belt-and-braces, tenant-scoped, purl-carrying sibling of
// SearchRepository.SearchByCVE's affectedQuery. SearchByCVE serves the existing
// single-CVE search page and relies on RLS alone (the braces) with no explicit
// tenant predicate; the blast-radius view crosses project_id deliberately, so
// it additionally pins tenant_id = $1 on projects, sboms and components (the
// belt) exactly as vex_aggregation.ListCrossProjectVEXCandidates does.
// project_id is crossed; tenant_id never is. component_vulnerabilities has no
// tenant_id column (a global join table); its rows are constrained transitively
// via the tenant-pinned components it joins to.
//
// Tenant isolation is therefore double-guarded:
//   - braces: projects / sboms / components are FORCE ROW LEVEL SECURITY
//     (migrations 023 / 042). The caller MUST run inside a TenantTx
//     (SET LOCAL app.current_tenant_id) so a foreign tenant's rows are
//     invisible regardless of the WHERE clause. This is the authoritative
//     boundary.
//   - belt: every tenant-scoped join carries an explicit tenant_id = $1, so the
//     boundary survives even if RLS were ever disabled (defence in depth). This
//     is the predicate the M28 tenant-isolation mutation removes to prove the
//     belt is load-bearing under a BYPASSRLS role.
//
// Snapshot de-duplication (M28-D / F390): a project can hold multiple SBOM
// uploads (SbomRepository keeps every snapshot; ListByProject returns them all,
// GetLatest is only used where a single "current" SBOM is needed). SBOMHub's
// cross-project / per-project vulnerability aggregations deliberately span ALL
// of a project's snapshots and DISTINCT away the duplicates a shared component
// produces across them — ListByProject (SELECT DISTINCT v.id),
// CountBySeverity (COUNT(DISTINCT v.id)) and DashboardRepository
// .GetTopRisksByTenant (DISTINCT ON (v.cve_id)) all do this. The blast-radius
// view MUST match that convention: it is rendered on the search page directly
// above SearchByCVE's affected/unaffected listing (which is also all-snapshots,
// project-deduped), so a latest-SBOM-only filter here would make the summary's
// "N of M" disagree with the listing right below it. We therefore aggregate over
// every snapshot and SELECT DISTINCT on the logical component identity
// (project, name, version, purl) — without it, the same logical component
// carried by two snapshots of one project inflates component_count (measured 2
// for a 2-snapshot project in R1). affected_project_count is unaffected (the
// grouping already dedups per project); this only corrects component_count /
// affected_components. A "remediated in the latest snapshot but present in an
// older one" project still surfaces — that is intentional and matches
// SearchByCVE and the dashboard, which likewise reflect all snapshots; changing
// it is a separate, whole-app convention decision, not an impact-only tweak.
func (r *SearchRepository) AggregateCVEImpact(ctx context.Context, tenantID, vulnID uuid.UUID) ([]model.ImpactProject, error) {
	const query = `
		SELECT DISTINCT
			p.id                    AS project_id,
			p.name                  AS project_name,
			c.name                  AS component_name,
			COALESCE(c.version, '') AS component_version,
			COALESCE(c.purl, '')    AS component_purl
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

	scanned := make([]impactRow, 0)
	for rows.Next() {
		var row impactRow
		if err := rows.Scan(
			&row.ProjectID,
			&row.ProjectName,
			&row.Component.Name,
			&row.Component.Version,
			&row.Component.Purl,
		); err != nil {
			return nil, err
		}
		scanned = append(scanned, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groupImpactRows(scanned), nil
}

// groupImpactRows folds the flat (project, component) rows into one
// ImpactProject per project — preserving the query's first-seen order
// (ORDER BY p.name) and stamping ComponentCount. Pure and side-effect-free so
// the rollup is unit-testable without a live database.
func groupImpactRows(rows []impactRow) []model.ImpactProject {
	order := make([]uuid.UUID, 0)
	byID := make(map[uuid.UUID]*model.ImpactProject)
	for _, row := range rows {
		proj, ok := byID[row.ProjectID]
		if !ok {
			proj = &model.ImpactProject{
				ProjectID:          row.ProjectID,
				ProjectName:        row.ProjectName,
				AffectedComponents: []model.ImpactComponent{},
			}
			byID[row.ProjectID] = proj
			order = append(order, row.ProjectID)
		}
		proj.AffectedComponents = append(proj.AffectedComponents, row.Component)
	}

	out := make([]model.ImpactProject, 0, len(order))
	for _, id := range order {
		proj := byID[id]
		proj.ComponentCount = len(proj.AffectedComponents)
		out = append(out, *proj)
	}
	return out
}

// CountProjectsByTenant returns the tenant's total project count — the
// denominator M in "N of M projects affected". Belt: an explicit
// WHERE tenant_id = $1 on top of the projects RLS braces; deliberately
// independent of any CVE so the denominator never depends on match state.
func (r *SearchRepository) CountProjectsByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := r.q(ctx).QueryRowContext(ctx,
		`SELECT COUNT(*) FROM projects WHERE tenant_id = $1`, tenantID).Scan(&n)
	return n, err
}
