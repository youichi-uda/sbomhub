package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type ComponentRepository struct {
	db *sql.DB
}

func NewComponentRepository(db *sql.DB) *ComponentRepository {
	return &ComponentRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
func (r *ComponentRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Create inserts a new component row.
//
// tenant_id is required because:
//   - the column is NOT NULL since migration 027, and
//   - FORCE ROW LEVEL SECURITY on `components` enforces a WITH CHECK clause
//     that rejects mismatched tenant_id at INSERT time.
//
// Callers must populate c.TenantID before calling Create. The typical flow
// is `comp.TenantID = sbom.TenantID` inside SbomService.Import /
// CLIService.UploadSBOM, since every component is scoped to a single SBOM.
func (r *ComponentRepository) Create(ctx context.Context, c *model.Component) error {
	query := `INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.q(ctx).ExecContext(ctx, query, c.ID, c.TenantID, c.SbomID, c.Name, c.Version, c.Type, c.Purl, c.License, c.CreatedAt)
	return err
}

func (r *ComponentRepository) ListBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.Component, error) {
	query := `SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE sbom_id = $1 ORDER BY name`
	rows, err := r.q(ctx).QueryContext(ctx, query, sbomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var components []model.Component
	for rows.Next() {
		var c model.Component
		if err := rows.Scan(&c.ID, &c.SbomID, &c.Name, &c.Version, &c.Type, &c.Purl, &c.License, &c.CreatedAt); err != nil {
			return nil, err
		}
		components = append(components, c)
	}
	return components, nil
}

func (r *ComponentRepository) GetVulnerabilities(ctx context.Context, sbomID uuid.UUID) ([]model.Vulnerability, error) {
	query := `
		SELECT v.id, v.cve_id, v.description, v.severity, v.cvss_score, COALESCE(v.source, 'NVD'),
		       v.in_kev, v.kev_date_added, v.kev_due_date, v.kev_ransomware_use,
		       v.published_at, v.updated_at
		FROM vulnerabilities v
		JOIN component_vulnerabilities cv ON cv.vulnerability_id = v.id
		JOIN components c ON c.id = cv.component_id
		WHERE c.sbom_id = $1
		ORDER BY v.cvss_score DESC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, sbomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		if err := rows.Scan(&v.ID, &v.CVEID, &v.Description, &v.Severity, &v.CVSSScore, &v.Source,
			&v.InKEV, &v.KEVDateAdded, &v.KEVDueDate, &v.KEVRansomwareUse,
			&v.PublishedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// GetVulnerabilitiesPaginated mirrors GetVulnerabilities but pages the
// result via SQL LIMIT/OFFSET. M1 Codex review #F26: the F20 fix
// exposed GET /api/v1/projects/:id/vulnerabilities to read-scoped API
// keys, but the handler returned the entire matched-vulns slice
// without any pagination — a single API-key request against a project
// with thousands of matches forced the server to scan + marshal +
// transmit the whole set, and the CLI then io.ReadAll'd the whole
// response body before unmarshalling. A read-only API key could
// therefore mount a cheap DoS by repeatedly hitting that route.
//
// Semantics:
//   - limit <= 0 falls back to no LIMIT (caller responsibility); the
//     handler clamps to MaxListLimit before calling this method, so the
//     "no LIMIT" path is reserved for internal aggregators (which we
//     currently do not have — every external call site clamps).
//   - offset < 0 is normalised to 0.
//
// Order is preserved (cvss_score DESC) so a consistent pagination
// cursor walks the most-severe vulns first; offset is stable across
// calls assuming the underlying join does not change between pages.
func (r *ComponentRepository) GetVulnerabilitiesPaginated(ctx context.Context, sbomID uuid.UUID, limit, offset int) ([]model.Vulnerability, error) {
	if offset < 0 {
		offset = 0
	}
	// We always emit ORDER BY + LIMIT/OFFSET when limit > 0; when limit <=
	// 0 fall through to the unpaginated query so internal aggregators
	// (e.g. scan-status severity counts) can opt out explicitly.
	if limit <= 0 {
		return r.GetVulnerabilities(ctx, sbomID)
	}
	const query = `
		SELECT v.id, v.cve_id, v.description, v.severity, v.cvss_score, COALESCE(v.source, 'NVD'),
		       v.in_kev, v.kev_date_added, v.kev_due_date, v.kev_ransomware_use,
		       v.published_at, v.updated_at
		FROM vulnerabilities v
		JOIN component_vulnerabilities cv ON cv.vulnerability_id = v.id
		JOIN components c ON c.id = cv.component_id
		WHERE c.sbom_id = $1
		ORDER BY v.cvss_score DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, sbomID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		if err := rows.Scan(&v.ID, &v.CVEID, &v.Description, &v.Severity, &v.CVSSScore, &v.Source,
			&v.InKEV, &v.KEVDateAdded, &v.KEVDueDate, &v.KEVRansomwareUse,
			&v.PublishedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

func (r *ComponentRepository) ListComponentVulnerabilitiesBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.ComponentVulnerability, error) {
	query := `
		SELECT c.id, c.name, c.version, c.purl, c.license, v.cve_id, v.severity
		FROM components c
		JOIN component_vulnerabilities cv ON cv.component_id = c.id
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE c.sbom_id = $1
		ORDER BY v.cvss_score DESC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, sbomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.ComponentVulnerability
	for rows.Next() {
		var item model.ComponentVulnerability
		if err := rows.Scan(
			&item.ComponentID,
			&item.ComponentName,
			&item.ComponentVersion,
			&item.ComponentPurl,
			&item.ComponentLicense,
			&item.CVEID,
			&item.Severity,
		); err != nil {
			return nil, err
		}
		results = append(results, item)
	}
	return results, nil
}

// GetByID retrieves a component by its UUID
func (r *ComponentRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Component, error) {
	query := `SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE id = $1`
	var c model.Component
	err := r.q(ctx).QueryRowContext(ctx, query, id).Scan(&c.ID, &c.SbomID, &c.Name, &c.Version, &c.Type, &c.Purl, &c.License, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListIDsByVulnerability returns the distinct component IDs in (tenant, project)
// scope that are linked to the given vulnerability via component_vulnerabilities.
//
// component_vulnerabilities is a global join table with no tenant_id column,
// so tenant scoping is enforced via:
//   - the explicit s.tenant_id = $1 / s.project_id = $2 predicates (belt),
//   - and the RLS policy on `sboms` / `components` activated by the surrounding
//     TenantTx middleware (braces). Callers MUST invoke this from inside a
//     TenantTx so SET LOCAL app.current_tenant_id is bound.
//
// Used by triage.Runner (M1 Codex review #F3) to fan out a single triage
// request across every (component, vuln) pair affected in the project. A
// zero-length slice means "vulnerability does not affect any component in
// this tenant's scope" — the runner translates that to a 404.
func (r *ComponentRepository) ListIDsByVulnerability(ctx context.Context, tenantID, projectID, vulnID uuid.UUID) ([]uuid.UUID, error) {
	const query = `
		SELECT DISTINCT cv.component_id
		FROM component_vulnerabilities cv
		JOIN components c ON c.id = cv.component_id
		JOIN sboms s ON s.id = c.sbom_id
		WHERE s.tenant_id = $1 AND s.project_id = $2 AND cv.vulnerability_id = $3
		ORDER BY cv.component_id
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, projectID, vulnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
