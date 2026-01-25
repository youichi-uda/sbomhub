package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type ComponentRepository struct {
	db *sql.DB
}

func NewComponentRepository(db *sql.DB) *ComponentRepository {
	return &ComponentRepository{db: db}
}

func (r *ComponentRepository) Create(ctx context.Context, c *model.Component) error {
	query := `INSERT INTO components (id, sbom_id, name, version, type, purl, license, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.db.ExecContext(ctx, query, c.ID, c.SbomID, c.Name, c.Version, c.Type, c.Purl, c.License, c.CreatedAt)
	return err
}

func (r *ComponentRepository) ListBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.Component, error) {
	query := `SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE sbom_id = $1 ORDER BY name`
	rows, err := r.db.QueryContext(ctx, query, sbomID)
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
		SELECT v.id, v.cve_id, v.description, v.severity, v.cvss_score, COALESCE(v.source, 'NVD'), v.published_at, v.updated_at
		FROM vulnerabilities v
		JOIN component_vulnerabilities cv ON cv.vulnerability_id = v.id
		JOIN components c ON c.id = cv.component_id
		WHERE c.sbom_id = $1
		ORDER BY v.cvss_score DESC
	`
	rows, err := r.db.QueryContext(ctx, query, sbomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		if err := rows.Scan(&v.ID, &v.CVEID, &v.Description, &v.Severity, &v.CVSSScore, &v.Source, &v.PublishedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}
