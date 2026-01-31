package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// EOLRepository handles EOL data access
type EOLRepository struct {
	db *sql.DB
}

// NewEOLRepository creates a new EOLRepository
func NewEOLRepository(db *sql.DB) *EOLRepository {
	return &EOLRepository{db: db}
}

// UpsertProduct creates or updates an EOL product
func (r *EOLRepository) UpsertProduct(ctx context.Context, p *model.EOLProduct) error {
	query := `
		INSERT INTO eol_products (
			id, name, title, category, link, total_cycles, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		ON CONFLICT (name) DO UPDATE SET
			title = $3, category = $4, link = $5, total_cycles = $6, updated_at = NOW()
		RETURNING id
	`
	return r.db.QueryRowContext(ctx, query,
		p.ID, p.Name, p.Title, p.Category, p.Link, p.TotalCycles,
	).Scan(&p.ID)
}

// GetProductByName gets a product by its name
func (r *EOLRepository) GetProductByName(ctx context.Context, name string) (*model.EOLProduct, error) {
	query := `
		SELECT id, name, title, category, link, total_cycles, created_at, updated_at
		FROM eol_products
		WHERE name = $1
	`

	var p model.EOLProduct
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&p.ID, &p.Name, &p.Title, &p.Category, &p.Link, &p.TotalCycles, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &p, nil
}

// GetProductByID gets a product by its ID
func (r *EOLRepository) GetProductByID(ctx context.Context, id uuid.UUID) (*model.EOLProduct, error) {
	query := `
		SELECT id, name, title, category, link, total_cycles, created_at, updated_at
		FROM eol_products
		WHERE id = $1
	`

	var p model.EOLProduct
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&p.ID, &p.Name, &p.Title, &p.Category, &p.Link, &p.TotalCycles, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &p, nil
}

// ListProducts lists all EOL products
func (r *EOLRepository) ListProducts(ctx context.Context, limit, offset int) ([]model.EOLProduct, int, error) {
	// Count query
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM eol_products`).Scan(&total); err != nil {
		return nil, 0, err
	}

	// List query
	query := `
		SELECT id, name, title, category, link, total_cycles, created_at, updated_at
		FROM eol_products
		ORDER BY name
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var products []model.EOLProduct
	for rows.Next() {
		var p model.EOLProduct
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Title, &p.Category, &p.Link, &p.TotalCycles, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		products = append(products, p)
	}

	return products, total, nil
}

// UpsertCycle creates or updates an EOL product cycle
func (r *EOLRepository) UpsertCycle(ctx context.Context, c *model.EOLProductCycle) error {
	query := `
		INSERT INTO eol_product_cycles (
			id, product_id, cycle, release_date, eol_date, eos_date,
			latest_version, is_lts, is_eol, discontinued, link, support_end_date,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
		ON CONFLICT (product_id, cycle) DO UPDATE SET
			release_date = $4, eol_date = $5, eos_date = $6,
			latest_version = $7, is_lts = $8, is_eol = $9, discontinued = $10,
			link = $11, support_end_date = $12, updated_at = NOW()
		RETURNING id
	`
	return r.db.QueryRowContext(ctx, query,
		c.ID, c.ProductID, c.Cycle, c.ReleaseDate, c.EOLDate, c.EOSDate,
		c.LatestVersion, c.IsLTS, c.IsEOL, c.Discontinued, c.Link, c.SupportEndDate,
	).Scan(&c.ID)
}

// GetCyclesByProduct gets all cycles for a product
func (r *EOLRepository) GetCyclesByProduct(ctx context.Context, productID uuid.UUID) ([]model.EOLProductCycle, error) {
	query := `
		SELECT id, product_id, cycle, release_date, eol_date, eos_date,
			latest_version, is_lts, is_eol, discontinued, link, support_end_date,
			created_at, updated_at
		FROM eol_product_cycles
		WHERE product_id = $1
		ORDER BY release_date DESC NULLS LAST
	`

	rows, err := r.db.QueryContext(ctx, query, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cycles []model.EOLProductCycle
	for rows.Next() {
		var c model.EOLProductCycle
		if err := rows.Scan(
			&c.ID, &c.ProductID, &c.Cycle, &c.ReleaseDate, &c.EOLDate, &c.EOSDate,
			&c.LatestVersion, &c.IsLTS, &c.IsEOL, &c.Discontinued, &c.Link, &c.SupportEndDate,
			&c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		cycles = append(cycles, c)
	}

	return cycles, nil
}

// FindMatchingCycle finds the best matching cycle for a version
func (r *EOLRepository) FindMatchingCycle(ctx context.Context, productID uuid.UUID, version string) (*model.EOLProductCycle, error) {
	// Try exact match first, then prefix match
	query := `
		SELECT id, product_id, cycle, release_date, eol_date, eos_date,
			latest_version, is_lts, is_eol, discontinued, link, support_end_date,
			created_at, updated_at
		FROM eol_product_cycles
		WHERE product_id = $1 AND (
			$2 = cycle OR
			$2 LIKE cycle || '.%' OR
			cycle = split_part($2, '.', 1) || '.' || split_part($2, '.', 2)
		)
		ORDER BY
			CASE WHEN $2 = cycle THEN 0 ELSE 1 END,
			release_date DESC NULLS LAST
		LIMIT 1
	`

	var c model.EOLProductCycle
	err := r.db.QueryRowContext(ctx, query, productID, version).Scan(
		&c.ID, &c.ProductID, &c.Cycle, &c.ReleaseDate, &c.EOLDate, &c.EOSDate,
		&c.LatestVersion, &c.IsLTS, &c.IsEOL, &c.Discontinued, &c.Link, &c.SupportEndDate,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// GetMappings gets all component mappings
func (r *EOLRepository) GetMappings(ctx context.Context) ([]model.EOLComponentMapping, error) {
	query := `
		SELECT id, product_id, component_pattern, component_type, purl_type, priority, is_active, created_at
		FROM eol_component_mappings
		WHERE is_active = true
		ORDER BY priority DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mappings []model.EOLComponentMapping
	for rows.Next() {
		var m model.EOLComponentMapping
		if err := rows.Scan(
			&m.ID, &m.ProductID, &m.ComponentPattern, &m.ComponentType, &m.PurlType, &m.Priority, &m.IsActive, &m.CreatedAt,
		); err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}

	return mappings, nil
}

// CreateMapping creates a new component mapping
func (r *EOLRepository) CreateMapping(ctx context.Context, m *model.EOLComponentMapping) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	query := `
		INSERT INTO eol_component_mappings (
			id, product_id, component_pattern, component_type, purl_type, priority, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (product_id, component_pattern, component_type) DO UPDATE SET
			purl_type = $5, priority = $6, is_active = $7
	`
	_, err := r.db.ExecContext(ctx, query,
		m.ID, m.ProductID, m.ComponentPattern, m.ComponentType, m.PurlType, m.Priority, m.IsActive,
	)
	return err
}

// GetSyncSettings gets the global EOL sync settings
func (r *EOLRepository) GetSyncSettings(ctx context.Context) (*model.EOLSyncSettings, error) {
	query := `
		SELECT id, enabled, sync_interval_hours, last_sync_at,
			total_products, total_cycles, created_at, updated_at
		FROM eol_sync_settings
		LIMIT 1
	`

	var s model.EOLSyncSettings
	err := r.db.QueryRowContext(ctx, query).Scan(
		&s.ID, &s.Enabled, &s.SyncIntervalHours, &s.LastSyncAt,
		&s.TotalProducts, &s.TotalCycles, &s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// UpdateSyncSettings updates the sync settings
func (r *EOLRepository) UpdateSyncSettings(ctx context.Context, s *model.EOLSyncSettings) error {
	query := `
		UPDATE eol_sync_settings SET
			enabled = $1, sync_interval_hours = $2, last_sync_at = $3,
			total_products = $4, total_cycles = $5, updated_at = NOW()
		WHERE id = $6
	`
	_, err := r.db.ExecContext(ctx, query,
		s.Enabled, s.SyncIntervalHours, s.LastSyncAt,
		s.TotalProducts, s.TotalCycles, s.ID,
	)
	return err
}

// CreateSyncLog creates a new sync log entry
func (r *EOLRepository) CreateSyncLog(ctx context.Context) (*model.EOLSyncLog, error) {
	log := &model.EOLSyncLog{
		ID:        uuid.New(),
		StartedAt: time.Now(),
		Status:    string(model.EOLSyncStatusRunning),
	}

	query := `
		INSERT INTO eol_sync_logs (id, started_at, status)
		VALUES ($1, $2, $3)
	`
	_, err := r.db.ExecContext(ctx, query, log.ID, log.StartedAt, log.Status)
	if err != nil {
		return nil, err
	}

	return log, nil
}

// UpdateSyncLog updates a sync log entry
func (r *EOLRepository) UpdateSyncLog(ctx context.Context, log *model.EOLSyncLog) error {
	query := `
		UPDATE eol_sync_logs SET
			completed_at = $1, status = $2, products_synced = $3,
			cycles_synced = $4, components_updated = $5, error_message = $6
		WHERE id = $7
	`
	_, err := r.db.ExecContext(ctx, query,
		log.CompletedAt, log.Status, log.ProductsSynced,
		log.CyclesSynced, log.ComponentsUpdated, log.ErrorMessage, log.ID,
	)
	return err
}

// GetLatestSyncLog gets the most recent sync log
func (r *EOLRepository) GetLatestSyncLog(ctx context.Context) (*model.EOLSyncLog, error) {
	query := `
		SELECT id, started_at, completed_at, status, products_synced,
			cycles_synced, components_updated, error_message
		FROM eol_sync_logs
		ORDER BY started_at DESC
		LIMIT 1
	`

	var log model.EOLSyncLog
	err := r.db.QueryRowContext(ctx, query).Scan(
		&log.ID, &log.StartedAt, &log.CompletedAt, &log.Status,
		&log.ProductsSynced, &log.CyclesSynced, &log.ComponentsUpdated, &log.ErrorMessage,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &log, nil
}

// UpdateComponentEOLStatus updates EOL fields for a component
func (r *EOLRepository) UpdateComponentEOLStatus(ctx context.Context, componentID uuid.UUID, info *model.ComponentEOLInfo) error {
	query := `
		UPDATE components SET
			eol_status = $1, eol_product_id = $2, eol_cycle_id = $3,
			eol_date = $4, eos_date = $5, eol_checked_at = NOW()
		WHERE id = $6
	`
	_, err := r.db.ExecContext(ctx, query,
		info.Status, info.ProductID, info.CycleID,
		info.EOLDate, info.EOSDate, componentID,
	)
	return err
}

// GetComponentsForEOLCheck gets components that need EOL checking
func (r *EOLRepository) GetComponentsForEOLCheck(ctx context.Context, projectID uuid.UUID, limit int) ([]model.Component, error) {
	query := `
		SELECT c.id, c.sbom_id, c.name, c.version, c.type, c.purl, c.license, c.created_at
		FROM components c
		JOIN sboms s ON s.id = c.sbom_id
		WHERE s.project_id = $1 AND (
			c.eol_checked_at IS NULL OR
			c.eol_checked_at < NOW() - INTERVAL '7 days'
		)
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var components []model.Component
	for rows.Next() {
		var c model.Component
		if err := rows.Scan(
			&c.ID, &c.SbomID, &c.Name, &c.Version, &c.Type, &c.Purl, &c.License, &c.CreatedAt,
		); err != nil {
			return nil, err
		}
		components = append(components, c)
	}

	return components, nil
}

// GetEOLSummary gets EOL summary for a project
func (r *EOLRepository) GetEOLSummary(ctx context.Context, projectID uuid.UUID) (*model.EOLSummary, error) {
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(CASE WHEN c.eol_status = 'active' THEN 1 END) as active,
			COUNT(CASE WHEN c.eol_status = 'eol' THEN 1 END) as eol,
			COUNT(CASE WHEN c.eol_status = 'eos' THEN 1 END) as eos,
			COUNT(CASE WHEN c.eol_status = 'unknown' OR c.eol_status IS NULL THEN 1 END) as unknown
		FROM components c
		JOIN sboms s ON s.id = c.sbom_id
		WHERE s.project_id = $1
	`

	summary := &model.EOLSummary{ProjectID: projectID}
	err := r.db.QueryRowContext(ctx, query, projectID).Scan(
		&summary.TotalComponents,
		&summary.Active,
		&summary.EOL,
		&summary.EOS,
		&summary.Unknown,
	)
	if err != nil {
		return nil, err
	}

	return summary, nil
}

// GetComponentsWithEOL gets components with their EOL information
func (r *EOLRepository) GetComponentsWithEOL(ctx context.Context, projectID uuid.UUID, eolStatus string, limit, offset int) ([]model.Component, int, error) {
	// Build where clause
	where := "s.project_id = $1"
	args := []interface{}{projectID}
	argIndex := 2

	if eolStatus != "" {
		where += fmt.Sprintf(" AND c.eol_status = $%d", argIndex)
		args = append(args, eolStatus)
		argIndex++
	}

	// Count query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM components c
		JOIN sboms s ON s.id = c.sbom_id
		WHERE %s
	`, where)

	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// List query
	listQuery := fmt.Sprintf(`
		SELECT c.id, c.sbom_id, c.name, c.version, c.type, c.purl, c.license, c.created_at,
			c.eol_status, c.eol_product_id, c.eol_cycle_id, c.eol_date, c.eos_date
		FROM components c
		JOIN sboms s ON s.id = c.sbom_id
		WHERE %s
		ORDER BY
			CASE c.eol_status WHEN 'eol' THEN 0 WHEN 'eos' THEN 1 WHEN 'active' THEN 2 ELSE 3 END,
			c.name
		LIMIT $%d OFFSET $%d
	`, where, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var components []model.Component
	for rows.Next() {
		var c model.Component
		var eolStatus, eolProductID, eolCycleID, eolDate, eosDate sql.NullString
		if err := rows.Scan(
			&c.ID, &c.SbomID, &c.Name, &c.Version, &c.Type, &c.Purl, &c.License, &c.CreatedAt,
			&eolStatus, &eolProductID, &eolCycleID, &eolDate, &eosDate,
		); err != nil {
			return nil, 0, err
		}
		// Store EOL fields in component (handled by extended model if needed)
		components = append(components, c)
	}

	return components, total, nil
}

// CountProducts returns the total number of EOL products
func (r *EOLRepository) CountProducts(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM eol_products`).Scan(&count)
	return count, err
}

// CountCycles returns the total number of EOL cycles
func (r *EOLRepository) CountCycles(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM eol_product_cycles`).Scan(&count)
	return count, err
}

// GetAllProductNames returns all product names for comparison
func (r *EOLRepository) GetAllProductNames(ctx context.Context) ([]string, error) {
	query := `SELECT name FROM eol_products`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}

	return names, nil
}
