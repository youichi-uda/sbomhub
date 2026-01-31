package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// KEVRepository handles KEV data access
type KEVRepository struct {
	db *sql.DB
}

// NewKEVRepository creates a new KEVRepository
func NewKEVRepository(db *sql.DB) *KEVRepository {
	return &KEVRepository{db: db}
}

// UpsertEntry creates or updates a KEV catalog entry
func (r *KEVRepository) UpsertEntry(ctx context.Context, e *model.KEVEntry) error {
	query := `
		INSERT INTO kev_catalog (
			id, cve_id, vendor_project, product, vulnerability_name,
			short_description, required_action, date_added, due_date,
			known_ransomware_use, notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
		ON CONFLICT (cve_id) DO UPDATE SET
			vendor_project = $3, product = $4, vulnerability_name = $5,
			short_description = $6, required_action = $7, date_added = $8,
			due_date = $9, known_ransomware_use = $10, notes = $11, updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		e.ID, e.CVEID, e.VendorProject, e.Product, e.VulnerabilityName,
		e.ShortDescription, e.RequiredAction, e.DateAdded, e.DueDate,
		e.KnownRansomwareUse, e.Notes,
	)
	return err
}

// GetByCVE gets a KEV entry by CVE ID
func (r *KEVRepository) GetByCVE(ctx context.Context, cveID string) (*model.KEVEntry, error) {
	query := `
		SELECT id, cve_id, vendor_project, product, vulnerability_name,
			short_description, required_action, date_added, due_date,
			known_ransomware_use, notes, created_at, updated_at
		FROM kev_catalog
		WHERE cve_id = $1
	`

	var e model.KEVEntry
	err := r.db.QueryRowContext(ctx, query, cveID).Scan(
		&e.ID, &e.CVEID, &e.VendorProject, &e.Product, &e.VulnerabilityName,
		&e.ShortDescription, &e.RequiredAction, &e.DateAdded, &e.DueDate,
		&e.KnownRansomwareUse, &e.Notes, &e.CreatedAt, &e.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &e, nil
}

// List lists KEV entries with pagination
func (r *KEVRepository) List(ctx context.Context, limit, offset int) ([]model.KEVEntry, int, error) {
	// Count query
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kev_catalog`).Scan(&total); err != nil {
		return nil, 0, err
	}

	// List query
	query := `
		SELECT id, cve_id, vendor_project, product, vulnerability_name,
			short_description, required_action, date_added, due_date,
			known_ransomware_use, notes, created_at, updated_at
		FROM kev_catalog
		ORDER BY date_added DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []model.KEVEntry
	for rows.Next() {
		var e model.KEVEntry
		if err := rows.Scan(
			&e.ID, &e.CVEID, &e.VendorProject, &e.Product, &e.VulnerabilityName,
			&e.ShortDescription, &e.RequiredAction, &e.DateAdded, &e.DueDate,
			&e.KnownRansomwareUse, &e.Notes, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}

	return entries, total, nil
}

// GetRecentEntries gets entries added after a given date
func (r *KEVRepository) GetRecentEntries(ctx context.Context, after time.Time) ([]model.KEVEntry, error) {
	query := `
		SELECT id, cve_id, vendor_project, product, vulnerability_name,
			short_description, required_action, date_added, due_date,
			known_ransomware_use, notes, created_at, updated_at
		FROM kev_catalog
		WHERE date_added > $1
		ORDER BY date_added DESC
	`

	rows, err := r.db.QueryContext(ctx, query, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []model.KEVEntry
	for rows.Next() {
		var e model.KEVEntry
		if err := rows.Scan(
			&e.ID, &e.CVEID, &e.VendorProject, &e.Product, &e.VulnerabilityName,
			&e.ShortDescription, &e.RequiredAction, &e.DateAdded, &e.DueDate,
			&e.KnownRansomwareUse, &e.Notes, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}

	return entries, nil
}

// GetAllCVEIDs returns all CVE IDs in the KEV catalog
func (r *KEVRepository) GetAllCVEIDs(ctx context.Context) ([]string, error) {
	query := `SELECT cve_id FROM kev_catalog`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			return nil, err
		}
		cveIDs = append(cveIDs, cveID)
	}

	return cveIDs, nil
}

// Count returns the total number of entries
func (r *KEVRepository) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kev_catalog`).Scan(&count)
	return count, err
}

// GetSyncSettings gets the global KEV sync settings
func (r *KEVRepository) GetSyncSettings(ctx context.Context) (*model.KEVSyncSettings, error) {
	query := `
		SELECT id, enabled, sync_interval_hours, last_sync_at,
			last_catalog_version, total_entries, created_at, updated_at
		FROM kev_sync_settings
		LIMIT 1
	`

	var s model.KEVSyncSettings
	err := r.db.QueryRowContext(ctx, query).Scan(
		&s.ID, &s.Enabled, &s.SyncIntervalHours, &s.LastSyncAt,
		&s.LastCatalogVersion, &s.TotalEntries, &s.CreatedAt, &s.UpdatedAt,
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
func (r *KEVRepository) UpdateSyncSettings(ctx context.Context, s *model.KEVSyncSettings) error {
	query := `
		UPDATE kev_sync_settings SET
			enabled = $1, sync_interval_hours = $2, last_sync_at = $3,
			last_catalog_version = $4, total_entries = $5, updated_at = NOW()
		WHERE id = $6
	`
	_, err := r.db.ExecContext(ctx, query,
		s.Enabled, s.SyncIntervalHours, s.LastSyncAt,
		s.LastCatalogVersion, s.TotalEntries, s.ID,
	)
	return err
}

// CreateSyncLog creates a new sync log entry
func (r *KEVRepository) CreateSyncLog(ctx context.Context) (*model.KEVSyncLog, error) {
	log := &model.KEVSyncLog{
		ID:        uuid.New(),
		StartedAt: time.Now(),
		Status:    string(model.KEVSyncStatusRunning),
	}

	query := `
		INSERT INTO kev_sync_logs (id, started_at, status)
		VALUES ($1, $2, $3)
	`
	_, err := r.db.ExecContext(ctx, query, log.ID, log.StartedAt, log.Status)
	if err != nil {
		return nil, err
	}

	return log, nil
}

// UpdateSyncLog updates a sync log entry
func (r *KEVRepository) UpdateSyncLog(ctx context.Context, log *model.KEVSyncLog) error {
	query := `
		UPDATE kev_sync_logs SET
			completed_at = $1, status = $2, new_entries = $3,
			updated_entries = $4, total_processed = $5, error_message = $6,
			catalog_version = $7
		WHERE id = $8
	`
	_, err := r.db.ExecContext(ctx, query,
		log.CompletedAt, log.Status, log.NewEntries,
		log.UpdatedEntries, log.TotalProcessed, log.ErrorMessage,
		log.CatalogVersion, log.ID,
	)
	return err
}

// GetLatestSyncLog gets the most recent sync log
func (r *KEVRepository) GetLatestSyncLog(ctx context.Context) (*model.KEVSyncLog, error) {
	query := `
		SELECT id, started_at, completed_at, status, new_entries,
			updated_entries, total_processed, error_message, catalog_version
		FROM kev_sync_logs
		ORDER BY started_at DESC
		LIMIT 1
	`

	var log model.KEVSyncLog
	err := r.db.QueryRowContext(ctx, query).Scan(
		&log.ID, &log.StartedAt, &log.CompletedAt, &log.Status,
		&log.NewEntries, &log.UpdatedEntries, &log.TotalProcessed,
		&log.ErrorMessage, &log.CatalogVersion,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &log, nil
}

// UpdateVulnerabilityKEVStatus updates KEV fields for a vulnerability
func (r *KEVRepository) UpdateVulnerabilityKEVStatus(ctx context.Context, cveID string, inKEV bool, dateAdded, dueDate *time.Time, ransomwareUse *bool) error {
	query := `
		UPDATE vulnerabilities SET
			in_kev = $1, kev_date_added = $2, kev_due_date = $3,
			kev_ransomware_use = $4, updated_at = NOW()
		WHERE cve_id = $5
	`
	_, err := r.db.ExecContext(ctx, query, inKEV, dateAdded, dueDate, ransomwareUse, cveID)
	return err
}

// SyncVulnerabilitiesKEVStatus syncs KEV status for all vulnerabilities
func (r *KEVRepository) SyncVulnerabilitiesKEVStatus(ctx context.Context) (int, error) {
	// First, reset all vulnerabilities to not in KEV
	resetQuery := `
		UPDATE vulnerabilities SET
			in_kev = false, kev_date_added = NULL, kev_due_date = NULL, kev_ransomware_use = NULL
		WHERE in_kev = true
	`
	if _, err := r.db.ExecContext(ctx, resetQuery); err != nil {
		return 0, fmt.Errorf("failed to reset KEV status: %w", err)
	}

	// Then, update vulnerabilities that are in KEV
	updateQuery := `
		UPDATE vulnerabilities v SET
			in_kev = true,
			kev_date_added = k.date_added,
			kev_due_date = k.due_date,
			kev_ransomware_use = k.known_ransomware_use
		FROM kev_catalog k
		WHERE v.cve_id = k.cve_id
	`
	result, err := r.db.ExecContext(ctx, updateQuery)
	if err != nil {
		return 0, fmt.Errorf("failed to update KEV status: %w", err)
	}

	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// GetKEVVulnerabilities gets all vulnerabilities that are in KEV
func (r *KEVRepository) GetKEVVulnerabilities(ctx context.Context, projectID uuid.UUID) ([]model.Vulnerability, error) {
	query := `
		SELECT DISTINCT v.id, v.cve_id, v.description, v.severity, v.cvss_score,
			v.epss_score, v.epss_percentile, v.epss_updated_at,
			v.in_kev, v.kev_date_added, v.kev_due_date, v.kev_ransomware_use,
			v.source, v.published_at, v.updated_at
		FROM vulnerabilities v
		JOIN component_vulnerabilities cv ON cv.vulnerability_id = v.id
		JOIN components c ON c.id = cv.component_id
		JOIN sboms s ON s.id = c.sbom_id
		WHERE s.project_id = $1 AND v.in_kev = true
		ORDER BY v.kev_due_date ASC NULLS LAST
	`

	rows, err := r.db.QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulnerabilities []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		if err := rows.Scan(
			&v.ID, &v.CVEID, &v.Description, &v.Severity, &v.CVSSScore,
			&v.EPSSScore, &v.EPSSPercentile, &v.EPSSUpdatedAt,
			&v.InKEV, &v.KEVDateAdded, &v.KEVDueDate, &v.KEVRansomwareUse,
			&v.Source, &v.PublishedAt, &v.UpdatedAt,
		); err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, v)
	}

	return vulnerabilities, nil
}
