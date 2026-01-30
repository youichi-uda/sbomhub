package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/model"
)

// IPARepository handles IPA data access
type IPARepository struct {
	db *sql.DB
}

// NewIPARepository creates a new IPARepository
func NewIPARepository(db *sql.DB) *IPARepository {
	return &IPARepository{db: db}
}

// CreateAnnouncement creates a new IPA announcement
func (r *IPARepository) CreateAnnouncement(ctx context.Context, a *model.IPAAnnouncement) error {
	query := `
		INSERT INTO ipa_announcements (
			id, ipa_id, title, title_ja, description, category, severity,
			source_url, related_cves, published_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
		ON CONFLICT (ipa_id) DO UPDATE SET
			title = $3, description = $5, severity = $7, related_cves = $9, updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		a.ID, a.IPAID, a.Title, a.TitleJa, a.Description, a.Category, a.Severity,
		a.SourceURL, pq.Array(a.RelatedCVEs), a.PublishedAt,
	)
	return err
}

// GetAnnouncementByIPAID gets an announcement by IPA ID
func (r *IPARepository) GetAnnouncementByIPAID(ctx context.Context, ipaID string) (*model.IPAAnnouncement, error) {
	query := `
		SELECT id, ipa_id, title, title_ja, description, category, severity,
			source_url, related_cves, published_at, created_at, updated_at
		FROM ipa_announcements
		WHERE ipa_id = $1
	`

	var a model.IPAAnnouncement
	err := r.db.QueryRowContext(ctx, query, ipaID).Scan(
		&a.ID, &a.IPAID, &a.Title, &a.TitleJa, &a.Description, &a.Category, &a.Severity,
		&a.SourceURL, pq.Array(&a.RelatedCVEs), &a.PublishedAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &a, nil
}

// ListAnnouncements lists IPA announcements with pagination
func (r *IPARepository) ListAnnouncements(ctx context.Context, category string, limit, offset int) ([]model.IPAAnnouncement, int, error) {
	// Count query
	countQuery := `SELECT COUNT(*) FROM ipa_announcements`
	countArgs := []interface{}{}
	if category != "" {
		countQuery += ` WHERE category = $1`
		countArgs = append(countArgs, category)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// List query
	query := `
		SELECT id, ipa_id, title, title_ja, description, category, severity,
			source_url, related_cves, published_at, created_at, updated_at
		FROM ipa_announcements
	`
	args := []interface{}{}
	argIndex := 1

	if category != "" {
		query += ` WHERE category = $1`
		args = append(args, category)
		argIndex++
	}

	query += ` ORDER BY published_at DESC LIMIT $` + string(rune('0'+argIndex)) + ` OFFSET $` + string(rune('0'+argIndex+1))
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var announcements []model.IPAAnnouncement
	for rows.Next() {
		var a model.IPAAnnouncement
		if err := rows.Scan(
			&a.ID, &a.IPAID, &a.Title, &a.TitleJa, &a.Description, &a.Category, &a.Severity,
			&a.SourceURL, pq.Array(&a.RelatedCVEs), &a.PublishedAt, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		announcements = append(announcements, a)
	}

	return announcements, total, nil
}

// GetAnnouncementsByCVE gets announcements related to a CVE
func (r *IPARepository) GetAnnouncementsByCVE(ctx context.Context, cveID string) ([]model.IPAAnnouncement, error) {
	query := `
		SELECT id, ipa_id, title, title_ja, description, category, severity,
			source_url, related_cves, published_at, created_at, updated_at
		FROM ipa_announcements
		WHERE $1 = ANY(related_cves)
		ORDER BY published_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var announcements []model.IPAAnnouncement
	for rows.Next() {
		var a model.IPAAnnouncement
		if err := rows.Scan(
			&a.ID, &a.IPAID, &a.Title, &a.TitleJa, &a.Description, &a.Category, &a.Severity,
			&a.SourceURL, pq.Array(&a.RelatedCVEs), &a.PublishedAt, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		announcements = append(announcements, a)
	}

	return announcements, nil
}

// GetSyncSettings gets IPA sync settings for a tenant
func (r *IPARepository) GetSyncSettings(ctx context.Context, tenantID uuid.UUID) (*model.IPASyncSettings, error) {
	query := `
		SELECT id, tenant_id, enabled, notify_on_new, notify_severity, last_sync_at, created_at, updated_at
		FROM ipa_sync_settings
		WHERE tenant_id = $1
	`

	var s model.IPASyncSettings
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(
		&s.ID, &s.TenantID, &s.Enabled, &s.NotifyOnNew, pq.Array(&s.NotifySeverity),
		&s.LastSyncAt, &s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// UpsertSyncSettings creates or updates IPA sync settings
func (r *IPARepository) UpsertSyncSettings(ctx context.Context, s *model.IPASyncSettings) error {
	query := `
		INSERT INTO ipa_sync_settings (
			id, tenant_id, enabled, notify_on_new, notify_severity, last_sync_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		ON CONFLICT (tenant_id)
		DO UPDATE SET
			enabled = $3, notify_on_new = $4, notify_severity = $5, last_sync_at = $6, updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		s.ID, s.TenantID, s.Enabled, s.NotifyOnNew, pq.Array(s.NotifySeverity), s.LastSyncAt,
	)
	return err
}

// UpdateLastSyncAt updates the last sync timestamp
func (r *IPARepository) UpdateLastSyncAt(ctx context.Context, tenantID uuid.UUID) error {
	query := `UPDATE ipa_sync_settings SET last_sync_at = NOW(), updated_at = NOW() WHERE tenant_id = $1`
	_, err := r.db.ExecContext(ctx, query, tenantID)
	return err
}

// GetRecentAnnouncements gets announcements published after a given time
func (r *IPARepository) GetRecentAnnouncements(ctx context.Context, after time.Time) ([]model.IPAAnnouncement, error) {
	query := `
		SELECT id, ipa_id, title, title_ja, description, category, severity,
			source_url, related_cves, published_at, created_at, updated_at
		FROM ipa_announcements
		WHERE published_at > $1
		ORDER BY published_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var announcements []model.IPAAnnouncement
	for rows.Next() {
		var a model.IPAAnnouncement
		if err := rows.Scan(
			&a.ID, &a.IPAID, &a.Title, &a.TitleJa, &a.Description, &a.Category, &a.Severity,
			&a.SourceURL, pq.Array(&a.RelatedCVEs), &a.PublishedAt, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		announcements = append(announcements, a)
	}

	return announcements, nil
}
