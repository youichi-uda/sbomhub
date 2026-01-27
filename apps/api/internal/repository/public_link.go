package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type PublicLinkRepository struct {
	db *sql.DB
}

func NewPublicLinkRepository(db *sql.DB) *PublicLinkRepository {
	return &PublicLinkRepository{db: db}
}

func (r *PublicLinkRepository) Create(ctx context.Context, link *model.PublicLink) error {
	query := `
		INSERT INTO public_links (
			id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	_, err := r.db.ExecContext(ctx, query,
		link.ID, link.TenantID, link.ProjectID, link.SbomID, link.Token, link.Name, link.ExpiresAt, link.IsActive,
		link.AllowedDownloads, link.PasswordHash, link.ViewCount, link.DownloadCount, link.CreatedAt, link.UpdatedAt,
	)
	return err
}

func (r *PublicLinkRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.PublicLink, error) {
	query := `
		SELECT id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at
		FROM public_links
		WHERE project_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []model.PublicLink
	for rows.Next() {
		var link model.PublicLink
		var passwordHash sql.NullString
		if err := rows.Scan(
			&link.ID, &link.TenantID, &link.ProjectID, &link.SbomID, &link.Token, &link.Name, &link.ExpiresAt, &link.IsActive,
			&link.AllowedDownloads, &passwordHash, &link.ViewCount, &link.DownloadCount, &link.CreatedAt, &link.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if passwordHash.Valid {
			link.PasswordHash = &passwordHash.String
		}
		links = append(links, link)
	}
	return links, nil
}

func (r *PublicLinkRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.PublicLink, error) {
	query := `
		SELECT id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at
		FROM public_links
		WHERE id = $1
	`
	var link model.PublicLink
	var passwordHash sql.NullString
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&link.ID, &link.TenantID, &link.ProjectID, &link.SbomID, &link.Token, &link.Name, &link.ExpiresAt, &link.IsActive,
		&link.AllowedDownloads, &passwordHash, &link.ViewCount, &link.DownloadCount, &link.CreatedAt, &link.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if passwordHash.Valid {
		link.PasswordHash = &passwordHash.String
	}
	return &link, nil
}

func (r *PublicLinkRepository) GetByToken(ctx context.Context, token string) (*model.PublicLink, error) {
	query := `
		SELECT id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at
		FROM public_links
		WHERE token = $1
	`
	var link model.PublicLink
	var passwordHash sql.NullString
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&link.ID, &link.TenantID, &link.ProjectID, &link.SbomID, &link.Token, &link.Name, &link.ExpiresAt, &link.IsActive,
		&link.AllowedDownloads, &passwordHash, &link.ViewCount, &link.DownloadCount, &link.CreatedAt, &link.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if passwordHash.Valid {
		link.PasswordHash = &passwordHash.String
	}
	return &link, nil
}

func (r *PublicLinkRepository) Update(ctx context.Context, link *model.PublicLink) error {
	query := `
		UPDATE public_links
		SET name = $1, sbom_id = $2, expires_at = $3, is_active = $4, allowed_downloads = $5, password_hash = $6,
			updated_at = $7
		WHERE id = $8
	`
	_, err := r.db.ExecContext(ctx, query,
		link.Name, link.SbomID, link.ExpiresAt, link.IsActive, link.AllowedDownloads, link.PasswordHash, link.UpdatedAt, link.ID,
	)
	return err
}

func (r *PublicLinkRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM public_links WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PublicLinkRepository) IncrementView(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE public_links SET view_count = view_count + 1 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PublicLinkRepository) IncrementDownload(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE public_links SET download_count = download_count + 1 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PublicLinkRepository) CreateAccessLog(ctx context.Context, log *model.PublicLinkAccessLog) error {
	query := `
		INSERT INTO public_link_access_logs (
			id, public_link_id, action, ip_address, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.ExecContext(ctx, query,
		log.ID, log.PublicLinkID, log.Action, log.IPAddress, log.UserAgent, log.CreatedAt,
	)
	return err
}

func (r *PublicLinkRepository) IsDownloadLimitReached(ctx context.Context, id uuid.UUID) (bool, error) {
	query := `SELECT allowed_downloads, download_count FROM public_links WHERE id = $1`
	var allowed sql.NullInt64
	var downloaded int
	if err := r.db.QueryRowContext(ctx, query, id).Scan(&allowed, &downloaded); err != nil {
		return false, err
	}
	if !allowed.Valid {
		return false, nil
	}
	return downloaded >= int(allowed.Int64), nil
}

func (r *PublicLinkRepository) UpdateCounts(ctx context.Context, id uuid.UUID, viewCount, downloadCount int) error {
	query := `UPDATE public_links SET view_count = $1, download_count = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, viewCount, downloadCount, id)
	return err
}

func (r *PublicLinkRepository) Touch(ctx context.Context, id uuid.UUID, updatedAt time.Time) error {
	query := `UPDATE public_links SET updated_at = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, updatedAt, id)
	return err
}
