package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// DiffWebhookRepository persists tenant_diff_webhook_settings rows
// (migration 046, M11-4 #79).
//
// Mirrors the TenantLLMConfigRepository pattern: one row per tenant,
// upsert by primary key, encrypted secret preserved via COALESCE when
// the caller omits the new ciphertext.
type DiffWebhookRepository struct {
	db *sql.DB
}

// NewDiffWebhookRepository constructs the repository.
func NewDiffWebhookRepository(db *sql.DB) *DiffWebhookRepository {
	return &DiffWebhookRepository{db: db}
}

// ErrDiffWebhookNotFound is returned by Get when no row exists for the
// given tenant. The handler translates this to "webhook disabled, no
// config" rather than a 404 so the UI can render the empty form.
var ErrDiffWebhookNotFound = errors.New("tenant_diff_webhook_settings: not found")

func (r *DiffWebhookRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Get fetches the row for tenantID.
func (r *DiffWebhookRepository) Get(ctx context.Context, tenantID uuid.UUID) (*model.DiffWebhookSettings, error) {
	const query = `
		SELECT tenant_id,
		       webhook_url,
		       webhook_secret,
		       critical_threshold,
		       high_threshold,
		       license_violation_threshold,
		       format,
		       enabled,
		       last_fired_at,
		       last_response_status,
		       last_error,
		       created_at,
		       updated_at
		FROM tenant_diff_webhook_settings
		WHERE tenant_id = $1
	`

	var (
		s          model.DiffWebhookSettings
		webhookURL sql.NullString
	)
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID).Scan(
		&s.TenantID,
		&webhookURL,
		&s.EncryptedSecret,
		&s.CriticalThreshold,
		&s.HighThreshold,
		&s.LicenseViolationThreshold,
		&s.Format,
		&s.Enabled,
		&s.LastFiredAt,
		&s.LastResponseStatus,
		&s.LastError,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDiffWebhookNotFound
	}
	if err != nil {
		return nil, err
	}
	s.WebhookURL = webhookURL.String
	return &s, nil
}

// UpsertDiffWebhookParams bundles the upsert input.
//
// EncryptedSecret = nil (or zero-length) preserves the existing
// ciphertext — same contract as TenantLLMConfigRepository.Upsert.
type UpsertDiffWebhookParams struct {
	TenantID                  uuid.UUID
	WebhookURL                string
	EncryptedSecret           []byte
	CriticalThreshold         int
	HighThreshold             int
	LicenseViolationThreshold int
	Format                    string
	Enabled                   bool
}

// Upsert inserts or updates the tenant row.
func (r *DiffWebhookRepository) Upsert(ctx context.Context, params UpsertDiffWebhookParams) (*model.DiffWebhookSettings, error) {
	if params.Format == "" {
		params.Format = model.DiffWebhookFormatJSON
	}
	const query = `
		INSERT INTO tenant_diff_webhook_settings (
			tenant_id, webhook_url, webhook_secret,
			critical_threshold, high_threshold, license_violation_threshold,
			format, enabled,
			created_at, updated_at
		) VALUES (
			$1, NULLIF($2, ''), $3,
			$4, $5, $6,
			$7, $8,
			NOW(), NOW()
		)
		ON CONFLICT (tenant_id) DO UPDATE
		SET webhook_url                  = EXCLUDED.webhook_url,
		    webhook_secret               = COALESCE(EXCLUDED.webhook_secret, tenant_diff_webhook_settings.webhook_secret),
		    critical_threshold           = EXCLUDED.critical_threshold,
		    high_threshold               = EXCLUDED.high_threshold,
		    license_violation_threshold  = EXCLUDED.license_violation_threshold,
		    format                       = EXCLUDED.format,
		    enabled                      = EXCLUDED.enabled,
		    updated_at                   = NOW()
	`
	var keyArg interface{}
	if len(params.EncryptedSecret) == 0 {
		keyArg = nil
	} else {
		keyArg = params.EncryptedSecret
	}
	if _, err := r.q(ctx).ExecContext(ctx, query,
		params.TenantID,
		params.WebhookURL,
		keyArg,
		params.CriticalThreshold,
		params.HighThreshold,
		params.LicenseViolationThreshold,
		params.Format,
		params.Enabled,
	); err != nil {
		return nil, err
	}
	return r.Get(ctx, params.TenantID)
}

// UpdateFireResult writes the operational visibility fields after a
// webhook delivery attempt. status >= 200 && < 300 counts as success
// (caller passes errMsg="" in that case).
func (r *DiffWebhookRepository) UpdateFireResult(
	ctx context.Context, tenantID uuid.UUID,
	status int, errMsg string,
) error {
	const query = `
		UPDATE tenant_diff_webhook_settings
		SET last_fired_at = NOW(),
		    last_response_status = $2,
		    last_error = NULLIF($3, ''),
		    updated_at = NOW()
		WHERE tenant_id = $1
	`
	_, err := r.q(ctx).ExecContext(ctx, query, tenantID, status, errMsg)
	return err
}
