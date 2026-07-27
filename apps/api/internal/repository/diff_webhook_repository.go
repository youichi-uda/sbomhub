package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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
// given tenant, and by UpdateFireResult when the UPDATE matched no row.
// The handler translates the Get case to "webhook disabled, no config"
// rather than a 404 so the UI can render the empty form.
//
// M47 W2: now WRAPS sql.ErrNoRows for the same reason as
// ErrTenantLLMConfigNotFound — every existing caller matches the named
// sentinel and is unaffected; wrapping only ADDS
// errors.Is(err, sql.ErrNoRows).
var ErrDiffWebhookNotFound = fmt.Errorf("tenant_diff_webhook_settings: not found: %w", sql.ErrNoRows)

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
//
// M47 W2 classification: BENIGN — `ON CONFLICT ... DO UPDATE` with no
// WHERE guard always affects exactly one row, so there is no 0-row
// outcome for the caller to adjudicate.
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
	res, err := r.q(ctx).ExecContext(ctx, query, tenantID, status, errMsg)
	if err != nil {
		return err
	}
	// M47 W2: 0 rows means this tenant has no settings row at all — the
	// delivery-attempt bookkeeping went nowhere. The caller
	// (service/diff_webhook) deliberately ignores this error so a webhook
	// send is never failed by its own telemetry, but it can only make that
	// choice knowingly if the error exists.
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update tenant_diff_webhook_settings fire result (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update fire result for tenant %s: %w", tenantID, ErrDiffWebhookNotFound)
	}
	return nil
}
