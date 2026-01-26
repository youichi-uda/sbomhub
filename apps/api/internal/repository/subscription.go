package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type SubscriptionRepository struct {
	db *sql.DB
}

func NewSubscriptionRepository(db *sql.DB) *SubscriptionRepository {
	return &SubscriptionRepository{db: db}
}

func (r *SubscriptionRepository) Create(ctx context.Context, s *model.Subscription) error {
	query := `
		INSERT INTO subscriptions (
			id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
			status, plan, billing_anchor, current_period_start, current_period_end,
			trial_ends_at, renews_at, ends_at, cancelled_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := r.db.ExecContext(ctx, query,
		s.ID, s.TenantID, s.LSSubscriptionID, s.LSCustomerID, s.LSVariantID, s.LSProductID,
		s.Status, s.Plan, s.BillingAnchor, s.CurrentPeriodStart, s.CurrentPeriodEnd,
		s.TrialEndsAt, s.RenewsAt, s.EndsAt, s.CancelledAt, s.CreatedAt, s.UpdatedAt)
	return err
}

func (r *SubscriptionRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*model.Subscription, error) {
	query := `
		SELECT id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
			status, plan, billing_anchor, current_period_start, current_period_end,
			trial_ends_at, renews_at, ends_at, cancelled_at, created_at, updated_at
		FROM subscriptions WHERE tenant_id = $1
	`
	var s model.Subscription
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(
		&s.ID, &s.TenantID, &s.LSSubscriptionID, &s.LSCustomerID, &s.LSVariantID, &s.LSProductID,
		&s.Status, &s.Plan, &s.BillingAnchor, &s.CurrentPeriodStart, &s.CurrentPeriodEnd,
		&s.TrialEndsAt, &s.RenewsAt, &s.EndsAt, &s.CancelledAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SubscriptionRepository) GetByLSSubscriptionID(ctx context.Context, lsSubID string) (*model.Subscription, error) {
	query := `
		SELECT id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
			status, plan, billing_anchor, current_period_start, current_period_end,
			trial_ends_at, renews_at, ends_at, cancelled_at, created_at, updated_at
		FROM subscriptions WHERE ls_subscription_id = $1
	`
	var s model.Subscription
	err := r.db.QueryRowContext(ctx, query, lsSubID).Scan(
		&s.ID, &s.TenantID, &s.LSSubscriptionID, &s.LSCustomerID, &s.LSVariantID, &s.LSProductID,
		&s.Status, &s.Plan, &s.BillingAnchor, &s.CurrentPeriodStart, &s.CurrentPeriodEnd,
		&s.TrialEndsAt, &s.RenewsAt, &s.EndsAt, &s.CancelledAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SubscriptionRepository) Update(ctx context.Context, s *model.Subscription) error {
	query := `
		UPDATE subscriptions SET
			ls_customer_id = $1, ls_variant_id = $2, ls_product_id = $3,
			status = $4, plan = $5, billing_anchor = $6,
			current_period_start = $7, current_period_end = $8,
			trial_ends_at = $9, renews_at = $10, ends_at = $11, cancelled_at = $12,
			updated_at = $13
		WHERE id = $14
	`
	s.UpdatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, query,
		s.LSCustomerID, s.LSVariantID, s.LSProductID,
		s.Status, s.Plan, s.BillingAnchor,
		s.CurrentPeriodStart, s.CurrentPeriodEnd,
		s.TrialEndsAt, s.RenewsAt, s.EndsAt, s.CancelledAt,
		s.UpdatedAt, s.ID)
	return err
}

func (r *SubscriptionRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `UPDATE subscriptions SET status = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, status, time.Now(), id)
	return err
}

func (r *SubscriptionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM subscriptions WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// CreateEvent logs a subscription event
func (r *SubscriptionRepository) CreateEvent(ctx context.Context, e *model.SubscriptionEvent) error {
	metadataJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO subscription_events (
			id, subscription_id, tenant_id, event_type, ls_event_id,
			previous_status, new_status, previous_plan, new_plan, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err = r.db.ExecContext(ctx, query,
		e.ID, e.SubscriptionID, e.TenantID, e.EventType, e.LSEventID,
		e.PreviousStatus, e.NewStatus, e.PreviousPlan, e.NewPlan, metadataJSON, e.CreatedAt)
	return err
}

// GetEvents returns subscription events for a tenant
func (r *SubscriptionRepository) GetEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]model.SubscriptionEvent, error) {
	query := `
		SELECT id, subscription_id, tenant_id, event_type, ls_event_id,
			previous_status, new_status, previous_plan, new_plan, metadata, created_at
		FROM subscription_events
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []model.SubscriptionEvent
	for rows.Next() {
		var e model.SubscriptionEvent
		var metadataJSON []byte
		if err := rows.Scan(
			&e.ID, &e.SubscriptionID, &e.TenantID, &e.EventType, &e.LSEventID,
			&e.PreviousStatus, &e.NewStatus, &e.PreviousPlan, &e.NewPlan, &metadataJSON, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(metadataJSON) > 0 {
			json.Unmarshal(metadataJSON, &e.Metadata)
		}
		events = append(events, e)
	}
	return events, nil
}

// GetPlanLimits returns the limits for a plan
func (r *SubscriptionRepository) GetPlanLimits(ctx context.Context, plan string) (*model.PlanLimits, error) {
	query := `
		SELECT id, plan, max_users, max_projects, max_sboms_per_project, max_api_keys,
			api_rate_limit, features, created_at, updated_at
		FROM plan_limits WHERE plan = $1
	`
	var pl model.PlanLimits
	var featuresJSON []byte
	err := r.db.QueryRowContext(ctx, query, plan).Scan(
		&pl.ID, &pl.Plan, &pl.MaxUsers, &pl.MaxProjects, &pl.MaxSBOMsPerProject, &pl.MaxAPIKeys,
		&pl.APIRateLimit, &featuresJSON, &pl.CreatedAt, &pl.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			// Return default limits if not found in DB
			defaults := model.DefaultPlanLimits(plan)
			return &defaults, nil
		}
		return nil, err
	}
	if len(featuresJSON) > 0 {
		json.Unmarshal(featuresJSON, &pl.Features)
	}
	return &pl, nil
}

// RecordUsage records usage for metered billing
func (r *SubscriptionRepository) RecordUsage(ctx context.Context, u *model.UsageRecord) error {
	query := `
		INSERT INTO usage_records (id, tenant_id, metric, quantity, period_start, period_end, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, metric, period_start) DO UPDATE SET
			quantity = usage_records.quantity + EXCLUDED.quantity
	`
	_, err := r.db.ExecContext(ctx, query,
		u.ID, u.TenantID, u.Metric, u.Quantity, u.PeriodStart, u.PeriodEnd, u.CreatedAt)
	return err
}

// GetUsage returns usage records for a tenant
func (r *SubscriptionRepository) GetUsage(ctx context.Context, tenantID uuid.UUID, metric string, start, end time.Time) ([]model.UsageRecord, error) {
	query := `
		SELECT id, tenant_id, metric, quantity, period_start, period_end, created_at
		FROM usage_records
		WHERE tenant_id = $1 AND metric = $2 AND period_start >= $3 AND period_end <= $4
		ORDER BY period_start ASC
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, metric, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []model.UsageRecord
	for rows.Next() {
		var u model.UsageRecord
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Metric, &u.Quantity, &u.PeriodStart, &u.PeriodEnd, &u.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, u)
	}
	return records, nil
}
