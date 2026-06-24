package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type SubscriptionRepository struct {
	db *sql.DB
}

func NewSubscriptionRepository(db *sql.DB) *SubscriptionRepository {
	return &SubscriptionRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
//
// RLS history note: migration 008 originally put `subscriptions`,
// `subscription_events`, and `usage_records` under ENABLE ROW LEVEL
// SECURITY with a USING-only tenant policy (which also implies a WITH
// CHECK fallback for INSERTs). That broke the Lemon Squeezy webhook path
// (`handler/webhook_lemonsqueezy.go`): the webhook route is mounted
// directly on the Echo instance, so by the time `GetByLSSubscriptionID`
// runs no `app.current_tenant_id` GUC is set under the `sbomhub_app`
// (NOBYPASSRLS) role, the predicate reduces to NULL, and every
// subscription_updated / cancelled / expired / paused / resumed event
// returned "subscription not found". Migration 031 dropped the policy
// on all three tables.
//
// Tenant scope is now enforced exclusively in this file:
//
//   - GetByLSSubscriptionID is intentionally tenant-unscoped (it is the
//     webhook lookup that REVEALS which tenant an event belongs to —
//     the equivalent of GetByKeyHash on api_keys, see migration 028).
//   - GetByTenantID / GetEvents / GetUsage are tenant-scoped by
//     parameter and always carry `WHERE tenant_id = $1`.
//   - Update / UpdateStatus / Delete add an explicit `AND tenant_id = $N`
//     guard so a buggy handler can't cross tenant boundaries even though
//     RLS is no longer the backstop.
//   - Create / CreateEvent / RecordUsage write the caller-supplied
//     TenantID; the FK to `tenants(id) ON DELETE CASCADE` still enforces
//     referential integrity.
//
// The q(ctx) indirection still matters for the billing endpoints that
// DO run inside a TenantTx — they should still join the request tx so
// reads/writes commit atomically with the rest of the request. Webhook
// callers have no tx and fall through to r.db, which is fine now that
// RLS is off. plan_limits has no RLS (it is a shared catalog) and reads
// gracefully through the fallback as before.
func (r *SubscriptionRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

func (r *SubscriptionRepository) Create(ctx context.Context, s *model.Subscription) error {
	query := `
		INSERT INTO subscriptions (
			id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
			status, plan, billing_anchor, current_period_start, current_period_end,
			trial_ends_at, renews_at, ends_at, cancelled_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
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
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID).Scan(
		&s.ID, &s.TenantID, &s.LSSubscriptionID, &s.LSCustomerID, &s.LSVariantID, &s.LSProductID,
		&s.Status, &s.Plan, &s.BillingAnchor, &s.CurrentPeriodStart, &s.CurrentPeriodEnd,
		&s.TrialEndsAt, &s.RenewsAt, &s.EndsAt, &s.CancelledAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetByLSSubscriptionID is the Lemon Squeezy webhook lookup: given the
// opaque subscription ID delivered over an HMAC-verified webhook (see
// handler/webhook_lemonsqueezy.go verifySignature), return the owning
// row (which carries tenant_id). It is intentionally tenant-UNSCOPED —
// this is the call that decides which tenant the event belongs to. All
// other reads MUST go through tenant-scoped helpers (GetByTenantID,
// GetEvents, GetUsage). Mirrors the GetByKeyHash invariant on api_keys
// (migration 028).
func (r *SubscriptionRepository) GetByLSSubscriptionID(ctx context.Context, lsSubID string) (*model.Subscription, error) {
	query := `
		SELECT id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
			status, plan, billing_anchor, current_period_start, current_period_end,
			trial_ends_at, renews_at, ends_at, cancelled_at, created_at, updated_at
		FROM subscriptions WHERE ls_subscription_id = $1
	`
	var s model.Subscription
	err := r.q(ctx).QueryRowContext(ctx, query, lsSubID).Scan(
		&s.ID, &s.TenantID, &s.LSSubscriptionID, &s.LSCustomerID, &s.LSVariantID, &s.LSProductID,
		&s.Status, &s.Plan, &s.BillingAnchor, &s.CurrentPeriodStart, &s.CurrentPeriodEnd,
		&s.TrialEndsAt, &s.RenewsAt, &s.EndsAt, &s.CancelledAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Update mutates an existing subscription row. The `AND tenant_id = $N`
// guard is load-bearing now that RLS is gone (migration 031) — without
// it a buggy or malicious caller that supplies a subscription struct
// whose ID belongs to tenant A but TenantID has been swapped to tenant
// B's id could rewrite tenant A's billing state. Callers MUST set
// s.TenantID from the trusted lookup (GetByLSSubscriptionID or
// GetByTenantID) and not from user input.
func (r *SubscriptionRepository) Update(ctx context.Context, s *model.Subscription) error {
	query := `
		UPDATE subscriptions SET
			ls_customer_id = $1, ls_variant_id = $2, ls_product_id = $3,
			status = $4, plan = $5, billing_anchor = $6,
			current_period_start = $7, current_period_end = $8,
			trial_ends_at = $9, renews_at = $10, ends_at = $11, cancelled_at = $12,
			updated_at = $13
		WHERE id = $14 AND tenant_id = $15
	`
	s.UpdatedAt = time.Now()
	_, err := r.q(ctx).ExecContext(ctx, query,
		s.LSCustomerID, s.LSVariantID, s.LSProductID,
		s.Status, s.Plan, s.BillingAnchor,
		s.CurrentPeriodStart, s.CurrentPeriodEnd,
		s.TrialEndsAt, s.RenewsAt, s.EndsAt, s.CancelledAt,
		s.UpdatedAt, s.ID, s.TenantID)
	return err
}

// UpdateStatus narrowly updates the status of a subscription, restricted
// to the calling tenant. The `tenant_id = $3` guard is defense-in-depth
// against cross-tenant mutation now that RLS is no longer enforcing it
// (migration 031).
func (r *SubscriptionRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	query := `UPDATE subscriptions SET status = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4`
	_, err := r.q(ctx).ExecContext(ctx, query, status, time.Now(), id, tenantID)
	return err
}

// Delete removes a subscription row, restricted to the calling tenant.
// With RLS off (migration 031) the `tenant_id = $2` clause is what
// stops any authenticated session from deleting another tenant's
// subscription by ID.
func (r *SubscriptionRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `DELETE FROM subscriptions WHERE id = $1 AND tenant_id = $2`
	_, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
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
	_, err = r.q(ctx).ExecContext(ctx, query,
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
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, limit)
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
	err := r.q(ctx).QueryRowContext(ctx, query, plan).Scan(
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
	_, err := r.q(ctx).ExecContext(ctx, query,
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
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, metric, start, end)
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
