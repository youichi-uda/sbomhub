package model

import (
	"time"

	"github.com/google/uuid"
)

// Subscription represents a Lemon Squeezy subscription
type Subscription struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	TenantID           uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	LSSubscriptionID   string     `json:"ls_subscription_id" db:"ls_subscription_id"`
	LSCustomerID       string     `json:"ls_customer_id" db:"ls_customer_id"`
	LSVariantID        string     `json:"ls_variant_id" db:"ls_variant_id"`
	LSProductID        string     `json:"ls_product_id,omitempty" db:"ls_product_id"`
	Status             string     `json:"status" db:"status"`
	Plan               string     `json:"plan" db:"plan"`
	BillingAnchor      *int       `json:"billing_anchor,omitempty" db:"billing_anchor"`
	CurrentPeriodStart *time.Time `json:"current_period_start,omitempty" db:"current_period_start"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end,omitempty" db:"current_period_end"`
	TrialEndsAt        *time.Time `json:"trial_ends_at,omitempty" db:"trial_ends_at"`
	RenewsAt           *time.Time `json:"renews_at,omitempty" db:"renews_at"`
	EndsAt             *time.Time `json:"ends_at,omitempty" db:"ends_at"`
	CancelledAt        *time.Time `json:"cancelled_at,omitempty" db:"cancelled_at"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
}

// SubscriptionStatus constants
const (
	StatusOnTrial  = "on_trial"
	StatusActive   = "active"
	StatusPaused   = "paused"
	StatusPastDue  = "past_due"
	StatusUnpaid   = "unpaid"
	StatusCancelled = "cancelled"
	StatusExpired  = "expired"
)

// IsActive returns true if the subscription is currently active
func (s *Subscription) IsActive() bool {
	return s.Status == StatusOnTrial || s.Status == StatusActive
}

// SubscriptionEvent represents a billing event
type SubscriptionEvent struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	SubscriptionID uuid.UUID              `json:"subscription_id" db:"subscription_id"`
	TenantID       uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	EventType      string                 `json:"event_type" db:"event_type"`
	LSEventID      string                 `json:"ls_event_id,omitempty" db:"ls_event_id"`
	PreviousStatus string                 `json:"previous_status,omitempty" db:"previous_status"`
	NewStatus      string                 `json:"new_status,omitempty" db:"new_status"`
	PreviousPlan   string                 `json:"previous_plan,omitempty" db:"previous_plan"`
	NewPlan        string                 `json:"new_plan,omitempty" db:"new_plan"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
}

// UsageRecord represents usage tracking for metered billing
type UsageRecord struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Metric      string    `json:"metric" db:"metric"`
	Quantity    int       `json:"quantity" db:"quantity"`
	PeriodStart time.Time `json:"period_start" db:"period_start"`
	PeriodEnd   time.Time `json:"period_end" db:"period_end"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// UsageMetric constants
const (
	MetricProjects    = "projects"
	MetricUsers       = "users"
	MetricSBOMs       = "sboms"
	MetricAPIRequests = "api_requests"
)
