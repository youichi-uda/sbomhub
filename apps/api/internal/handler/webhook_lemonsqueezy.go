package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// LemonSqueezyWebhookHandler handles Lemon Squeezy webhook events
type LemonSqueezyWebhookHandler struct {
	cfg        *config.Config
	tenantRepo *repository.TenantRepository
	subRepo    *repository.SubscriptionRepository
	auditRepo  *repository.AuditRepository
}

// NewLemonSqueezyWebhookHandler creates a new LemonSqueezyWebhookHandler
func NewLemonSqueezyWebhookHandler(
	cfg *config.Config,
	tenantRepo *repository.TenantRepository,
	subRepo *repository.SubscriptionRepository,
	auditRepo *repository.AuditRepository,
) *LemonSqueezyWebhookHandler {
	return &LemonSqueezyWebhookHandler{
		cfg:        cfg,
		tenantRepo: tenantRepo,
		subRepo:    subRepo,
		auditRepo:  auditRepo,
	}
}

// LSWebhookPayload represents the Lemon Squeezy webhook payload
type LSWebhookPayload struct {
	Meta LSWebhookMeta `json:"meta"`
	Data LSWebhookData `json:"data"`
}

// LSWebhookMeta contains webhook metadata
type LSWebhookMeta struct {
	EventName  string            `json:"event_name"`
	CustomData map[string]string `json:"custom_data"`
}

// LSWebhookData contains the subscription data
type LSWebhookData struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Attributes LSSubscriptionAttrs    `json:"attributes"`
}

// LSSubscriptionAttrs contains subscription attributes
type LSSubscriptionAttrs struct {
	StoreID                int    `json:"store_id"`
	CustomerID             int    `json:"customer_id"`
	OrderID                int    `json:"order_id"`
	ProductID              int    `json:"product_id"`
	VariantID              int    `json:"variant_id"`
	ProductName            string `json:"product_name"`
	VariantName            string `json:"variant_name"`
	Status                 string `json:"status"`
	StatusFormatted        string `json:"status_formatted"`
	BillingAnchor          int    `json:"billing_anchor"`
	RenewsAt               string `json:"renews_at"`
	EndsAt                 string `json:"ends_at"`
	TrialEndsAt            string `json:"trial_ends_at"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
}

// Handle processes Lemon Squeezy webhook events
func (h *LemonSqueezyWebhookHandler) Handle(c echo.Context) error {
	// Skip in self-hosted mode
	if h.cfg.IsSelfHosted() {
		return c.JSON(http.StatusOK, map[string]string{"status": "skipped", "reason": "self-hosted mode"})
	}

	// Skip if billing not enabled
	if !h.cfg.IsBillingEnabled() {
		return c.JSON(http.StatusOK, map[string]string{"status": "skipped", "reason": "billing not enabled"})
	}

	// Read body
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
	}

	// Verify HMAC signature
	if !h.verifySignature(c.Request(), body) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
	}

	// Parse payload
	var payload LSWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid payload"})
	}

	slog.Info("received Lemon Squeezy webhook", "event", payload.Meta.EventName)

	switch payload.Meta.EventName {
	case "subscription_created":
		return h.handleSubscriptionCreated(c, &payload)
	case "subscription_updated":
		return h.handleSubscriptionUpdated(c, &payload)
	case "subscription_cancelled":
		return h.handleSubscriptionCancelled(c, &payload)
	case "subscription_resumed":
		return h.handleSubscriptionResumed(c, &payload)
	case "subscription_expired":
		return h.handleSubscriptionExpired(c, &payload)
	case "subscription_paused":
		return h.handleSubscriptionPaused(c, &payload)
	case "subscription_unpaused":
		return h.handleSubscriptionUnpaused(c, &payload)
	default:
		slog.Info("unhandled Lemon Squeezy event", "event", payload.Meta.EventName)
		return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "unhandled event"})
	}
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionCreated(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	// Get tenant ID from custom data
	tenantIDStr := payload.Meta.CustomData["tenant_id"]
	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "missing tenant_id in custom data"})
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	// Get tenant
	tenant, err := h.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
	}

	// Determine plan from variant
	plan := h.variantToPlan(payload.Data.Attributes.VariantID)

	// Parse dates
	renewsAt := parseTime(payload.Data.Attributes.RenewsAt)
	trialEndsAt := parseTime(payload.Data.Attributes.TrialEndsAt)
	endsAt := parseTime(payload.Data.Attributes.EndsAt)

	now := time.Now()
	sub := &model.Subscription{
		ID:               uuid.New(),
		TenantID:         tenantID,
		LSSubscriptionID: payload.Data.ID,
		LSCustomerID:     intToString(payload.Data.Attributes.CustomerID),
		LSVariantID:      intToString(payload.Data.Attributes.VariantID),
		LSProductID:      intToString(payload.Data.Attributes.ProductID),
		Status:           payload.Data.Attributes.Status,
		Plan:             plan,
		BillingAnchor:    &payload.Data.Attributes.BillingAnchor,
		RenewsAt:         renewsAt,
		TrialEndsAt:      trialEndsAt,
		EndsAt:           endsAt,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := h.subRepo.Create(ctx, sub); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create subscription"})
	}

	// Update tenant plan - return error to trigger webhook retry if this fails
	if err := h.tenantRepo.UpdatePlan(ctx, tenantID, plan); err != nil {
		slog.Error("failed to update tenant plan", "error", err, "tenant_id", tenantID, "plan", plan)
		// Don't fail the webhook - subscription is already created, tenant.plan is secondary
		// The GetSubscription API now uses subscription.plan as source of truth
	}

	// Log event
	h.subRepo.CreateEvent(ctx, &model.SubscriptionEvent{
		ID:             uuid.New(),
		SubscriptionID: sub.ID,
		TenantID:       tenantID,
		EventType:      "subscription_created",
		LSEventID:      "",
		PreviousPlan:   tenant.Plan,
		NewPlan:        plan,
		NewStatus:      payload.Data.Attributes.Status,
		CreatedAt:      now,
	})

	h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		Action:       model.ActionSubscriptionCreated,
		ResourceType: model.ResourceSubscription,
		ResourceID:   &sub.ID,
		Details:      map[string]interface{}{"plan": plan, "status": payload.Data.Attributes.Status},
	})

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionUpdated(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	// Get existing subscription
	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "subscription not found"})
	}

	previousStatus := sub.Status
	previousPlan := sub.Plan

	// Update subscription
	newPlan := h.variantToPlan(payload.Data.Attributes.VariantID)
	sub.LSVariantID = intToString(payload.Data.Attributes.VariantID)
	sub.Status = payload.Data.Attributes.Status
	sub.Plan = newPlan
	sub.RenewsAt = parseTime(payload.Data.Attributes.RenewsAt)
	sub.EndsAt = parseTime(payload.Data.Attributes.EndsAt)
	sub.UpdatedAt = time.Now()

	if err := h.subRepo.Update(ctx, sub); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
	}

	// Update tenant plan if changed
	if newPlan != previousPlan {
		if err := h.tenantRepo.UpdatePlan(ctx, sub.TenantID, newPlan); err != nil {
			slog.Error("failed to update tenant plan", "error", err)
		}
	}

	// Log event
	h.subRepo.CreateEvent(ctx, &model.SubscriptionEvent{
		ID:             uuid.New(),
		SubscriptionID: sub.ID,
		TenantID:       sub.TenantID,
		EventType:      "subscription_updated",
		PreviousStatus: previousStatus,
		NewStatus:      payload.Data.Attributes.Status,
		PreviousPlan:   previousPlan,
		NewPlan:        newPlan,
		CreatedAt:      time.Now(),
	})

	h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		TenantID:     &sub.TenantID,
		Action:       model.ActionSubscriptionUpdated,
		ResourceType: model.ResourceSubscription,
		ResourceID:   &sub.ID,
	})

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionCancelled(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "subscription not found"})
	}

	now := time.Now()
	previousStatus := sub.Status
	sub.Status = model.StatusCancelled
	sub.CancelledAt = &now
	sub.EndsAt = parseTime(payload.Data.Attributes.EndsAt)
	sub.UpdatedAt = now

	if err := h.subRepo.Update(ctx, sub); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
	}

	// Note: Don't downgrade plan immediately - subscription is still active until ends_at

	h.subRepo.CreateEvent(ctx, &model.SubscriptionEvent{
		ID:             uuid.New(),
		SubscriptionID: sub.ID,
		TenantID:       sub.TenantID,
		EventType:      "subscription_cancelled",
		PreviousStatus: previousStatus,
		NewStatus:      model.StatusCancelled,
		CreatedAt:      now,
	})

	h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		TenantID:     &sub.TenantID,
		Action:       model.ActionSubscriptionCancelled,
		ResourceType: model.ResourceSubscription,
		ResourceID:   &sub.ID,
	})

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionResumed(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "subscription not found"})
	}

	sub.Status = model.StatusActive
	sub.CancelledAt = nil
	sub.UpdatedAt = time.Now()

	if err := h.subRepo.Update(ctx, sub); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionExpired(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "subscription not found"})
	}

	sub.Status = model.StatusExpired
	sub.UpdatedAt = time.Now()

	if err := h.subRepo.Update(ctx, sub); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
	}

	// Downgrade tenant to free plan
	if err := h.tenantRepo.UpdatePlan(ctx, sub.TenantID, model.PlanFree); err != nil {
		slog.Error("failed to downgrade tenant plan", "error", err)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionPaused(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "subscription not found"})
	}

	sub.Status = model.StatusPaused
	sub.UpdatedAt = time.Now()

	if err := h.subRepo.Update(ctx, sub); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionUnpaused(c echo.Context, payload *LSWebhookPayload) error {
	return h.handleSubscriptionResumed(c, payload)
}

// verifySignature verifies the Lemon Squeezy HMAC signature
func (h *LemonSqueezyWebhookHandler) verifySignature(r *http.Request, body []byte) bool {
	if h.cfg.LemonSqueezyWebhookSecret == "" {
		return !h.cfg.IsProduction()
	}

	signature := r.Header.Get("X-Signature")
	if signature == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(h.cfg.LemonSqueezyWebhookSecret))
	mac.Write(body)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

// variantToPlan maps Lemon Squeezy variant ID to plan name
func (h *LemonSqueezyWebhookHandler) variantToPlan(variantID int) string {
	variantStr := intToString(variantID)
	switch variantStr {
	case h.cfg.LemonSqueezyStarterVariant:
		return model.PlanStarter
	case h.cfg.LemonSqueezyProVariant:
		return model.PlanPro
	case h.cfg.LemonSqueezyTeamVariant:
		return model.PlanTeam
	default:
		return model.PlanFree
	}
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

func intToString(i int) string {
	return fmt.Sprintf("%d", i)
}
