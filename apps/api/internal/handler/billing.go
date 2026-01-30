package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// BillingHandler handles billing-related endpoints
type BillingHandler struct {
	cfg        *config.Config
	tenantRepo *repository.TenantRepository
	subRepo    *repository.SubscriptionRepository
}

// NewBillingHandler creates a new BillingHandler
func NewBillingHandler(
	cfg *config.Config,
	tenantRepo *repository.TenantRepository,
	subRepo *repository.SubscriptionRepository,
) *BillingHandler {
	return &BillingHandler{
		cfg:        cfg,
		tenantRepo: tenantRepo,
		subRepo:    subRepo,
	}
}

// SubscriptionResponse represents the subscription info returned to clients
type SubscriptionResponse struct {
	HasSubscription bool               `json:"has_subscription"`
	Subscription    *model.Subscription `json:"subscription,omitempty"`
	Plan            string             `json:"plan"`
	Limits          *model.PlanLimits  `json:"limits"`
	BillingEnabled  bool               `json:"billing_enabled"`
	IsSelfHosted    bool               `json:"is_self_hosted"`
}

// GetSubscription returns the current subscription info
func (h *BillingHandler) GetSubscription(c echo.Context) error {
	ctx := c.Request().Context()
	tc := middleware.NewTenantContext(c)

	// Self-hosted mode returns enterprise plan with no billing
	if tc.IsSelfHosted() {
		limits := model.DefaultPlanLimits(model.PlanEnterprise)
		return c.JSON(http.StatusOK, SubscriptionResponse{
			HasSubscription: false,
			Plan:            model.PlanEnterprise,
			Limits:          &limits,
			BillingEnabled:  false,
			IsSelfHosted:    true,
		})
	}

	tenant := tc.Tenant()
	if tenant == nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "tenant not found"})
	}

	// Get subscription
	sub, err := h.subRepo.GetByTenantID(ctx, tc.TenantID())

	if err != nil {
		// No subscription - return tenant plan (free or previously set)
		plan := tenant.Plan
		if plan == "" {
			plan = model.PlanFree
		}
		limits, _ := h.subRepo.GetPlanLimits(ctx, plan)
		return c.JSON(http.StatusOK, SubscriptionResponse{
			HasSubscription: false,
			Plan:            plan,
			Limits:          limits,
			BillingEnabled:  h.cfg.IsBillingEnabled(),
			IsSelfHosted:    false,
		})
	}

	// Use subscription.Plan as source of truth (more reliable than tenant.Plan)
	plan := sub.Plan
	if plan == "" {
		plan = tenant.Plan
	}
	if plan == "" {
		plan = model.PlanFree
	}
	limits, _ := h.subRepo.GetPlanLimits(ctx, plan)

	return c.JSON(http.StatusOK, SubscriptionResponse{
		HasSubscription: true,
		Subscription:    sub,
		Plan:            plan,
		Limits:          limits,
		BillingEnabled:  h.cfg.IsBillingEnabled(),
		IsSelfHosted:    false,
	})
}

// CheckoutRequest represents a checkout request
type CheckoutRequest struct {
	Plan string `json:"plan" validate:"required,oneof=starter pro team"`
}

// CheckoutResponse contains the checkout URL
type CheckoutResponse struct {
	URL string `json:"url"`
}

// CreateCheckout creates a Lemon Squeezy checkout URL
func (h *BillingHandler) CreateCheckout(c echo.Context) error {
	tc := middleware.NewTenantContext(c)

	// Not available in self-hosted mode
	if tc.IsSelfHosted() {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "billing not available in self-hosted mode",
		})
	}

	// Check if billing is enabled
	if !h.cfg.IsBillingEnabled() {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "billing not enabled",
		})
	}

	var req CheckoutRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	// Get variant ID for plan
	variantID := h.planToVariant(req.Plan)
	if variantID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid plan"})
	}

	// Build checkout URL with custom data
	// Format: https://{store}.lemonsqueezy.com/checkout/buy/{variant_id}?checkout[custom][tenant_id]={tenant_id}
	checkoutURL := fmt.Sprintf(
		"https://sbomhub.lemonsqueezy.com/checkout/buy/%s?checkout[custom][tenant_id]=%s",
		variantID,
		tc.TenantID().String(),
	)

	return c.JSON(http.StatusOK, CheckoutResponse{URL: checkoutURL})
}

// GetPortalURL returns the Lemon Squeezy customer portal URL
func (h *BillingHandler) GetPortalURL(c echo.Context) error {
	ctx := c.Request().Context()
	tc := middleware.NewTenantContext(c)

	// Not available in self-hosted mode
	if tc.IsSelfHosted() {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "billing not available in self-hosted mode",
		})
	}

	// Get subscription
	sub, err := h.subRepo.GetByTenantID(ctx, tc.TenantID())
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "no subscription found"})
	}

	// Build customer portal URL
	// Lemon Squeezy provides a customer portal at /billing
	portalURL := fmt.Sprintf(
		"https://sbomhub.lemonsqueezy.com/billing?customer_id=%s",
		sub.LSCustomerID,
	)

	return c.JSON(http.StatusOK, map[string]string{"url": portalURL})
}

// GetUsage returns current usage statistics
func (h *BillingHandler) GetUsage(c echo.Context) error {
	ctx := c.Request().Context()
	tc := middleware.NewTenantContext(c)

	tenant := tc.Tenant()
	if tenant == nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "tenant not found"})
	}

	// Get tenant with stats
	stats, err := h.tenantRepo.GetWithStats(ctx, tc.TenantID())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get usage"})
	}

	// Get plan limits
	limits, _ := h.subRepo.GetPlanLimits(ctx, tenant.Plan)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"users": map[string]interface{}{
			"current": stats.UserCount,
			"limit":   limits.MaxUsers,
		},
		"projects": map[string]interface{}{
			"current": stats.ProjectCount,
			"limit":   limits.MaxProjects,
		},
		"plan":        tenant.Plan,
		"isSelfHosted": tc.IsSelfHosted(),
	})
}

// planToVariant maps plan name to Lemon Squeezy variant ID
func (h *BillingHandler) planToVariant(plan string) string {
	switch plan {
	case model.PlanStarter:
		return h.cfg.LemonSqueezyStarterVariant
	case model.PlanPro:
		return h.cfg.LemonSqueezyProVariant
	case model.PlanTeam:
		return h.cfg.LemonSqueezyTeamVariant
	default:
		return ""
	}
}

// SelectFreePlan explicitly sets the tenant's plan to free
func (h *BillingHandler) SelectFreePlan(c echo.Context) error {
	ctx := c.Request().Context()
	tc := middleware.NewTenantContext(c)

	// Not applicable in self-hosted mode
	if tc.IsSelfHosted() {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "not applicable in self-hosted mode",
		})
	}

	tenant := tc.Tenant()
	if tenant == nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "tenant not found"})
	}

	// Set plan to free
	if err := h.tenantRepo.UpdatePlan(ctx, tc.TenantID(), model.PlanFree); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update plan"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok", "plan": model.PlanFree})
}

// SyncSubscriptionRequest represents a manual sync request
type SyncSubscriptionRequest struct {
	LSSubscriptionID string `json:"ls_subscription_id"`
}

// SyncSubscription syncs subscription from Lemon Squeezy API
// This is a recovery mechanism when webhook fails
func (h *BillingHandler) SyncSubscription(c echo.Context) error {
	ctx := c.Request().Context()
	tc := middleware.NewTenantContext(c)

	if tc.IsSelfHosted() {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "not available in self-hosted mode"})
	}

	if !h.cfg.IsBillingEnabled() {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "billing not enabled"})
	}

	tenant := tc.Tenant()
	if tenant == nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "tenant not found"})
	}

	tenantID := tc.TenantID()

	// Check if request body contains ls_subscription_id for manual sync
	var req SyncSubscriptionRequest
	if err := c.Bind(&req); err == nil && req.LSSubscriptionID != "" {
		return h.syncBySubscriptionID(c, ctx, tenantID, req.LSSubscriptionID)
	}

	// Try to fetch subscription directly from Lemon Squeezy API
	sub, err := h.fetchLemonSqueezySubscriptionByID(req.LSSubscriptionID)
	if err != nil {
		slog.Error("failed to fetch subscription from Lemon Squeezy", "error", err)
		// Return helpful error message
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":  "manual_required",
			"message": "自動同期に失敗しました。Lemon SqueezyダッシュボードからサブスクリプションIDを入力してください。",
			"help":    "https://app.lemonsqueezy.com → Subscriptions から ID を確認できます",
		})
	}

	if sub == nil {
		return c.JSON(http.StatusOK, map[string]string{
			"status":  "no_subscription",
			"message": "サブスクリプションが見つかりませんでした",
		})
	}

	// Determine plan from variant name
	plan := h.variantNameToPlan(sub.Attributes.VariantName)

	// Check if subscription already exists
	existingSub, _ := h.subRepo.GetByLSSubscriptionID(ctx, sub.ID)
	if existingSub != nil {
		// Update existing subscription
		existingSub.Status = sub.Attributes.Status
		existingSub.Plan = plan
		existingSub.UpdatedAt = time.Now()
		if err := h.subRepo.Update(ctx, existingSub); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
		}
	} else {
		// Create new subscription
		now := time.Now()
		newSub := &model.Subscription{
			ID:               uuid.New(),
			TenantID:         tenantID,
			LSSubscriptionID: sub.ID,
			LSCustomerID:     fmt.Sprintf("%d", sub.Attributes.CustomerID),
			LSVariantID:      fmt.Sprintf("%d", sub.Attributes.VariantID),
			LSProductID:      fmt.Sprintf("%d", sub.Attributes.ProductID),
			Status:           sub.Attributes.Status,
			Plan:             plan,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if err := h.subRepo.Create(ctx, newSub); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create subscription"})
		}
	}

	// Update tenant plan
	if err := h.tenantRepo.UpdatePlan(ctx, tenantID, plan); err != nil {
		slog.Error("failed to update tenant plan during sync", "error", err)
	}

	slog.Info("subscription synced successfully", "tenant_id", tenantID, "plan", plan)

	return c.JSON(http.StatusOK, map[string]string{
		"status": "synced",
		"plan":   plan,
	})
}

// syncBySubscriptionID syncs a specific subscription by its Lemon Squeezy ID
func (h *BillingHandler) syncBySubscriptionID(c echo.Context, ctx context.Context, tenantID uuid.UUID, lsSubID string) error {
	sub, err := h.fetchLemonSqueezySubscriptionByID(lsSubID)
	if err != nil {
		slog.Error("failed to fetch subscription by ID", "error", err, "ls_subscription_id", lsSubID)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Failed to fetch subscription: %v", err)})
	}

	if sub == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Subscription not found in Lemon Squeezy"})
	}

	// Determine plan from variant name
	plan := h.variantNameToPlan(sub.Attributes.VariantName)

	// Check if subscription already exists in our DB
	existingSub, _ := h.subRepo.GetByLSSubscriptionID(ctx, sub.ID)
	if existingSub != nil {
		// Update existing
		existingSub.Status = sub.Attributes.Status
		existingSub.Plan = plan
		existingSub.TenantID = tenantID // Link to current tenant
		existingSub.UpdatedAt = time.Now()
		if err := h.subRepo.Update(ctx, existingSub); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
		}
	} else {
		// Create new
		now := time.Now()
		newSub := &model.Subscription{
			ID:               uuid.New(),
			TenantID:         tenantID,
			LSSubscriptionID: sub.ID,
			LSCustomerID:     fmt.Sprintf("%d", sub.Attributes.CustomerID),
			LSVariantID:      fmt.Sprintf("%d", sub.Attributes.VariantID),
			LSProductID:      fmt.Sprintf("%d", sub.Attributes.ProductID),
			Status:           sub.Attributes.Status,
			Plan:             plan,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if err := h.subRepo.Create(ctx, newSub); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create subscription"})
		}
	}

	// Update tenant plan
	if err := h.tenantRepo.UpdatePlan(ctx, tenantID, plan); err != nil {
		slog.Error("failed to update tenant plan", "error", err)
	}

	slog.Info("subscription synced by ID", "tenant_id", tenantID, "ls_subscription_id", lsSubID, "plan", plan)

	return c.JSON(http.StatusOK, map[string]string{
		"status": "synced",
		"plan":   plan,
	})
}

// fetchLemonSqueezySubscriptionByID fetches a single subscription by ID
func (h *BillingHandler) fetchLemonSqueezySubscriptionByID(subID string) (*LSAPISubscription, error) {
	if subID == "" {
		return nil, fmt.Errorf("subscription ID is required")
	}

	url := fmt.Sprintf("https://api.lemonsqueezy.com/v1/subscriptions/%s", subID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+h.cfg.LemonSqueezyAPIKey)
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Content-Type", "application/vnd.api+json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Lemon Squeezy API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data LSAPISubscription `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// LSAPISubscription represents a subscription from Lemon Squeezy API
type LSAPISubscription struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		StoreID     int    `json:"store_id"`
		CustomerID  int    `json:"customer_id"`
		ProductID   int    `json:"product_id"`
		VariantID   int    `json:"variant_id"`
		Status      string `json:"status"`
		VariantName string `json:"variant_name"`
		ProductName string `json:"product_name"`
	} `json:"attributes"`
}

// LSAPIResponse represents the Lemon Squeezy API response
type LSAPIResponse struct {
	Data  []LSAPISubscription `json:"data"`
	Meta  json.RawMessage     `json:"meta"`
	Links json.RawMessage     `json:"links"`
}

// fetchLemonSqueezySubscriptions fetches all subscriptions from Lemon Squeezy API
func (h *BillingHandler) fetchLemonSqueezySubscriptions() ([]LSAPISubscription, error) {
	req, err := http.NewRequest("GET", "https://api.lemonsqueezy.com/v1/subscriptions", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+h.cfg.LemonSqueezyAPIKey)
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Filter by store if configured
	if h.cfg.LemonSqueezyStoreID != "" {
		q := req.URL.Query()
		q.Add("filter[store_id]", h.cfg.LemonSqueezyStoreID)
		req.URL.RawQuery = q.Encode()
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Lemon Squeezy API error: %d - %s", resp.StatusCode, string(body))
	}

	var apiResp LSAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	return apiResp.Data, nil
}

// variantNameToPlan maps Lemon Squeezy variant name to plan name
func (h *BillingHandler) variantNameToPlan(variantName string) string {
	name := strings.ToLower(variantName)

	if strings.Contains(name, "team") {
		return model.PlanTeam
	}
	if strings.Contains(name, "pro") {
		return model.PlanPro
	}
	if strings.Contains(name, "starter") {
		return model.PlanStarter
	}
	return model.PlanFree
}
