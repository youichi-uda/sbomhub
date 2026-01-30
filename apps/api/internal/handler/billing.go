package handler

import (
	"fmt"
	"net/http"

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
