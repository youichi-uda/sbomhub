package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// lemonSqueezyDefaultBaseURL is the production Lemon Squeezy REST API root.
// It is the single source of truth for the default; BillingHandler.lsBaseURL
// only ever deviates from it when a test injects a stub (see
// WithLemonSqueezyBaseURL). Mirrors the client.DefaultOSVBaseURL /
// githubDefaultBaseURL convention used elsewhere in this package.
const lemonSqueezyDefaultBaseURL = "https://api.lemonsqueezy.com"

// BillingHandler handles billing-related endpoints
type BillingHandler struct {
	cfg        *config.Config
	tenantRepo *repository.TenantRepository
	subRepo    *repository.SubscriptionRepository

	// lsBaseURL is the Lemon Squeezy REST API root used by
	// fetchLemonSqueezySubscriptionByID. Defaults to
	// lemonSqueezyDefaultBaseURL; overridden only by tests via
	// WithLemonSqueezyBaseURL so the sync endpoint can be driven end-to-end
	// against an httptest stub instead of the live billing provider.
	lsBaseURL string
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
		lsBaseURL:  lemonSqueezyDefaultBaseURL,
	}
}

// WithLemonSqueezyBaseURL overrides the Lemon Squeezy REST API root. An empty
// string resets the handler to lemonSqueezyDefaultBaseURL, so a misconfigured
// caller can never end up issuing requests to a relative URL.
func (h *BillingHandler) WithLemonSqueezyBaseURL(base string) *BillingHandler {
	if base == "" {
		h.lsBaseURL = lemonSqueezyDefaultBaseURL
		return h
	}
	h.lsBaseURL = strings.TrimRight(base, "/")
	return h
}

// SubscriptionResponse represents the subscription info returned to clients
type SubscriptionResponse struct {
	HasSubscription bool                `json:"has_subscription"`
	Subscription    *model.Subscription `json:"subscription,omitempty"`
	Plan            string              `json:"plan"`
	Limits          *model.PlanLimits   `json:"limits"`
	BillingEnabled  bool                `json:"billing_enabled"`
	IsSelfHosted    bool                `json:"is_self_hosted"`
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

// checkoutClaimTokenBytes is the entropy behind a claim token. 32 bytes is
// the same budget the API-key generator works from and is far beyond
// guessing: the token is the only thing standing between a checkout and the
// tenant it bills.
const checkoutClaimTokenBytes = 32

// newCheckoutClaimToken returns a fresh claim token (hex).
func newCheckoutClaimToken() (string, error) {
	buf := make([]byte, checkoutClaimTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate checkout claim token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// hashCheckoutClaimToken is the one-way mapping stored in
// subscription_checkout_claims.token_hash. Mirrors the api_keys convention:
// the table is read from an unauthenticated route, so it must not hold
// anything usable as a credential.
func hashCheckoutClaimToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateCheckout creates a Lemon Squeezy checkout for the calling tenant and
// returns the buyer-facing URL.
//
// M47 (High) — this used to ASSEMBLE the URL locally:
//
//	https://sbomhub.lemonsqueezy.com/checkout/buy/<variant>
//	  ?checkout[custom][tenant_id]=<caller's tenant>
//
// and handleSubscriptionCreated billed whatever tenant came back in
// `meta.custom_data`. The HMAC on that delivery proves Lemon Squeezy sent it
// and nothing else: the custom payload had made a round trip through the
// BUYER's browser, where `checkout[custom][...]` is a documented, editable
// URL parameter (docs.lemonsqueezy.com/help/checkout/passing-custom-data,
// re-read 2026-07-28, which also confirms custom data comes back only in the
// webhook's `meta`). A buyer willing to pay could therefore attach their
// subscription to ANOTHER tenant — taking over its plan lifecycle, so a
// later cancel/expire downgrades the victim, and occupying its single
// subscription slot (`subscriptions` carries UNIQUE(tenant_id), migration
// 008) so the victim can no longer buy its own.
//
// Two changes, and the SECOND is the fix:
//
//  1. the checkout is now created server-to-server through
//     POST /v1/checkouts (docs.lemonsqueezy.com/api/checkouts/create-checkout,
//     fetched 2026-07-28), so the custom data is handed to the provider over
//     a channel the client is not on, and the URL we return is whatever that
//     authenticated call answered with. (The provider's documented example
//     URL carries `expires`/`signature` query parameters, but nothing here
//     verifies them — createLemonSqueezyCheckout only checks that the answer
//     is an absolute https URL. Treat it as "came from the provider over
//     TLS", not as "cryptographically bound".)
//
//  2. the custom data no longer NAMES A TENANT. It carries an opaque claim
//     token; subscription_checkout_claims maps its hash to the issuing
//     tenant server-side. This is what actually closes the finding, and it
//     is deliberately independent of (1): we have NOT verified whether
//     appending `?checkout[custom][...]` to a provider-issued checkout URL
//     overrides the stored custom data — the docs say nothing either way —
//     so the design does not depend on it being impossible. Even if a buyer
//     can inject custom fields, there is no tenant id to forge, and a token
//     they did not receive is not guessable.
//
// The residual (documented in docs/SAAS_SETUP.md §2.5): whoever holds the
// checkout URL can pay into the tenant that created it. The URL — not the
// token, which never leaves the server-to-server call — is what this endpoint
// returns, and only to an authenticated Owner/Admin. The outcome is a gift
// rather than a takeover, but it also consumes that tenant's single
// subscription slot, so it is the same class of bearer secret as a share
// link. That is what bounds the window: the provider checkout is created with
// expires_at = now + model.CheckoutClaimTTL.
func (h *BillingHandler) CreateCheckout(c echo.Context) error {
	ctx := c.Request().Context()
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

	// The store id is a relationship on the create-checkout call, so an
	// unset LEMONSQUEEZY_STORE_ID is a misconfiguration rather than
	// something to paper over: refusing here is better than building a
	// request the provider will reject with a message we would have to
	// forward.
	if h.cfg.LemonSqueezyStoreID == "" {
		slog.Error("billing: LEMONSQUEEZY_STORE_ID is not set; cannot create a checkout",
			"tenant_id", tc.TenantID())
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "billing is not fully configured"})
	}

	token, err := newCheckoutClaimToken()
	if err != nil {
		slog.Error("billing: failed to generate a checkout claim token", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create checkout"})
	}

	// Provider first, claim second. If the provider refuses we answer >= 400
	// and the buyer never receives a URL, so the (never-created) claim cannot
	// be missing for a checkout anyone holds. If the claim INSERT fails we
	// also answer >= 400 without returning the URL, which leaves an unused
	// checkout at the provider and no way to reach it — the safe direction.
	now := time.Now()
	checkoutExpiresAt := now.Add(model.CheckoutClaimTTL)
	checkoutURL, lsCheckoutID, err := h.createLemonSqueezyCheckout(ctx, variantID, token, checkoutExpiresAt)
	if err != nil {
		// The provider error can carry its raw response body; keep it in the
		// log only (same contract as the sync path, F44x).
		slog.Error("billing: failed to create checkout at Lemon Squeezy",
			"error", err, "tenant_id", tc.TenantID(), "plan", req.Plan, "variant_id", variantID)
		return c.JSON(http.StatusBadGateway, map[string]string{"error": "failed to create checkout"})
	}

	if err := h.subRepo.CreateCheckoutClaim(ctx, &model.CheckoutClaim{
		TokenHash:    hashCheckoutClaimToken(token),
		TenantID:     tc.TenantID(),
		Plan:         req.Plan,
		LSVariantID:  variantID,
		LSCheckoutID: lsCheckoutID,
		CreatedAt:    now,
		// The row outlives the provider-side cutoff by the grace window so a
		// delayed or replayed FIRST delivery for a payment the provider DID
		// accept still resolves (Codex round 3, Medium).
		ExpiresAt: checkoutExpiresAt.Add(model.CheckoutClaimGrace),
	}); err != nil {
		slog.Error("billing: failed to record the checkout claim",
			"error", err, "tenant_id", tc.TenantID(), "ls_checkout_id", lsCheckoutID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create checkout"})
	}

	slog.Info("checkout created", "tenant_id", tc.TenantID(), "plan", req.Plan,
		"ls_checkout_id", lsCheckoutID,
		"checkout_expires_at", checkoutExpiresAt,
		"claim_expires_at", checkoutExpiresAt.Add(model.CheckoutClaimGrace))

	return c.JSON(http.StatusOK, CheckoutResponse{URL: checkoutURL})
}

// lsCheckoutRelationship is one JSON:API relationship in the create-checkout
// request body.
type lsCheckoutRelationship struct {
	Data struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"data"`
}

// createLemonSqueezyCheckout performs POST /v1/checkouts and returns the
// buyer-facing URL plus the provider's checkout id.
//
// Request/response shape verified against
// docs.lemonsqueezy.com/api/checkouts/create-checkout on 2026-07-28.
//
// `expires_at` is deliberately NOT sent, so the checkout is perpetual on the
// provider side and the binding window is bounded solely by
// model.CheckoutClaimTTL — a value we control and can test. Sending it would
// add an unverified field to the one call standing between a customer and
// paying us; the acceptance of its format has not been exercised against the
// live API from this codebase.
func (h *BillingHandler) createLemonSqueezyCheckout(
	ctx context.Context, variantID, claimToken string, expiresAt time.Time,
) (checkoutURL, checkoutID string, err error) {
	type reqBody struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				CheckoutData struct {
					Custom map[string]string `json:"custom"`
				} `json:"checkout_data"`
				ExpiresAt string `json:"expires_at"`
			} `json:"attributes"`
			Relationships struct {
				Store   lsCheckoutRelationship `json:"store"`
				Variant lsCheckoutRelationship `json:"variant"`
			} `json:"relationships"`
		} `json:"data"`
	}

	var body reqBody
	body.Data.Type = "checkouts"
	// The ONLY custom field. Note what is absent: no tenant id, no user id,
	// nothing the buyer could rewrite into someone else's identifier.
	body.Data.Attributes.CheckoutData.Custom = map[string]string{"claim_token": claimToken}
	// "An ISO 8601 formatted date-time string indicating when the checkout
	// expires" (docs.lemonsqueezy.com/api/checkouts/create-checkout, fetched
	// 2026-07-28); the documented example is `2022-10-30T15:20:06Z`, which is
	// what RFC3339 on a UTC time produces. NOT exercised against the live API
	// from this codebase — if the provider ever rejects it, checkout creation
	// fails loudly with 502 and the raw provider body in the log, and the
	// field can be dropped (at the cost of reopening the perpetual-URL
	// residual in docs/SAAS_SETUP.md §2.5).
	body.Data.Attributes.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	body.Data.Relationships.Store.Data.Type = "stores"
	body.Data.Relationships.Store.Data.ID = h.cfg.LemonSqueezyStoreID
	body.Data.Relationships.Variant.Data.Type = "variants"
	body.Data.Relationships.Variant.Data.ID = variantID

	encoded, err := json.Marshal(&body)
	if err != nil {
		return "", "", fmt.Errorf("encode checkout request: %w", err)
	}

	base := h.lsBaseURL
	if base == "" {
		base = lemonSqueezyDefaultBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/checkouts", bytes.NewReader(encoded))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+h.cfg.LemonSqueezyAPIKey)
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Content-Type", "application/vnd.api+json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// The provider answers 201 on success; accept any 2xx and treat the rest
	// as a failure carrying a bounded excerpt for the log.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", "", fmt.Errorf("lemon squeezy checkout API error: %d - %s", resp.StatusCode, string(excerpt))
	}

	var out struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				URL string `json:"url"`
			} `json:"attributes"`
		} `json:"data"`
	}
	// Bounded read: this response is small and we do not want a
	// misbehaving/compromised endpoint to be able to exhaust memory here.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", "", fmt.Errorf("decode checkout response: %w", err)
	}

	// The URL is handed straight to a browser, so refuse anything that is not
	// an absolute https URL rather than forwarding whatever arrived. This is
	// a sanity check on OUR side of a call we authenticated over TLS — it
	// does NOT pin the host (stores can serve checkouts from a custom domain)
	// and does NOT verify the provider's expires/signature parameters.
	parsed, err := url.Parse(out.Data.Attributes.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", "", fmt.Errorf("checkout response carried no usable https url (%q)", out.Data.Attributes.URL)
	}

	return out.Data.Attributes.URL, out.Data.ID, nil
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
		"plan":         tenant.Plan,
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

// endedSubscriptionStatus is the ONLY subscription status that means "this
// tenant is no longer on a paid contract". Every other status — including
// `cancelled` — still counts as live for the purposes of SelectFreePlan.
//
// That line is not invented here: handleSubscriptionExpired is the single
// webhook that downgrades tenants.plan to free, handleSubscriptionCancelled
// deliberately does not ("still active until ends_at"), and `paused` /
// `past_due` / `unpaid` keep their plan today. entitlementPlan draws the same
// line. Drawing a different one here would make this endpoint disagree with
// the webhook — the class of bug M46 spent three rounds on.
const endedSubscriptionStatus = model.StatusExpired

// SelectFreePlan explicitly sets the tenant's plan to free.
//
// M47 (High) — this used to write tenants.plan unconditionally, from any
// authenticated role, with no look at `subscriptions`:
//
//   - the route now carries appmw.RequireAdmin() (cmd/server/main.go), so a
//     Viewer or Member can no longer strip their own tenant of the features
//     it is paying for;
//   - a LIVE subscription now refuses the downgrade with 409.
//
// Why refuse rather than downgrade-and-cancel (product decision, deliberately
// the safest option — see docs/SAAS_SETUP.md §2.5): this endpoint has never
// talked to Lemon Squeezy, so "allow" means the tenant keeps being charged
// while losing the entitlement, AND the local state disagrees with
// `subscriptions` until the next webhook overwrites it. The alternative —
// cancelling at the provider from here — is a new outbound money-affecting
// call that needs its own idempotency and failure handling; it is not
// something to bolt onto a plan-selection endpoint. The supported path is to
// cancel in the customer portal (GET /subscription/portal); the existing
// subscription_expired webhook then performs the downgrade at period end.
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

	// Check and write in ONE statement. Reading `subscriptions` first and
	// updating after left a window in which the Lemon Squeezy webhook — which
	// runs outside this request's TenantTx — creates or reactivates a
	// subscription, and the request would answer 200 while the tenant keeps
	// being charged on a free entitlement (Codex round 1, Medium).
	//
	// This NARROWS that window rather than closing it: under READ COMMITTED an
	// INSERT that has not committed yet is invisible to the guard's subquery
	// too. See UpdatePlanUnlessSubscriptionLive for the measured behaviour of
	// both interleavings.
	//
	// The endedStatus argument keeps the policy here, next to
	// endedSubscriptionStatus, rather than in the repository.
	applied, err := h.tenantRepo.UpdatePlanUnlessSubscriptionLive(
		ctx, tc.TenantID(), model.PlanFree, endedSubscriptionStatus)
	if err != nil {
		slog.Error("billing: guarded plan update failed during select-free",
			"error", err, "tenant_id", tc.TenantID())
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update plan"})
	}
	if !applied {
		// Refused. Re-read only to name the blocking status in the log and the
		// response; the refusal itself has already been decided above, so a
		// failure here is not worth failing the request over.
		status := "unknown"
		if sub, lerr := h.subRepo.GetByTenantID(ctx, tc.TenantID()); lerr == nil && sub != nil {
			status = sub.Status
		} else if lerr != nil && !errors.Is(lerr, sql.ErrNoRows) {
			slog.Warn("billing: could not read the blocking subscription for diagnostics",
				"error", lerr, "tenant_id", tc.TenantID())
		}
		slog.Warn("billing: select-free refused, subscription is still live",
			"tenant_id", tc.TenantID(), "status", status, "user_id", tc.UserID())
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "active subscription",
			"message": "有効なサブスクリプションがあるため free プランに変更できません。" +
				"Lemon Squeezy のカスタマーポータル（GET /api/v1/subscription/portal）から解約してください。" +
				"解約後、契約期間の終了時に自動で free へ移行します。",
			"status": status,
		})
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

	// Check if request body contains ls_subscription_id for manual sync.
	// This is the ONLY sync path: without an id there is nothing to look up
	// (Lemon Squeezy has no "which subscription belongs to this tenant?"
	// query — the link is created at checkout time via
	// checkout[custom][tenant_id] and delivered back only over the webhook).
	//
	// M46: the code that used to live below this point carried a second copy
	// of the cross-tenant escalation fixed in syncBySubscriptionID. For any
	// well-formed request it was unreachable — the old guard was
	// `Bind(&req) == nil && id != ""`, so the fall-through always ran
	// fetchLemonSqueezySubscriptionByID("") which returns "subscription ID is
	// required" and produced `manual_required`. It was NOT unreachable for
	// malformed input, though (Codex round 1, Low): Go's JSON decoder can
	// populate a field and then fail on a later token — e.g. a duplicate
	// `ls_subscription_id` whose second occurrence has the wrong type — which
	// left `err != nil` with a NON-empty id and dropped straight into the
	// escalating branch. Hence the explicit Bind error below (matching
	// CreateCheckout's 400) rather than a silent fall-through, and the
	// deletion of the duplicate branch rather than fixing it twice.
	//
	// The `manual_required` response shape is preserved because the billing
	// page keys off it to reveal the manual subscription-id input
	// (apps/web/src/app/[locale]/(dashboard)/billing/page.tsx).
	var req SyncSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}
	if req.LSSubscriptionID != "" {
		return h.syncBySubscriptionID(c, ctx, tenantID, req.LSSubscriptionID)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "manual_required",
		"message": "自動同期に失敗しました。Lemon SqueezyダッシュボードからサブスクリプションIDを入力してください。",
		"help":    "https://app.lemonsqueezy.com → Subscriptions から ID を確認できます",
	})
}

// syncNotLinkedSentinel is the single refusal answer of the manual sync
// endpoint. "no such subscription in Lemon Squeezy", "this subscription
// belongs to another tenant" and "this subscription has never been linked
// here" all collapse into it.
//
// Why one sentinel (M46): Lemon Squeezy subscription ids are short
// sequential integers and the store-scoped API key means a caller can only
// name ids belonging to OUR store. Distinguishable answers would therefore
// turn this endpoint into an enumerator for "which of the store's
// subscriptions are already claimed, and by implication how many paying
// tenants exist" — a cross-tenant leak that costs nothing to avoid. Same
// discipline as the triage/SSVC 404 sentinels (#F10).
func syncNotLinkedSentinel(c echo.Context) error {
	return c.JSON(http.StatusNotFound, map[string]string{
		"error":   "subscription not found",
		"message": "このサブスクリプションはこのテナントに紐付いていません。Lemon Squeezy の購入時に発行された紐付けが見つからない場合は、サポートにお問い合わせください。",
	})
}

// syncBySubscriptionID re-syncs a subscription that is ALREADY linked to the
// calling tenant. It is a recovery mechanism for a dropped
// `subscription_created` / `subscription_updated` webhook — not a way to
// claim a subscription.
//
// M46 — why this cannot create or re-parent links:
//
// The tenant⇄subscription link is established exactly once, at checkout —
// since M47 through an opaque claim token that CreateCheckout hands to the
// provider server-to-server and stores, hashed, in
// subscription_checkout_claims. Lemon Squeezy returns custom data ONLY in
// the webhook envelope's `meta.custom_data`, so the webhook remains the only
// place a link can be made. The REST subscription object this handler fetches has
// no custom_data field at all — verified against
// docs.lemonsqueezy.com/api/subscriptions/the-subscription-object on
// 2026-07-27, whose complete attribute list is store_id, customer_id,
// order_id, order_item_id, product_id, variant_id, product_name,
// variant_name, user_name, user_email, status, status_formatted, card_brand,
// card_last_four, payment_processor, pause, cancelled, trial_ends_at,
// billing_anchor, first_subscription_item, urls, renews_at, ends_at,
// created_at, updated_at, test_mode. The order object (reachable via
// order_id) has no custom_data either, and the provider's own "Passing
// custom data" page states custom data is returned in the `meta` field of
// webhooks. `user_email` is the only identity-ish attribute, and it names a
// Lemon Squeezy CUSTOMER, not a tenant: `tenants` carries no billing email
// column, a user may belong to several tenants, and the address is not
// verified against anything we control.
//
// So an API answer can prove "this subscription exists in our store"; it can
// never prove "it belongs to the caller". Rather than invent a weaker proof,
// the endpoint refuses everything it cannot verify against a link the
// webhook already made. See docs/SAAS_SETUP.md for the operator-facing
// consequence.
func (h *BillingHandler) syncBySubscriptionID(c echo.Context, ctx context.Context, tenantID uuid.UUID, lsSubID string) error {
	// Step 1 — resolve the caller's OWN link with a TENANT-SCOPED read, and
	// refuse anything that is not it, before the provider is contacted.
	//
	// Ordering is load-bearing (M46 Codex round 1, Medium). Doing the
	// provider fetch first and the ownership check second made the identical
	// 404 an execution-path oracle: a subscription id unknown to Lemon
	// Squeezy short-circuited after one outbound call, while a known one
	// went on to hit the database — observable in latency, and divergent
	// again during a database outage (500 for a known id, 404 for an unknown
	// one). Resolving locally first means every refusal executes exactly the
	// same statements, whatever id was supplied.
	//
	// It also shrinks the surface in two further ways: this handler no
	// longer calls the tenant-UNSCOPED GetByLSSubscriptionID at all (that
	// lookup exists for the webhook, which has no tenant context), and an
	// unauthorised caller can no longer make the server issue an outbound
	// request to Lemon Squeezy for an id of their choosing.
	//
	// `subscriptions` carries UNIQUE(tenant_id) (migration 008), so a tenant
	// has at most one subscription and this single read is the whole
	// ownership question. Only sql.ErrNoRows means "no subscription"; any
	// other error is a transient failure that must not be misread as one.
	own, err := h.subRepo.GetByTenantID(ctx, tenantID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.Error("billing: subscription lookup failed during sync",
			"error", err, "tenant_id", tenantID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up subscription"})
	}

	if own == nil || own.LSSubscriptionID != lsSubID {
		// Either the caller has no subscription at all, or it named one that
		// is not theirs — another tenant's, or one that has never been linked
		// here. All of it is refused with the one sentinel, and none of it
		// reaches the provider. Ownership of an unlinked subscription is
		// unprovable (see the doc comment), so there is nothing to fall back
		// on; the caller's own id is the only thing this endpoint accepts.
		slog.Warn("billing: manual sync refused, subscription is not the caller's",
			"tenant_id", tenantID,
			"requested_ls_subscription_id", lsSubID,
			"has_own_subscription", own != nil,
			"ip", c.RealIP())
		return syncNotLinkedSentinel(c)
	}

	// Step 2 — the id is the caller's own; refresh it from the provider.
	sub, err := h.fetchLemonSqueezySubscriptionByID(lsSubID)
	if err != nil {
		// F44x: the Lemon Squeezy API error (which can carry the raw upstream
		// HTTP status + response body from fetchLemonSqueezySubscriptionByID)
		// must not reach the client. The raw error is already captured in the
		// server log above; return a generic message only.
		slog.Error("billing: fetch subscription by ID failed", "error", err, "ls_subscription_id", lsSubID)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to fetch subscription"})
	}

	if sub == nil {
		// Our link points at a subscription Lemon Squeezy no longer knows.
		// That is an operator-facing data anomaly, not something the caller
		// can act on — same sentinel, loud log.
		slog.Warn("billing: linked subscription is unknown to Lemon Squeezy",
			"tenant_id", tenantID, "ls_subscription_id", lsSubID)
		return syncNotLinkedSentinel(c)
	}

	// Step 2b — re-read the row before writing (M46 Codex round 6).
	//
	// The provider call above can take up to 30s, and the webhook route runs
	// OUTSIDE this transaction, so a subscription_cancelled / _expired /
	// _paused delivery can land while we wait. `own` was read BEFORE that
	// call and Update writes the WHOLE row, so writing it back would silently
	// revert whatever the webhook just recorded (renews_at, ends_at,
	// cancelled_at, periods). Checking ownership before the fetch — which is
	// what removes the enumeration oracle and the unauthorised outbound call
	// — is what widened that window, so it is closed here rather than by
	// going back to fetch-first.
	//
	// On its own this narrows the window back to the ordinary read-then-write
	// gap instead of the length of an HTTP call. The revision claim in step 2c
	// below is the other half added in M47: a webhook that applied a NEWER
	// provider revision while we waited now wins outright, instead of being
	// overwritten by the snapshot this handler is holding.
	fresh, err := h.subRepo.GetByTenantID(ctx, tenantID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.Error("billing: subscription re-read failed during sync",
			"error", err, "tenant_id", tenantID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up subscription"})
	}
	if fresh == nil || fresh.LSSubscriptionID != lsSubID {
		// The link was deleted or re-pointed while we were talking to the
		// provider. The ownership proof no longer holds — refuse rather than
		// write against a row we never verified.
		slog.Warn("billing: subscription link changed during the provider call, sync abandoned",
			"tenant_id", tenantID, "ls_subscription_id", lsSubID, "still_linked", fresh != nil)
		return syncNotLinkedSentinel(c)
	}
	own = fresh

	// Step 2c — claim the provider revision (M47 W3 #4, Codex round 1 High).
	//
	// Without this, sync wrote newer provider state while leaving the
	// watermark at whatever the last webhook set: stored R2, sync applies the
	// provider's current R3 state, watermark stays R2 — and a replayed R2
	// `subscription_updated` is then accepted as an equal revision and undoes
	// the sync. Claiming R3 here makes the two paths share one ordering.
	//
	// A refusal means a webhook applied something NEWER while we were talking
	// to the provider. Its state supersedes the snapshot we hold, so there is
	// nothing to write and nothing to retry.
	//
	// Deliberate limit, same as the webhook gate: a provider object with no
	// parseable updated_at cannot be ordered and is applied without claiming.
	if rev := parseTime(sub.Attributes.UpdatedAt); rev != nil {
		apply, err := h.subRepo.ClaimProviderRevision(ctx, own.ID, *rev)
		if err != nil {
			slog.Error("billing: revision claim failed during sync",
				"error", err, "tenant_id", tenantID, "ls_subscription_id", lsSubID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to order sync"})
		}
		if !apply {
			slog.Info("billing: sync skipped, a newer webhook revision is already applied",
				"tenant_id", tenantID, "ls_subscription_id", lsSubID,
				"provider_updated_at", sub.Attributes.UpdatedAt)
			return c.JSON(http.StatusOK, map[string]string{
				"status":  "up_to_date",
				"message": "Lemon Squeezy から取得した状態より新しい Webhook が既に適用済みのため、同期は不要でした。",
			})
		}
	} else {
		slog.Warn("billing: provider subscription carries no parseable updated_at; syncing without ordering",
			"tenant_id", tenantID, "ls_subscription_id", lsSubID,
			"raw_updated_at", sub.Attributes.UpdatedAt)
	}

	// Step 3 — ownership confirmed. TenantID is NOT reassigned: the stored
	// link is authoritative and this endpoint only refreshes provider-side
	// state.
	//
	// Two DIFFERENT plan values, deliberately (M46 Codex round 4):
	//
	//   - subscriptions.plan records WHAT WAS BOUGHT. Every webhook handler
	//     writes productNameToPlan(product) there and nothing else, so sync
	//     must too. The first cut of the expiry fix wrote the entitlement
	//     (free) into this column instead, and that desynchronised it from
	//     the webhook with a nasty consequence: handleSubscriptionUpdated
	//     upgrades the tenant whenever `newPlan != previousPlan`, reading
	//     previousPlan out of this very column. Lemon Squeezy emits
	//     subscription_updated alongside subscription_expired, so a caller
	//     who synced in between saw free != team and got Team back for
	//     nothing. Pinned by
	//     TestBillingSync_ExpiredSyncThenUpdatedWebhookStaysFree.
	//   - tenants.plan is the ENTITLEMENT — the field the limit/feature
	//     gates read (middleware/tenant.go) and the one
	//     handleSubscriptionExpired sets to free. This is where the
	//     status-aware value belongs, and what the response reports.
	productPlan := h.productNameToPlan(sub.Attributes.ProductName)
	plan := h.entitlementPlan(sub.Attributes.ProductName, sub.Attributes.Status)
	own.Status = sub.Attributes.Status
	own.Plan = productPlan
	own.UpdatedAt = time.Now()
	if err := h.subRepo.Update(ctx, own); err != nil {
		// Includes repository.ErrSubscriptionNotFound: the row moved or was
		// deleted between the read above and this write. Fail the request —
		// the tenant plan update below must not run on an unwritten row.
		slog.Error("billing: failed to update subscription during sync",
			"error", err, "tenant_id", tenantID, "ls_subscription_id", lsSubID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
	}

	// Update tenant plan. Only reachable once the subscription row is proven
	// to belong to this tenant AND the write above actually landed.
	//
	// M46 (Codex round 3): a failure here used to be logged and then
	// answered with `{"status":"synced"}`, which is a lie — the subscription
	// row moved but tenants.plan (what the limit/feature gates read) did
	// not. Returning 500 makes TenantTx roll BOTH writes back (it treats any
	// >=400 response as a rollback signal, see middleware/tx.go), so the two
	// halves of the billing state can no longer diverge on this path.
	if err := h.tenantRepo.UpdatePlan(ctx, tenantID, plan); err != nil {
		slog.Error("billing: failed to update tenant plan during sync",
			"error", err, "tenant_id", tenantID, "plan", plan)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update plan"})
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

	base := h.lsBaseURL
	if base == "" {
		base = lemonSqueezyDefaultBaseURL
	}
	url := fmt.Sprintf("%s/v1/subscriptions/%s", base, subID)
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
		return nil, fmt.Errorf("lemon squeezy API error: %d - %s", resp.StatusCode, string(body))
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
		// UpdatedAt is the provider's revision of this subscription — the
		// same clock the webhook's data.attributes.updated_at carries. Sync
		// claims it (M47 W3 #4) so that re-syncing does not leave the
		// watermark behind the state it just wrote, which would let a
		// replayed older webhook be accepted afterwards.
		UpdatedAt string `json:"updated_at"`
	} `json:"attributes"`
}

// entitlementPlan maps a Lemon Squeezy subscription to the plan the tenant is
// actually entitled to, from BOTH the product name and the subscription
// status. Its result belongs in tenants.plan ONLY — subscriptions.plan keeps
// recording the purchased product, see the two-values comment in
// syncBySubscriptionID.
//
// M46 (Codex round 3, High): the manual sync path used productNameToPlan
// alone and ignored status entirely. A tenant whose Team subscription had
// EXPIRED — and had therefore already been downgraded to free by
// handleSubscriptionExpired — could POST its own stored ls_subscription_id
// and get Team back, for free, as often as it liked. The stale row is no
// guard either: handleSubscriptionExpired writes only `status`, so
// subscriptions.plan stays "team" through expiry.
//
// The policy below is NOT invented here; it is the policy the webhook
// handlers already implement, which is what a recovery endpoint must
// reproduce:
//
//   - expired  → free. handleSubscriptionExpired calls UpdatePlan(PlanFree).
//   - cancelled → keep the product plan. handleSubscriptionCancelled
//     deliberately does not downgrade ("still active until ends_at").
//   - paused / past_due / unpaid / on_trial / active → keep the product
//     plan. No webhook handler downgrades for these today.
//
// Tightening cancelled/paused/past_due/unpaid is a product decision, not a
// bug fix, and is deliberately left alone here: doing it in one path only
// would make sync and webhook disagree, which is the exact class of bug this
// function exists to close. See docs/SAAS_SETUP.md residuals.
func (h *BillingHandler) entitlementPlan(productName, status string) string {
	if status == model.StatusExpired {
		return model.PlanFree
	}
	return h.productNameToPlan(productName)
}

// productNameToPlan maps Lemon Squeezy product name to plan name
func (h *BillingHandler) productNameToPlan(productName string) string {
	name := strings.ToLower(productName)

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
