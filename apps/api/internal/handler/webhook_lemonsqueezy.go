package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
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
	ID         string              `json:"id"`
	Type       string              `json:"type"`
	Attributes LSSubscriptionAttrs `json:"attributes"`
}

// LSSubscriptionAttrs contains subscription attributes
type LSSubscriptionAttrs struct {
	StoreID         int    `json:"store_id"`
	CustomerID      int    `json:"customer_id"`
	OrderID         int    `json:"order_id"`
	ProductID       int    `json:"product_id"`
	VariantID       int    `json:"variant_id"`
	ProductName     string `json:"product_name"`
	VariantName     string `json:"variant_name"`
	Status          string `json:"status"`
	StatusFormatted string `json:"status_formatted"`
	BillingAnchor   int    `json:"billing_anchor"`
	RenewsAt        string `json:"renews_at"`
	EndsAt          string `json:"ends_at"`
	TrialEndsAt     string `json:"trial_ends_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// Handle processes Lemon Squeezy webhook events
func (h *LemonSqueezyWebhookHandler) Handle(c echo.Context) error {
	// Skip in self-hosted mode
	if h.cfg.IsSelfHosted() {
		slog.Info("webhook skipped: self-hosted mode")
		return c.JSON(http.StatusOK, map[string]string{"status": "skipped", "reason": "self-hosted mode"})
	}

	// Skip if billing not enabled
	if !h.cfg.IsBillingEnabled() {
		slog.Info("webhook skipped: billing not enabled")
		return c.JSON(http.StatusOK, map[string]string{"status": "skipped", "reason": "billing not enabled"})
	}

	// Read body
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		slog.Error("webhook failed to read body", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
	}

	slog.Info("webhook received", "body_length", len(body))

	// Verify HMAC signature
	if !h.verifySignature(c.Request(), body) {
		slog.Error("webhook signature verification failed", "has_secret", h.cfg.LemonSqueezyWebhookSecret != "")
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
	}

	// Parse payload.
	//
	// M47 (Codex round 2, Medium): the raw body is NOT logged. It used to log
	// its first 500 bytes, which since the checkout rework is enough to leak a
	// live `claim_token` — a signed delivery whose JSON goes wrong AFTER the
	// custom_data object (a later field with the wrong type, a truncated tail)
	// reaches this branch with the token already inside those 500 bytes.
	// Length plus the decoder's error is what an operator actually needs; the
	// payload itself is retrievable from the provider's own delivery log.
	var payload LSWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		slog.Error("webhook failed to parse payload", "error", err, "body_length", len(body))
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid payload"})
	}

	// M47 (Codex round 1, Medium): log the custom_data KEYS, never the values.
	// Since the checkout rework, `claim_token` lives in there — a live bearer
	// secret that binds a purchase to a tenant. Logging the map put it in
	// plaintext in the log of every delivery, including failed first
	// deliveries whose claim is still unconsumed.
	slog.Info("received Lemon Squeezy webhook",
		"event", payload.Meta.EventName,
		"custom_data_keys", customDataKeys(payload.Meta.CustomData),
		"subscription_id", payload.Data.ID,
		"status", payload.Data.Attributes.Status)

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

// resolveCheckoutClaim maps the delivered custom data to the tenant that
// started the checkout (M47 W3 #2).
//
// It reads exactly one field — `claim_token` — and deliberately ignores
// `tenant_id`, which is what this handler used to trust. That value made a
// round trip through the buyer's browser inside an editable URL parameter, so
// honouring it let anyone who completed a purchase attach it to another
// tenant. See BillingHandler.CreateCheckout for the issuing half.
//
// A delivery we cannot resolve is refused with 400: there is nothing to
// retry into (Lemon Squeezy will re-attempt up to three more times and then
// drop it), and the purchase needs the manual operator linking documented in
// docs/SAAS_SETUP.md §2.5. A legacy `tenant_id` is named in the log because
// that is the single most useful thing an operator can see when a checkout
// created before this change lands.
func (h *LemonSqueezyWebhookHandler) resolveCheckoutClaim(
	ctx context.Context, payload *LSWebhookPayload,
) (uuid.UUID, error) {
	token := payload.Meta.CustomData["claim_token"]
	if token == "" {
		_, hadLegacyTenantID := payload.Meta.CustomData["tenant_id"]
		slog.Error("subscription_created: no claim_token in custom data",
			"ls_subscription_id", payload.Data.ID,
			"has_legacy_tenant_id", hadLegacyTenantID,
			"custom_data_keys", customDataKeys(payload.Meta.CustomData))
		return uuid.Nil, errNoCheckoutClaim
	}

	claim, err := h.subRepo.ConsumeCheckoutClaim(
		ctx, hashCheckoutClaimToken(token), payload.Data.ID, time.Now())
	if err != nil {
		if errors.Is(err, repository.ErrCheckoutClaimNotFound) {
			// Unknown / expired / already spent by a different subscription —
			// one refusal for all three, see ErrCheckoutClaimNotFound.
			slog.Warn("subscription_created: claim token did not resolve",
				"ls_subscription_id", payload.Data.ID)
			return uuid.Nil, errNoCheckoutClaim
		}
		return uuid.Nil, err
	}
	slog.Info("subscription_created: claim resolved",
		"tenant_id", claim.TenantID, "ls_subscription_id", payload.Data.ID,
		"claim_plan", claim.Plan)
	return claim.TenantID, nil
}

// errNoCheckoutClaim marks "this delivery cannot be bound to a tenant" —
// answered with 400, as distinct from an infrastructure failure (500).
var errNoCheckoutClaim = errors.New("subscription_created: no resolvable checkout claim")

// customDataKeys lists the keys present without echoing their values, which
// may carry buyer-controlled content.
func customDataKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionCreated(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	// Resolve the tenant from the server-held claim, NOT from custom_data.
	tenantID, err := h.resolveCheckoutClaim(ctx, payload)
	if err != nil {
		if errors.Is(err, errNoCheckoutClaim) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "unresolvable checkout claim"})
		}
		slog.Error("subscription_created: claim lookup failed",
			"error", err, "ls_subscription_id", payload.Data.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to resolve checkout claim"})
	}

	// Get tenant
	tenant, err := h.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		slog.Error("subscription_created: tenant not found", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
	}

	slog.Info("subscription_created: found tenant", "tenant_id", tenantID, "tenant_name", tenant.Name)

	// Determine plan from product name (variant_name is often "Default")
	plan := h.productNameToPlan(payload.Data.Attributes.ProductName)
	slog.Info("subscription_created: determined plan", "product_name", payload.Data.Attributes.ProductName, "plan", plan)

	// Parse dates
	renewsAt := parseTime(payload.Data.Attributes.RenewsAt)
	trialEndsAt := parseTime(payload.Data.Attributes.TrialEndsAt)
	endsAt := parseTime(payload.Data.Attributes.EndsAt)

	now := time.Now()

	// Check if subscription already exists (upsert logic). Only
	// sql.ErrNoRows means "not found"; any other error is a transient
	// lookup failure that must NOT fall through to Create — that would
	// collide with the ls_subscription_id UNIQUE index on redelivery
	// (500 loop) and misread infra trouble as a brand-new subscription
	// (M46 Codex round A). Lemon Squeezy retries a non-2xx delivery up
	// to 3 more times (5s/25s/125s backoff), so an explicit 500 gets a
	// clean re-attempt once the DB recovers.
	existingSub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.Error("subscription_created: subscription lookup failed",
			"error", err, "ls_subscription_id", payload.Data.ID, "tenant_id", tenantID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up subscription"})
	}

	var sub *model.Subscription
	if existingSub != nil {
		// M47: the row belongs to whoever it already belongs to. Reaching
		// here with a different tenant means the claim resolved to A while
		// the subscription is B's — which the claim rules should make
		// impossible (a claim binds to one ls_subscription_id) — so treat it
		// as a state we do not understand and refuse rather than re-parent.
		// Pre-M47 this line read `existingSub.TenantID = tenantID`, i.e. it
		// re-parented on request; the repository's `AND tenant_id` guard was
		// the only thing that stopped it, and it stopped it silently until
		// M46 made 0-row updates audible.
		if existingSub.TenantID != tenantID {
			slog.Error("subscription_created: claim tenant does not own the existing subscription",
				"ls_subscription_id", payload.Data.ID,
				"claim_tenant_id", tenantID, "row_tenant_id", existingSub.TenantID)
			return c.JSON(http.StatusConflict, map[string]string{"error": "subscription is linked to another tenant"})
		}

		// Ordering gate — see acceptRevision. A redelivery carries the same
		// revision and is applied again (idempotent); a genuinely older one
		// is discarded.
		apply, err := h.acceptRevision(ctx, existingSub, payload)
		if err != nil {
			slog.Error("subscription_created: revision claim failed",
				"error", err, "ls_subscription_id", payload.Data.ID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to order delivery"})
		}
		if !apply {
			return staleDelivery(c, "subscription_created", payload)
		}

		// Update existing subscription
		existingSub.LSCustomerID = intToString(payload.Data.Attributes.CustomerID)
		existingSub.LSVariantID = intToString(payload.Data.Attributes.VariantID)
		existingSub.LSProductID = intToString(payload.Data.Attributes.ProductID)
		existingSub.Status = payload.Data.Attributes.Status
		existingSub.Plan = plan
		existingSub.BillingAnchor = &payload.Data.Attributes.BillingAnchor
		existingSub.RenewsAt = renewsAt
		existingSub.TrialEndsAt = trialEndsAt
		existingSub.EndsAt = endsAt
		existingSub.UpdatedAt = now

		if err := h.subRepo.Update(ctx, existingSub); err != nil {
			slog.Error("failed to update existing subscription", "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update subscription"})
		}
		sub = existingSub
		slog.Info("subscription_created: updated existing subscription", "subscription_id", sub.ID)
	} else {
		// Create new subscription
		sub = &model.Subscription{
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
			slog.Error("failed to create subscription", "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create subscription"})
		}
		// Stamp the watermark on the brand-new row so a delivery that is
		// already older than this one cannot be applied next. Best-effort:
		// SubscriptionRepository.Create does not write the column (it
		// predates it), and failing the whole webhook over a missing
		// watermark would be worse than starting the row at NULL — which
		// simply accepts the next delivery, the pre-M47 behaviour.
		if _, err := h.acceptRevision(ctx, sub, payload); err != nil {
			slog.Error("subscription_created: failed to stamp the initial provider revision",
				"error", err, "subscription_id", sub.ID)
		}
		slog.Info("subscription_created: created new subscription", "subscription_id", sub.ID)
	}

	// Update tenant plan - return error to trigger webhook retry if this fails
	if err := h.tenantRepo.UpdatePlan(ctx, tenantID, plan); err != nil {
		slog.Error("failed to update tenant plan", "error", err, "tenant_id", tenantID, "plan", plan)
		// Don't fail the webhook - subscription is already created, tenant.plan is secondary
		// The GetSubscription API now uses subscription.plan as source of truth
	}

	// Log event. Failures must not change the HTTP response.
	//
	// Retry facts (M46: verified against the official docs on 2026-07-25,
	// docs.lemonsqueezy.com/help/webhooks/webhook-requests — an earlier
	// comment here wrongly claimed "re-delivers forever"): Lemon Squeezy
	// retries a non-2xx delivery "up to three more times using an
	// exponential backoff strategy (e.g. 5 secs, 25 secs, 125 secs)" and
	// then marks the webhook permanently failed.
	//
	// Why still 200 on event/audit write failure: the subscription row is
	// already committed above, so a 5xx would re-deliver the WHOLE event —
	// the redelivery re-runs the upsert (safe) but can DUPLICATE
	// subscription_events/audit_logs rows when only one of the two writes
	// failed. Neither duplicated nor lost history is clean; we keep the 200
	// so billing state stays consistent, and surface the loss via slog.
	// TRADE-OFF (doc'd because the retry budget is finite): once we answer
	// 200, this event's history row is irreversibly lost — there is no
	// further redelivery to recover it from. Durable fix (M46 residual,
	// out of scope this wave): persist the raw payload into an inbox table
	// BEFORE processing and replay event/audit writes from there.
	if err := h.subRepo.CreateEvent(ctx, &model.SubscriptionEvent{
		ID:             uuid.New(),
		SubscriptionID: sub.ID,
		TenantID:       tenantID,
		EventType:      "subscription_created",
		LSEventID:      "",
		PreviousPlan:   tenant.Plan,
		NewPlan:        plan,
		NewStatus:      payload.Data.Attributes.Status,
		CreatedAt:      now,
	}); err != nil {
		slog.Error("failed to record subscription event",
			"error", err, "event_type", "subscription_created",
			"subscription_id", sub.ID, "tenant_id", tenantID)
	}

	if err := h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		Action:       model.ActionSubscriptionCreated,
		ResourceType: model.ResourceSubscription,
		ResourceID:   &sub.ID,
		Details:      map[string]interface{}{"plan": plan, "status": payload.Data.Attributes.Status},
	}); err != nil {
		slog.Error("failed to write subscription audit log",
			"error", err, "action", model.ActionSubscriptionCreated,
			"subscription_id", sub.ID, "tenant_id", tenantID)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// acceptRevision is the ordering gate for every subscription write driven by
// a webhook (M47 W3 #4).
//
// Webhook delivery order is best-effort. Lemon Squeezy retries a non-2xx
// delivery up to three more times (5s/25s/125s,
// docs.lemonsqueezy.com/help/webhooks/webhook-requests) and any delivery can
// be replayed from the dashboard later, so a DELAYED OLD event used to
// overwrite newer state — downgrade Team → Starter, then the retried Team
// `subscription_updated` lands and the tenant is back on Team, unpaid.
//
// The gate is a compare-and-swap on the provider's own revision
// (`data.attributes.updated_at`); see
// SubscriptionRepository.ClaimProviderRevision for why equal revisions are
// accepted (Lemon Squeezy emits several events per transition sharing one
// updated_at, and dropping a terminal event would grant entitlement).
//
// Two deliberate limits, both stated in docs/SAAS_SETUP.md §2.5:
//
//   - A delivery with no parseable updated_at cannot be ordered and is
//     APPLIED, with a warning. Refusing it instead would mean a
//     provider-side change to that field silently freezes all billing
//     updates — a worse failure than the ordering hole it would close.
//   - Two deliveries sharing one revision are still applied in arrival
//     order, whatever that is.
//
// The claim happens BEFORE the write it guards, so a write that fails after
// a successful claim leaves the watermark advanced. That is safe precisely
// because equal revisions are accepted: the redelivery re-claims its own
// revision and re-applies.
func (h *LemonSqueezyWebhookHandler) acceptRevision(
	ctx context.Context, sub *model.Subscription, payload *LSWebhookPayload,
) (bool, error) {
	rev := parseTime(payload.Data.Attributes.UpdatedAt)
	if rev == nil {
		slog.Warn("lemon squeezy webhook carries no parseable updated_at; applying without ordering",
			"event", payload.Meta.EventName, "ls_subscription_id", payload.Data.ID,
			"raw_updated_at", payload.Data.Attributes.UpdatedAt)
		return true, nil
	}
	return h.subRepo.ClaimProviderRevision(ctx, sub.ID, *rev)
}

// staleDelivery is the answer to a superseded event: 200, because there is
// nothing to retry — the event is genuinely obsolete and a redelivery would
// be discarded the same way.
func staleDelivery(c echo.Context, event string, payload *LSWebhookPayload) error {
	slog.Warn("lemon squeezy webhook discarded: older than the state already applied",
		"event", event, "ls_subscription_id", payload.Data.ID,
		"delivery_updated_at", payload.Data.Attributes.UpdatedAt)
	return c.JSON(http.StatusOK, map[string]string{
		"status": "skipped",
		"reason": "stale revision",
		"event":  event,
	})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionUpdated(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	// Get existing subscription
	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "subscription not found"})
	}

	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error("subscription_updated: revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to order delivery"})
	}
	if !apply {
		return staleDelivery(c, "subscription_updated", payload)
	}

	previousStatus := sub.Status
	previousPlan := sub.Plan

	// Update subscription
	newPlan := h.productNameToPlan(payload.Data.Attributes.ProductName)
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

	// Log event. Same contract as subscription_created (see the retry-facts
	// comment there: Lemon Squeezy retries non-2xx at most 3 more times,
	// then drops the event): keep the 200 on event/audit write failure so a
	// redelivery cannot duplicate history rows, but make the — then
	// irreversible — loss visible via slog. Durable inbox is the M46
	// residual.
	if err := h.subRepo.CreateEvent(ctx, &model.SubscriptionEvent{
		ID:             uuid.New(),
		SubscriptionID: sub.ID,
		TenantID:       sub.TenantID,
		EventType:      "subscription_updated",
		PreviousStatus: previousStatus,
		NewStatus:      payload.Data.Attributes.Status,
		PreviousPlan:   previousPlan,
		NewPlan:        newPlan,
		CreatedAt:      time.Now(),
	}); err != nil {
		slog.Error("failed to record subscription event",
			"error", err, "event_type", "subscription_updated",
			"subscription_id", sub.ID, "tenant_id", sub.TenantID)
	}

	if err := h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		TenantID:     &sub.TenantID,
		Action:       model.ActionSubscriptionUpdated,
		ResourceType: model.ResourceSubscription,
		ResourceID:   &sub.ID,
	}); err != nil {
		slog.Error("failed to write subscription audit log",
			"error", err, "action", model.ActionSubscriptionUpdated,
			"subscription_id", sub.ID, "tenant_id", sub.TenantID)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionCancelled(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "subscription not found"})
	}

	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error("subscription_cancelled: revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to order delivery"})
	}
	if !apply {
		return staleDelivery(c, "subscription_cancelled", payload)
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

	// Keep the 200 on event/audit write failure (same contract as
	// subscription_created — provider retries non-2xx at most 3 more
	// times, then drops the event; see the retry-facts comment there),
	// but make the — then irreversible — loss visible via slog.
	if err := h.subRepo.CreateEvent(ctx, &model.SubscriptionEvent{
		ID:             uuid.New(),
		SubscriptionID: sub.ID,
		TenantID:       sub.TenantID,
		EventType:      "subscription_cancelled",
		PreviousStatus: previousStatus,
		NewStatus:      model.StatusCancelled,
		CreatedAt:      now,
	}); err != nil {
		slog.Error("failed to record subscription event",
			"error", err, "event_type", "subscription_cancelled",
			"subscription_id", sub.ID, "tenant_id", sub.TenantID)
	}

	if err := h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		TenantID:     &sub.TenantID,
		Action:       model.ActionSubscriptionCancelled,
		ResourceType: model.ResourceSubscription,
		ResourceID:   &sub.ID,
	}); err != nil {
		slog.Error("failed to write subscription audit log",
			"error", err, "action", model.ActionSubscriptionCancelled,
			"subscription_id", sub.ID, "tenant_id", sub.TenantID)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionResumed(c echo.Context, payload *LSWebhookPayload) error {
	ctx := c.Request().Context()

	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "subscription not found"})
	}

	// handleSubscriptionUnpaused delegates here, so the log line names the
	// delivered event rather than a hardcoded one.
	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error("subscription_resumed: revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to order delivery"})
	}
	if !apply {
		return staleDelivery(c, payload.Meta.EventName, payload)
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

	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error("subscription_expired: revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to order delivery"})
	}
	if !apply {
		return staleDelivery(c, "subscription_expired", payload)
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

	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error("subscription_paused: revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to order delivery"})
	}
	if !apply {
		return staleDelivery(c, "subscription_paused", payload)
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

// verifySignature verifies the Lemon Squeezy HMAC signature.
//
// M47 (High) — this used to be FAIL-OPEN. With LEMONSQUEEZY_WEBHOOK_SECRET
// unset it returned `!IsProduction()`, and config.Load falls back to
// "development" when neither APP_ENV nor ENVIRONMENT is set, so the default
// posture of an unconfigured deployment was "accept unsigned webhooks from
// anyone". That is enough on its own to move another tenant's plan: the
// lifecycle events key off `data.id` (a short sequential Lemon Squeezy
// subscription id) and need no custom_data, so posting subscription_expired
// for a guessed id downgrades whoever owns it. Pinned by
// TestLSWebhook_NoSecret_UnsignedPayloadIsRejected.
//
// Now: no secret means no verification is possible, so the delivery is
// refused — unless an operator has named the bypass explicitly via
// SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS outside production (see
// config.UnsignedWebhooksAllowed), in which case every accepted delivery
// says so in the log.
//
// cmd/server/main.go's validateWebhookVerification covers a SUBSET of this at
// startup: it refuses to boot a PRODUCTION SaaS process that would reject
// everything here (or that asked for the bypass), so that misconfiguration
// surfaces before traffic. A non-production process with no secret still
// boots and rejects each delivery individually — this function is the
// decision, that guard is only an early warning.
func (h *LemonSqueezyWebhookHandler) verifySignature(r *http.Request, body []byte) bool {
	if h.cfg.LemonSqueezyWebhookSecret == "" {
		if !h.cfg.UnsignedWebhooksAllowed() {
			return false
		}
		slog.Warn("Lemon Squeezy webhook signature verification BYPASSED — "+
			"SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS is set and no LEMONSQUEEZY_WEBHOOK_SECRET is configured. "+
			"Anyone who can reach this endpoint can change billing state. Development only.",
			"app_env", h.cfg.Environment, "ip", r.RemoteAddr)
		return true
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

// productNameToPlan maps Lemon Squeezy product name to plan name
func (h *LemonSqueezyWebhookHandler) productNameToPlan(productName string) string {
	// Normalize to lowercase for comparison
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
