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
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// LemonSqueezyWebhookHandler handles Lemon Squeezy webhook events
type LemonSqueezyWebhookHandler struct {
	cfg *config.Config
	// db backs applyDelivery's per-delivery transaction. The webhook route is
	// mounted directly on the Echo instance (no TenantTx), so this handler
	// owns its own transaction boundary — see applyDelivery.
	db         *sql.DB
	tenantRepo *repository.TenantRepository
	subRepo    *repository.SubscriptionRepository
	auditRepo  *repository.AuditRepository
}

// NewLemonSqueezyWebhookHandler creates a new LemonSqueezyWebhookHandler.
//
// db is required, not optional: without it a delivery cannot be applied
// atomically and applyDelivery answers 500 for every event rather than
// falling back to the pre-M47R shape (autocommit statement-by-statement,
// which is exactly the split-entitlement defect). The parameter is positional
// so an existing call site cannot keep compiling while silently losing
// atomicity.
func NewLemonSqueezyWebhookHandler(
	cfg *config.Config,
	db *sql.DB,
	tenantRepo *repository.TenantRepository,
	subRepo *repository.SubscriptionRepository,
	auditRepo *repository.AuditRepository,
) *LemonSqueezyWebhookHandler {
	return &LemonSqueezyWebhookHandler{
		cfg:        cfg,
		db:         db,
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

// webhookResult is the HTTP answer one delivery earns. It exists so the
// answer can be decided INSIDE the transaction and written OUTSIDE it — see
// applyDelivery.
type webhookResult struct {
	status int
	body   map[string]string
}

func webhookOK() webhookResult {
	return webhookResult{status: http.StatusOK, body: map[string]string{"status": "ok"}}
}

func webhookRefusal(status int, message string) webhookResult {
	return webhookResult{status: status, body: map[string]string{"error": message}}
}

// errWebhookNotApplied rolls the delivery back while keeping the refusal the
// inner function already decided on. It never reaches a caller.
var errWebhookNotApplied = errors.New("lemon squeezy webhook: delivery not applied")

// applyDelivery runs one delivery inside a single transaction and only then
// writes the response.
//
// M47R (Codex cross-wave review, High). Before this, every plan-carrying
// event wrote the `subscriptions` row and `tenants.plan` as two independent
// autocommit statements, and SWALLOWED a failure of the second:
//
//	if err := h.tenantRepo.UpdatePlan(ctx, tenantID, plan); err != nil {
//	    slog.Error("failed to update tenant plan", ...)   // ...and then 200
//	}
//
// That contradicted both of the other M47 waves at once — W3 made
// `tenants.plan` the entitlement every feature gate reads and gave every
// other billing caller a 5xx on a failed plan write; W2 made a write that
// changed nothing audible instead of silent. And it was not self-healing:
// the subscription row and the revision watermark (migration 061) had
// already advanced, the 200 told Lemon Squeezy the delivery was done, so an
// expired subscription kept its paid plan until an operator noticed.
//
// The shape now:
//
//   - BEGIN; the whole event — claim consumption, revision CAS, subscription
//     row, tenant plan, subscription_events, audit_logs — runs on that one
//     transaction (repositories join it through database.Querier, so no
//     repository changed);
//   - the inner function returns the answer instead of writing it. A non-2xx
//     answer (a refusal we decided on, or an infrastructure fault we mapped
//     to 500) rolls the transaction back and is then returned verbatim;
//   - a 2xx is written only after COMMIT returns nil. A commit that fails
//     downgrades the answer to 500, so the client never holds a success the
//     database did not keep.
//
// What that buys, beyond the plan write itself:
//
//   - the "keep the 200 when the history row fails, because a redelivery
//     would DUPLICATE subscription_events / audit_logs" trade-off is gone.
//     A rolled-back delivery leaves nothing to duplicate, so history
//     failures can now be fatal — which is the house audit-or-nothing
//     contract (F5 / F32) the rest of the API already follows;
//   - the revision CAS and the write it guards are in one transaction, so
//     the row lock the CAS takes actually serialises two concurrent
//     deliveries of the same subscription (docs/SAAS_SETUP.md §2.5 residual).
//
// Retry facts (M46, verified against docs.lemonsqueezy.com/help/webhooks/
// webhook-requests on 2026-07-25): Lemon Squeezy retries a non-2xx delivery
// "up to three more times using an exponential backoff strategy (e.g. 5 secs,
// 25 secs, 125 secs)" and then marks the webhook permanently failed. A 5xx
// here is therefore a real repair opportunity, not a guaranteed one; a
// delivery that exhausts the budget needs the operator path in
// docs/SAAS_SETUP.md §2.5 — but it leaves CONSISTENT state behind either way,
// which is the property this function is for.
func (h *LemonSqueezyWebhookHandler) applyDelivery(
	c echo.Context, event string,
	fn func(ctx context.Context, tx *sql.Tx) (webhookResult, error),
) error {
	if h.db == nil {
		// Fail closed on a misconfigured wiring rather than apply the event
		// non-atomically (see NewLemonSqueezyWebhookHandler).
		slog.Error("lemon squeezy webhook is not fully wired (no database handle)", "event", event)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "webhook is not available"})
	}

	var res webhookResult
	txErr := database.WithTxFunc(c.Request().Context(), h.db,
		func(txCtx context.Context, tx *sql.Tx) error {
			var err error
			res, err = fn(txCtx, tx)
			if err != nil {
				return err
			}
			if res.status < 200 || res.status > 299 {
				return errWebhookNotApplied
			}
			return nil
		})
	if txErr != nil && !errors.Is(txErr, errWebhookNotApplied) {
		slog.Error("lemon squeezy webhook: delivery rolled back",
			"event", event, "error", txErr)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to apply webhook"})
	}
	if res.status == 0 {
		// Unreachable today: every branch of every apply* returns either a
		// populated result or an error, and an error takes the arm above. It
		// is checked anyway because the failure mode is not a wrong status —
		// net/http panics on WriteHeader(0), so a future branch that forgot
		// its result would take the process down rather than answer badly.
		slog.Error("lemon squeezy webhook: handler produced no result", "event", event)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to apply webhook"})
	}
	return c.JSON(res.status, res.body)
}

// bindWebhookTenant pins `app.current_tenant_id` on the delivery transaction
// once the owning tenant is known.
//
// None of the tables this transaction touches has RLS today — migration 031
// removed it from `subscriptions` / `subscription_events`, 029 from
// `audit_logs`, `tenants` never had it, and `subscription_checkout_claims`
// (060) was created without it, all for the same reason: this route runs
// outside TenantTx, so a tenant policy would evaluate against a NULL GUC
// under the NOBYPASSRLS `sbomhub_app` role and match nothing.
//
// It is bound anyway, exactly as scheduler.runWithTenantTx does for
// background jobs: if `subscription_events`, `audit_logs` or `tenants` ever
// regain a policy, the writes AFTER this point keep working instead of
// silently matching nothing. It is one statement per delivery.
//
// It does NOT cover everything, and cannot (Codex round 3, Low). Two lookups
// necessarily run BEFORE it, because they are what reveal which tenant to
// bind: `subscription_checkout_claims` on the created path and `subscriptions`
// on every other event. Both tables must therefore stay reachable without a
// tenant context — which is exactly why migration 060 created the claims table
// without RLS and migration 031 removed it from `subscriptions`. Re-adding a
// policy to either would break tenant discovery, and this binding would not
// save it.
func bindWebhookTenant(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String(),
	); err != nil {
		return fmt.Errorf("bind webhook tenant context for %s: %w", tenantID, err)
	}
	return nil
}

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
	return h.applyDelivery(c, "subscription_created",
		func(ctx context.Context, tx *sql.Tx) (webhookResult, error) {
			return h.applySubscriptionCreated(ctx, tx, payload)
		})
}

func (h *LemonSqueezyWebhookHandler) applySubscriptionCreated(
	ctx context.Context, tx *sql.Tx, payload *LSWebhookPayload,
) (webhookResult, error) {
	// Resolve the tenant from the server-held claim, NOT from custom_data.
	//
	// M47R: consuming the claim is now part of the delivery transaction. A
	// delivery that is refused or fails later therefore does not spend the
	// claim — pre-M47R a failed plan write left the token consumed, so the
	// redelivery could no longer resolve which tenant had bought anything.
	tenantID, err := h.resolveCheckoutClaim(ctx, payload)
	if err != nil {
		if errors.Is(err, errNoCheckoutClaim) {
			return webhookRefusal(http.StatusBadRequest, "unresolvable checkout claim"), nil
		}
		slog.Error("subscription_created: claim lookup failed",
			"error", err, "ls_subscription_id", payload.Data.ID)
		return webhookRefusal(http.StatusInternalServerError, "failed to resolve checkout claim"), nil
	}

	if err := bindWebhookTenant(ctx, tx, tenantID); err != nil {
		return webhookResult{}, err
	}

	// Get tenant. M47R: the same not-found-vs-broken split the cross-wave
	// review demanded of the delete handlers. This mapped EVERY lookup error
	// to 404 "tenant not found", so a statement timeout while resolving a
	// completed purchase read, in the log, as "that tenant does not exist" —
	// and the operator investigating an unbilled subscription was pointed at
	// the wrong problem. (Both answers are non-2xx, so the delivery is
	// retried either way; what changes is what the operator is told.)
	tenant, err := h.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Not the ordinary "the tenant was deleted" path (Codex round 2,
			// Low): the claim row FKs to tenants ON DELETE CASCADE, so a
			// deleted tenant takes its claim with it and the delivery is
			// refused with 400 by resolveCheckoutClaim above. Reaching here
			// means the claim resolved to a tenant id that has no row — an
			// inconsistent state, not a normal outcome. Refused, and loudly.
			slog.Error("subscription_created: claim resolved to a tenant that does not exist",
				"tenant_id", tenantID, "ls_subscription_id", payload.Data.ID)
			return webhookRefusal(http.StatusNotFound, "tenant not found"), nil
		}
		slog.Error("subscription_created: tenant lookup failed", "tenant_id", tenantID, "error", err)
		return webhookRefusal(http.StatusInternalServerError, "failed to look up tenant"), nil
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
		return webhookRefusal(http.StatusInternalServerError, "failed to look up subscription"), nil
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
			return webhookRefusal(http.StatusConflict, "subscription is linked to another tenant"), nil
		}

		// Ordering gate — see acceptRevision. A redelivery carries the same
		// revision and is applied again (idempotent); a genuinely older one
		// is discarded.
		apply, err := h.acceptRevision(ctx, existingSub, payload)
		if err != nil {
			slog.Error("subscription_created: revision claim failed",
				"error", err, "ls_subscription_id", payload.Data.ID)
			return webhookRefusal(http.StatusInternalServerError, "failed to order delivery"), nil
		}
		if !apply {
			return staleDelivery("subscription_created", payload), nil
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
			return webhookRefusal(http.StatusInternalServerError, "failed to update subscription"), nil
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
			return webhookRefusal(http.StatusInternalServerError, "failed to create subscription"), nil
		}
		// Stamp the watermark on the brand-new row so a delivery that is
		// already older than this one cannot be applied next.
		// SubscriptionRepository.Create does not write the column (it
		// predates it), so it takes a second statement.
		//
		// M47R: no longer best-effort. It used to be, because failing the
		// whole webhook over a missing watermark would have discarded a
		// subscription row that was already committed; inside the delivery
		// transaction there is nothing to discard — the row goes back with
		// it and the redelivery retries the pair.
		if _, err := h.acceptRevision(ctx, sub, payload); err != nil {
			slog.Error("subscription_created: failed to stamp the initial provider revision",
				"error", err, "subscription_id", sub.ID)
			return webhookRefusal(http.StatusInternalServerError, "failed to order delivery"), nil
		}
		slog.Info("subscription_created: created new subscription", "subscription_id", sub.ID)
	}

	// Re-read the tenant for the history row's `previous_plan`.
	//
	// M47R (Codex round 3, Medium): the value used to come from the lookup at
	// the top of this function, taken before the revision claim took the
	// subscription row lock. A concurrent delivery that changed `tenants.plan`
	// while this one waited therefore wrote a `previous_plan` that had not
	// been the previous plan for some time — permanently wrong history in an
	// audit trail this product exists to produce.
	//
	// The read is taken UNDER A LOCK, which closes the race rather than
	// narrowing it (Codex round 4, Low, correcting a first attempt that only
	// re-read): by this point the delivery already holds the subscription row
	// — the CAS locked it, or this transaction inserted it — so taking the
	// tenant row here keeps the lock order `subscriptions` -> `tenants` that
	// every billing writer uses (see
	// repository.UpdatePlanUnlessSubscriptionLive). FOR NO KEY UPDATE is the
	// right strength: it is what the UPDATE below takes anyway, and unlike FOR
	// UPDATE it does not conflict with the FOR KEY SHARE that another
	// transaction's subscriptions INSERT holds on this row.
	if _, err := tx.ExecContext(ctx,
		`SELECT 1 FROM tenants WHERE id = $1 FOR NO KEY UPDATE`, tenantID,
	); err != nil {
		return webhookResult{}, fmt.Errorf("lock tenant %s for the history row: %w", tenantID, err)
	}
	freshTenant, err := h.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		slog.Error("subscription_created: could not re-read the tenant for the history row",
			"error", err, "tenant_id", tenantID)
		return webhookRefusal(http.StatusInternalServerError, "failed to look up tenant"), nil
	}
	previousPlan := freshTenant.Plan

	// Update tenant plan.
	//
	// M47R (High): this is the entitlement of record — every feature and
	// limit gate reads `tenants.plan` — and it used to be applied outside the
	// write above with its failure swallowed behind a 200. It is now the same
	// transaction as the subscription row, so the two cannot disagree, and a
	// failure refuses the delivery so Lemon Squeezy re-attempts it.
	if err := h.tenantRepo.UpdatePlan(ctx, tenantID, plan); err != nil {
		slog.Error("failed to update tenant plan", "error", err, "tenant_id", tenantID, "plan", plan)
		return webhookRefusal(http.StatusInternalServerError, "failed to update tenant plan"), nil
	}

	// Log event.
	//
	// M47R: a history write failure is now fatal to the delivery. The old
	// contract answered 200 and logged the loss, because the subscription row
	// was already committed and a 5xx would have re-delivered the whole event
	// — duplicating subscription_events / audit_logs rows when ONE of the two
	// had failed. Inside one transaction that particular duplication cannot
	// happen: a rolled-back delivery leaves no history and no state, so the
	// redelivery writes both. That also restores the audit-or-nothing
	// contract (F5 / F32) the rest of the API follows.
	//
	// It is not delivery-level idempotency, and the difference matters. The
	// precise contract is: a rolled-back attempt contributes ZERO history
	// rows, and each SUCCESSFUL delivery contributes exactly one pair. So if
	// the transaction commits but the 2xx never reaches Lemon Squeezy (or an
	// operator replays the delivery from the dashboard), the retry is accepted
	// — equal revisions apply by design — and contributes a SECOND pair with
	// fresh ids. Deduplicating those needs a delivery-id key, i.e. the durable
	// inbox in docs/SAAS_SETUP.md §2.5.
	//
	// Residual: the retry budget is finite (see applyDelivery), so a history
	// table that is down for longer than it stalls the BILLING update too
	// rather than losing only the history. That is the fail-closed direction
	// for a compliance product, and it is loud; the durable-inbox design in
	// docs/SAAS_SETUP.md §2.5 is what would make it neither.
	if err := h.subRepo.CreateEvent(ctx, &model.SubscriptionEvent{
		ID:             uuid.New(),
		SubscriptionID: sub.ID,
		TenantID:       tenantID,
		EventType:      "subscription_created",
		LSEventID:      "",
		PreviousPlan:   previousPlan,
		NewPlan:        plan,
		NewStatus:      payload.Data.Attributes.Status,
		CreatedAt:      now,
	}); err != nil {
		slog.Error("failed to record subscription event",
			"error", err, "event_type", "subscription_created",
			"subscription_id", sub.ID, "tenant_id", tenantID)
		return webhookRefusal(http.StatusInternalServerError, "failed to record subscription event"), nil
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
		return webhookRefusal(http.StatusInternalServerError, "failed to write audit log"), nil
	}

	return webhookOK(), nil
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
// The claim happens BEFORE the write it guards. Under M47R that is no longer
// a durability question — the claim and the write share one transaction, so a
// failure after a successful claim rolls the watermark back with everything
// else (Codex round 3, Low: the previous wording still described the
// autocommit behaviour). What accepting equal revisions buys now is REPLAY: a
// delivery that committed and is then re-sent re-claims its own revision and
// re-applies instead of being discarded as stale.
//
// M47R (Codex round 2, High) — RELOAD ON SUCCESS. The caller reads the
// subscription BEFORE calling this, i.e. before the CAS takes the row lock, so
// the values it is holding can be stale by the time it is allowed to write.
// The transaction alone did not fix that; it made the delivery atomic, not
// serialised. Two concurrent subscription_updated deliveries:
//
//	both read plan = starter
//	A (older revision, Team) commits first -> subscriptions.plan = tenants.plan = team
//	B (newer revision, Starter) then claims and applies — but its stale
//	  previousPlan is "starter", so `newPlan != previousPlan` is false and B
//	  SKIPS the tenants write
//	final: subscriptions.plan = starter beside tenants.plan = team.
//
// So on success `sub` is refreshed from the row this transaction now holds the
// lock on, and every comparison the caller makes afterwards (previousPlan,
// previousStatus, TenantID) is against committed state.
//
// The unordered branch below does NOT get this: with no parseable updated_at
// there is no CAS, therefore no lock, therefore nothing a reload would be
// consistent with. That branch is already a documented ordering hole
// (docs/SAAS_SETUP.md §2.5 residual 9) and this does not widen it.
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
	applied, err := h.subRepo.ClaimProviderRevision(ctx, sub.ID, *rev)
	if err != nil || !applied {
		return applied, err
	}
	fresh, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return false, fmt.Errorf(
			"reload subscription %s after claiming its revision: %w", payload.Data.ID, err)
	}
	*sub = *fresh
	return true, nil
}

// staleDelivery is the answer to a superseded event: 200, because there is
// nothing to retry — the event is genuinely obsolete and a redelivery would
// be discarded the same way.
//
// M47R: it is a 2xx, so applyDelivery COMMITS the transaction. What that
// commits is not nothing, but it is nothing that changes billing state: the
// lookups, the tenant GUC binding, and the CAS that matched no row. On the
// subscription_created path it ALSO commits the claim consumption, which is
// deliberate — the claim is bound to this ls_subscription_id and staying
// consumed is what lets a later redelivery of the same subscription resolve
// its tenant again (see migration 060).
func staleDelivery(event string, payload *LSWebhookPayload) webhookResult {
	slog.Warn("lemon squeezy webhook discarded: older than the state already applied",
		"event", event, "ls_subscription_id", payload.Data.ID,
		"delivery_updated_at", payload.Data.Attributes.UpdatedAt)
	return webhookResult{status: http.StatusOK, body: map[string]string{
		"status": "skipped",
		"reason": "stale revision",
		"event":  event,
	}}
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionUpdated(c echo.Context, payload *LSWebhookPayload) error {
	return h.applyDelivery(c, "subscription_updated",
		func(ctx context.Context, tx *sql.Tx) (webhookResult, error) {
			return h.applySubscriptionUpdated(ctx, tx, payload)
		})
}

func (h *LemonSqueezyWebhookHandler) applySubscriptionUpdated(
	ctx context.Context, tx *sql.Tx, payload *LSWebhookPayload,
) (webhookResult, error) {
	// Get existing subscription
	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return webhookRefusal(http.StatusNotFound, "subscription not found"), nil
	}

	if err := bindWebhookTenant(ctx, tx, sub.TenantID); err != nil {
		return webhookResult{}, err
	}

	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error("subscription_updated: revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return webhookRefusal(http.StatusInternalServerError, "failed to order delivery"), nil
	}
	if !apply {
		return staleDelivery("subscription_updated", payload), nil
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
		return webhookRefusal(http.StatusInternalServerError, "failed to update subscription"), nil
	}

	// Update tenant plan if changed. M47R (High): same transaction as the
	// subscription row above, and a failure refuses the delivery — see
	// applySubscriptionCreated.
	if newPlan != previousPlan {
		if err := h.tenantRepo.UpdatePlan(ctx, sub.TenantID, newPlan); err != nil {
			slog.Error("failed to update tenant plan",
				"error", err, "tenant_id", sub.TenantID, "plan", newPlan)
			return webhookRefusal(http.StatusInternalServerError, "failed to update tenant plan"), nil
		}
	}

	// Log event. Same contract as subscription_created: inside the delivery
	// transaction a history write failure is fatal, because a rolled-back
	// delivery leaves nothing for the redelivery to duplicate.
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
		return webhookRefusal(http.StatusInternalServerError, "failed to record subscription event"), nil
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
		return webhookRefusal(http.StatusInternalServerError, "failed to write audit log"), nil
	}

	return webhookOK(), nil
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionCancelled(c echo.Context, payload *LSWebhookPayload) error {
	return h.applyDelivery(c, "subscription_cancelled",
		func(ctx context.Context, tx *sql.Tx) (webhookResult, error) {
			return h.applySubscriptionCancelled(ctx, tx, payload)
		})
}

func (h *LemonSqueezyWebhookHandler) applySubscriptionCancelled(
	ctx context.Context, tx *sql.Tx, payload *LSWebhookPayload,
) (webhookResult, error) {
	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return webhookRefusal(http.StatusNotFound, "subscription not found"), nil
	}

	if err := bindWebhookTenant(ctx, tx, sub.TenantID); err != nil {
		return webhookResult{}, err
	}

	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error("subscription_cancelled: revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return webhookRefusal(http.StatusInternalServerError, "failed to order delivery"), nil
	}
	if !apply {
		return staleDelivery("subscription_cancelled", payload), nil
	}

	now := time.Now()
	previousStatus := sub.Status
	sub.Status = model.StatusCancelled
	sub.CancelledAt = &now
	sub.EndsAt = parseTime(payload.Data.Attributes.EndsAt)
	sub.UpdatedAt = now

	if err := h.subRepo.Update(ctx, sub); err != nil {
		return webhookRefusal(http.StatusInternalServerError, "failed to update subscription"), nil
	}

	// Note: Don't downgrade plan immediately - subscription is still active until ends_at

	// M47R: history writes are fatal to the delivery, same as
	// subscription_created — a rolled-back attempt leaves no rows for a
	// retry to duplicate, which is what the old 200-and-log was avoiding.
	// (A delivery that COMMITS and is then replayed still adds a second pair;
	// see the longer note on the created path.)
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
		return webhookRefusal(http.StatusInternalServerError, "failed to record subscription event"), nil
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
		return webhookRefusal(http.StatusInternalServerError, "failed to write audit log"), nil
	}

	return webhookOK(), nil
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionResumed(c echo.Context, payload *LSWebhookPayload) error {
	// handleSubscriptionUnpaused delegates here, so BOTH the transaction and
	// the ordering-failure log are named after the DELIVERED event rather than
	// a hardcoded one (M47R, Codex round 2, Low: logName was still hardcoded
	// to "subscription_resumed" while the comment claimed otherwise).
	return h.applyDelivery(c, payload.Meta.EventName,
		func(ctx context.Context, tx *sql.Tx) (webhookResult, error) {
			return h.applyStatusOnly(ctx, tx, payload, payload.Meta.EventName, model.StatusActive)
		})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionExpired(c echo.Context, payload *LSWebhookPayload) error {
	return h.applyDelivery(c, "subscription_expired",
		func(ctx context.Context, tx *sql.Tx) (webhookResult, error) {
			return h.applySubscriptionExpired(ctx, tx, payload)
		})
}

func (h *LemonSqueezyWebhookHandler) applySubscriptionExpired(
	ctx context.Context, tx *sql.Tx, payload *LSWebhookPayload,
) (webhookResult, error) {
	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return webhookRefusal(http.StatusNotFound, "subscription not found"), nil
	}

	if err := bindWebhookTenant(ctx, tx, sub.TenantID); err != nil {
		return webhookResult{}, err
	}

	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error("subscription_expired: revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return webhookRefusal(http.StatusInternalServerError, "failed to order delivery"), nil
	}
	if !apply {
		return staleDelivery("subscription_expired", payload), nil
	}

	sub.Status = model.StatusExpired
	sub.UpdatedAt = time.Now()

	if err := h.subRepo.Update(ctx, sub); err != nil {
		return webhookRefusal(http.StatusInternalServerError, "failed to update subscription"), nil
	}

	// Downgrade tenant to free plan.
	//
	// M47R (High): this is the case the swallow hurt most. `subscriptions`
	// said expired while `tenants.plan` — the column every feature and limit
	// gate reads — still said team, and the 200 meant no redelivery ever
	// revisited it. The two writes are now one transaction and a failure
	// refuses the delivery.
	if err := h.tenantRepo.UpdatePlan(ctx, sub.TenantID, model.PlanFree); err != nil {
		slog.Error("failed to downgrade tenant plan", "error", err, "tenant_id", sub.TenantID)
		return webhookRefusal(http.StatusInternalServerError, "failed to update tenant plan"), nil
	}

	return webhookOK(), nil
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionPaused(c echo.Context, payload *LSWebhookPayload) error {
	return h.applyDelivery(c, "subscription_paused",
		func(ctx context.Context, tx *sql.Tx) (webhookResult, error) {
			return h.applyStatusOnly(ctx, tx, payload, "subscription_paused", model.StatusPaused)
		})
}

func (h *LemonSqueezyWebhookHandler) handleSubscriptionUnpaused(c echo.Context, payload *LSWebhookPayload) error {
	return h.handleSubscriptionResumed(c, payload)
}

// applyStatusOnly is the shared body of the two events that move only the
// subscription status and leave `tenants.plan` alone (resumed/unpaused and
// paused). `logName` names the event in the ordering-failure log line;
// resumed and unpaused share one body but not one name.
//
// Resumed clears cancelled_at as well, which is why `status` alone is not
// enough to describe the transition — see the branch below.
func (h *LemonSqueezyWebhookHandler) applyStatusOnly(
	ctx context.Context, tx *sql.Tx, payload *LSWebhookPayload, logName, status string,
) (webhookResult, error) {
	sub, err := h.subRepo.GetByLSSubscriptionID(ctx, payload.Data.ID)
	if err != nil {
		return webhookRefusal(http.StatusNotFound, "subscription not found"), nil
	}

	if err := bindWebhookTenant(ctx, tx, sub.TenantID); err != nil {
		return webhookResult{}, err
	}

	apply, err := h.acceptRevision(ctx, sub, payload)
	if err != nil {
		slog.Error(logName+": revision claim failed", "error", err, "ls_subscription_id", payload.Data.ID)
		return webhookRefusal(http.StatusInternalServerError, "failed to order delivery"), nil
	}
	if !apply {
		// The stale log names the delivered event (unpaused vs resumed).
		return staleDelivery(payload.Meta.EventName, payload), nil
	}

	sub.Status = status
	if status == model.StatusActive {
		sub.CancelledAt = nil
	}
	sub.UpdatedAt = time.Now()

	if err := h.subRepo.Update(ctx, sub); err != nil {
		return webhookRefusal(http.StatusInternalServerError, "failed to update subscription"), nil
	}

	return webhookOK(), nil
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
