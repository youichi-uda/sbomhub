//go:build integration

// Package handler — M47 W3: checkout tenant binding (#2) and webhook
// revision ordering (#4), pinned against a real Postgres.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M47' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// # #2 — the checkout tenant id was client-modifiable
//
// CreateCheckout used to answer with
//
//	https://sbomhub.lemonsqueezy.com/checkout/buy/<variant>?checkout[custom][tenant_id]=<caller>
//
// and handleSubscriptionCreated billed whatever tenant `meta.custom_data`
// named. The HMAC on the delivery proves Lemon Squeezy sent it; it says
// nothing about the custom payload, which made a round trip through the
// buyer's browser inside an editable query string
// (docs.lemonsqueezy.com/help/checkout/passing-custom-data documents
// `checkout[custom][...]` as a supported URL parameter and returns whatever
// arrives in the webhook's `meta`). A buyer could therefore attach their
// purchase to someone else's tenant: taking over its plan lifecycle and
// occupying its single subscription slot (UNIQUE(tenant_id), migration 008)
// so the victim could not buy its own.
//
// Contract after the fix:
//   - the tenant id never leaves the server. The checkout carries an opaque
//     256-bit claim token whose SHA-256 is stored in
//     subscription_checkout_claims alongside the issuing tenant;
//   - `custom_data.tenant_id` is not read at all — a delivery carrying only
//     that is refused;
//   - a claim resolves for exactly one subscription, and keeps resolving for
//     THAT subscription (redelivery) but no other (replay);
//   - claims expire.
//
// # #4 — webhooks had no ordering guarantee
//
// Delivery order is best-effort: Lemon Squeezy retries a non-2xx up to three
// more times (5s/25s/125s) and the dashboard can replay any delivery. Every
// handler applied what it was handed, so a delayed OLD delivery overwrote
// newer state. Contract after the fix: a delivery whose
// `attributes.updated_at` is STRICTLY older than the last one applied is
// discarded (200, logged); equal revisions still apply, because Lemon
// Squeezy emits several events per transition sharing one updated_at and
// dropping a terminal event would grant entitlement.
//
// C27: `tenants` CASCADE reaps the seeded subscriptions / claims rows.
package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// m47CheckoutStub stands in for POST https://api.lemonsqueezy.com/v1/checkouts
// and records the custom data the SERVER sent. That recording is the point:
// the claim token must reach the provider over this server-to-server call and
// never through the client, so the test reads it from here rather than from
// the URL handed back to the caller.
type m47CheckoutStub struct {
	*httptest.Server
	custom     map[string]string
	variantID  string
	storeID    string
	expiresAt  string
	calls      int
	statusCode int // override for the failure-path test
}

func m47StubCheckouts(t *testing.T) *m47CheckoutStub {
	t.Helper()
	stub := &m47CheckoutStub{custom: map[string]string{}}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.calls++
		if stub.statusCode != 0 {
			w.WriteHeader(stub.statusCode)
			_, _ = w.Write([]byte(`{"errors":[{"detail":"nope"}]}`))
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/checkouts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct {
			Data struct {
				Attributes struct {
					CheckoutData struct {
						Custom map[string]string `json:"custom"`
					} `json:"checkout_data"`
					ExpiresAt string `json:"expires_at"`
				} `json:"attributes"`
				Relationships struct {
					Store struct {
						Data struct {
							ID string `json:"id"`
						} `json:"data"`
					} `json:"store"`
					Variant struct {
						Data struct {
							ID string `json:"id"`
						} `json:"data"`
					} `json:"variant"`
				} `json:"relationships"`
			} `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stub.custom = body.Data.Attributes.CheckoutData.Custom
		stub.variantID = body.Data.Relationships.Variant.Data.ID
		stub.storeID = body.Data.Relationships.Store.Data.ID
		stub.expiresAt = body.Data.Attributes.ExpiresAt

		w.Header().Set("Content-Type", "application/vnd.api+json")
		// Shape copied from docs.lemonsqueezy.com/api/checkouts/create-checkout
		// (fetched 2026-07-28): the buyer-facing link lives at
		// data.attributes.url. The documented example carries expires/signature
		// query parameters; the handler does not verify them (it only requires
		// an absolute https URL), so neither does this stub's assertion.
		_, _ = fmt.Fprint(w, `{"data":{"type":"checkouts","id":"5e8b546c-c561-4a2c-a586-40c18bb2a195",
			"attributes":{"store_id":1,"variant_id":9002,
			"url":"https://sbomhub.lemonsqueezy.com/checkout/custom/5e8b546c?expires=1&signature=deadbeef"}}}`)
	}))
	t.Cleanup(stub.Server.Close)
	return stub
}

// m47BillingHandler builds a BillingHandler in SaaS mode pointed at the stub.
func m47BillingHandler(t *testing.T, appDB *sql.DB, lsBase string) *BillingHandler {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_m47")           // SaaS mode
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key")   // IsBillingEnabled
	t.Setenv("LEMONSQUEEZY_STORE_ID", "4242")             // required to create a checkout
	t.Setenv("LEMONSQUEEZY_TEAM_VARIANT_ID", "9002")      //
	t.Setenv("LEMONSQUEEZY_PRO_VARIANT_ID", "9001")       //
	t.Setenv("LEMONSQUEEZY_STARTER_VARIANT_ID", "9000")   //
	t.Setenv("APP_ENV", "development")                    //
	t.Setenv("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", "")       // fail-closed default
	t.Setenv("LEMONSQUEEZY_WEBHOOK_SECRET", "m47-secret") // handlers are driven directly
	return NewBillingHandler(
		config.Load(),
		repository.NewTenantRepository(appDB),
		repository.NewSubscriptionRepository(appDB),
	).WithLemonSqueezyBaseURL(lsBase)
}

// m47PostCheckout drives POST /api/v1/subscription/checkout inside an
// app-role tenant tx, exactly like a live request behind Auth -> TenantTx.
func m47PostCheckout(t *testing.T, appDB *sql.DB, h *BillingHandler,
	tenantID uuid.UUID, plan string) (int, string) {
	t.Helper()

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL app.current_tenant_id: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/subscription/checkout",
		strings.NewReader(fmt.Sprintf(`{"plan":%q}`, plan)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req = req.WithContext(database.WithTx(context.Background(), tx))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyTenant, &model.Tenant{ID: tenantID})
	c.Set(middleware.ContextKeyRole, model.RoleOwner)

	if err := h.CreateCheckout(c); err != nil {
		t.Fatalf("CreateCheckout: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tenant tx: %v", err)
	}
	committed = true
	return rec.Code, rec.Body.String()
}

// m47Webhook builds the Lemon Squeezy receiver on the raw app DB — webhooks
// run outside TenantTx in production (their route is mounted directly on the
// Echo instance), so that is how they are driven here.
func m47Webhook(t *testing.T, cfg *config.Config, appDB *sql.DB) *LemonSqueezyWebhookHandler {
	t.Helper()
	return NewLemonSqueezyWebhookHandler(
		cfg,
		appDB,
		repository.NewTenantRepository(appDB),
		repository.NewSubscriptionRepository(appDB),
		repository.NewAuditRepository(appDB),
	)
}

// m47Deliver drives one already-parsed event through its handler, bypassing
// only the HMAC (which has its own tests in
// webhook_signature_failopen_test.go).
func m47Deliver(t *testing.T, wh *LemonSqueezyWebhookHandler, payload *LSWebhookPayload) (int, string) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/lemonsqueezy", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var err error
	switch payload.Meta.EventName {
	case "subscription_created":
		err = wh.handleSubscriptionCreated(c, payload)
	case "subscription_updated":
		err = wh.handleSubscriptionUpdated(c, payload)
	case "subscription_expired":
		err = wh.handleSubscriptionExpired(c, payload)
	case "subscription_cancelled":
		err = wh.handleSubscriptionCancelled(c, payload)
	default:
		t.Fatalf("m47Deliver: unhandled event %q", payload.Meta.EventName)
	}
	if err != nil {
		t.Fatalf("%s: %v", payload.Meta.EventName, err)
	}
	return rec.Code, rec.Body.String()
}

func m47SubscriptionRows(t *testing.T, migDB *sql.DB, tenantID uuid.UUID) int {
	t.Helper()
	var n int
	if err := migDB.QueryRow(
		`SELECT COUNT(*) FROM subscriptions WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
		t.Fatalf("count subscriptions for %s: %v", tenantID, err)
	}
	return n
}

// ---------------------------------------------------------------------------
// #2 — checkout tenant binding
// ---------------------------------------------------------------------------

// TestM47Checkout_CustomDataTenantIDIsNotTrusted is the attack: the buyer
// edits `checkout[custom][tenant_id]` to the victim's id before paying, and
// the resulting subscription_created carries it. Pre-fix the victim got the
// subscription (and the attacker's cancel/expire could later downgrade it).
func TestM47Checkout_CustomDataTenantIDIsNotTrusted(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	victim := billingSyncSeedTenant(t, migDB, "m47victim", model.PlanFree)
	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)
	wh := m47Webhook(t, h.cfg, appDB)

	code, body := m47Deliver(t, wh, &LSWebhookPayload{
		Meta: LSWebhookMeta{
			EventName:  "subscription_created",
			CustomData: map[string]string{"tenant_id": victim.String()},
		},
		Data: LSWebhookData{
			ID: "ls-" + uuid.NewString(),
			Attributes: LSSubscriptionAttrs{
				ProductName: "SBOMHub Team",
				Status:      model.StatusActive,
				CustomerID:  9001, VariantID: 9002, ProductID: 9003,
			},
		},
	})

	if code == http.StatusOK {
		t.Errorf("subscription_created carrying only custom_data.tenant_id was accepted "+
			"(status %d body %s). That value travelled through the buyer's browser and "+
			"must not bind a subscription.", code, body)
	}
	if n := m47SubscriptionRows(t, migDB, victim); n != 0 {
		t.Errorf("subscriptions rows for the victim tenant = %d, want 0 "+
			"(cross-tenant checkout binding)", n)
	}
	if got := billingSyncTenantPlan(t, migDB, victim); got != model.PlanFree {
		t.Errorf("victim tenants.plan = %q, want %q", got, model.PlanFree)
	}
}

// TestM47Checkout_ClaimTokenBindsToTheIssuingTenant is the positive control
// AND the proof that the binding never passes through the client: the token
// is read out of the server-to-server checkout creation, not out of the URL
// the caller received.
func TestM47Checkout_ClaimTokenBindsToTheIssuingTenant(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	buyer := billingSyncSeedTenant(t, migDB, "m47buyer", model.PlanFree)
	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)

	code, body := m47PostCheckout(t, appDB, h, buyer, model.PlanTeam)
	if code != http.StatusOK {
		t.Fatalf("CreateCheckout: status %d body %s, want 200", code, body)
	}
	if stub.calls != 1 {
		t.Fatalf("checkout creations at the provider = %d, want 1 "+
			"(the URL must be created server-side, not assembled locally)", stub.calls)
	}
	if !strings.Contains(body, "checkout/custom/") {
		t.Errorf("response URL = %s, want the provider-issued checkout URL", body)
	}
	if strings.Contains(body, buyer.String()) {
		t.Errorf("the checkout URL handed to the client still names the tenant: %s", body)
	}
	token := stub.custom["claim_token"]
	if token == "" {
		t.Fatalf("no claim_token was sent to the provider; custom=%v", stub.custom)
	}
	if _, ok := stub.custom["tenant_id"]; ok {
		t.Errorf("custom data still carries tenant_id: %v", stub.custom)
	}
	if stub.storeID != "4242" || stub.variantID != "9002" {
		t.Errorf("store/variant relationships = %q/%q, want 4242/9002", stub.storeID, stub.variantID)
	}
	// Codex round 3 (Medium): the provider-side checkout must expire with the
	// claim, or a customer can pay through a months-old URL and have the
	// binding refused — money taken, no entitlement.
	exp, err := time.Parse(time.RFC3339, stub.expiresAt)
	if err != nil {
		t.Fatalf("checkout expires_at = %q, want an RFC3339 instant: %v", stub.expiresAt, err)
	}
	if d := time.Until(exp); d < model.CheckoutClaimTTL-time.Minute || d > model.CheckoutClaimTTL+time.Minute {
		t.Errorf("checkout expires in %v, want ~%v (model.CheckoutClaimTTL)", d, model.CheckoutClaimTTL)
	}
	var claimExpiry time.Time
	if err := migDB.QueryRow(
		`SELECT expires_at FROM subscription_checkout_claims WHERE tenant_id = $1`, buyer).Scan(&claimExpiry); err != nil {
		t.Fatalf("read claim expiry: %v", err)
	}
	if !claimExpiry.After(exp) {
		t.Errorf("claim expires_at %v must outlive the provider cutoff %v by the grace window, "+
			"so a delayed first delivery for an accepted payment still resolves", claimExpiry, exp)
	}

	wh := m47Webhook(t, h.cfg, appDB)
	lsSubID := "ls-" + uuid.NewString()
	if code, body := m47Deliver(t, wh, m47CreatedPayload(token, lsSubID, "SBOMHub Team")); code != http.StatusOK {
		t.Fatalf("subscription_created with a valid claim: status %d body %s, want 200", code, body)
	}
	if n := m47SubscriptionRows(t, migDB, buyer); n != 1 {
		t.Fatalf("subscriptions rows for the issuing tenant = %d, want 1", n)
	}
	if got := billingSyncTenantPlan(t, migDB, buyer); got != model.PlanTeam {
		t.Errorf("tenants.plan = %q, want %q", got, model.PlanTeam)
	}
}

func m47CreatedPayload(claimToken, lsSubID, product string) *LSWebhookPayload {
	return &LSWebhookPayload{
		Meta: LSWebhookMeta{
			EventName:  "subscription_created",
			CustomData: map[string]string{"claim_token": claimToken},
		},
		Data: LSWebhookData{
			ID: lsSubID,
			Attributes: LSSubscriptionAttrs{
				ProductName: product,
				Status:      model.StatusActive,
				CustomerID:  9001, VariantID: 9002, ProductID: 9003,
			},
		},
	}
}

// TestM47Checkout_ClaimIsRedeliverableButNotReplayable covers the two halves
// of the consumption rule that pull in opposite directions: the SAME
// subscription must keep resolving (Lemon Squeezy retries a non-2xx up to
// three more times, and the dashboard replays), while a DIFFERENT
// subscription presenting the spent token must be refused.
func TestM47Checkout_ClaimIsRedeliverableButNotReplayable(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	buyer := billingSyncSeedTenant(t, migDB, "m47replay", model.PlanFree)
	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)
	if code, body := m47PostCheckout(t, appDB, h, buyer, model.PlanTeam); code != http.StatusOK {
		t.Fatalf("CreateCheckout: status %d body %s", code, body)
	}
	token := stub.custom["claim_token"]
	wh := m47Webhook(t, h.cfg, appDB)

	first := "ls-" + uuid.NewString()
	if code, body := m47Deliver(t, wh, m47CreatedPayload(token, first, "SBOMHub Team")); code != http.StatusOK {
		t.Fatalf("first delivery: status %d body %s", code, body)
	}
	if code, body := m47Deliver(t, wh, m47CreatedPayload(token, first, "SBOMHub Team")); code != http.StatusOK {
		t.Errorf("REdelivery of the same subscription: status %d body %s, want 200 "+
			"(a transient failure must not make the purchase permanently unlinkable)", code, body)
	}

	second := "ls-" + uuid.NewString()
	code, body := m47Deliver(t, wh, m47CreatedPayload(token, second, "SBOMHub Team"))
	if code == http.StatusOK {
		t.Errorf("a second subscription reused the spent claim token: status %d body %s", code, body)
	}
	if n := m47SubscriptionRows(t, migDB, buyer); n != 1 {
		t.Errorf("subscriptions rows = %d, want 1 (the replay must not mint another)", n)
	}
}

// TestM47Checkout_ExpiredClaimIsRefused pins the binding window. The claim
// TTL is the only bound on it — the provider-side checkout is created
// perpetual — so an expired claim must be inert.
func TestM47Checkout_ExpiredClaimIsRefused(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	buyer := billingSyncSeedTenant(t, migDB, "m47expired", model.PlanFree)
	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)
	if code, body := m47PostCheckout(t, appDB, h, buyer, model.PlanTeam); code != http.StatusOK {
		t.Fatalf("CreateCheckout: status %d body %s", code, body)
	}
	token := stub.custom["claim_token"]

	// Age the claim past its TTL.
	if _, err := migDB.Exec(
		`UPDATE subscription_checkout_claims SET expires_at = NOW() - INTERVAL '1 second'
		 WHERE tenant_id = $1`, buyer); err != nil {
		t.Fatalf("age the claim: %v", err)
	}

	wh := m47Webhook(t, h.cfg, appDB)
	code, body := m47Deliver(t, wh, m47CreatedPayload(token, "ls-"+uuid.NewString(), "SBOMHub Team"))
	if code == http.StatusOK {
		t.Errorf("an expired claim was honoured: status %d body %s", code, body)
	}
	if n := m47SubscriptionRows(t, migDB, buyer); n != 0 {
		t.Errorf("subscriptions rows = %d, want 0", n)
	}
}

// TestM47Checkout_ProviderFailureCreatesNoClaim: a checkout that the provider
// refused must leave no bindable claim behind. The whole handler runs inside
// TenantTx, whose >=400 rollback is what enforces this — the assertion is
// that the two halves cannot diverge.
func TestM47Checkout_ProviderFailureCreatesNoClaim(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	buyer := billingSyncSeedTenant(t, migDB, "m47provfail", model.PlanFree)
	stub := m47StubCheckouts(t)
	stub.statusCode = http.StatusUnprocessableEntity
	h := m47BillingHandler(t, appDB, stub.URL)

	// The tx is committed by the harness regardless of status (see
	// billingSyncPost's note) so this proves the HANDLER wrote nothing,
	// not that a rollback tidied up behind it.
	code, _ := m47PostCheckout(t, appDB, h, buyer, model.PlanTeam)
	if code < 400 {
		t.Fatalf("provider failure produced status %d, want >= 400", code)
	}

	var n int
	if err := migDB.QueryRow(
		`SELECT COUNT(*) FROM subscription_checkout_claims WHERE tenant_id = $1`, buyer).Scan(&n); err != nil {
		t.Fatalf("count claims: %v", err)
	}
	if n != 0 {
		t.Errorf("claims left behind by a failed checkout = %d, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// #4 — webhook revision ordering
// ---------------------------------------------------------------------------

func m47UpdatedPayload(lsSubID, product, status string, updatedAt time.Time) *LSWebhookPayload {
	return &LSWebhookPayload{
		Meta: LSWebhookMeta{EventName: "subscription_updated"},
		Data: LSWebhookData{
			ID: lsSubID,
			Attributes: LSSubscriptionAttrs{
				ProductName: product,
				Status:      status,
				VariantID:   9002,
				UpdatedAt:   updatedAt.UTC().Format(time.RFC3339),
			},
		},
	}
}

// TestM47Webhook_StaleDeliveryCannotResurrectAPaidPlan is the regression: a
// tenant downgrades Team -> Starter, then the retried/replayed OLD Team
// delivery lands. Pre-fix it restored Team for free.
func TestM47Webhook_StaleDeliveryCannotResurrectAPaidPlan(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "m47stale", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)
	wh := m47Webhook(t, h.cfg, appDB)

	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	// The downgrade the customer actually made.
	if code, body := m47Deliver(t, wh,
		m47UpdatedPayload(lsSubID, "SBOMHub Starter", model.StatusActive, recent)); code != http.StatusOK {
		t.Fatalf("downgrade delivery: status %d body %s", code, body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanStarter {
		t.Fatalf("tenants.plan after the downgrade = %q, want %q", got, model.PlanStarter)
	}

	// The delayed old delivery.
	if code, body := m47Deliver(t, wh,
		m47UpdatedPayload(lsSubID, "SBOMHub Team", model.StatusActive, old)); code != http.StatusOK {
		t.Fatalf("stale delivery: status %d body %s, want 200 (an obsolete event must not be "+
			"retried — nothing would change)", code, body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanStarter {
		t.Errorf("tenants.plan after the STALE Team delivery = %q, want %q "+
			"(a delayed old delivery overwrote newer billing state)", got, model.PlanStarter)
	}

	var storedPlan string
	if err := migDB.QueryRow(
		`SELECT plan FROM subscriptions WHERE ls_subscription_id = $1`, lsSubID).Scan(&storedPlan); err != nil {
		t.Fatalf("read subscriptions.plan: %v", err)
	}
	if storedPlan != model.PlanStarter {
		t.Errorf("subscriptions.plan after the stale delivery = %q, want %q", storedPlan, model.PlanStarter)
	}
}

// TestM47Webhook_EqualRevisionTerminalEventStillApplies is the guard against
// over-tightening. Lemon Squeezy emits subscription_updated alongside
// subscription_expired with ONE updated_at; requiring a strictly newer
// revision would drop whichever arrived second — and dropping the expiry
// grants entitlement for free. Equal revisions must still apply.
func TestM47Webhook_EqualRevisionTerminalEventStillApplies(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "m47equal", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)
	wh := m47Webhook(t, h.cfg, appDB)

	rev := time.Now().Add(-30 * time.Minute)
	if code, body := m47Deliver(t, wh,
		m47UpdatedPayload(lsSubID, "SBOMHub Team", model.StatusExpired, rev)); code != http.StatusOK {
		t.Fatalf("subscription_updated: status %d body %s", code, body)
	}
	if code, body := m47Deliver(t, wh, &LSWebhookPayload{
		Meta: LSWebhookMeta{EventName: "subscription_expired"},
		Data: LSWebhookData{
			ID: lsSubID,
			Attributes: LSSubscriptionAttrs{
				ProductName: "SBOMHub Team",
				Status:      model.StatusExpired,
				UpdatedAt:   rev.UTC().Format(time.RFC3339),
			},
		},
	}); code != http.StatusOK {
		t.Fatalf("subscription_expired at the same revision: status %d body %s", code, body)
	}

	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanFree {
		t.Errorf("tenants.plan = %q, want %q — the terminal event at the SAME revision "+
			"must still downgrade", got, model.PlanFree)
	}
}

// TestM47Webhook_MissingRevisionStillApplies documents the deliberate limit:
// a delivery with no parseable attributes.updated_at cannot be ordered, so it
// is applied rather than dropped. Dropping it would let a provider-side
// change to that field silently stop all billing updates.
func TestM47Webhook_MissingRevisionStillApplies(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "m47norev", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)
	wh := m47Webhook(t, h.cfg, appDB)

	if code, body := m47Deliver(t, wh,
		m47UpdatedPayload(lsSubID, "SBOMHub Starter", model.StatusActive, time.Now())); code != http.StatusOK {
		t.Fatalf("seed revision: status %d body %s", code, body)
	}

	p := m47UpdatedPayload(lsSubID, "SBOMHub Pro", model.StatusActive, time.Now())
	p.Data.Attributes.UpdatedAt = "" // no revision at all
	if code, body := m47Deliver(t, wh, p); code != http.StatusOK {
		t.Fatalf("unversioned delivery: status %d body %s", code, body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanPro {
		t.Errorf("tenants.plan = %q, want %q (an unversioned delivery is applied, not dropped)",
			got, model.PlanPro)
	}
}

// ---------------------------------------------------------------------------
// Codex round 1 regressions
// ---------------------------------------------------------------------------

// TestM47Sync_AdvancesTheRevisionWatermark is the round-1 High: the manual
// sync wrote provider state without claiming its revision, so the watermark
// stayed wherever the last webhook left it — and a replayed OLDER webhook was
// then accepted as an equal revision and undid the sync.
//
// Sequence: webhook applies Team at R2, the customer downgrades, sync pulls
// Starter at R3, then the R2 Team delivery is replayed. The tenant must stay
// on Starter.
func TestM47Sync_AdvancesTheRevisionWatermark(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "m47syncrev", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	r2 := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	r3 := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)

	// The provider currently reports the DOWNGRADED state at R3.
	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Starter", status: model.StatusActive,
			updatedAt: r3.Format(time.RFC3339)},
	})
	h := billingSyncHandler(t, appDB, srv.URL)
	wh := m47Webhook(t, h.cfg, appDB)

	// The webhook that established R2.
	if code, body := m47Deliver(t, wh,
		m47UpdatedPayload(lsSubID, "SBOMHub Team", model.StatusActive, r2)); code != http.StatusOK {
		t.Fatalf("R2 delivery: status %d body %s", code, body)
	}

	// Recovery sync pulls R3 (Starter).
	if code, body := billingSyncPost(t, appDB, h,
		tenant, fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID)); code != http.StatusOK {
		t.Fatalf("sync: status %d body %s, want 200", code, body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanStarter {
		t.Fatalf("tenants.plan after sync = %q, want %q", got, model.PlanStarter)
	}

	// The delayed replay of R2.
	if code, body := m47Deliver(t, wh,
		m47UpdatedPayload(lsSubID, "SBOMHub Team", model.StatusActive, r2)); code != http.StatusOK {
		t.Fatalf("R2 replay: status %d body %s", code, body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanStarter {
		t.Errorf("tenants.plan after the replayed R2 delivery = %q, want %q "+
			"(sync must advance the watermark, otherwise a replay undoes it "+
			"and restores a paid plan for free)", got, model.PlanStarter)
	}
}

// TestM47Sync_OlderProviderStateIsNotApplied is the other side of the same
// gate: if a webhook applied something NEWER while sync was talking to the
// provider, the snapshot sync holds is obsolete and must not be written.
func TestM47Sync_OlderProviderStateIsNotApplied(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "m47syncold", model.PlanStarter)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanStarter, model.StatusActive)

	r2 := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	r3 := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)

	// The provider answers with the OLD (Team) state at R2.
	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Team", status: model.StatusActive,
			updatedAt: r2.Format(time.RFC3339)},
	})
	h := billingSyncHandler(t, appDB, srv.URL)
	wh := m47Webhook(t, h.cfg, appDB)

	// A newer webhook (R3, Starter) has already been applied.
	if code, body := m47Deliver(t, wh,
		m47UpdatedPayload(lsSubID, "SBOMHub Starter", model.StatusActive, r3)); code != http.StatusOK {
		t.Fatalf("R3 delivery: status %d body %s", code, body)
	}

	code, body := billingSyncPost(t, appDB, h, tenant,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID))
	if code != http.StatusOK {
		t.Fatalf("sync: status %d body %s, want 200", code, body)
	}
	if !strings.Contains(body, "up_to_date") {
		t.Errorf("body = %s, want the up_to_date answer (nothing to apply)", body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanStarter {
		t.Errorf("tenants.plan after syncing an OLDER provider snapshot = %q, want %q",
			got, model.PlanStarter)
	}
}

// TestM47Checkout_ConsumedClaimSurvivesItsTTL is the round-1 Medium: expiry
// applies to the FIRST use only. A Lemon Squeezy dashboard replay can arrive
// long after the claim TTL, and refusing it would strand a paid subscription
// with no way to link it.
func TestM47Checkout_ConsumedClaimSurvivesItsTTL(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	buyer := billingSyncSeedTenant(t, migDB, "m47ttlreplay", model.PlanFree)
	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)
	if code, body := m47PostCheckout(t, appDB, h, buyer, model.PlanTeam); code != http.StatusOK {
		t.Fatalf("CreateCheckout: status %d body %s", code, body)
	}
	token := stub.custom["claim_token"]
	wh := m47Webhook(t, h.cfg, appDB)

	lsSubID := "ls-" + uuid.NewString()
	if code, body := m47Deliver(t, wh, m47CreatedPayload(token, lsSubID, "SBOMHub Team")); code != http.StatusOK {
		t.Fatalf("first delivery: status %d body %s", code, body)
	}

	// The claim is now consumed AND long expired.
	if _, err := migDB.Exec(
		`UPDATE subscription_checkout_claims SET expires_at = NOW() - INTERVAL '30 days'
		 WHERE tenant_id = $1`, buyer); err != nil {
		t.Fatalf("age the claim: %v", err)
	}

	if code, body := m47Deliver(t, wh, m47CreatedPayload(token, lsSubID, "SBOMHub Team")); code != http.StatusOK {
		t.Errorf("replay of the bound subscription after the TTL: status %d body %s, want 200 "+
			"(the binding is already established; expiry gates the first use only)", code, body)
	}

	// A different subscription is still refused, expired or not.
	if code, _ := m47Deliver(t, wh, m47CreatedPayload(token, "ls-"+uuid.NewString(), "SBOMHub Team")); code == http.StatusOK {
		t.Errorf("a different subscription reused the spent claim: status %d", code)
	}
	if n := m47SubscriptionRows(t, migDB, buyer); n != 1 {
		t.Errorf("subscriptions rows = %d, want 1", n)
	}
}
