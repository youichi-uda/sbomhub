//go:build integration

// Package handler — M47 R (Codex cross-wave review, High): the Lemon Squeezy
// webhook applied `tenants.plan` OUTSIDE the write that produced it, and
// swallowed its failure.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M47RWebhook' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// # The contradiction between waves
//
// W3 made `tenants.plan` the entitlement of record and gave every billing
// caller a 5xx on a failed plan write; W2 made a 0-row UPDATE audible so a
// write that changed nothing can no longer be reported as success. This
// handler kept a third contract: `if err := UpdatePlan(...); err != nil {
// slog.Error(...) }` and then answered 200 anyway.
//
// # Why a swallowed plan write is not self-healing
//
// The three events that carry a plan transition (`subscription_created`,
// `subscription_updated`, `subscription_expired`) each write the
// `subscriptions` row FIRST and the tenant plan SECOND. Between them sits the
// revision watermark (`provider_updated_at`, migration 061), which the
// subscription write has already advanced. So when the plan UPDATE fails:
//
//   - the subscription row says "expired" while `tenants.plan` still says
//     "team" — every feature gate reads the tenant column, so the tenant keeps
//     paid features it no longer pays for (or, on the created path, does not
//     get the ones it just bought);
//   - the 200 tells Lemon Squeezy the delivery succeeded, so there is no
//     retry;
//   - a MANUAL dashboard replay does not fix it either: the watermark is
//     already at this revision... it is accepted (equal revisions apply), but
//     nothing re-drives it automatically. Recovery requires an operator to
//     notice.
//
// # How the failure is induced
//
// A BEFORE UPDATE trigger on `tenants` that raises only for the tenant under
// test. That is a genuine server-side failure of exactly the shape the
// swallow was written for (a transient DB fault on the second write), driven
// against a real Postgres rather than a mock: the statement the handler
// issues really does fail, and everything the handler did before it really is
// already in the database.
//
// C27: `tenants` CASCADE reaps the seeded subscriptions / claims rows.
package handler

import (
	"database/sql"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
)

// m47rFailTenantPlanUpdate installs a BEFORE UPDATE trigger on `tenants` that
// raises for exactly one tenant id, and removes it again on cleanup.
//
// Scoped to one id on purpose: `tenants` is a shared table in the dev
// database and other tests in this package update it concurrently within the
// same package run.
func m47rFailTenantPlanUpdate(t *testing.T, migDB *sql.DB, tenantID uuid.UUID) {
	t.Helper()
	// Trigger names are per-table, so they must be unique across concurrent
	// installs; the tenant uuid supplies that.
	suffix := "m47r_" + fmt.Sprintf("%x", tenantID[:8])
	fn := "fn_" + suffix
	trg := "trg_" + suffix

	if _, err := migDB.Exec(fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION %s() RETURNS trigger AS $fn$
		BEGIN
			IF NEW.id = '%s'::uuid THEN
				RAISE EXCEPTION 'm47r: simulated transient failure updating tenants.plan';
			END IF;
			RETURN NEW;
		END
		$fn$ LANGUAGE plpgsql`, fn, tenantID)); err != nil {
		t.Fatalf("create failure trigger function: %v", err)
	}
	if _, err := migDB.Exec(fmt.Sprintf(
		`CREATE TRIGGER %s BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION %s()`,
		trg, fn)); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON tenants`, trg)); err != nil {
			t.Errorf("drop failure trigger: %v", err)
		}
		if _, err := migDB.Exec(fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn)); err != nil {
			t.Errorf("drop failure trigger function: %v", err)
		}
	})
}

// m47rSubscriptionState reads back the two columns the ordering gate and the
// entitlement split are visible in.
func m47rSubscriptionState(t *testing.T, migDB *sql.DB, lsSubID string) (status, plan string) {
	t.Helper()
	if err := migDB.QueryRow(
		`SELECT status, plan FROM subscriptions WHERE ls_subscription_id = $1`, lsSubID,
	).Scan(&status, &plan); err != nil {
		t.Fatalf("read subscriptions row %s: %v", lsSubID, err)
	}
	return status, plan
}

func m47rCountSubscriptions(t *testing.T, migDB *sql.DB, lsSubID string) int {
	t.Helper()
	var n int
	if err := migDB.QueryRow(
		`SELECT COUNT(*) FROM subscriptions WHERE ls_subscription_id = $1`, lsSubID).Scan(&n); err != nil {
		t.Fatalf("count subscriptions %s: %v", lsSubID, err)
	}
	return n
}

// m47rConfig is the SaaS + billing-enabled config the webhook needs. The
// handlers are driven directly, so the HMAC never runs (it has its own tests
// in webhook_signature_failopen_test.go).
func m47rConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_m47r")
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key")
	t.Setenv("LEMONSQUEEZY_STORE_ID", "4242")
	t.Setenv("APP_ENV", "development")
	t.Setenv("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", "")
	t.Setenv("LEMONSQUEEZY_WEBHOOK_SECRET", "m47r-secret")
	return config.Load()
}

// TestM47RWebhook_ExpiredDoesNotSplitEntitlement is the headline case: the
// subscription expires, the downgrade of `tenants.plan` fails, and the tenant
// keeps the paid plan forever while the subscription row says it is over.
func TestM47RWebhook_ExpiredDoesNotSplitEntitlement(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "m47r-expired", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	m47rFailTenantPlanUpdate(t, migDB, tenant)

	wh := m47Webhook(t, m47rConfig(t), appDB)
	code, body := m47Deliver(t, wh, &LSWebhookPayload{
		Meta: LSWebhookMeta{EventName: "subscription_expired"},
		Data: LSWebhookData{
			ID: lsSubID,
			Attributes: LSSubscriptionAttrs{
				Status:    model.StatusExpired,
				UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			},
		},
	})

	if code == http.StatusOK {
		t.Errorf("subscription_expired answered %d %s after tenants.plan could not be written. "+
			"A 2xx tells Lemon Squeezy the delivery is done, so the downgrade is never retried.",
			code, body)
	}

	status, _ := m47rSubscriptionState(t, migDB, lsSubID)
	plan := billingSyncTenantPlan(t, migDB, tenant)
	if status == model.StatusExpired && plan == model.PlanTeam {
		t.Errorf("SPLIT ENTITLEMENT: subscriptions.status = %q while tenants.plan = %q. "+
			"Every feature gate reads the tenant column, so an expired subscription keeps "+
			"paid features and no redelivery repairs it (the revision watermark already moved).",
			status, plan)
	}
	if status != model.StatusActive {
		t.Errorf("subscriptions.status = %q, want %q — a delivery that could not be applied "+
			"in full must leave no part of itself behind", status, model.StatusActive)
	}
	if plan != model.PlanTeam {
		t.Errorf("tenants.plan = %q, want %q (unchanged)", plan, model.PlanTeam)
	}
}

// TestM47RWebhook_UpdatedDoesNotSplitEntitlement is the same split on the
// upgrade/downgrade path: subscription_updated moves the subscription to a new
// plan and then fails to move the tenant.
func TestM47RWebhook_UpdatedDoesNotSplitEntitlement(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "m47r-updated", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	m47rFailTenantPlanUpdate(t, migDB, tenant)

	wh := m47Webhook(t, m47rConfig(t), appDB)
	code, body := m47Deliver(t, wh, &LSWebhookPayload{
		Meta: LSWebhookMeta{EventName: "subscription_updated"},
		Data: LSWebhookData{
			ID: lsSubID,
			Attributes: LSSubscriptionAttrs{
				ProductName: "SBOMHub Starter",
				Status:      model.StatusActive,
				UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
			},
		},
	})

	if code == http.StatusOK {
		t.Errorf("subscription_updated answered %d %s after tenants.plan could not be written", code, body)
	}
	_, subPlan := m47rSubscriptionState(t, migDB, lsSubID)
	plan := billingSyncTenantPlan(t, migDB, tenant)
	if subPlan == model.PlanStarter && plan == model.PlanTeam {
		t.Errorf("SPLIT ENTITLEMENT: subscriptions.plan = %q while tenants.plan = %q", subPlan, plan)
	}
	if subPlan != model.PlanTeam {
		t.Errorf("subscriptions.plan = %q, want %q (unchanged)", subPlan, model.PlanTeam)
	}
}

// TestM47RWebhook_CreatedDoesNotLeaveAnUnbilledSubscription is the created
// path. Pre-fix the subscription row (and the consumed claim) survived a
// failed plan write, so the tenant had a paid subscription on record and a
// free plan in the column every gate reads — and the claim was spent, so a
// redelivery could not even re-resolve the tenant.
func TestM47RWebhook_CreatedDoesNotLeaveAnUnbilledSubscription(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	buyer := billingSyncSeedTenant(t, migDB, "m47r-created", model.PlanFree)
	stub := m47StubCheckouts(t)
	h := m47BillingHandler(t, appDB, stub.URL)

	code, body := m47PostCheckout(t, appDB, h, buyer, model.PlanTeam)
	if code != http.StatusOK {
		t.Fatalf("CreateCheckout: status %d body %s, want 200", code, body)
	}
	token := stub.custom["claim_token"]
	if token == "" {
		t.Fatal("checkout stub recorded no claim_token")
	}

	m47rFailTenantPlanUpdate(t, migDB, buyer)

	lsSubID := "ls-" + uuid.NewString()
	wh := m47Webhook(t, h.cfg, appDB)
	code, body = m47Deliver(t, wh, &LSWebhookPayload{
		Meta: LSWebhookMeta{
			EventName:  "subscription_created",
			CustomData: map[string]string{"claim_token": token},
		},
		Data: LSWebhookData{
			ID: lsSubID,
			Attributes: LSSubscriptionAttrs{
				ProductName: "SBOMHub Team",
				Status:      model.StatusActive,
				CustomerID:  9001, VariantID: 9002, ProductID: 9003,
				UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			},
		},
	})

	if code == http.StatusOK {
		t.Errorf("subscription_created answered %d %s after tenants.plan could not be written", code, body)
	}
	if n := m47rCountSubscriptions(t, migDB, lsSubID); n != 0 {
		t.Errorf("subscriptions rows for %s = %d, want 0 — a purchase that could not be "+
			"reflected in tenants.plan must not be half-recorded", lsSubID, n)
	}
	var consumed sql.NullTime
	if err := migDB.QueryRow(
		`SELECT consumed_at FROM subscription_checkout_claims WHERE tenant_id = $1`, buyer,
	).Scan(&consumed); err != nil {
		t.Fatalf("read checkout claim for %s: %v", buyer, err)
	}
	if consumed.Valid {
		t.Errorf("checkout claim was consumed (%v) by a delivery that was not applied — "+
			"the redelivery can no longer resolve its tenant", consumed.Time)
	}
	if plan := billingSyncTenantPlan(t, migDB, buyer); plan != model.PlanFree {
		t.Errorf("tenants.plan = %q, want %q (unchanged)", plan, model.PlanFree)
	}
}

// TestM47RWebhook_AppliesBothWritesOnTheHappyPath is the positive control:
// with no induced failure the same three deliveries must still move BOTH the
// subscription row and the tenant plan. Without it, "nothing was written"
// would pass the tests above for the wrong reason.
func TestM47RWebhook_AppliesBothWritesOnTheHappyPath(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "m47r-control", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	wh := m47Webhook(t, m47rConfig(t), appDB)
	code, body := m47Deliver(t, wh, &LSWebhookPayload{
		Meta: LSWebhookMeta{EventName: "subscription_expired"},
		Data: LSWebhookData{
			ID: lsSubID,
			Attributes: LSSubscriptionAttrs{
				Status:    model.StatusExpired,
				UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("subscription_expired: status %d body %s, want 200", code, body)
	}
	status, _ := m47rSubscriptionState(t, migDB, lsSubID)
	if status != model.StatusExpired {
		t.Errorf("subscriptions.status = %q, want %q", status, model.StatusExpired)
	}
	if plan := billingSyncTenantPlan(t, migDB, tenant); plan != model.PlanFree {
		t.Errorf("tenants.plan = %q, want %q — the downgrade must still happen", plan, model.PlanFree)
	}
}
