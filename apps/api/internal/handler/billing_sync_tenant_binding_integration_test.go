//go:build integration

// Package handler — POST /api/v1/subscription/sync cross-tenant plan
// escalation (M46).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'BillingSync' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// The hole this file pins, exactly as it was reachable pre-fix by any
// authenticated member of any tenant (no admin gate on the route):
//
//  1. `GetByLSSubscriptionID` is deliberately tenant-UNSCOPED (it is the
//     webhook lookup that REVEALS the owning tenant; `subscriptions` lost
//     its RLS policy in migration 031). Handing it an attacker-supplied
//     ls_subscription_id therefore returns ANOTHER tenant's row.
//  2. `syncBySubscriptionID` then overwrote `existingSub.TenantID` with the
//     CALLER's tenant id ("Link to current tenant").
//  3. `SubscriptionRepository.Update` filters `WHERE id = $14 AND
//     tenant_id = $15`, so that statement matched ZERO rows.
//  4. `ExecContext` returns a nil error for a 0-row UPDATE, and the result
//     was discarded — so step 3's refusal was indistinguishable from
//     success and the `if err != nil` guard waved it through.
//  5. `tenantRepo.UpdatePlan(ctx, tenantID, plan)` then ran with the
//     VICTIM's plan and the ATTACKER's tenant id.
//
// Net effect: tenant A posts tenant B's Lemon Squeezy subscription ID and A's
// plan silently becomes B's paid plan. The `else` (create) branch escalated
// the same way, by minting a fresh row under A for an unrelated subscription.
//
// Contract after the fix (kept by this file):
//   - the endpoint accepts exactly ONE id: the one already stored on the
//     caller's own subscription row. Ownership is resolved with the
//     tenant-scoped GetByTenantID BEFORE the provider is contacted, so the
//     tenant-unscoped GetByLSSubscriptionID is no longer on this path at
//     all and an unauthorised id never triggers an outbound call;
//   - a subscription row owned by another tenant is never re-parented; the
//     request is refused and nothing is written;
//   - a subscription with no local row is refused too — the Lemon Squeezy
//     REST subscription object carries NO custom_data (verified against
//     docs.lemonsqueezy.com/api/subscriptions/the-subscription-object on
//     2026-07-27: custom_data is delivered ONLY in webhook `meta`), so
//     ownership cannot be proven from the provider's answer;
//   - refusal uses ONE sentinel — 404 with an identical body, reached by
//     the identical statement sequence, for "no such subscription in Lemon
//     Squeezy", "belongs to someone else" and "not linked here" — so the
//     endpoint cannot be used to enumerate which of the store's
//     subscription IDs are claimed by other tenants, by body or by timing;
//   - the caller's own subscription still re-syncs (the endpoint's actual
//     purpose: recovery from a dropped webhook).
//
// C27: `tenants` CASCADE reaps the seeded subscriptions rows.
package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// billingSyncSeedTenant inserts a tenant carrying `plan` and registers the
// CASCADE cleanup. `subscriptions` has no RLS (migration 031) so the seed
// needs no GUC, but the tenants insert goes through the migrator role like
// every other integration seed in this package.
func billingSyncSeedTenant(t *testing.T, migDB *sql.DB, label, plan string) uuid.UUID {
	t.Helper()
	tenantID := uuid.New()
	org := "billingsync-" + label + "-" + tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug, plan) VALUES ($1, $2, $3, $4, $5)`,
		tenantID, org, "billingsync "+label, org, plan); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s: %v", tenantID, err)
		}
	})
	return tenantID
}

// billingSyncSeedSubscription links an ls_subscription_id to a tenant.
func billingSyncSeedSubscription(t *testing.T, migDB *sql.DB,
	tenantID uuid.UUID, lsSubID, plan, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO subscriptions (
			id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
			status, plan, created_at, updated_at)
		VALUES ($1, $2, $3, '9001', '9002', '9003', $4, $5, NOW(), NOW())`,
		id, tenantID, lsSubID, status, plan); err != nil {
		t.Fatalf("seed subscription %s for tenant %s: %v", lsSubID, tenantID, err)
	}
	return id
}

// billingSyncLSSub is one subscription the stub knows about.
type billingSyncLSSub struct {
	product string
	status  string
	// updatedAt is the provider's revision (RFC3339). Empty means the stub
	// omits the field entirely, which is the pre-M47 shape and exercises the
	// "cannot be ordered, apply anyway" branch of the sync path.
	updatedAt string
}

// billingSyncStub is an httptest stand-in for
// GET https://api.lemonsqueezy.com/v1/subscriptions/{id}. `calls` counts every
// request that reached it, which is what lets the refusal tests assert the
// STRONGER invariant: an unauthorised id must never produce an outbound
// provider call at all (Codex round 3). Comparing response bytes alone would
// still pass for an implementation that fetched first and checked ownership
// second — i.e. the timing/outage oracle this design deliberately removed.
type billingSyncStub struct {
	*httptest.Server
	mu    sync.Mutex
	calls int
	// duringRequest, when set, runs while the handler is blocked on the
	// provider call. It is how the tests land a "webhook" in the middle of a
	// sync deterministically, without goroutines or sleeps.
	duringRequest func()
}

func (s *billingSyncStub) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// billingSyncStubLS builds the stub. `known` maps subscription id -> what the
// provider reports for it; anything else answers 404 the way the provider
// does. Returning the real JSON:API envelope keeps
// fetchLemonSqueezySubscriptionByID's decoding on the tested path.
func billingSyncStubLS(t *testing.T, known map[string]billingSyncLSSub) *billingSyncStub {
	t.Helper()
	stub := &billingSyncStub{}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.calls++
		hook := stub.duringRequest
		stub.mu.Unlock()
		if hook != nil {
			hook()
		}

		const prefix = "/v1/subscriptions/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		subID := strings.TrimPrefix(r.URL.Path, prefix)
		got, ok := known[subID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		// NOTE (the whole reason the create branch must refuse): the real
		// subscription object has no custom_data — store_id/customer_id/
		// product_id/variant_id/status/product_name/user_email and nothing
		// that names OUR tenant. This stub mirrors that shape exactly.
		//
		// M47: it DOES carry updated_at (the provider's revision), which the
		// sync path claims so that re-syncing cannot leave the watermark
		// behind the state it just wrote.
		updatedAt := ""
		if got.updatedAt != "" {
			updatedAt = fmt.Sprintf(`,"updated_at":%q`, got.updatedAt)
		}
		fmt.Fprintf(w, `{"data":{"id":%q,"type":"subscriptions","attributes":{
			"store_id":1,"customer_id":9001,"product_id":9003,"variant_id":9002,
			"status":%q,"variant_name":"Default","product_name":%q,
			"user_email":"buyer@example.com"%s}}}`, subID, got.status, got.product, updatedAt)
	}))
	t.Cleanup(stub.Server.Close)
	return stub
}

// billingSyncHandler builds a BillingHandler in SaaS mode with billing
// enabled, pointed at the stub instead of the live provider.
func billingSyncHandler(t *testing.T, appDB *sql.DB, lsBase string) *BillingHandler {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_billing_sync") // SaaS mode
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key")  // IsBillingEnabled
	t.Setenv("APP_ENV", "development")
	cfg := config.Load()
	return NewBillingHandler(
		cfg,
		repository.NewTenantRepository(appDB),
		repository.NewSubscriptionRepository(appDB),
	).WithLemonSqueezyBaseURL(lsBase)
}

// billingSyncPost drives POST /api/v1/subscription/sync through a real echo
// context inside an app-role tenant tx, exactly like a live request behind
// Auth -> TenantTx.
func billingSyncPost(t *testing.T, appDB *sql.DB, h *BillingHandler,
	tenantID uuid.UUID, body string) (int, string) {
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/subscription/sync", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req = req.WithContext(database.WithTx(context.Background(), tx))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(middleware.ContextKeyTenantID, tenantID)
	// SyncSubscription only requires the tenant to be present in context;
	// the authoritative plan lives in the `tenants` row the handler writes,
	// so the struct is deliberately minimal.
	c.Set(middleware.ContextKeyTenant, &model.Tenant{ID: tenantID})

	herr := h.SyncSubscription(c)
	// Commit either way. Production TenantTx rolls back on error, but
	// committing here regardless lets the assertions prove the HANDLER
	// refused to write — not that a rollback tidied up behind it.
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tenant tx: %v", err)
	}
	committed = true

	if herr != nil {
		var he *echo.HTTPError
		if errors.As(herr, &he) {
			return he.Code, fmt.Sprintf("%v", he.Message)
		}
		t.Fatalf("SyncSubscription returned non-HTTP error: %v", herr)
	}
	return rec.Code, rec.Body.String()
}

func billingSyncTenantPlan(t *testing.T, migDB *sql.DB, tenantID uuid.UUID) string {
	t.Helper()
	var plan string
	if err := migDB.QueryRow(`SELECT plan FROM tenants WHERE id = $1`, tenantID).Scan(&plan); err != nil {
		t.Fatalf("read tenants.plan for %s: %v", tenantID, err)
	}
	return plan
}

// TestBillingSync_ForeignSubscriptionCannotEscalatePlan is the attack:
// attacker tenant A (free) posts victim tenant B's ls_subscription_id and,
// pre-fix, ended up on B's paid plan.
func TestBillingSync_ForeignSubscriptionCannotEscalatePlan(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	victim := billingSyncSeedTenant(t, migDB, "victim", model.PlanTeam)
	attacker := billingSyncSeedTenant(t, migDB, "attacker", model.PlanFree)

	lsSubID := "ls-" + uuid.NewString()
	victimSubRow := billingSyncSeedSubscription(t, migDB, victim, lsSubID, model.PlanTeam, "active")

	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Team", status: model.StatusActive},
	})
	h := billingSyncHandler(t, appDB, srv.URL)

	code, body := billingSyncPost(t, appDB, h, attacker,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID))
	if code != http.StatusNotFound {
		t.Errorf("sync of another tenant's subscription: status %d body %s, want 404", code, body)
	}
	if strings.Contains(body, "synced") {
		t.Errorf("response reports a successful sync for a foreign subscription: %s", body)
	}

	// The escalation itself: the attacker's tenants.plan must not move.
	if got := billingSyncTenantPlan(t, migDB, attacker); got != model.PlanFree {
		t.Errorf("attacker tenants.plan = %q, want %q (cross-tenant plan escalation)", got, model.PlanFree)
	}
	// The victim's row must be untouched — same owner, same plan, same status.
	var ownerID uuid.UUID
	var plan, status string
	if err := migDB.QueryRow(
		`SELECT tenant_id, plan, status FROM subscriptions WHERE id = $1`, victimSubRow).
		Scan(&ownerID, &plan, &status); err != nil {
		t.Fatalf("read victim subscription row: %v", err)
	}
	if ownerID != victim {
		t.Errorf("victim subscription re-parented to %s, want %s", ownerID, victim)
	}
	if plan != model.PlanTeam || status != "active" {
		t.Errorf("victim subscription mutated: plan=%q status=%q, want %q/%q",
			plan, status, model.PlanTeam, "active")
	}
	if got := billingSyncTenantPlan(t, migDB, victim); got != model.PlanTeam {
		t.Errorf("victim tenants.plan = %q, want %q", got, model.PlanTeam)
	}
	// And no row may have been minted under the attacker.
	var attackerRows int
	if err := migDB.QueryRow(
		`SELECT COUNT(*) FROM subscriptions WHERE tenant_id = $1`, attacker).Scan(&attackerRows); err != nil {
		t.Fatalf("count attacker subscriptions: %v", err)
	}
	if attackerRows != 0 {
		t.Errorf("attacker subscriptions rows = %d, want 0", attackerRows)
	}
	// Stronger than the response bytes: an unauthorised id must never even
	// reach Lemon Squeezy. This is what keeps the refusal free of a
	// timing/outage oracle and stops the endpoint being used to probe the
	// provider on someone else's behalf.
	if n := srv.callCount(); n != 0 {
		t.Errorf("provider was contacted %d time(s) for a foreign subscription id, want 0", n)
	}
}

// TestBillingSync_UnlinkedSubscriptionIsRefused covers the `else` (create)
// branch: the subscription exists in Lemon Squeezy but has never been linked
// here. Ownership is unprovable (the REST subscription object carries no
// custom_data), so the request must be refused rather than minting a row —
// pre-fix this was a one-request upgrade to any plan whose subscription id
// the caller could name.
func TestBillingSync_UnlinkedSubscriptionIsRefused(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := billingSyncSeedTenant(t, migDB, "unlinked", model.PlanFree)

	lsSubID := "ls-" + uuid.NewString()
	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Pro", status: model.StatusActive},
	})
	h := billingSyncHandler(t, appDB, srv.URL)

	code, body := billingSyncPost(t, appDB, h, caller,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID))
	if code != http.StatusNotFound {
		t.Errorf("sync of an unlinked subscription: status %d body %s, want 404", code, body)
	}

	if got := billingSyncTenantPlan(t, migDB, caller); got != model.PlanFree {
		t.Errorf("caller tenants.plan = %q, want %q (unprovable ownership must not upgrade)", got, model.PlanFree)
	}
	var rows int
	if err := migDB.QueryRow(
		`SELECT COUNT(*) FROM subscriptions WHERE ls_subscription_id = $1`, lsSubID).Scan(&rows); err != nil {
		t.Fatalf("count subscriptions for %s: %v", lsSubID, err)
	}
	if rows != 0 {
		t.Errorf("subscriptions rows minted for an unlinked id = %d, want 0", rows)
	}
	if n := srv.callCount(); n != 0 {
		t.Errorf("provider was contacted %d time(s) for an unlinked subscription id, want 0", n)
	}
}

// TestBillingSync_OwnSubscriptionStillSyncs is the endpoint's actual purpose
// (recovery from a dropped webhook) and the regression guard against fixing
// the hole by breaking the feature.
func TestBillingSync_OwnSubscriptionStillSyncs(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	owner := billingSyncSeedTenant(t, migDB, "owner", model.PlanFree)
	lsSubID := "ls-" + uuid.NewString()
	rowID := billingSyncSeedSubscription(t, migDB, owner, lsSubID, model.PlanStarter, "past_due")

	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Pro", status: model.StatusActive},
	})
	h := billingSyncHandler(t, appDB, srv.URL)

	code, body := billingSyncPost(t, appDB, h, owner,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID))
	if code != http.StatusOK {
		t.Fatalf("sync of the caller's own subscription: status %d body %s, want 200", code, body)
	}
	if !strings.Contains(body, `"synced"`) || !strings.Contains(body, model.PlanPro) {
		t.Errorf("response = %s, want a synced/%s result", body, model.PlanPro)
	}

	var ownerID uuid.UUID
	var plan, status string
	if err := migDB.QueryRow(
		`SELECT tenant_id, plan, status FROM subscriptions WHERE id = $1`, rowID).
		Scan(&ownerID, &plan, &status); err != nil {
		t.Fatalf("read own subscription row: %v", err)
	}
	if ownerID != owner {
		t.Errorf("subscription owner = %s, want %s", ownerID, owner)
	}
	if plan != model.PlanPro || status != "active" {
		t.Errorf("subscription after sync: plan=%q status=%q, want %q/%q",
			plan, status, model.PlanPro, "active")
	}
	if got := billingSyncTenantPlan(t, migDB, owner); got != model.PlanPro {
		t.Errorf("tenants.plan after sync = %q, want %q", got, model.PlanPro)
	}
}

// TestBillingSync_RefusalIsOneSentinel: "belongs to another tenant", "not
// linked here" and "does not exist in Lemon Squeezy" must be byte-identical
// responses. Lemon Squeezy subscription ids are short sequential integers and
// the API key is store-scoped, so a distinguishable answer would let any
// member enumerate which of the store's subscriptions other tenants hold.
func TestBillingSync_RefusalIsOneSentinel(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	victim := billingSyncSeedTenant(t, migDB, "sentvictim", model.PlanTeam)
	caller := billingSyncSeedTenant(t, migDB, "sentcaller", model.PlanStarter)

	foreignID := "ls-" + uuid.NewString()  // exists in LS, owned by the victim
	unlinkedID := "ls-" + uuid.NewString() // exists in LS, linked nowhere
	unknownID := "ls-" + uuid.NewString()  // does not exist in LS at all
	ownID := "ls-" + uuid.NewString()      // the caller's own link
	billingSyncSeedSubscription(t, migDB, victim, foreignID, model.PlanTeam, "active")
	// The caller HOLDS a subscription of its own. This is the realistic
	// upgrade attempt (starter tenant reaching for a team subscription) and
	// it exercises the "own row exists but the id does not match" branch,
	// which the no-row cases above cannot reach.
	callerRow := billingSyncSeedSubscription(t, migDB, caller, ownID, model.PlanStarter, "active")

	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		foreignID:  {product: "SBOMHub Team", status: model.StatusActive},
		unlinkedID: {product: "SBOMHub Team", status: model.StatusActive},
		ownID:      {product: "SBOMHub Starter", status: model.StatusActive},
	})
	h := billingSyncHandler(t, appDB, srv.URL)

	foreignCode, foreignBody := billingSyncPost(t, appDB, h, caller,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, foreignID))
	unlinkedCode, unlinkedBody := billingSyncPost(t, appDB, h, caller,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, unlinkedID))
	unknownCode, unknownBody := billingSyncPost(t, appDB, h, caller,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, unknownID))

	if foreignCode != unlinkedCode || foreignCode != unknownCode {
		t.Errorf("refusal statuses differ: foreign=%d unlinked=%d unknown=%d (must be one sentinel)",
			foreignCode, unlinkedCode, unknownCode)
	}
	if foreignBody != unlinkedBody || foreignBody != unknownBody {
		t.Errorf("refusal bodies differ:\n foreign  = %s\n unlinked = %s\n unknown  = %s\n(must be one sentinel)",
			foreignBody, unlinkedBody, unknownBody)
	}
	if foreignCode != http.StatusNotFound {
		t.Errorf("refusal status = %d, want 404", foreignCode)
	}

	// A refused probe must not disturb the caller's own billing state
	// either — no partial write, no re-pointing of its link.
	var gotLSID, gotPlan string
	if err := migDB.QueryRow(
		`SELECT ls_subscription_id, plan FROM subscriptions WHERE id = $1`, callerRow).
		Scan(&gotLSID, &gotPlan); err != nil {
		t.Fatalf("read caller subscription row: %v", err)
	}
	if gotLSID != ownID || gotPlan != model.PlanStarter {
		t.Errorf("caller subscription mutated by refused probes: ls_id=%q plan=%q, want %q/%q",
			gotLSID, gotPlan, ownID, model.PlanStarter)
	}
	if got := billingSyncTenantPlan(t, migDB, caller); got != model.PlanStarter {
		t.Errorf("caller tenants.plan = %q, want %q", got, model.PlanStarter)
	}
	if got := billingSyncTenantPlan(t, migDB, victim); got != model.PlanTeam {
		t.Errorf("victim tenants.plan = %q, want %q", got, model.PlanTeam)
	}
	// None of the three refusals may reach the provider — identical bytes
	// AND an identical (empty) side-effect trace.
	if n := srv.callCount(); n != 0 {
		t.Errorf("provider was contacted %d time(s) across three refused ids, want 0", n)
	}
}

// TestBillingSync_ExpiredSubscriptionCannotRestorePaidPlan: the endpoint may
// only reproduce what the webhook would have done. `handleSubscriptionExpired`
// downgrades the tenant to free, so re-syncing an EXPIRED subscription must
// not hand the paid plan back.
//
// Pre-fix the plan was derived from the product name alone
// (productNameToPlan) with the provider's `status` ignored entirely, so a
// tenant whose Team subscription had expired — and had been correctly
// downgraded to free — could POST its own stored id and be back on Team, for
// free, indefinitely (Codex round 3, High). Note the subscriptions row keeps
// plan="team" through expiry (handleSubscriptionExpired only writes status),
// so the stale row is not a usable guard either.
func TestBillingSync_ExpiredSubscriptionCannotRestorePaidPlan(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	// Exactly the state handleSubscriptionExpired leaves behind.
	tenant := billingSyncSeedTenant(t, migDB, "expired", model.PlanFree)
	lsSubID := "ls-" + uuid.NewString()
	rowID := billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusExpired)

	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Team", status: model.StatusExpired},
	})
	h := billingSyncHandler(t, appDB, srv.URL)

	code, body := billingSyncPost(t, appDB, h, tenant,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID))
	// The sync itself is legitimate (it IS the caller's subscription) and
	// still succeeds; what must not happen is the entitlement coming back.
	if code != http.StatusOK {
		t.Fatalf("re-sync of the caller's expired subscription: status %d body %s, want 200", code, body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanFree {
		t.Errorf("tenants.plan after re-syncing an EXPIRED subscription = %q, want %q "+
			"(the paid plan must not be restorable by re-sync)", got, model.PlanFree)
	}
	if !strings.Contains(body, model.PlanFree) {
		t.Errorf("response = %s, want the free plan reported for an expired subscription", body)
	}

	var plan, status string
	if err := migDB.QueryRow(
		`SELECT plan, status FROM subscriptions WHERE id = $1`, rowID).Scan(&plan, &status); err != nil {
		t.Fatalf("read subscription row: %v", err)
	}
	if status != model.StatusExpired {
		t.Errorf("subscription status after sync = %q, want %q", status, model.StatusExpired)
	}
	// subscriptions.plan keeps recording WHAT WAS BOUGHT, not the current
	// entitlement — exactly what every webhook handler writes. Writing the
	// entitlement here instead would desynchronise this row from the webhook
	// and re-open the escalation pinned by
	// TestBillingSync_ExpiredSyncThenUpdatedWebhookStaysFree.
	if plan != model.PlanTeam {
		t.Errorf("subscription plan after sync = %q, want %q (the row records the purchased product; "+
			"the entitlement lives in tenants.plan)", plan, model.PlanTeam)
	}
}

// TestBillingSync_ExpiredSyncThenUpdatedWebhookStaysFree is the cross-path
// regression for the interaction Codex round 4 found in the first cut of the
// expiry fix.
//
// Lemon Squeezy emits `subscription_updated` alongside `subscription_expired`.
// `handleSubscriptionUpdated` derives the plan from the product name only and
// calls UpdatePlan when `newPlan != previousPlan`, where previousPlan is read
// from `subscriptions.plan`. The first cut of the fix wrote the ENTITLEMENT
// (free) into that column, so the very next `subscription_updated` saw
// free != team and upgraded the tenant straight back to Team — turning a
// downgrade into a free paid plan for anyone who synced around ends_at.
//
// The fix keeps subscriptions.plan recording the purchased product (what the
// webhook itself writes) and applies the status-aware entitlement only to
// tenants.plan. This test drives the real sequence:
//
//	expired state -> sync -> subscription_updated(status=expired)
//
// and requires the tenant to stay on free throughout.
func TestBillingSync_ExpiredSyncThenUpdatedWebhookStaysFree(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	// Post-expiry state left by handleSubscriptionExpired.
	tenant := billingSyncSeedTenant(t, migDB, "expseq", model.PlanFree)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusExpired)

	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Team", status: model.StatusExpired},
	})
	h := billingSyncHandler(t, appDB, srv.URL)

	if code, body := billingSyncPost(t, appDB, h, tenant,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID)); code != http.StatusOK {
		t.Fatalf("re-sync of expired subscription: status %d body %s, want 200", code, body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanFree {
		t.Fatalf("tenants.plan directly after sync = %q, want %q", got, model.PlanFree)
	}

	// Now the accompanying subscription_updated lands. The webhook runs
	// OUTSIDE any TenantTx (its route is mounted directly on the Echo
	// instance and the tenant is unknown at receipt time), so it is driven
	// here on the raw app DB — the same way production does.
	wh := NewLemonSqueezyWebhookHandler(
		h.cfg,
		appDB,
		repository.NewTenantRepository(appDB),
		repository.NewSubscriptionRepository(appDB),
		repository.NewAuditRepository(appDB),
	)
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/lemonsqueezy", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	payload := &LSWebhookPayload{
		Meta: LSWebhookMeta{EventName: "subscription_updated"},
		Data: LSWebhookData{
			ID: lsSubID,
			Attributes: LSSubscriptionAttrs{
				ProductName: "SBOMHub Team",
				VariantID:   9002,
				Status:      model.StatusExpired,
			},
		},
	}
	if err := wh.handleSubscriptionUpdated(c, payload); err != nil {
		t.Fatalf("handleSubscriptionUpdated: %v", err)
	}

	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanFree {
		t.Errorf("tenants.plan after sync + subscription_updated = %q, want %q "+
			"(an expired subscription must not be upgradable by re-syncing around the webhook)",
			got, model.PlanFree)
	}
}

// TestBillingSync_CancelledSubscriptionKeepsPlan is the counterpart control:
// `handleSubscriptionCancelled` deliberately does NOT downgrade ("still
// active until ends_at"), so sync must not invent a stricter policy than the
// webhook it mirrors. Without this test the expiry fix could silently
// over-reach into every non-active status.
func TestBillingSync_CancelledSubscriptionKeepsPlan(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "cancelled", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Team", status: model.StatusCancelled},
	})
	h := billingSyncHandler(t, appDB, srv.URL)

	code, body := billingSyncPost(t, appDB, h, tenant,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID))
	if code != http.StatusOK {
		t.Fatalf("re-sync of a cancelled subscription: status %d body %s, want 200", code, body)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanTeam {
		t.Errorf("tenants.plan after re-syncing a CANCELLED subscription = %q, want %q "+
			"(cancelled runs to ends_at — same policy as handleSubscriptionCancelled)", got, model.PlanTeam)
	}
}

// TestBillingSync_LinkRemovedDuringProviderCallIsRefused pins the re-read
// added in Codex round 6.
//
// Ownership is proven BEFORE the provider is contacted (that is what removes
// the enumeration oracle and stops unauthorised ids triggering outbound
// calls), which means the proof is up to 30s old by the time the write
// happens — and the webhook route runs outside this transaction. Update
// writes the WHOLE row, so a stale snapshot would silently revert whatever a
// webhook recorded in the meantime, or write against a link that no longer
// exists.
//
// The stub deletes the caller's subscription row WHILE serving the provider
// request, which is exactly "a webhook landed mid-sync", deterministically.
// The handler must notice on re-read and refuse.
func TestBillingSync_LinkRemovedDuringProviderCallIsRefused(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "midflight", model.PlanFree)
	lsSubID := "ls-" + uuid.NewString()
	rowID := billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanStarter, model.StatusActive)

	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Team", status: model.StatusActive},
	})
	srv.duringRequest = func() {
		if _, err := migDB.Exec(`DELETE FROM subscriptions WHERE id = $1`, rowID); err != nil {
			t.Errorf("mid-flight delete: %v", err)
		}
	}
	h := billingSyncHandler(t, appDB, srv.URL)

	code, body := billingSyncPost(t, appDB, h, tenant,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID))
	if code != http.StatusNotFound {
		t.Errorf("sync whose link vanished mid-flight: status %d body %s, want 404", code, body)
	}
	// And crucially the tenant must not have been granted the Team plan the
	// provider reported for a link that no longer exists.
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanFree {
		t.Errorf("tenants.plan = %q, want %q (a link that vanished mid-sync must grant nothing)",
			got, model.PlanFree)
	}
	var rows int
	if err := migDB.QueryRow(
		`SELECT COUNT(*) FROM subscriptions WHERE id = $1`, rowID).Scan(&rows); err != nil {
		t.Fatalf("count subscription rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("subscription rows = %d, want 0 (the handler must not resurrect a deleted link)", rows)
	}
}

// TestBillingSync_ConcurrentWebhookTimestampsSurviveTheProviderCall is the
// substantive half of the round-6 re-read: the mid-flight-DELETE case above
// was already fail-closed (a 0-row Update surfaces as an error), but a
// mid-flight UPDATE was not. `SubscriptionRepository.Update` writes the WHOLE
// row, so a snapshot taken before a 30s provider call would silently revert
// the renewal / end / cancellation timestamps a webhook recorded while we
// waited. Here the stub performs the timestamp write handleSubscriptionCancelled
// does, and those columns must survive the sync.
//
// SCOPE (Codex round 7, deliberately narrow): this pins the
// NON-PROVIDER-OWNED columns only. `status` and `plan` are provider-owned and
// are intentionally overwritten from the fetched snapshot, so a webhook's
// status change CAN still be lost to an older provider read — that is the
// documented revision-ordering residual (docs/SAAS_SETUP.md #6/#8) and needs
// the provider's updated_at persisted to fix. Do not read this test as "every
// concurrent webhook write survives".
func TestBillingSync_ConcurrentWebhookTimestampsSurviveTheProviderCall(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "midwrite", model.PlanTeam)
	lsSubID := "ls-" + uuid.NewString()
	rowID := billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanTeam, model.StatusActive)

	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{
		lsSubID: {product: "SBOMHub Team", status: model.StatusActive},
	})
	// A subscription_cancelled webhook lands while we are talking to the
	// provider (which still reports the pre-cancellation snapshot).
	srv.duringRequest = func() {
		if _, err := migDB.Exec(`
			UPDATE subscriptions
			SET cancelled_at = NOW(), ends_at = NOW() + INTERVAL '30 days', updated_at = NOW()
			WHERE id = $1`, rowID); err != nil {
			t.Errorf("mid-flight webhook write: %v", err)
		}
	}
	h := billingSyncHandler(t, appDB, srv.URL)

	if code, body := billingSyncPost(t, appDB, h, tenant,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID)); code != http.StatusOK {
		t.Fatalf("sync with a concurrent webhook write: status %d body %s, want 200", code, body)
	}

	var cancelledAt, endsAt sql.NullTime
	if err := migDB.QueryRow(
		`SELECT cancelled_at, ends_at FROM subscriptions WHERE id = $1`, rowID).
		Scan(&cancelledAt, &endsAt); err != nil {
		t.Fatalf("read subscription row: %v", err)
	}
	if !cancelledAt.Valid {
		t.Error("cancelled_at was reverted to NULL — the sync wrote a snapshot taken before the webhook landed")
	}
	if !endsAt.Valid {
		t.Error("ends_at was reverted to NULL — the sync wrote a snapshot taken before the webhook landed")
	}
}

// billingSyncSentinelBody returns the canonical refusal body by driving the
// simplest refusal there is — a tenant with no subscription at all naming an
// arbitrary id. Every other refusal must match it byte for byte.
func billingSyncSentinelBody(t *testing.T, appDB *sql.DB, h *BillingHandler, migDB *sql.DB) string {
	t.Helper()
	probe := billingSyncSeedTenant(t, migDB, "sentinelprobe", model.PlanFree)
	_, body := billingSyncPost(t, appDB, h, probe,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, "ls-"+uuid.NewString()))
	return body
}

// TestBillingSync_OwnedLinkUnknownToProviderIsRefused covers the branch where
// the caller's link is intact locally but Lemon Squeezy answers 404 — an
// operator-facing data anomaly. It must produce the same sentinel as every
// other refusal and must not touch the tenant's plan.
func TestBillingSync_OwnedLinkUnknownToProviderIsRefused(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	tenant := billingSyncSeedTenant(t, migDB, "ghostlink", model.PlanStarter)
	lsSubID := "ls-" + uuid.NewString()
	billingSyncSeedSubscription(t, migDB, tenant, lsSubID, model.PlanStarter, model.StatusActive)

	// The provider knows nothing about it.
	srv := billingSyncStubLS(t, map[string]billingSyncLSSub{})
	h := billingSyncHandler(t, appDB, srv.URL)

	code, body := billingSyncPost(t, appDB, h, tenant,
		fmt.Sprintf(`{"ls_subscription_id":%q}`, lsSubID))
	if code != http.StatusNotFound {
		t.Errorf("sync of a link unknown to the provider: status %d body %s, want 404", code, body)
	}
	// Byte-identical to every other refusal: this branch must not become the
	// one place where the sentinel is distinguishable (Codex round 7).
	if want := billingSyncSentinelBody(t, appDB, h, migDB); body != want {
		t.Errorf("provider-404 refusal body = %s, want the common sentinel %s", body, want)
	}
	if got := billingSyncTenantPlan(t, migDB, tenant); got != model.PlanStarter {
		t.Errorf("tenants.plan = %q, want %q (unchanged)", got, model.PlanStarter)
	}
	// This id IS the caller's own, so the provider is legitimately consulted.
	if n := srv.callCount(); n != 1 {
		t.Errorf("provider calls = %d, want 1 (the caller's own id is the one case that may be fetched)", n)
	}
}

// TestBillingSync_RepositoryUpdateRejectsZeroRows pins step 4 of the chain in
// isolation: a subscription struct whose TenantID does not match the stored
// row matches no row, and the repository must say so instead of returning a
// nil error that reads as success.
func TestBillingSync_RepositoryUpdateRejectsZeroRows(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	owner := billingSyncSeedTenant(t, migDB, "repoowner", model.PlanTeam)
	other := billingSyncSeedTenant(t, migDB, "repoother", model.PlanFree)
	lsSubID := "ls-" + uuid.NewString()
	rowID := billingSyncSeedSubscription(t, migDB, owner, lsSubID, model.PlanTeam, "active")

	repo := repository.NewSubscriptionRepository(appDB)
	err := repo.Update(context.Background(), &model.Subscription{
		ID:               rowID,
		TenantID:         other, // the swap the handler used to perform
		LSSubscriptionID: lsSubID,
		LSCustomerID:     "9001",
		LSVariantID:      "9002",
		LSProductID:      "9003",
		Status:           "active",
		Plan:             model.PlanTeam,
	})
	if err == nil {
		t.Fatal("Update with a mismatched TenantID returned nil error; a 0-row UPDATE must not read as success")
	}
	if !errors.Is(err, repository.ErrSubscriptionNotFound) {
		t.Errorf("Update error = %v, want ErrSubscriptionNotFound", err)
	}

	// And it really did not write.
	var plan string
	if err := migDB.QueryRow(`SELECT plan FROM subscriptions WHERE id = $1`, rowID).Scan(&plan); err != nil {
		t.Fatalf("read subscription row: %v", err)
	}
	if plan != model.PlanTeam {
		t.Errorf("subscription plan = %q, want %q", plan, model.PlanTeam)
	}
}
