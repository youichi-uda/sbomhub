package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// TestBillingSyncRoute_NonAdmin_Rejected pins the route-level half of the
// M46 cross-tenant sync fix: POST /api/v1/subscription/sync is wired behind
// appmw.RequireAdmin() (cmd/server/main.go). Pre-fix the route sat on the
// bare `auth` group, so every Member and Viewer of every tenant could post a
// Lemon Squeezy subscription id and move the tenant's billing plan.
//
// The guard is exercised in isolation, following the F16 convention in
// apikey_test.go: role enforcement is a route-level contract that lives in
// middleware.RequireAdmin, not in BillingHandler. The matrix pins both ends
// so a refactor that swaps the guard for an ad-hoc check is caught.
//
// Note this is defence-in-depth only. The actual escalation fix is the
// ownership check inside syncBySubscriptionID (pinned end-to-end against a
// real Postgres in billing_sync_tenant_binding_integration_test.go) — an
// Owner must not be able to claim another tenant's subscription either.
func TestBillingSyncRoute_NonAdmin_Rejected(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		wantStatus int
	}{
		{"viewer rejected", model.RoleViewer, http.StatusForbidden},
		{"member rejected", model.RoleMember, http.StatusForbidden},
		{"unset role rejected", "", http.StatusForbidden},
		// Positive controls: the guard passes the request to the handler
		// (the stub stands in for BillingHandler.SyncSubscription).
		{"admin allowed", model.RoleAdmin, http.StatusOK},
		{"owner allowed", model.RoleOwner, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false
			final := func(c echo.Context) error {
				handlerCalled = true
				return c.JSON(http.StatusOK, map[string]string{"status": "manual_required"})
			}

			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/subscription/sync",
				strings.NewReader(`{"ls_subscription_id":"123456"}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(middleware.ContextKeyTenantID, uuid.New())
			c.Set(middleware.ContextKeyUserID, uuid.New())
			c.Set(middleware.ContextKeyRole, tc.role)

			if err := middleware.RequireAdmin()(final)(c); err != nil {
				t.Fatalf("RequireAdmin returned unexpected error: %v", err)
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusForbidden && handlerCalled {
				t.Fatal("BillingHandler.SyncSubscription MUST NOT run for a below-admin role")
			}
			if tc.wantStatus == http.StatusOK && !handlerCalled {
				t.Fatal("BillingHandler.SyncSubscription must run for admin / owner")
			}
		})
	}
}

// billingSyncRouteRe matches the production wiring of the manual-sync route
// with its admin gate attached.
//
// M47R: the gate moved from a per-route argument onto the `authAdmin` group
// (declared with appmw.RequireAdmin() ahead of TenantTx, so a denial costs no
// transaction — see cmd/server/main.go). The anchor is now the group name,
// which keeps the original property: a route moved to a different (ungated)
// group still fails. TestM47RGatedGroupsAreDeclaredCorrectly pins that
// `authAdmin` really carries RequireAdmin.
var billingSyncRouteRe = regexp.MustCompile(
	`authAdmin\.POST\(\s*"/subscription/sync"\s*,\s*billingHandler\.SyncSubscription\s*\)`)

// TestBillingSyncRoute_IsAdminGatedInMain closes the gap the guard-in-
// isolation test above cannot: that test drives middleware.RequireAdmin
// directly, so it would still pass if someone deleted appmw.RequireAdmin()
// from the route registration (Codex round 1, Low). This one reads the
// actual wiring out of cmd/server/main.go.
//
// A source-text assertion is the cheap option here because route
// registration lives inline in main()'s ~1500-line body; extracting it into
// a testable function is a refactor with a far larger blast radius than the
// regression it would guard. The same technique is already used in
// internal/model/plan_parity_test.go to pin migration content.
func TestBillingSyncRoute_IsAdminGatedInMain(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// this file: apps/api/internal/handler/billing_test.go
	// target:    apps/api/cmd/server/main.go
	mainPath := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "cmd", "server", "main.go"))
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !billingSyncRouteRe.Match(raw) {
		t.Errorf("POST /subscription/sync is not wired with appmw.RequireAdmin() in %s.\n"+
			"M46: the route mutates the tenant's billing plan from a caller-supplied "+
			"Lemon Squeezy subscription id and must stay Owner/Admin only.", mainPath)
	}
}

// TestBillingSync_NoSubscriptionIDReturnsManualRequired pins the frontend
// contract that survived the M46 deletion of the unreachable branch in
// SyncSubscription.
//
// Pre-fix, a request without ls_subscription_id fell through to
// fetchLemonSqueezySubscriptionByID(""), which returns "subscription ID is
// required" by construction, so the only reachable outcome was the
// `manual_required` payload — everything after that call was dead code that
// also carried a duplicate of the cross-tenant escalation. The branch is
// gone; the response the billing page keys off to reveal the manual
// subscription-id input must not be.
//
// The sqlmock DB deliberately expects NO statements: this path must answer
// without touching the database at all.
func TestBillingSync_NoSubscriptionIDReturnsManualRequired(t *testing.T) {
	t.Setenv("CLERK_SECRET_KEY", "sk_test_billing_sync_manual") // SaaS mode
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key")         // IsBillingEnabled
	t.Setenv("APP_ENV", "development")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	h := NewBillingHandler(
		config.Load(),
		repository.NewTenantRepository(db),
		repository.NewSubscriptionRepository(db),
	)
	// Point the handler at an unroutable address as a tripwire: if a
	// refactor ever reintroduces a provider call on this path, the test
	// fails loudly instead of silently reaching out to Lemon Squeezy.
	h.WithLemonSqueezyBaseURL("http://127.0.0.1:1")

	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"empty id", `{"ls_subscription_id":""}`},
		{"absent field", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/subscription/sync", strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			tenantID := uuid.New()
			c.Set(middleware.ContextKeyTenantID, tenantID)
			c.Set(middleware.ContextKeyTenant, &model.Tenant{ID: tenantID})
			c.Set(middleware.ContextKeyRole, model.RoleOwner)

			if err := h.SyncSubscription(c); err != nil {
				t.Fatalf("SyncSubscription: %v", err)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "manual_required") {
				t.Errorf("body = %s, want the manual_required contract the billing page keys off", rec.Body.String())
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the no-id path must not touch the database: %v", err)
	}
}

// TestBillingSync_MalformedBodyIs400 pins the Bind-error branch. This is the
// input the old fall-through actually mishandled (Codex round 1, Low): Go's
// JSON decoder populates `ls_subscription_id` from the first occurrence and
// then fails on the second, so `err != nil` came back with a NON-empty id and
// the old code dropped into the escalating branch. The handler must refuse
// outright, without touching the database or the provider.
func TestBillingSync_MalformedBodyIs400(t *testing.T) {
	t.Setenv("CLERK_SECRET_KEY", "sk_test_billing_sync_malformed")
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key")
	t.Setenv("APP_ENV", "development")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	h := NewBillingHandler(
		config.Load(),
		repository.NewTenantRepository(db),
		repository.NewSubscriptionRepository(db),
	)
	// Unroutable: any provider call would fail loudly rather than silently
	// reaching Lemon Squeezy.
	h.WithLemonSqueezyBaseURL("http://127.0.0.1:1")

	for _, tc := range []struct {
		name string
		body string
	}{
		// The duplicate-key case: the decoder sets the field, then errors.
		{"duplicate key, second wrong type", `{"ls_subscription_id":"123456","ls_subscription_id":42}`},
		{"wrong type", `{"ls_subscription_id":42}`},
		{"truncated", `{"ls_subscription_id":"123456"`},
		{"not an object", `["ls_subscription_id"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/subscription/sync", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			tenantID := uuid.New()
			c.Set(middleware.ContextKeyTenantID, tenantID)
			c.Set(middleware.ContextKeyTenant, &model.Tenant{ID: tenantID})
			c.Set(middleware.ContextKeyRole, model.RoleOwner)

			if err := h.SyncSubscription(c); err != nil {
				t.Fatalf("SyncSubscription: %v", err)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "synced") {
				t.Errorf("malformed body produced a sync: %s", rec.Body.String())
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a malformed body must not touch the database: %v", err)
	}
}

// TestBillingSync_WithLemonSqueezyBaseURL pins the injection point the
// integration test depends on: an empty override must fall back to the
// production root rather than leaving a relative URL behind, and a trailing
// slash must not produce a double slash in the request path.
func TestBillingSync_WithLemonSqueezyBaseURL(t *testing.T) {
	h := &BillingHandler{}

	h.WithLemonSqueezyBaseURL("")
	if h.lsBaseURL != lemonSqueezyDefaultBaseURL {
		t.Errorf("empty override: lsBaseURL = %q, want %q", h.lsBaseURL, lemonSqueezyDefaultBaseURL)
	}

	h.WithLemonSqueezyBaseURL("http://127.0.0.1:1234/")
	if h.lsBaseURL != "http://127.0.0.1:1234" {
		t.Errorf("trailing slash not trimmed: lsBaseURL = %q", h.lsBaseURL)
	}
}

// ----------------------------------------------------------------------------
// M47 W3 #3 — POST /api/v1/plan/select-free.
//
// Pre-fix the route sat on the bare `auth` group and the handler wrote
// tenants.plan = free unconditionally. Two separate holes:
//
//  1. No role gate: any Viewer or Member of a tenant could downgrade it. The
//     plan is what the limit/feature gates read (middleware/tenant.go), so
//     this is a self-service denial of the tenant's own paid features.
//  2. No subscription check: the downgrade ran even with a LIVE Lemon Squeezy
//     subscription. Nothing in it touches the provider, so the tenant keeps
//     being charged while losing the entitlement, and the local state now
//     disagrees with `subscriptions` until the next webhook.
//
// Both halves are pinned below. The refusal is the deliberately safest
// product answer (see docs/SAAS_SETUP.md §2.5): cancel at the provider
// first, and the existing subscription_expired webhook performs the
// downgrade at period end.
// ----------------------------------------------------------------------------

// selectFreeRouteRe matches the production wiring with its admin gate.
var selectFreeRouteRe = regexp.MustCompile(
	`authAdmin\.POST\(\s*"/plan/select-free"\s*,\s*billingHandler\.SelectFreePlan\s*\)`)

// checkoutRouteRe matches the checkout route with its admin gate. Completing
// a checkout occupies the tenant's single subscription slot
// (UNIQUE(tenant_id)) and moves its plan, so it is an administrative act for
// the same reason /subscription/sync is — this closes the residual flagged
// as #7 in docs/SAAS_SETUP.md §2.5.
var checkoutRouteRe = regexp.MustCompile(
	`authAdmin\.POST\(\s*"/subscription/checkout"\s*,\s*billingHandler\.CreateCheckout\s*\)`)

func TestBillingRoutes_PlanMutatorsAreAdminGatedInMain(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	mainPath := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "cmd", "server", "main.go"))
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !selectFreeRouteRe.Match(raw) {
		t.Errorf("POST /plan/select-free is not wired with appmw.RequireAdmin() in %s.\n"+
			"M47: it rewrites tenants.plan — the value every limit/feature gate reads — "+
			"and must stay Owner/Admin only (M47R: on the authAdmin group).", mainPath)
	}
	if !checkoutRouteRe.Match(raw) {
		t.Errorf("POST /subscription/checkout is not wired with appmw.RequireAdmin() in %s.\n"+
			"M47: completing the checkout it creates occupies the tenant's single "+
			"subscription slot and changes its plan.", mainPath)
	}
}

// selectFreeHandler builds a BillingHandler in SaaS mode over sqlmock.
func selectFreeHandler(t *testing.T) (*BillingHandler, sqlmock.Sqlmock) {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_select_free") // SaaS mode
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key")
	t.Setenv("APP_ENV", "development")

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return NewBillingHandler(
		config.Load(),
		repository.NewTenantRepository(db),
		repository.NewSubscriptionRepository(db),
	), mock
}

func driveSelectFree(t *testing.T, h *BillingHandler) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/select-free", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	tenantID := uuid.New()
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyTenant, &model.Tenant{ID: tenantID, Plan: model.PlanTeam})
	c.Set(middleware.ContextKeyRole, model.RoleOwner)
	if err := h.SelectFreePlan(c); err != nil {
		t.Fatalf("SelectFreePlan: %v", err)
	}
	return rec
}

// TestSelectFreePlan_LiveSubscriptionIsRefused drives the statuses that mean
// "this tenant is still on a paid contract". The guard is a SINGLE conditional
// UPDATE (Codex round 1, Medium: a read-then-write left a window in which the
// webhook could create a subscription between the two), so the assertion is
// that the statement matched no row and the handler answered 409 — not that
// no statement ran.
func TestSelectFreePlan_LiveSubscriptionIsRefused(t *testing.T) {
	for _, status := range []string{
		model.StatusActive,
		model.StatusOnTrial,
		model.StatusPastDue,
		model.StatusUnpaid,
		model.StatusPaused,
		// cancelled != ended: handleSubscriptionCancelled deliberately keeps
		// the plan until ends_at, so the tenant is still entitled here.
		model.StatusCancelled,
	} {
		t.Run(status, func(t *testing.T) {
			h, mock := selectFreeHandler(t)
			now := time.Now()
			// M47R: the guard takes the subscriptions and tenants row locks in
			// their own statements first, so a concurrent billing transaction
			// has to commit before the conditional UPDATE takes its snapshot.
			mock.ExpectExec(regexp.QuoteMeta(`FROM subscriptions WHERE tenant_id = $1 FOR UPDATE`)).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(regexp.QuoteMeta(`FROM tenants WHERE id = $1 FOR UPDATE`)).
				WillReturnResult(sqlmock.NewResult(0, 1))
			// The guarded UPDATE matches nothing: a live subscription exists.
			mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
				WithArgs(model.PlanFree, sqlmock.AnyArg(), model.StatusExpired).
				WillReturnResult(sqlmock.NewResult(0, 0))
			// Diagnostic re-read that names the blocking status in the 409.
			mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE tenant_id = $1`)).
				WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
					AddRow(uuid.New(), uuid.New(), "ls-sub-live", "10", "2", "3",
						status, model.PlanTeam, nil, nil, nil,
						nil, nil, nil, nil, now, now))

			rec := driveSelectFree(t, h)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409 — a tenant with a %s subscription must not be "+
					"able to drop itself to free while it is still being charged; body=%s",
					rec.Code, status, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), status) {
				t.Errorf("body = %s, want the blocking status named", rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}

// TestSelectFreePlan_AllowedWhenNothingIsLive is the positive control: the
// guarded UPDATE matches, so the endpoint keeps working as the onboarding
// "stay on free" action.
func TestSelectFreePlan_AllowedWhenNothingIsLive(t *testing.T) {
	h, mock := selectFreeHandler(t)
	// M47R: the guard's subscriptions + tenants row locks
	// (see UpdatePlanUnlessSubscriptionLive).
	mock.ExpectExec(regexp.QuoteMeta(`FROM subscriptions WHERE tenant_id = $1 FOR UPDATE`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`FROM tenants WHERE id = $1 FOR UPDATE`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WithArgs(model.PlanFree, sqlmock.AnyArg(), model.StatusExpired).
		WillReturnResult(sqlmock.NewResult(0, 1))

	rec := driveSelectFree(t, h)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestSelectFreePlan_UpdateFailureIsNotADowngrade: a transient failure on the
// guarded write must surface as 500, not as a silent success.
func TestSelectFreePlan_UpdateFailureIsNotADowngrade(t *testing.T) {
	h, mock := selectFreeHandler(t)
	// M47R: the guard's subscriptions + tenants row locks
	// (see UpdatePlanUnlessSubscriptionLive).
	mock.ExpectExec(regexp.QuoteMeta(`FROM subscriptions WHERE tenant_id = $1 FOR UPDATE`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`FROM tenants WHERE id = $1 FOR UPDATE`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WillReturnError(errors.New("transient: connection reset by peer"))

	rec := driveSelectFree(t, h)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestSelectFreePlan_DiagnosticReadFailureStillRefuses: the refusal is decided
// by the guarded UPDATE alone. If the follow-up read that names the blocking
// status fails, the answer must still be 409 — never a 500 that suggests the
// caller should retry into a downgrade.
func TestSelectFreePlan_DiagnosticReadFailureStillRefuses(t *testing.T) {
	h, mock := selectFreeHandler(t)
	// M47R: the guard's subscriptions + tenants row locks
	// (see UpdatePlanUnlessSubscriptionLive).
	mock.ExpectExec(regexp.QuoteMeta(`FROM subscriptions WHERE tenant_id = $1 FOR UPDATE`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`FROM tenants WHERE id = $1 FOR UPDATE`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE tenant_id = $1`)).
		WillReturnError(errors.New("transient: connection reset by peer"))

	rec := driveSelectFree(t, h)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
