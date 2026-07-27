package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

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
// with its admin gate attached. Anchored on `auth.POST` so a route moved to
// a different (ungated) group also fails.
var billingSyncRouteRe = regexp.MustCompile(
	`auth\.POST\(\s*"/subscription/sync"\s*,\s*billingHandler\.SyncSubscription\s*,\s*appmw\.RequireAdmin\(\)\s*\)`)

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
