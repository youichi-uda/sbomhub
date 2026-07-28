package handler

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// ----------------------------------------------------------------------------
// M47 W3 #1 — webhook signature verification must be FAIL-CLOSED.
//
// Pre-fix both receivers answered
//
//	if secret == "" { return !cfg.IsProduction() }
//
// so a deployment that simply had not set LEMONSQUEEZY_WEBHOOK_SECRET /
// CLERK_WEBHOOK_SECRET accepted UNSIGNED webhooks from anyone, as long as
// APP_ENV was anything other than "production" — and "development" is the
// value config.Load falls back to when APP_ENV and ENVIRONMENT are both
// unset. Combined with Lemon Squeezy's short sequential subscription ids,
// an unauthenticated caller could post subscription_expired /
// subscription_updated for a guessed id and move another tenant's plan; the
// Clerk receiver would let one create/rename/delete tenants and users.
//
// The contract pinned here:
//
//   - no secret configured           -> 401, whatever APP_ENV says;
//   - explicit opt-in + non-production -> verification skipped (the local
//     ngrok-less development flow), and the bypass is announced in the log;
//   - explicit opt-in + production   -> still 401. The startup guard in
//     cmd/server/main.go refuses to boot in that combination, so this is
//     the defence-in-depth half: a process that got there anyway does not
//     accept unsigned traffic.
//
// Every case drives the real Handle entry point, and the sqlmock DB is
// created with NO expectations: a rejected webhook must not reach the
// database at all, so any statement the handler issues surfaces as an
// error response instead of the 401 these tests demand.
// ----------------------------------------------------------------------------

// unsignedLSWebhookHandler builds the Lemon Squeezy receiver in SaaS mode
// with billing enabled and NO webhook secret.
func unsignedLSWebhookHandler(t *testing.T, appEnv string, allowUnsigned bool) *LemonSqueezyWebhookHandler {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_ls_failopen") // SaaS mode
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key") // IsBillingEnabled
	t.Setenv("LEMONSQUEEZY_WEBHOOK_SECRET", "")         // the finding
	t.Setenv("APP_ENV", appEnv)
	if allowUnsigned {
		t.Setenv("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", "true")
	} else {
		t.Setenv("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", "")
	}

	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return NewLemonSqueezyWebhookHandler(
		config.Load(),
		db,
		repository.NewTenantRepository(db),
		repository.NewSubscriptionRepository(db),
		repository.NewAuditRepository(db),
	)
}

// postUnsignedLS posts lsExpiryAttack with NO X-Signature header at all. The
// payload is fixed: what varies across these tests is the CONFIGURATION, and
// one weaponised event is enough to show the endpoint is reachable.
func postUnsignedLS(t *testing.T, h *LemonSqueezyWebhookHandler) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/lemonsqueezy", bytes.NewReader([]byte(lsExpiryAttack)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	if err := h.Handle(e.NewContext(req, rec)); err != nil {
		t.Fatalf("Handle returned unexpected error: %v", err)
	}
	return rec
}

// lsExpiryAttack is the cheapest weaponisation of the fail-open: a guessed
// subscription id plus subscription_expired downgrades the owning tenant to
// free. It needs no custom_data, so it is independent of the checkout
// tenant-binding finding.
const lsExpiryAttack = `{
	"meta": {"event_name": "subscription_expired", "custom_data": {}},
	"data": {"id": "424242", "type": "subscriptions", "attributes": {
		"customer_id": 1, "variant_id": 2, "product_id": 3,
		"product_name": "SBOMHub Team", "status": "expired"
	}}
}`

func TestLSWebhook_NoSecret_UnsignedPayloadIsRejected(t *testing.T) {
	for _, appEnv := range []string{"development", "staging", "", "production"} {
		name := appEnv
		if name == "" {
			name = "unset(defaults to development)"
		}
		t.Run(name, func(t *testing.T) {
			h := unsignedLSWebhookHandler(t, appEnv, false)
			rec := postUnsignedLS(t, h)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 — an unsigned webhook was accepted with no "+
					"LEMONSQUEEZY_WEBHOOK_SECRET configured (APP_ENV=%q); body=%s",
					rec.Code, appEnv, rec.Body.String())
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte("invalid signature")) {
				t.Errorf("body = %s, want the invalid-signature refusal", rec.Body.String())
			}
		})
	}
}

// TestLSWebhook_NoSecret_ExplicitOptInAllowsUnsigned pins the escape hatch
// that keeps local development workable: the bypass exists, but only when an
// operator asks for it by name, and never in production.
func TestLSWebhook_NoSecret_ExplicitOptInAllowsUnsigned(t *testing.T) {
	t.Run("development opt-in is honoured and announced", func(t *testing.T) {
		h := unsignedLSWebhookHandler(t, "development", true)
		logs := captureSlog(t)
		rec := postUnsignedLS(t, h)

		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("status = 401 with SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS=true in development: "+
				"the documented local-development escape hatch is broken; body=%s", rec.Body.String())
		}
		if !bytes.Contains(logs.Bytes(), []byte("signature verification BYPASSED")) {
			t.Errorf("the bypass must be loud; logs:\n%s", logs.String())
		}
	})

	// The bypass is DEVELOPMENT-only, not merely non-production (Codex round
	// 3, Low): `!IsProduction()` also admitted staging and every misspelling
	// of "production", which is the opposite of the posture this flag lives
	// inside.
	for _, appEnv := range []string{"production", "staging", "Production", "prod"} {
		t.Run(appEnv+" ignores the opt-in", func(t *testing.T) {
			h := unsignedLSWebhookHandler(t, appEnv, true)
			rec := postUnsignedLS(t, h)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 — SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS is honoured "+
					"in development only (APP_ENV=%q); body=%s", rec.Code, appEnv, rec.Body.String())
			}
		})
	}
}

// unsignedClerkWebhookHandler is the Clerk mirror of the helper above.
func unsignedClerkWebhookHandler(t *testing.T, appEnv string, allowUnsigned bool) *ClerkWebhookHandler {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_clerk_failopen") // SaaS mode
	t.Setenv("CLERK_WEBHOOK_SECRET", "")                   // the finding
	t.Setenv("APP_ENV", appEnv)
	if allowUnsigned {
		t.Setenv("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", "true")
	} else {
		t.Setenv("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", "")
	}

	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return NewClerkWebhookHandler(
		config.Load(),
		repository.NewTenantRepository(db),
		repository.NewUserRepository(db),
		repository.NewAuditRepository(db),
	)
}

func postUnsignedClerk(t *testing.T, h *ClerkWebhookHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/clerk", bytes.NewReader([]byte(body)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	if err := h.Handle(e.NewContext(req, rec)); err != nil {
		t.Fatalf("Handle returned unexpected error: %v", err)
	}
	return rec
}

// clerkOrgDeleteAttack: organization.deleted cascades a whole tenant away
// (tenants → projects/sboms/... via ON DELETE CASCADE), which is the loudest
// thing the unsigned Clerk path buys an attacker.
var clerkOrgDeleteAttack = `{"type":"organization.deleted","data":{"id":"org_` + uuid.NewString() + `"}}`

func TestClerkWebhook_NoSecret_UnsignedPayloadIsRejected(t *testing.T) {
	for _, appEnv := range []string{"development", "staging", "", "production"} {
		name := appEnv
		if name == "" {
			name = "unset(defaults to development)"
		}
		t.Run(name, func(t *testing.T) {
			h := unsignedClerkWebhookHandler(t, appEnv, false)
			rec := postUnsignedClerk(t, h, clerkOrgDeleteAttack)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 — an unsigned Clerk webhook was accepted with no "+
					"CLERK_WEBHOOK_SECRET configured (APP_ENV=%q); body=%s",
					rec.Code, appEnv, rec.Body.String())
			}
		})
	}
}

func TestClerkWebhook_NoSecret_ExplicitOptInAllowsUnsigned(t *testing.T) {
	t.Run("development opt-in is honoured and announced", func(t *testing.T) {
		h := unsignedClerkWebhookHandler(t, "development", true)
		logs := captureSlog(t)
		rec := postUnsignedClerk(t, h, `{"type":"unhandled.event","data":{}}`)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for an unhandled event under the development "+
				"opt-in; body=%s", rec.Code, rec.Body.String())
		}
		if !bytes.Contains(logs.Bytes(), []byte("signature verification BYPASSED")) {
			t.Errorf("the bypass must be loud; logs:\n%s", logs.String())
		}
	})

	for _, appEnv := range []string{"production", "staging", "Production", "prod"} {
		t.Run(appEnv+" ignores the opt-in", func(t *testing.T) {
			h := unsignedClerkWebhookHandler(t, appEnv, true)
			rec := postUnsignedClerk(t, h, clerkOrgDeleteAttack)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (APP_ENV=%q); body=%s",
					rec.Code, appEnv, rec.Body.String())
			}
		})
	}
}

// TestWebhookSecretConfigured_OptInIsIgnored guards the other direction: the
// opt-in only ever governs the "no secret at all" case. With a secret set,
// a bogus signature is refused regardless of the flag — otherwise the flag
// would silently disable verification on a properly configured deployment.
func TestWebhookSecretConfigured_OptInIsIgnored(t *testing.T) {
	t.Setenv("CLERK_SECRET_KEY", "sk_test_optin_ignored")
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key")
	t.Setenv("LEMONSQUEEZY_WEBHOOK_SECRET", lsTestWebhookSecret)
	t.Setenv("CLERK_WEBHOOK_SECRET", "whsec_"+base64.StdEncoding.EncodeToString([]byte(clerkTestWebhookKey)))
	t.Setenv("APP_ENV", "development")
	t.Setenv("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", "true")

	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := config.Load()

	ls := NewLemonSqueezyWebhookHandler(cfg, db,
		repository.NewTenantRepository(db),
		repository.NewSubscriptionRepository(db),
		repository.NewAuditRepository(db))
	if rec := postUnsignedLS(t, ls); rec.Code != http.StatusUnauthorized {
		t.Errorf("Lemon Squeezy: status = %d, want 401 (a configured secret must always be "+
			"enforced); body=%s", rec.Code, rec.Body.String())
	}

	clerk := NewClerkWebhookHandler(cfg,
		repository.NewTenantRepository(db),
		repository.NewUserRepository(db),
		repository.NewAuditRepository(db))
	if rec := postUnsignedClerk(t, clerk, clerkOrgDeleteAttack); rec.Code != http.StatusUnauthorized {
		t.Errorf("Clerk: status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}
