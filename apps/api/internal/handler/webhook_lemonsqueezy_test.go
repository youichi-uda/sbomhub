package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// ----------------------------------------------------------------------------
// M46 Track C regression — billing-event / audit-log write failures inside the
// Lemon Squeezy webhook MUST NOT change the HTTP response. Retry facts
// (verified against docs.lemonsqueezy.com/help/webhooks/webhook-requests,
// 2026-07-25 — an earlier revision of this comment wrongly claimed
// "indefinitely"): a non-2xx is retried at most 3 more times (5s/25s/125s
// exponential backoff) and then permanently dropped. A 500 after the
// subscription row committed would therefore re-deliver the whole event up
// to 3 times and could DUPLICATE event/audit history rows, while a 200
// irreversibly loses the failed row once the (finite) retry budget cannot
// be tapped again. The pinned contract: keep the 200, surface every failed
// write through slog; durable inbox is the M46 residual. The pre-fix code
// guaranteed the 200 by silently DISCARDING the errors (errcheck findings).
// ----------------------------------------------------------------------------

const lsTestWebhookSecret = "ls-test-webhook-secret"

// newLSWebhookTestHandler builds the handler against a sqlmock-backed DB in
// SaaS mode with billing enabled and a webhook secret configured, so Handle
// exercises the real HMAC verification path.
func newLSWebhookTestHandler(t *testing.T) (*LemonSqueezyWebhookHandler, sqlmock.Sqlmock) {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_lemonsqueezy_webhook") // SaaS mode
	t.Setenv("LEMONSQUEEZY_API_KEY", "ls-test-api-key")          // billing enabled
	t.Setenv("LEMONSQUEEZY_WEBHOOK_SECRET", lsTestWebhookSecret)
	t.Setenv("APP_ENV", "development")
	cfg := config.Load()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	h := NewLemonSqueezyWebhookHandler(
		cfg,
		repository.NewTenantRepository(db),
		repository.NewSubscriptionRepository(db),
		repository.NewAuditRepository(db),
	)
	return h, mock
}

// captureSlog swaps the default slog logger for a buffer-backed one for the
// duration of the test, so assertions can check what the handler surfaced.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// driveLSWebhook POSTs the payload with a valid HMAC signature and returns
// the recorder. Handle must never return a transport-level error.
func driveLSWebhook(t *testing.T, h *LemonSqueezyWebhookHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/lemonsqueezy", bytes.NewReader([]byte(body)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	mac := hmac.New(sha256.New, []byte(lsTestWebhookSecret))
	mac.Write([]byte(body))
	req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle returned unexpected error: %v", err)
	}
	return rec
}

// lsClaimColumns mirrors the RETURNING list of
// SubscriptionRepository.ConsumeCheckoutClaim.
func lsClaimColumns() []string {
	return []string{
		"token_hash", "tenant_id", "plan", "ls_variant_id", "ls_checkout_id",
		"created_at", "expires_at", "consumed_at", "ls_subscription_id",
	}
}

// expectClaimResolves registers the M47 claim consumption that now precedes
// every subscription_created. `token` is the raw token the payload carries;
// the repository looks it up by SHA-256, which is what this asserts.
func expectClaimResolves(mock sqlmock.Sqlmock, token string, tenantID uuid.UUID, lsSubID string) {
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE subscription_checkout_claims`)).
		WithArgs(hashCheckoutClaimToken(token), lsSubID, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(lsClaimColumns()).
			AddRow(hashCheckoutClaimToken(token), tenantID, model.PlanPro, "2", "",
				now, now.Add(time.Hour), nil, lsSubID))
}

// lsCreatedBody builds a subscription_created delivery carrying a claim
// token — the only tenant binding this handler accepts since M47. The status
// is fixed at "active" because that is what Lemon Squeezy sends with this
// event; the status-dependent paths live on the other lifecycle events.
func lsCreatedBody(token, lsSubID, product string) string {
	return `{
		"meta": {"event_name": "subscription_created", "custom_data": {"claim_token": "` + token + `"}},
		"data": {"id": "` + lsSubID + `", "type": "subscriptions", "attributes": {
			"customer_id": 1, "variant_id": 2, "product_id": 3,
			"product_name": "` + product + `", "status": "active"
		}}
	}`
}

func lsSubscriptionColumns() []string {
	return []string{
		"id", "tenant_id", "ls_subscription_id", "ls_customer_id", "ls_variant_id", "ls_product_id",
		"status", "plan", "billing_anchor", "current_period_start", "current_period_end",
		"trial_ends_at", "renews_at", "ends_at", "cancelled_at", "created_at", "updated_at",
	}
}

// TestLSWebhook_SubscriptionCreated_EventAndAuditFailuresStillReturn200 pins
// the core contract: subscription row committed, but BOTH the
// subscription_events INSERT and the audit_logs INSERT fail — the webhook
// must still answer 200 (no provider retry storm) while logging both
// failures. Pre-fix, the 200 held but the buffer stayed silent.
func TestLSWebhook_SubscriptionCreated_EventAndAuditFailuresStillReturn200(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	tenantID := uuid.New()
	now := time.Now()

	// M47: the claim resolves the tenant before anything else happens.
	expectClaimResolves(mock, "tok-1", tenantID, "ls-sub-1")
	// tenantRepo.GetByID
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, clerk_org_id, name, slug, plan, created_at, updated_at
		FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(tenantID, "org_1", "Acme", "acme", model.PlanFree, now, now))
	// subRepo.GetByLSSubscriptionID — no existing subscription
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-1").
		WillReturnError(sql.ErrNoRows)
	// subRepo.Create
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscriptions`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// tenantRepo.UpdatePlan
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// subRepo.CreateEvent — FAILS
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnError(errors.New("subscription_events insert boom"))
	// auditRepo.Log → Create — FAILS
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnError(errors.New("audit_logs insert boom"))

	rec := driveLSWebhook(t, h, lsCreatedBody("tok-1", "ls-sub-1", "SBOMHub Pro"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (non-2xx triggers up to 3 redeliveries that could duplicate history rows); body=%s", rec.Code, rec.Body.String())
	}
	out := logs.String()
	if !bytes.Contains([]byte(out), []byte("failed to record subscription event")) {
		t.Fatalf("subscription event write failure was not logged; logs:\n%s", out)
	}
	if !bytes.Contains([]byte(out), []byte("failed to write subscription audit log")) {
		t.Fatalf("audit log write failure was not logged; logs:\n%s", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_SubscriptionUpdated_AuditFailureStillReturns200 pins the
// same contract on the subscription_updated path (plan unchanged, so no
// tenants UPDATE is issued).
func TestLSWebhook_SubscriptionUpdated_AuditFailureStillReturns200(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	subID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-2").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-2", "10", "2", "3",
				model.StatusActive, model.PlanPro, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnError(errors.New("subscription_events insert boom"))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnError(errors.New("audit_logs insert boom"))

	body := `{
		"meta": {"event_name": "subscription_updated", "custom_data": {}},
		"data": {"id": "ls-sub-2", "type": "subscriptions", "attributes": {
			"customer_id": 10, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "active"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	out := logs.String()
	if !bytes.Contains([]byte(out), []byte("failed to record subscription event")) {
		t.Fatalf("subscription event write failure was not logged; logs:\n%s", out)
	}
	if !bytes.Contains([]byte(out), []byte("failed to write subscription audit log")) {
		t.Fatalf("audit log write failure was not logged; logs:\n%s", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_SubscriptionCancelled_EventFailureStillReturns200 covers the
// third errcheck site pair (cancelled path).
func TestLSWebhook_SubscriptionCancelled_EventFailureStillReturns200(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	subID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-3").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-3", "10", "2", "3",
				model.StatusActive, model.PlanPro, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnError(errors.New("subscription_events insert boom"))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnError(errors.New("audit_logs insert boom"))

	body := `{
		"meta": {"event_name": "subscription_cancelled", "custom_data": {}},
		"data": {"id": "ls-sub-3", "type": "subscriptions", "attributes": {
			"customer_id": 10, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "cancelled"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	out := logs.String()
	if !bytes.Contains([]byte(out), []byte("failed to record subscription event")) {
		t.Fatalf("subscription event write failure was not logged; logs:\n%s", out)
	}
	if !bytes.Contains([]byte(out), []byte("failed to write subscription audit log")) {
		t.Fatalf("audit log write failure was not logged; logs:\n%s", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_SubscriptionCreated_LookupFailureIs500WithoutInsert pins the
// M46 Codex round A finding at webhook_lemonsqueezy.go:187: the
// subscription lookup error used to be discarded with `_`, so a TRANSIENT
// SELECT failure was misread as "subscription does not exist" and the
// handler fell through to Create — colliding with the ls_subscription_id
// UNIQUE index on every redelivery (500 loop) and misclassifying infra
// trouble as a new subscription. The pinned contract: only sql.ErrNoRows
// takes the create branch; any other lookup error is logged and answered
// with an explicit 500 (Lemon Squeezy retries up to 3 more times, so a
// recovered DB gets a clean second attempt) and NO insert is attempted.
func TestLSWebhook_SubscriptionCreated_LookupFailureIs500WithoutInsert(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	tenantID := uuid.New()
	now := time.Now()

	expectClaimResolves(mock, "tok-5", tenantID, "ls-sub-5")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(tenantID, "org_1", "Acme", "acme", model.PlanFree, now, now))
	// Transient failure — NOT sql.ErrNoRows. No INSERT expectation follows:
	// attempting one is itself a violation of the pinned contract.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-5").
		WillReturnError(errors.New("transient: connection reset by peer"))

	rec := driveLSWebhook(t, h, lsCreatedBody("tok-5", "ls-sub-5", "SBOMHub Pro"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (lookup failure must be an explicit error, "+
			"not a fall-through to Create); body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("failed to look up subscription")) {
		t.Fatalf("response must name the lookup failure (not a create failure); body=%s",
			rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("subscription lookup failed")) {
		t.Fatalf("lookup failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_SubscriptionCreated_HappyPath guards the success path: with
// every write succeeding the handler answers 200 and consumes every
// expectation — i.e. the new error checks did not change the call sequence.
func TestLSWebhook_SubscriptionCreated_HappyPath(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)

	tenantID := uuid.New()
	now := time.Now()

	expectClaimResolves(mock, "tok-4", tenantID, "ls-sub-4")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(tenantID, "org_1", "Acme", "acme", model.PlanFree, now, now))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-4").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscriptions`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	rec := driveLSWebhook(t, h, lsCreatedBody("tok-4", "ls-sub-4", "SBOMHub Pro"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// ----------------------------------------------------------------------------
// M47 W3 — unit-level mirrors of the contracts pinned end-to-end in
// m47_billing_webhook_hardening_integration_test.go. They exist because the
// integration file is tag-gated and skips without a live Postgres, so CI
// would otherwise carry no regression net for either finding.
// ----------------------------------------------------------------------------

// TestLSWebhook_SubscriptionCreated_TenantIDCustomDataIsRejected: the value
// that used to bind the subscription travelled through the buyer's browser.
// It is no longer read at all, and a delivery carrying only it is refused
// WITHOUT touching the database (the sqlmock DB has no expectations).
func TestLSWebhook_SubscriptionCreated_TenantIDCustomDataIsRejected(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)
	tenantID := uuid.New()

	body := `{
		"meta": {"event_name": "subscription_created", "custom_data": {"tenant_id": "` + tenantID.String() + `"}},
		"data": {"id": "ls-sub-legacy", "type": "subscriptions", "attributes": {
			"customer_id": 1, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Team", "status": "active"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — custom_data.tenant_id is buyer-editable and must not "+
			"bind a subscription; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("has_legacy_tenant_id=true")) {
		t.Errorf("the refusal must name the legacy tenant_id so an operator can link the "+
			"purchase by hand; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an unbindable delivery must not touch the database: %v", err)
	}
}

// TestLSWebhook_SubscriptionCreated_UnresolvableClaimIsRejected covers the
// other half: a token that does not resolve (unknown / expired / spent by a
// different subscription — one refusal for all three) stops the delivery
// before any subscription write.
func TestLSWebhook_SubscriptionCreated_UnresolvableClaimIsRejected(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)

	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE subscription_checkout_claims`)).
		WithArgs(hashCheckoutClaimToken("nope"), "ls-sub-x", sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)

	rec := driveLSWebhook(t, h, lsCreatedBody("nope", "ls-sub-x", "SBOMHub Team"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_StaleDeliveryIsDiscarded pins the ordering gate: the
// compare-and-swap matches no row (the stored revision is newer), so the
// handler must answer 200 "skipped" and issue NO further statement — no
// subscription UPDATE, no tenants UPDATE, no history rows.
func TestLSWebhook_StaleDeliveryIsDiscarded(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	subID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-stale").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-stale", "10", "2", "3",
				model.StatusActive, model.PlanStarter, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	// The CAS matches nothing: the delivery is older than what was applied.
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions
		SET provider_updated_at = $2`)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	body := `{
		"meta": {"event_name": "subscription_updated", "custom_data": {}},
		"data": {"id": "ls-sub-stale", "type": "subscriptions", "attributes": {
			"customer_id": 10, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Team", "status": "active",
			"updated_at": "2020-01-01T00:00:00Z"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an obsolete delivery must not be retried; body=%s",
			rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("stale revision")) {
		t.Errorf("body = %s, want the stale-revision skip", rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("older than the state already applied")) {
		t.Errorf("a discarded delivery must be visible in the log; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a discarded delivery must write nothing further: %v", err)
	}
}

// TestLSWebhook_FreshDeliveryPassesTheGate is the positive control for the
// same path: the CAS matches, so the delivery is applied as before.
func TestLSWebhook_FreshDeliveryPassesTheGate(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)

	subID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-fresh").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-fresh", "10", "2", "3",
				model.StatusActive, model.PlanPro, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions
		SET provider_updated_at = $2`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{
		"meta": {"event_name": "subscription_updated", "custom_data": {}},
		"data": {"id": "ls-sub-fresh", "type": "subscriptions", "attributes": {
			"customer_id": 10, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "active",
			"updated_at": "2026-07-28T00:00:00Z"
		}}
	}`
	if rec := driveLSWebhook(t, h, body); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_SubscriptionCreated_RefusesToReparent: the claim resolved to
// tenant A but the subscription row belongs to B. The old code assigned the
// caller's tenant onto the row and relied on the repository's `AND tenant_id`
// guard to silently block the write; now it is an explicit refusal.
func TestLSWebhook_SubscriptionCreated_RefusesToReparent(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)

	claimTenant := uuid.New()
	rowTenant := uuid.New()
	now := time.Now()

	expectClaimResolves(mock, "tok-reparent", claimTenant, "ls-sub-owned")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
		WithArgs(claimTenant).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(claimTenant, "org_a", "A", "a", model.PlanFree, now, now))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-owned").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(uuid.New(), rowTenant, "ls-sub-owned", "10", "2", "3",
				model.StatusActive, model.PlanTeam, nil, nil, nil,
				nil, nil, nil, nil, now, now))

	rec := driveLSWebhook(t, h, lsCreatedBody("tok-reparent", "ls-sub-owned", "SBOMHub Team"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a refused re-parent must write nothing: %v", err)
	}
}

// TestLSWebhook_ClaimTokenIsNeverLogged pins the M47 round-1 (Codex, Medium)
// fix: since the checkout rework, `meta.custom_data` carries `claim_token` —
// a live bearer secret that binds a purchase to a tenant. The receive log used
// to print the whole map, so a failed FIRST delivery left a still-unconsumed
// token in plaintext in the log. Keys may be logged; values must not.
func TestLSWebhook_ClaimTokenIsNeverLogged(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	const token = "unmistakable-claim-token-value"
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE subscription_checkout_claims`)).
		WithArgs(hashCheckoutClaimToken(token), "ls-sub-log", sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)

	driveLSWebhook(t, h, lsCreatedBody(token, "ls-sub-log", "SBOMHub Team"))

	if bytes.Contains(logs.Bytes(), []byte(token)) {
		t.Fatalf("the raw claim token appears in the log:\n%s", logs.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("custom_data_keys")) {
		t.Errorf("the key list should still be logged for diagnostics; logs:\n%s", logs.String())
	}
}

// TestLSWebhook_MalformedPayloadDoesNotLogTheBody is the Codex round-2
// (Medium) regression: the parse-failure branch used to log the first 500
// bytes of the raw body. Since M47 those bytes can contain a live
// `claim_token`, and a delivery that is correctly SIGNED but malformed after
// the custom_data object reaches exactly that branch.
func TestLSWebhook_MalformedPayloadDoesNotLogTheBody(t *testing.T) {
	h, _ := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	const token = "live-token-that-must-not-be-logged"
	// Valid JSON up to and including custom_data, then a type error.
	body := `{"meta":{"event_name":"subscription_created","custom_data":{"claim_token":"` +
		token + `"}},"data":{"id":42}}`

	rec := driveLSWebhook(t, h, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(logs.Bytes(), []byte(token)) {
		t.Fatalf("the raw claim token leaked through the parse-failure log:\n%s", logs.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("body_length")) {
		t.Errorf("the parse failure should still record the body length; logs:\n%s", logs.String())
	}
}
