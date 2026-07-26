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

	body := `{
		"meta": {"event_name": "subscription_created", "custom_data": {"tenant_id": "` + tenantID.String() + `"}},
		"data": {"id": "ls-sub-1", "type": "subscriptions", "attributes": {
			"customer_id": 1, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "active"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

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

	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(tenantID, "org_1", "Acme", "acme", model.PlanFree, now, now))
	// Transient failure — NOT sql.ErrNoRows. No INSERT expectation follows:
	// attempting one is itself a violation of the pinned contract.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-5").
		WillReturnError(errors.New("transient: connection reset by peer"))

	body := `{
		"meta": {"event_name": "subscription_created", "custom_data": {"tenant_id": "` + tenantID.String() + `"}},
		"data": {"id": "ls-sub-5", "type": "subscriptions", "attributes": {
			"customer_id": 1, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "active"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

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

	body := `{
		"meta": {"event_name": "subscription_created", "custom_data": {"tenant_id": "` + tenantID.String() + `"}},
		"data": {"id": "ls-sub-4", "type": "subscriptions", "attributes": {
			"customer_id": 1, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "active"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}
