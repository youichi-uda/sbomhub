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
// Lemon Squeezy webhook. Retry facts (verified against
// docs.lemonsqueezy.com/help/webhooks/webhook-requests, 2026-07-25 — an
// earlier revision of this comment wrongly claimed "indefinitely"): a non-2xx
// is retried at most 3 more times (5s/25s/125s exponential backoff) and then
// permanently dropped.
//
// M46 pinned "keep the 200 and log the loss", because the subscription row
// was ALREADY COMMITTED by then: a 5xx would re-deliver the whole event and
// could duplicate subscription_events / audit_logs rows when only one of the
// two writes had failed. The pre-fix code got the 200 by silently DISCARDING
// the errors (errcheck findings), which is why these tests also assert the
// slog output.
//
// M47R replaced the premise. The whole delivery — claim, revision CAS,
// subscription row, tenants.plan, history — now runs in ONE transaction
// (handler.applyDelivery), so a failed history write rolls the delivery back
// and the redelivery has nothing to duplicate. The contract these tests pin
// is therefore inverted: a history failure is a 500, and the state is
// UNCHANGED. That is the same audit-or-nothing rule (F5 / F32) the rest of
// the API follows. The slog assertions are kept — the operator still needs to
// see which write failed.
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
		db,
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

// expectTenantBind registers the `SET LOCAL app.current_tenant_id` that
// applyDelivery issues on the delivery transaction once the owning tenant is
// known (handler.bindWebhookTenant). It is an Exec because the repository
// layer never sees it — the handler runs it straight on the *sql.Tx.
func expectTenantBind(mock sqlmock.Sqlmock, tenantID uuid.UUID) {
	mock.ExpectExec(regexp.QuoteMeta(`set_config('app.current_tenant_id'`)).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 1))
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

// TestLSWebhook_SubscriptionCreated_EventFailureRollsTheDeliveryBack pins the
// M47R contract on the created path: the subscription_events INSERT fails, so
// the whole delivery — including the subscription row and the tenants.plan
// write that already succeeded — is rolled back and answered 500.
//
// The audit_logs INSERT is deliberately NOT expected: reaching it would mean
// the handler carried on past a failed history write, which is the M46
// behaviour this replaces.
func TestLSWebhook_SubscriptionCreated_EventFailureRollsTheDeliveryBack(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	// M47: the claim resolves the tenant before anything else happens.
	expectClaimResolves(mock, "tok-1", tenantID, "ls-sub-1")
	expectTenantBind(mock, tenantID)
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
	// M47R (Codex rounds 3 + 4): the tenant is locked and re-read for the
	// history row's previous_plan, so it is not the value seen before the
	// revision claim.
	mock.ExpectExec(regexp.QuoteMeta(`FROM tenants WHERE id = $1 FOR NO KEY UPDATE`)).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(tenantID, "org_1", "Acme", "acme", model.PlanFree, now, now))
	// tenantRepo.UpdatePlan
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// subRepo.CreateEvent — FAILS
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnError(errors.New("subscription_events insert boom"))
	mock.ExpectRollback()

	rec := driveLSWebhook(t, h, lsCreatedBody("tok-1", "ls-sub-1", "SBOMHub Pro"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — a delivery whose history could not be written must "+
			"be rolled back and retried, not reported as applied; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to record subscription event")) {
		t.Fatalf("subscription event write failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_SubscriptionUpdated_AuditFailureRollsTheDeliveryBack pins the
// same contract on the subscription_updated path, one write later: the
// history row succeeds and the AUDIT row fails (plan unchanged, so no tenants
// UPDATE is issued).
func TestLSWebhook_SubscriptionUpdated_AuditFailureRollsTheDeliveryBack(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	subID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-2").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-2", "10", "2", "3",
				model.StatusActive, model.PlanPro, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	expectTenantBind(mock, tenantID)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnError(errors.New("audit_logs insert boom"))
	mock.ExpectRollback()

	body := `{
		"meta": {"event_name": "subscription_updated", "custom_data": {}},
		"data": {"id": "ls-sub-2", "type": "subscriptions", "attributes": {
			"customer_id": 10, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "active"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (audit-or-nothing); body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to write subscription audit log")) {
		t.Fatalf("audit log write failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_SubscriptionCancelled_EventFailureRollsTheDeliveryBack covers
// the third errcheck site pair (cancelled path).
func TestLSWebhook_SubscriptionCancelled_EventFailureRollsTheDeliveryBack(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	subID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-3").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-3", "10", "2", "3",
				model.StatusActive, model.PlanPro, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	expectTenantBind(mock, tenantID)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnError(errors.New("subscription_events insert boom"))
	mock.ExpectRollback()

	body := `{
		"meta": {"event_name": "subscription_cancelled", "custom_data": {}},
		"data": {"id": "ls-sub-3", "type": "subscriptions", "attributes": {
			"customer_id": 10, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "cancelled"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to record subscription event")) {
		t.Fatalf("subscription event write failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestLSWebhook_SubscriptionExpired_PlanFailureRollsTheDeliveryBack is the
// M47R headline case at unit level: the subscription row moves to expired,
// the tenants.plan downgrade fails, and pre-fix the handler answered 200
// leaving `subscriptions.status = expired` next to `tenants.plan = pro`
// forever. The rollback must take the subscription UPDATE with it.
func TestLSWebhook_SubscriptionExpired_PlanFailureRollsTheDeliveryBack(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)
	logs := captureSlog(t)

	subID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-exp").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-exp", "10", "2", "3",
				model.StatusActive, model.PlanPro, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	expectTenantBind(mock, tenantID)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WillReturnError(errors.New("tenants update boom"))
	mock.ExpectRollback()

	body := `{
		"meta": {"event_name": "subscription_expired", "custom_data": {}},
		"data": {"id": "ls-sub-exp", "type": "subscriptions", "attributes": {
			"customer_id": 10, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Pro", "status": "expired"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — a swallowed plan write splits the entitlement "+
			"permanently (tenants.plan is what every gate reads); body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to downgrade tenant plan")) {
		t.Fatalf("the plan write failure was not logged; logs:\n%s", logs.String())
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

	mock.ExpectBegin()
	expectClaimResolves(mock, "tok-5", tenantID, "ls-sub-5")
	expectTenantBind(mock, tenantID)
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(tenantID, "org_1", "Acme", "acme", model.PlanFree, now, now))
	// Transient failure — NOT sql.ErrNoRows. No INSERT expectation follows:
	// attempting one is itself a violation of the pinned contract.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-5").
		WillReturnError(errors.New("transient: connection reset by peer"))
	mock.ExpectRollback()

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

// TestM47RWebhook_ReloadsTheSubscriptionAfterClaimingTheRevision pins the
// Codex round-2 High: the transaction alone did not make the delivery a
// serialised read-modify-write.
//
// The subscription is READ before acceptRevision's compare-and-swap takes the
// row lock, so the values the handler compares against can already be stale by
// the time it is allowed to write. Two concurrent subscription_updated
// deliveries:
//
//	both read plan = starter
//	A (older revision, Team) commits first  -> subscriptions.plan = team,
//	                                           tenants.plan       = team
//	B (newer revision, Starter) then claims its revision and applies, but its
//	  stale previousPlan is "starter", so `newPlan != previousPlan` is FALSE
//	  and it SKIPS the tenants write entirely
//	final: subscriptions.plan = starter, tenants.plan = team  -- split again,
//	  the exact defect this wave exists to remove.
//
// Driven with sqlmock rather than two live deliveries because the interleaving
// has to be exact: what is asserted is that the handler works from a row read
// AFTER the claim, and that is observable as "the reload happens and its values
// drive the decision". The reloaded row carries the plan a concurrent delivery
// would have committed; the handler must therefore issue the tenants UPDATE
// that the stale read would have skipped.
func TestM47RWebhook_ReloadsTheSubscriptionAfterClaimingTheRevision(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)

	subID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	subRow := func(plan string) *sqlmock.Rows {
		return sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-race", "10", "2", "3",
				model.StatusActive, plan, nil, nil, nil,
				nil, nil, nil, nil, now, now)
	}

	mock.ExpectBegin()
	// The pre-claim read: what this delivery saw before it was allowed to write.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-race").
		WillReturnRows(subRow(model.PlanStarter))
	expectTenantBind(mock, tenantID)
	// The CAS succeeds — and takes the row lock.
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions
		SET provider_updated_at = $2`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// The reload: the row a concurrent delivery committed while this one was
	// waiting for the lock.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-race").
		WillReturnRows(subRow(model.PlanTeam))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// The write the stale read would have skipped: reloaded previousPlan is
	// "team", this delivery carries "starter", so tenants.plan MUST move.
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WithArgs(model.PlanStarter, sqlmock.AnyArg(), tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	body := `{
		"meta": {"event_name": "subscription_updated", "custom_data": {}},
		"data": {"id": "ls-sub-race", "type": "subscriptions", "attributes": {
			"customer_id": 10, "variant_id": 2, "product_id": 3,
			"product_name": "SBOMHub Starter", "status": "active",
			"updated_at": "2026-07-28T00:00:00Z"
		}}
	}`
	rec := driveLSWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the delivery did not re-read the subscription after claiming its revision, "+
			"so it compared against a snapshot taken before it held the lock: %v", err)
	}
}

// TestLSWebhook_SubscriptionCreated_TenantLookupErrorsAreSeparated pins the
// M47R extension of the not-found-vs-broken split to the tenant lookup on the
// created path: it used to answer 404 "tenant not found" for a transient
// failure too, pointing an operator investigating an unbilled purchase at a
// tenant that is in fact perfectly fine.
func TestLSWebhook_SubscriptionCreated_TenantLookupErrorsAreSeparated(t *testing.T) {
	cases := []struct {
		name       string
		lookupErr  error
		wantStatus int
		wantLog    string
	}{
		// Not the ordinary deletion path — a deleted tenant cascades its claim
		// away and the delivery is refused earlier with 400 (Codex round 2).
		// Reaching this branch means the claim resolved to a tenant id with no
		// row, which is an inconsistent state.
		{"claim resolves to a missing tenant", sql.ErrNoRows, http.StatusNotFound,
			"claim resolved to a tenant that does not exist"},
		{"transient failure", errors.New("pq: statement timeout"),
			http.StatusInternalServerError, "tenant lookup failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, mock := newLSWebhookTestHandler(t)
			logs := captureSlog(t)
			tenantID := uuid.New()

			mock.ExpectBegin()
			expectClaimResolves(mock, "tok-tenant", tenantID, "ls-sub-tenant")
			expectTenantBind(mock, tenantID)
			mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
				WithArgs(tenantID).
				WillReturnError(tc.lookupErr)
			mock.ExpectRollback()

			rec := driveLSWebhook(t, h, lsCreatedBody("tok-tenant", "ls-sub-tenant", "SBOMHub Pro"))

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !bytes.Contains(logs.Bytes(), []byte(tc.wantLog)) {
				t.Errorf("log does not name the cause (%q); logs:\n%s", tc.wantLog, logs.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}

// TestLSWebhook_SubscriptionCreated_HappyPath guards the success path: with
// every write succeeding the handler answers 200 and consumes every
// expectation — i.e. the new error checks did not change the call sequence.
func TestLSWebhook_SubscriptionCreated_HappyPath(t *testing.T) {
	h, mock := newLSWebhookTestHandler(t)

	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectClaimResolves(mock, "tok-4", tenantID, "ls-sub-4")
	expectTenantBind(mock, tenantID)
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(tenantID, "org_1", "Acme", "acme", model.PlanFree, now, now))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-4").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscriptions`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// M47R (Codex rounds 3 + 4): the tenant lock + re-read for the history row.
	mock.ExpectExec(regexp.QuoteMeta(`FROM tenants WHERE id = $1 FOR NO KEY UPDATE`)).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}).
			AddRow(tenantID, "org_1", "Acme", "acme", model.PlanFree, now, now))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants SET plan = $1`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

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

	// M47R: applyDelivery opens the delivery transaction before the handler
	// can decide anything, so the refusal shows up as an EMPTY transaction —
	// no statement at all between BEGIN and ROLLBACK. That is the property
	// this test is really about: nothing was read and nothing was written.
	mock.ExpectBegin()
	mock.ExpectRollback()

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

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE subscription_checkout_claims`)).
		WithArgs(hashCheckoutClaimToken("nope"), "ls-sub-x", sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

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

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-stale").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-stale", "10", "2", "3",
				model.StatusActive, model.PlanStarter, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	expectTenantBind(mock, tenantID)
	// The CAS matches nothing: the delivery is older than what was applied.
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions
		SET provider_updated_at = $2`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// A skip is a 2xx, so the (empty) transaction commits — see staleDelivery.
	mock.ExpectCommit()

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

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-fresh").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-fresh", "10", "2", "3",
				model.StatusActive, model.PlanPro, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	expectTenantBind(mock, tenantID)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions
		SET provider_updated_at = $2`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// M47R (Codex round 2): a successful claim re-reads the now-locked row, so
	// every comparison that follows is against committed state.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM subscriptions WHERE ls_subscription_id = $1`)).
		WithArgs("ls-sub-fresh").
		WillReturnRows(sqlmock.NewRows(lsSubscriptionColumns()).
			AddRow(subID, tenantID, "ls-sub-fresh", "10", "2", "3",
				model.StatusActive, model.PlanPro, nil, nil, nil,
				nil, nil, nil, nil, now, now))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE subscriptions SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO subscription_events`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

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

	mock.ExpectBegin()
	expectClaimResolves(mock, "tok-reparent", claimTenant, "ls-sub-owned")
	expectTenantBind(mock, claimTenant)
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
	mock.ExpectRollback()

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
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE subscription_checkout_claims`)).
		WithArgs(hashCheckoutClaimToken(token), "ls-sub-log", sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

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
