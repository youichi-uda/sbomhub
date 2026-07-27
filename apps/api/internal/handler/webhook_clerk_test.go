package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
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
// M46 Track C-3b regression — Clerk webhook error contract.
//
// Retry facts (verified 2026-07-26 against the official docs: Clerk delegates
// delivery to Svix — clerk.com/docs/webhooks/overview — and the Svix schedule
// at docs.svix.com/retries): a non-2xx (including 3xx) is retried on a FINITE
// schedule of 8 total attempts ("Immediately, 5 seconds, 5 minutes, 30
// minutes, 2 hours, 5 hours, 10 hours, 10 hours"), after which the message is
// marked Failed and can still be REPLAYED MANUALLY from the Clerk Dashboard.
// Automatic endpoint disabling only happens after ~5 days of continuous
// failure, so answering 500 on a transient DB error is safe and buys a clean
// redelivery once the DB recovers.
//
// Pinned contract (mirrors webhook_lemonsqueezy.go, M46 3a7d483):
//   - Lookup errors: only sql.ErrNoRows means "not found"; any other error
//     answers 500 (pre-fix: silently misread as not-found and answered 200,
//     permanently dropping the event since Svix does not retry a 2xx).
//   - State-changing writes (Delete / RemoveFromTenant): failure answers 500.
//     The deletes are idempotent, so the Svix redelivery is a clean re-run.
//   - Audit log failure AFTER a committed upsert (user/org created/updated):
//     answers 500 — the upsert is idempotent and the audit row is the ONLY
//     history write, so redelivery recovers the audit trail with no
//     duplication risk (unlike Lemon Squeezy's two history writes).
//   - Audit log failure AFTER a committed delete: keeps the 200 + slog. A
//     5xx could NOT recover the row — the redelivery's lookup would hit
//     ErrNoRows (row already deleted) and answer 200 without ever logging.
// ----------------------------------------------------------------------------

// clerkTestWebhookKey is the raw HMAC key; the env var carries it in Clerk's
// "whsec_<base64>" format so the handler's decode path is exercised too.
const clerkTestWebhookKey = "clerk-test-webhook-signing-key"

func newClerkWebhookTestHandler(t *testing.T) (*ClerkWebhookHandler, sqlmock.Sqlmock) {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_clerk_webhook") // SaaS mode
	t.Setenv("CLERK_WEBHOOK_SECRET", "whsec_"+base64.StdEncoding.EncodeToString([]byte(clerkTestWebhookKey)))
	t.Setenv("APP_ENV", "development")
	cfg := config.Load()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	h := NewClerkWebhookHandler(
		cfg,
		repository.NewTenantRepository(db),
		repository.NewUserRepository(db),
		repository.NewAuditRepository(db),
	)
	return h, mock
}

// driveClerkWebhook POSTs the payload with valid Svix headers (real HMAC over
// "id.timestamp.body") so every test exercises the production verification
// path end-to-end.
func driveClerkWebhook(t *testing.T, h *ClerkWebhookHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/clerk", bytes.NewReader([]byte(body)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	svixID := "msg_" + uuid.NewString()
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(clerkTestWebhookKey))
	mac.Write([]byte(svixID + "." + ts + "." + body))
	req.Header.Set("svix-id", svixID)
	req.Header.Set("svix-timestamp", ts)
	req.Header.Set("svix-signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle returned unexpected error: %v", err)
	}
	return rec
}

func clerkUserColumns() []string {
	return []string{"id", "clerk_user_id", "email", "name", "avatar_url", "created_at", "updated_at"}
}

func clerkTenantColumns() []string {
	return []string{"id", "clerk_org_id", "name", "slug", "plan", "created_at", "updated_at"}
}

func clerkUserRow(id uuid.UUID, clerkUserID string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(clerkUserColumns()).
		AddRow(id, clerkUserID, "u@example.com", "U Ser", "", now, now)
}

func clerkTenantRow(id uuid.UUID, clerkOrgID string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(clerkTenantColumns()).
		AddRow(id, clerkOrgID, "Acme", "acme", model.PlanFree, now, now)
}

// TestClerkWebhook_BadSignatureIs401 pins that the (S1017-refactored)
// signature path still rejects a wrong signature.
func TestClerkWebhook_BadSignatureIs401(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)

	e := echo.New()
	body := `{"type":"user.deleted","data":{"id":"user_1"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/clerk", bytes.NewReader([]byte(body)))
	req.Header.Set("svix-id", "msg_bad")
	req.Header.Set("svix-timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("svix-signature", "v1,ZGVmaW5pdGVseS1ub3QtdmFsaWQ=")
	rec := httptest.NewRecorder()
	if err := h.Handle(e.NewContext(req, rec)); err != nil {
		t.Fatalf("Handle returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_UserDeleted_LookupFailureIs500 pins that a TRANSIENT user
// lookup error is NOT misread as "user already gone". Pre-fix the handler
// answered 200 on any lookup error, permanently dropping the deletion (Svix
// does not retry a 2xx) — the user row would outlive its IdP identity.
func TestClerkWebhook_UserDeleted_LookupFailureIs500(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_del_1").
		WillReturnError(errors.New("transient: connection reset by peer"))

	rec := driveClerkWebhook(t, h, `{"type":"user.deleted","data":{"id":"user_del_1"}}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (transient lookup error must trigger a Svix redelivery, not drop the deletion); body=%s",
			rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("user lookup failed")) {
		t.Fatalf("lookup failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_UserDeleted_DeleteFailureIs500 pins the errcheck fix at the
// userRepo.Delete call: pre-fix a failed DELETE was discarded and the webhook
// answered 200, so the user was never deleted and never retried.
func TestClerkWebhook_UserDeleted_DeleteFailureIs500(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	userID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_del_2").
		WillReturnRows(clerkUserRow(userID, "user_del_2"))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM users WHERE id = $1`)).
		WithArgs(userID).
		WillReturnError(errors.New("delete boom"))

	rec := driveClerkWebhook(t, h, `{"type":"user.deleted","data":{"id":"user_del_2"}}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (failed DELETE must be redelivered — the delete is idempotent); body=%s",
			rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to delete user")) {
		t.Fatalf("delete failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_UserDeleted_AuditFailureStillReturns200 pins the
// delete-path audit contract: the user row is already gone, so a 5xx could
// never recover the audit row (the redelivery's lookup hits ErrNoRows and
// answers 200 without logging). Keep the 200, surface the loss via slog.
func TestClerkWebhook_UserDeleted_AuditFailureStillReturns200(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	userID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_del_3").
		WillReturnRows(clerkUserRow(userID, "user_del_3"))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM users WHERE id = $1`)).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnError(errors.New("audit_logs insert boom"))

	rec := driveClerkWebhook(t, h, `{"type":"user.deleted","data":{"id":"user_del_3"}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (user row already deleted — a 5xx cannot recover the audit row); body=%s",
			rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to write user deletion audit log")) {
		t.Fatalf("audit write failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_UserDeleted_NotFoundIs200 pins that sql.ErrNoRows (user
// already gone or never provisioned) stays a 200 — deletion is idempotent
// and a redelivery must not loop.
func TestClerkWebhook_UserDeleted_NotFoundIs200(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_del_4").
		WillReturnError(sql.ErrNoRows)

	rec := driveClerkWebhook(t, h, `{"type":"user.deleted","data":{"id":"user_del_4"}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_UserDeleted_HappyPath_AuditRowAvoidsDeadFK pins the M46
// Codex C-3b round-1 [High] finding: audit_logs.user_id is FK'd to
// users(id), and the user row is deleted BEFORE the audit INSERT — so an
// audit input carrying the deleted id can never insert (deletion audit rows
// were silently lost forever pre-fix). The pinned contract: user_id (and
// tenant_id) are NULL — the documented convention for system-level webhook
// events (AuditRepository.List) — and the deleted id stays queryable via
// resource_id, which carries no FK.
func TestClerkWebhook_UserDeleted_HappyPath_AuditRowAvoidsDeadFK(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)

	userID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_del_5").
		WillReturnRows(clerkUserRow(userID, "user_del_5"))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM users WHERE id = $1`)).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// audit_logs args: id, tenant_id, user_id, action, resource_type,
	// resource_id, details, ip_address, user_agent, created_at.
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WithArgs(sqlmock.AnyArg(), nil, nil, model.ActionUserDeleted, model.ResourceUser,
			userID, sqlmock.AnyArg(), nil, "", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	rec := driveClerkWebhook(t, h, `{"type":"user.deleted","data":{"id":"user_del_5"}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("audit row must carry NULL user_id/tenant_id (dead-FK) and the deleted id in resource_id: %v", err)
	}
}

// TestClerkWebhook_OrgDeleted_HappyPath_AuditRowAvoidsDeadFK is the tenant
// twin of the pin above. audit_logs.tenant_id is FK'd ON DELETE CASCADE, so
// a non-NULL tenant_id is doubly impossible: the post-delete INSERT
// violates the FK, and even a pre-delete write would be cascaded away with
// the tenant. NULL tenant_id + resource_id is the only shape that survives.
func TestClerkWebhook_OrgDeleted_HappyPath_AuditRowAvoidsDeadFK(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)

	tenantID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_del_4").
		WillReturnRows(clerkTenantRow(tenantID, "org_del_4"))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WithArgs(sqlmock.AnyArg(), nil, nil, model.ActionTenantDeleted, model.ResourceTenant,
			tenantID, sqlmock.AnyArg(), nil, "", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	rec := driveClerkWebhook(t, h, `{"type":"organization.deleted","data":{"id":"org_del_4"}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("audit row must carry NULL tenant_id (dead-FK) and the deleted id in resource_id: %v", err)
	}
}

// TestClerkWebhook_UserUpdated_AuditReferencesPersistedID pins the M46 Codex
// C-3b round-1 [High] finding on the upsert path: UserRepository.Upsert is
// ON CONFLICT (clerk_user_id) DO UPDATE and the conflict branch KEEPS the
// original row id, so the uuid.New() the handler generates never hits the
// table for an existing user. Pre-fix the audit INSERT used that discarded
// uuid — violating the audit_logs.user_id FK on EVERY user.updated, i.e.
// update audit rows were silently lost forever (and under the new
// 500-on-audit-failure contract it would have become a systematic delivery
// failure). The pinned contract: re-read the persisted row after Upsert and
// log ITS id.
func TestClerkWebhook_UserUpdated_AuditReferencesPersistedID(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)

	persistedID := uuid.New() // the id the conflict branch keeps
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO users`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_upd_1").
		WillReturnRows(clerkUserRow(persistedID, "user_upd_1"))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WithArgs(sqlmock.AnyArg(), nil, persistedID, model.ActionUserUpdated, model.ResourceUser,
			persistedID, sqlmock.AnyArg(), nil, "", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"type":"user.updated","data":{"id":"user_upd_1",
		"email_addresses":[{"email_address":"upd@example.com"}],
		"first_name":"Up","last_name":"Dated","image_url":""}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("audit row must reference the PERSISTED user id, not the discarded uuid.New(): %v", err)
	}
}

// TestClerkWebhook_UserCreated_AuditFailureIs500 pins the upsert-path audit
// contract: the users upsert is idempotent and the audit row is the only
// history write, so a 500 lets the (finite, 8-attempt) Svix redelivery
// recover the audit trail with no duplication risk. Pre-fix the Log error
// was discarded and the audit row silently lost forever.
func TestClerkWebhook_UserCreated_AuditFailureIs500(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO users`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Post-upsert re-read (persisted-id audit reference, see
	// TestClerkWebhook_UserUpdated_AuditReferencesPersistedID).
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_new_1").
		WillReturnRows(clerkUserRow(uuid.New(), "user_new_1"))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnError(errors.New("audit_logs insert boom"))

	body := `{"type":"user.created","data":{"id":"user_new_1",
		"email_addresses":[{"email_address":"new@example.com"}],
		"first_name":"New","last_name":"User","image_url":""}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (audit row is the only history write — redelivery recovers it, a 200 loses it forever); body=%s",
			rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to write user audit log")) {
		t.Fatalf("audit write failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_UserCreated_HappyPath guards that the new error checks did
// not change the success-path call sequence.
func TestClerkWebhook_UserCreated_HappyPath(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO users`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_new_2").
		WillReturnRows(clerkUserRow(uuid.New(), "user_new_2"))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"type":"user.created","data":{"id":"user_new_2",
		"email_addresses":[{"email_address":"new2@example.com"}],
		"first_name":"New","last_name":"User","image_url":""}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_OrgDeleted_LookupFailureIs500 mirrors the user.deleted
// lookup pin for organization.deleted.
func TestClerkWebhook_OrgDeleted_LookupFailureIs500(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_del_1").
		WillReturnError(errors.New("transient: broken pipe"))

	rec := driveClerkWebhook(t, h, `{"type":"organization.deleted","data":{"id":"org_del_1"}}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("tenant lookup failed")) {
		t.Fatalf("lookup failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_OrgDeleted_DeleteFailureIs500 pins the errcheck fix at the
// tenantRepo.Delete call (pre-fix: discarded, answered 200, tenant survived).
func TestClerkWebhook_OrgDeleted_DeleteFailureIs500(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	tenantID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_del_2").
		WillReturnRows(clerkTenantRow(tenantID, "org_del_2"))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnError(errors.New("delete boom"))

	rec := driveClerkWebhook(t, h, `{"type":"organization.deleted","data":{"id":"org_del_2"}}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to delete tenant")) {
		t.Fatalf("delete failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_OrgDeleted_AuditFailureStillReturns200 mirrors the
// user.deleted audit contract (200 + slog; 5xx cannot recover).
func TestClerkWebhook_OrgDeleted_AuditFailureStillReturns200(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	tenantID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_del_3").
		WillReturnRows(clerkTenantRow(tenantID, "org_del_3"))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenants WHERE id = $1`)).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnError(errors.New("audit_logs insert boom"))

	rec := driveClerkWebhook(t, h, `{"type":"organization.deleted","data":{"id":"org_del_3"}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (tenant row already deleted — a 5xx cannot recover the audit row); body=%s",
			rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to write tenant deletion audit log")) {
		t.Fatalf("audit write failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_OrgCreated_AuditFailureIs500 pins the upsert-path audit
// contract on organization.created (same rationale as user.created).
func TestClerkWebhook_OrgCreated_AuditFailureIs500(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_new_1").
		WillReturnError(sql.ErrNoRows)
	// TenantRepository.Create runs a tx: INSERT tenants + tx-scoped
	// set_config + default scan_settings INSERT.
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenants`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('app.current_tenant_id', $1, true)`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO scan_settings`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WillReturnError(errors.New("audit_logs insert boom"))

	body := `{"type":"organization.created","data":{"id":"org_new_1","name":"Acme","slug":"acme"}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (redelivery recovers the audit row via the idempotent upsert path); body=%s",
			rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to write tenant audit log")) {
		t.Fatalf("audit write failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_OrgCreated_RedeliveryLogsCreatedAction pins the
// audit-recovery semantics: when an organization.created event is
// REDELIVERED after the tenant row already exists (first attempt created the
// row but failed the audit write → 500), the update branch runs — and must
// log ActionTenantCreated (the event that actually happened per the IdP),
// not ActionTenantUpdated. This is what makes the 500-on-audit-failure
// contract actually recover the correct audit row.
func TestClerkWebhook_OrgCreated_RedeliveryLogsCreatedAction(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)

	tenantID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_new_2").
		WillReturnRows(clerkTenantRow(tenantID, "org_new_2"))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenants`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// audit_logs arg #4 is `action` — must be tenant.created, not
	// tenant.updated, because the delivered event is organization.created.
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs`)).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			model.ActionTenantCreated, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"type":"organization.created","data":{"id":"org_new_2","name":"Acme","slug":"acme"}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations (action must be tenant.created on a redelivered organization.created): %v", err)
	}
}

// TestClerkWebhook_MembershipDeleted_RemoveFailureIs500 pins the errcheck fix
// at userRepo.RemoveFromTenant: pre-fix a failed DELETE was discarded and the
// membership silently survived (never retried).
func TestClerkWebhook_MembershipDeleted_RemoveFailureIs500(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	tenantID := uuid.New()
	userID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_mem_1").
		WillReturnRows(clerkTenantRow(tenantID, "org_mem_1"))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_mem_1").
		WillReturnRows(clerkUserRow(userID, "user_mem_1"))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenant_users WHERE tenant_id = $1 AND user_id = $2`)).
		WithArgs(tenantID, userID).
		WillReturnError(errors.New("remove boom"))

	body := `{"type":"organizationMembership.deleted","data":{"id":"mem_1",
		"organization":{"id":"org_mem_1","name":"Acme","slug":"acme"},
		"public_user_data":{"user_id":"user_mem_1"},"role":"org:member"}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (failed removal must be redelivered — the DELETE is idempotent); body=%s",
			rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("failed to remove user from tenant")) {
		t.Fatalf("removal failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_MembershipDeleted_AlreadyAbsentIs200 pins the idempotency
// half of the removal contract, which M47 W2 put at risk.
//
// W2 made RemoveFromTenant report a 0-row DELETE (previously swallowed) so the
// API paths stop claiming "member removed" when nobody was removed. For THIS
// event the opposite reading is required: Svix redelivers, the event IS a
// delete, so "already not a member" is the desired end state. Answering 5xx
// there would burn the finite retry budget on work that is already done — the
// same reasoning the tenant/user lookups apply to sql.ErrNoRows just above.
//
// Sibling test TestClerkWebhook_MembershipDeleted_RemoveFailureIs500 keeps the
// other half honest: a genuine DB error still answers 500.
func TestClerkWebhook_MembershipDeleted_AlreadyAbsentIs200(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	tenantID := uuid.New()
	userID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_mem_absent").
		WillReturnRows(clerkTenantRow(tenantID, "org_mem_absent"))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_mem_absent").
		WillReturnRows(clerkUserRow(userID, "user_mem_absent"))
	// 0 rows affected: the membership is already gone (redelivery).
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenant_users WHERE tenant_id = $1 AND user_id = $2`)).
		WithArgs(tenantID, userID).
		WillReturnResult(sqlmock.NewResult(0, 0))

	body := `{"type":"organizationMembership.deleted","data":{"id":"mem_absent",
		"organization":{"id":"org_mem_absent","name":"Acme","slug":"acme"},
		"public_user_data":{"user_id":"user_mem_absent"},"role":"org:member"}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a redelivered delete whose row is already gone is the desired end state, not a failure); body=%s",
			rec.Code, rec.Body.String())
	}
	if bytes.Contains(logs.Bytes(), []byte("failed to remove user from tenant")) {
		t.Fatalf("an already-absent membership must not be logged as a failure; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_MembershipDeleted_TenantLookupTransientIs500 pins that a
// transient tenant lookup error on the membership-removal path is not
// misread as "tenant not found" (pre-fix: 200 + note, event dropped).
func TestClerkWebhook_MembershipDeleted_TenantLookupTransientIs500(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_mem_2").
		WillReturnError(errors.New("transient: i/o timeout"))

	body := `{"type":"organizationMembership.deleted","data":{"id":"mem_2",
		"organization":{"id":"org_mem_2","name":"Acme","slug":"acme"},
		"public_user_data":{"user_id":"user_mem_2"},"role":"org:member"}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("tenant lookup failed")) {
		t.Fatalf("lookup failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_MembershipCreated_TenantLookupTransientIs500NoInsert pins
// the LS round-A finding shape on the membership path: pre-fix ANY tenant
// lookup error fell through to tenantRepo.Create, colliding with the
// clerk_org_id UNIQUE index on redelivery and misreading infra trouble as a
// brand-new organization. Only sql.ErrNoRows may take the create branch; no
// INSERT expectation is registered here — attempting one is itself a
// violation.
func TestClerkWebhook_MembershipCreated_TenantLookupTransientIs500NoInsert(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)
	logs := captureSlog(t)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_mem_3").
		WillReturnError(errors.New("transient: connection refused"))

	body := `{"type":"organizationMembership.created","data":{"id":"mem_3",
		"organization":{"id":"org_mem_3","name":"Acme","slug":"acme"},
		"public_user_data":{"user_id":"user_mem_3"},"role":"org:member"}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("failed to look up tenant")) {
		t.Fatalf("response must name the lookup failure (not a create failure); body=%s", rec.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("tenant lookup failed")) {
		t.Fatalf("lookup failure was not logged; logs:\n%s", logs.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestClerkWebhook_MembershipCreated_HappyPath guards the success path:
// tenant exists, user exists, membership upserted — 200 with every
// expectation consumed.
func TestClerkWebhook_MembershipCreated_HappyPath(t *testing.T) {
	h, mock := newClerkWebhookTestHandler(t)

	tenantID := uuid.New()
	userID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM tenants WHERE clerk_org_id = $1`)).
		WithArgs("org_mem_4").
		WillReturnRows(clerkTenantRow(tenantID, "org_mem_4"))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM users WHERE clerk_user_id = $1`)).
		WithArgs("user_mem_4").
		WillReturnRows(clerkUserRow(userID, "user_mem_4"))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenant_users`)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"type":"organizationMembership.created","data":{"id":"mem_4",
		"organization":{"id":"org_mem_4","name":"Acme","slug":"acme"},
		"public_user_data":{"user_id":"user_mem_4"},"role":"org:member"}}`
	rec := driveClerkWebhook(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}
