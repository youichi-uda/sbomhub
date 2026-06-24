package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// TestTenantTx_BufferedSuccessFlushesHandlerResponse verifies that on the
// happy path the handler's buffered status code, headers, and body are
// delivered to the wire intact AFTER the tx commits. Codex R20 P2: the
// whole point of buffering is to gate the wire on Commit, so the success
// path must still produce the exact response the handler asked for.
func TestTenantTx_BufferedSuccessFlushesHandlerResponse(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, uuid.New())

	handler := func(c echo.Context) error {
		c.Response().Header().Set("X-Custom-Header", "from-handler")
		return c.JSON(http.StatusCreated, map[string]string{"id": "abc"})
	}

	if err := TenantTx(db)(handler)(c); err != nil {
		t.Fatalf("middleware err: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"id":"abc"`) {
		t.Fatalf("body missing handler payload: %s", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, echo.MIMEApplicationJSON) {
		t.Fatalf("Content-Type = %q, want %s prefix", ct, echo.MIMEApplicationJSON)
	}
	if got := rec.Header().Get("X-Custom-Header"); got != "from-handler" {
		t.Fatalf("X-Custom-Header = %q, want %q", got, "from-handler")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestTenantTx_CommitFailDropsHandler2xxAndReturns500 is the core Codex R20
// P2 invariant: if Commit() returns an error AFTER the handler has called
// c.JSON(http.StatusCreated, ...), the buffered 201 + body MUST NOT reach
// the client. Instead the client sees a 500 so it does not store a
// reference to a row that was rolled back. Post-commit hooks must also be
// suppressed because the data they would observe never landed.
func TestTenantTx_CommitFailDropsHandler2xxAndReturns500(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(errors.New("simulated commit failure"))

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, uuid.New())

	var hookRan int32
	handler := func(c echo.Context) error {
		RegisterPostCommit(c, func() { atomic.AddInt32(&hookRan, 1) })
		return c.JSON(http.StatusCreated, map[string]string{
			"id":      "rolled-back-sbom",
			"warning": "should-not-reach-client",
		})
	}

	if err := TenantTx(db)(handler)(c); err != nil {
		t.Fatalf("middleware err: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — client must not see the rolled-back 201", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "rolled-back-sbom") || strings.Contains(body, "should-not-reach-client") {
		t.Fatalf("commit-fail response leaked handler body to client: %s", body)
	}
	if !strings.Contains(body, "transaction commit failed") {
		t.Fatalf("commit-fail response missing diagnostic body: %s", body)
	}
	if got := atomic.LoadInt32(&hookRan); got != 0 {
		t.Fatalf("post-commit hook ran %d times after commit failure, want 0", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestTenantTx_CommitFailWithEmptyResponseStillReturns500 verifies that
// when the handler returned nil without writing anything (e.g. an opaque
// success path that relies on Echo's default 200), a commit failure still
// surfaces a 500 to the client instead of silently emitting a misleading
// "looks fine" response.
func TestTenantTx_CommitFailWithEmptyResponseStillReturns500(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(errors.New("simulated commit failure"))

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, uuid.New())

	handler := func(c echo.Context) error {
		// Deliberately do not write any response — c.Response().Status
		// defaults to 200, which previously could escape to the client
		// even though the tx subsequently rolled back.
		return nil
	}

	if err := TenantTx(db)(handler)(c); err != nil {
		t.Fatalf("middleware err: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "transaction commit failed") {
		t.Fatalf("commit-fail response missing diagnostic body: %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestTenantTx_BufferedHandler4xxFlushesAndRollsBack confirms that a
// handler-emitted 4xx still reaches the client verbatim while the tx rolls
// back. The buffer must not swallow user-facing error responses.
func TestTenantTx_BufferedHandler4xxFlushesAndRollsBack(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, uuid.New())

	handler := func(c echo.Context) error {
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{
			"error": "validation failed",
			"field": "name",
		})
	}

	if err := TenantTx(db)(handler)(c); err != nil {
		t.Fatalf("middleware err: %v", err)
	}
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"validation failed"`) || !strings.Contains(body, `"name"`) {
		t.Fatalf("handler 4xx body not flushed verbatim: %s", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestTenantTx_BufferedHandlerErrorDelegatesToEchoErrorHandler verifies
// that when the handler returns an error without writing anything, the
// buffer flush is a no-op and Echo's default error handler emits the
// response on the real writer. The original behaviour (before R20)
// already worked here; the assertion guards against a regression where
// we accidentally swallow Echo's error handler write.
func TestTenantTx_BufferedHandlerErrorDelegatesToEchoErrorHandler(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, uuid.New())

	sentinel := echo.NewHTTPError(http.StatusTeapot, "i am a teapot")
	handler := func(c echo.Context) error {
		return sentinel
	}

	err := TenantTx(db)(handler)(c)
	if err == nil {
		t.Fatalf("expected handler error to propagate")
	}
	// Drive Echo's default error handler manually because we are not in a
	// full server pipeline. This mirrors how Echo would dispatch the
	// returned error in production once TenantTx hands it back.
	e.DefaultHTTPErrorHandler(err, c)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 (handler error must reach Echo error handler on the real writer)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "i am a teapot") {
		t.Fatalf("Echo error handler body missing: %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
