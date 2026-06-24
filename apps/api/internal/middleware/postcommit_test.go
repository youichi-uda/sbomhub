package middleware

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// TestRegisterPostCommit_RunsOnSuccess verifies that hooks registered inside a
// successful handler do run after Commit. Codex R2 P1: this is the contract
// the SBOM upload background-scan launch relies on.
func TestRegisterPostCommit_RunsOnSuccess(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	var ran int32
	status, herr := runWithTenantTx(t, db, uuid.New(), func(c echo.Context) error {
		RegisterPostCommit(c, func() {
			atomic.AddInt32(&ran, 1)
		})
		return c.NoContent(http.StatusNoContent)
	})
	if herr != nil {
		t.Fatalf("handler err: %v", herr)
	}
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	if got := atomic.LoadInt32(&ran); got != 1 {
		t.Fatalf("hook ran %d times, want 1", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRegisterPostCommit_RunsAllHooksInOrder verifies sequential execution in
// registration order.
func TestRegisterPostCommit_RunsAllHooksInOrder(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	var order []int
	if _, herr := runWithTenantTx(t, db, uuid.New(), func(c echo.Context) error {
		RegisterPostCommit(c, func() { order = append(order, 1) })
		RegisterPostCommit(c, func() { order = append(order, 2) })
		RegisterPostCommit(c, func() { order = append(order, 3) })
		return c.NoContent(http.StatusNoContent)
	}); herr != nil {
		t.Fatalf("handler err: %v", herr)
	}
	if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
		t.Fatalf("hooks ran in wrong order: %v", order)
	}
}

// TestRegisterPostCommit_RollbackOnHandlerError verifies that a handler error
// rolls back the tx and does NOT run any registered hook. Codex R2 P1: this
// is what guarantees we never launch a background scan for an SBOM whose
// INSERT actually rolled back.
func TestRegisterPostCommit_RollbackOnHandlerError(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	var ran int32
	sentinel := errors.New("intentional handler err")
	_, herr := runWithTenantTx(t, db, uuid.New(), func(c echo.Context) error {
		RegisterPostCommit(c, func() {
			atomic.AddInt32(&ran, 1)
		})
		return sentinel
	})
	if !errors.Is(herr, sentinel) {
		t.Fatalf("handler err = %v, want %v", herr, sentinel)
	}
	if got := atomic.LoadInt32(&ran); got != 0 {
		t.Fatalf("hook ran %d times after rollback, want 0", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRegisterPostCommit_RollbackOn4xx verifies that a 4xx response (with nil
// handler error) still triggers rollback AND blocks post-commit hooks. This
// mirrors the TenantTx contract that 4xx is "the request was rejected; treat
// it as a failed write".
func TestRegisterPostCommit_RollbackOn4xx(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	var ran int32
	status, herr := runWithTenantTx(t, db, uuid.New(), func(c echo.Context) error {
		RegisterPostCommit(c, func() {
			atomic.AddInt32(&ran, 1)
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "no"})
	})
	if herr != nil {
		t.Fatalf("handler err: %v", herr)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if got := atomic.LoadInt32(&ran); got != 0 {
		t.Fatalf("hook ran %d times after 4xx rollback, want 0", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRegisterPostCommit_DoesNotRunOnPanic verifies that a panic inside the
// handler rolls back AND blocks post-commit hooks. The panic must also
// propagate so outer recovery middleware can log it.
func TestRegisterPostCommit_DoesNotRunOnPanic(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	var ran int32

	defer func() {
		p := recover()
		if p == nil {
			t.Fatal("expected panic to propagate")
		}
		if got := atomic.LoadInt32(&ran); got != 0 {
			t.Fatalf("hook ran %d times after panic, want 0", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	}()

	_, _ = runWithTenantTx(t, db, uuid.New(), func(c echo.Context) error {
		RegisterPostCommit(c, func() {
			atomic.AddInt32(&ran, 1)
		})
		panic("intentional")
	})
}

// TestRegisterPostCommit_HookPanicDoesNotCrashOthers verifies that a panic in
// one hook is recovered and sibling hooks still run. This protects the
// response writer chain from a single buggy hook.
func TestRegisterPostCommit_HookPanicDoesNotCrashOthers(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	var firstRan, secondRan int32
	status, herr := runWithTenantTx(t, db, uuid.New(), func(c echo.Context) error {
		RegisterPostCommit(c, func() {
			atomic.AddInt32(&firstRan, 1)
			panic("hook 1 panic")
		})
		RegisterPostCommit(c, func() {
			atomic.AddInt32(&secondRan, 1)
		})
		return c.NoContent(http.StatusNoContent)
	})
	if herr != nil {
		t.Fatalf("handler err: %v", herr)
	}
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	if atomic.LoadInt32(&firstRan) != 1 {
		t.Fatalf("hook 1 did not run")
	}
	if atomic.LoadInt32(&secondRan) != 1 {
		t.Fatalf("hook 2 did not run after hook 1 panicked")
	}
}

// TestRegisterPostCommit_NoOpOutsideMiddleware verifies that calling
// RegisterPostCommit on a context that was never wrapped in TenantTx is a
// silent no-op (logged, but does not panic). This keeps handler code safe to
// call from unit tests or from exotic non-tenant code paths.
func TestRegisterPostCommit_NoOpOutsideMiddleware(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Should NOT panic, even though no TenantTx ever ran.
	RegisterPostCommit(c, func() { t.Fatal("hook should not run") })
}

// TestRegisterPostCommit_NilHookIsNoOp verifies that a nil function is safely
// ignored.
func TestRegisterPostCommit_NilHookIsNoOp(t *testing.T) {
	db, mock := newPostCommitMockDB(t)
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if _, herr := runWithTenantTx(t, db, uuid.New(), func(c echo.Context) error {
		RegisterPostCommit(c, nil)
		return c.NoContent(http.StatusNoContent)
	}); herr != nil {
		t.Fatalf("handler err: %v", herr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func newPostCommitMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	return db, mock
}

// runWithTenantTx wires the TenantTx middleware around handler against the
// provided sqlmock DB. Returns the captured response status and the handler's
// error.
func runWithTenantTx(t *testing.T, db *sql.DB, tenantID uuid.UUID, handler echo.HandlerFunc) (int, error) {
	t.Helper()
	e := echo.New()
	mw := TenantTx(db)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, tenantID)
	err := mw(handler)(c)
	return rec.Code, err
}
