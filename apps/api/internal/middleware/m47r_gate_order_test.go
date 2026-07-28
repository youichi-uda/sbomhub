package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/model"
)

// m47rBrokenTenantTx returns a TenantTx bound to a database whose BeginTx
// fails, plus the sqlmock assertion that reports whether BeginTx was reached.
func m47rBrokenTenantTx(t *testing.T) (echo.MiddlewareFunc, func() error) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectBegin().WillReturnError(errors.New("pq: could not connect to server"))
	return TenantTx(db), mock.ExpectationsWereMet
}

// m47rSeedTenantContext stands in for the Auth middleware: it publishes the
// tenant + role that the guard and TenantTx both read.
func m47rSeedTenantContext(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(ContextKeyTenantID, uuid.New())
			c.Set(ContextKeyUserID, uuid.New())
			c.Set(ContextKeyRole, role)
			return next(c)
		}
	}
}

// TestM47RRoleGuardRefusesWithoutTheRequestTransaction is the behavioural
// half of the M47R Low finding: a caller who authenticated successfully and
// lacks the role must be refused WITHOUT ENTERING TenantTx.
//
// The claim is deliberately narrow, and was narrowed twice by the Codex review
// (round 1 Medium, round 3 Low, both catching a larger version of it). The
// guard does not make a 403 independent of Postgres, and does not reduce the
// request to a single query: the auth middleware ahead of it issues several of
// its own, and an outage there is answered before the guard runs. What it
// removes is precisely the request transaction — BeginTx, the tenant GUC, and
// the pooled connection they pin for the rest of the request.
//
// The source-level guard (cmd/server/m47r_route_role_gate_test.go) proves the
// registration sites put the gate ahead of TenantTx. This proves WHY that
// matters, by composing the two real middlewares in both orders with a
// TenantTx whose BeginTx fails.
//
// Pre-M47R the `auth` and `cli` groups carried TenantTx and each gated route
// passed its guard as ROUTE middleware, which Echo places INSIDE the group's —
// exactly the "wrong" order below. A Viewer probing a write endpoint during a
// database outage was answered 500, and every probe cost a BeginTx attempt.
func TestM47RRoleGuardRefusesWithoutTheRequestTransaction(t *testing.T) {
	run := func(t *testing.T, chain ...echo.MiddlewareFunc) (int, bool) {
		t.Helper()
		handlerRan := false
		h := echo.HandlerFunc(func(c echo.Context) error {
			handlerRan = true
			return c.NoContent(http.StatusNoContent)
		})
		for i := len(chain) - 1; i >= 0; i-- {
			h = chain[i](h)
		}
		e := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/projects/00000000-0000-0000-0000-000000000000", nil)
		if err := h(e.NewContext(req, rec)); err != nil {
			t.Fatalf("chain returned unexpected error: %v", err)
		}
		return rec.Code, handlerRan
	}

	t.Run("guard before TenantTx: 403 and no BeginTx", func(t *testing.T) {
		tx, expectationsMet := m47rBrokenTenantTx(t)
		code, ran := run(t, m47rSeedTenantContext(model.RoleViewer), RequireWrite(), tx)
		if ran {
			t.Fatal("the handler ran for a Viewer on a write route")
		}
		if code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 — an authenticated caller who lacks the role must "+
				"be refused without entering TenantTx", code)
		}
		// The Begin expectation is deliberately left UNMET: the guard
		// short-circuits before TenantTx runs, so no transaction is attempted.
		if err := expectationsMet(); err == nil {
			t.Error("TenantTx opened a transaction for a request the guard had already refused — " +
				"a read-scoped caller probing write endpoints can pin a DB connection per attempt")
		}
	})

	t.Run("guard after TenantTx: the outage wins", func(t *testing.T) {
		tx, expectationsMet := m47rBrokenTenantTx(t)
		// This is the PRE-M47R shape, kept as the contrast that makes the case
		// above meaningful rather than vacuous.
		code, ran := run(t, m47rSeedTenantContext(model.RoleViewer), tx, RequireWrite())
		if ran {
			t.Fatal("the handler ran for a Viewer on a write route")
		}
		if code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500 — with TenantTx outermost the DB failure is "+
				"answered before the guard is consulted (this is the shape M47R removed)", code)
		}
		if err := expectationsMet(); err != nil {
			t.Errorf("expected TenantTx to have attempted BeginTx in this order: %v", err)
		}
	})

	t.Run("permitted role still reaches TenantTx", func(t *testing.T) {
		tx, expectationsMet := m47rBrokenTenantTx(t)
		code, ran := run(t, m47rSeedTenantContext(model.RoleMember), RequireWrite(), tx)
		if ran {
			t.Fatal("the handler ran despite the transaction failing to open")
		}
		if code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500 — a Member is allowed through, so the DB outage "+
				"is what they should see", code)
		}
		if err := expectationsMet(); err != nil {
			t.Errorf("a permitted request must reach TenantTx: %v", err)
		}
	})
}
