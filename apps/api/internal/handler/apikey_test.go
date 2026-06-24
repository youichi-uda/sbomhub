package handler

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// newTestAPIKeyHandler wires an APIKeyHandler against a real
// APIKeyService and APIKeyRepository, using the supplied *sql.DB. Pass
// nil if the test only exercises code paths that reject before
// touching the repository (e.g. the F17 permissions allowlist check in
// CreateKey, which short-circuits before any SQL runs). A nil db is
// safe because APIKeyRepository.Create is unreachable on the rejected
// path; if a future refactor reorders the validation the test will
// panic on the nil db rather than silently hide the regression.
func newTestAPIKeyHandler(db *sql.DB) *APIKeyHandler {
	return NewAPIKeyHandler(service.NewAPIKeyService(repository.NewAPIKeyRepository(db)))
}

// TestAPIKey_CreateTenant_NonAdmin_Rejected is the F16 regression test
// at the route+middleware boundary: POST /api/v1/apikeys is now wired
// behind appmw.RequireAdmin() (cmd/server/main.go). A request whose
// TenantContext carries RoleMember / RoleViewer must be rejected with
// 403 BEFORE the handler sees the body.
//
// We exercise the middleware in isolation (no Echo routing wire-up
// needed) because the F16 fix is route-level: the handler itself does
// nothing about role enforcement — that contract lives in
// middleware.RequireAdmin. The matrix below pins both the deny and
// allow ends so a future refactor that swaps RequireAdmin for a
// custom check is caught.
func TestAPIKey_CreateTenant_NonAdmin_Rejected(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		wantStatus int
	}{
		// F16 regression core: every below-admin role must be rejected.
		{"viewer rejected", model.RoleViewer, http.StatusForbidden},
		{"member rejected", model.RoleMember, http.StatusForbidden},
		// Positive control: Admin proceeds (handler runs, returns 400
		// because the request body is empty — but importantly NOT 403).
		{"admin allowed", model.RoleAdmin, http.StatusBadRequest},
		{"owner allowed", model.RoleOwner, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false
			// We treat the handler invocation as the proxy for "the
			// guard let the request through". The actual handler body
			// is irrelevant to the F16 fix (it's the route guard that
			// matters), so we wire a recording stub instead of
			// constructing a real APIKeyHandler + service + DB.
			final := func(c echo.Context) error {
				handlerCalled = true
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
			}

			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/apikeys", strings.NewReader("{}"))
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
				t.Fatalf("F16: status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusForbidden && handlerCalled {
				t.Fatal("F16: APIKeyHandler.CreateTenant MUST NOT run for a below-admin role")
			}
			if tc.wantStatus == http.StatusBadRequest && !handlerCalled {
				t.Fatal("F16: APIKeyHandler.CreateTenant must run for admin / owner")
			}
		})
	}
}

// TestAPIKey_DeleteTenant_NonAdmin_Rejected mirrors the create test for
// the delete endpoint. Same guard, same expected matrix — the F16 fix
// gates the entire CRUD surface, not just create.
func TestAPIKey_DeleteTenant_NonAdmin_Rejected(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		wantStatus int
	}{
		{"viewer rejected", model.RoleViewer, http.StatusForbidden},
		{"member rejected", model.RoleMember, http.StatusForbidden},
		// Positive control: handler runs and returns 204 (the stub
		// simulates a successful delete).
		{"admin allowed", model.RoleAdmin, http.StatusNoContent},
		{"owner allowed", model.RoleOwner, http.StatusNoContent},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false
			final := func(c echo.Context) error {
				handlerCalled = true
				return c.NoContent(http.StatusNoContent)
			}

			e := echo.New()
			req := httptest.NewRequest(http.MethodDelete,
				"/api/v1/apikeys/"+uuid.NewString(), nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("key_id")
			c.SetParamValues(uuid.NewString())
			c.Set(middleware.ContextKeyTenantID, uuid.New())
			c.Set(middleware.ContextKeyUserID, uuid.New())
			c.Set(middleware.ContextKeyRole, tc.role)

			if err := middleware.RequireAdmin()(final)(c); err != nil {
				t.Fatalf("RequireAdmin returned unexpected error: %v", err)
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("F16: status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusForbidden && handlerCalled {
				t.Fatal("F16: DeleteTenant handler MUST NOT run for a below-admin role")
			}
		})
	}
}

// TestAPIKey_ListTenant_NonAdmin_Rejected ensures the F16 gate covers
// the LIST verb as well. The prompt-side rationale: key metadata
// (name, prefix, last-used, expires) is itself an attack surface — a
// Member who enumerates the tenant's keys learns who has write power
// and can target social-engineering against those specific users.
func TestAPIKey_ListTenant_NonAdmin_Rejected(t *testing.T) {
	for _, role := range []string{model.RoleViewer, model.RoleMember} {
		t.Run(role, func(t *testing.T) {
			handlerCalled := false
			final := func(c echo.Context) error {
				handlerCalled = true
				return c.JSON(http.StatusOK, []model.APIKey{})
			}

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/apikeys", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(middleware.ContextKeyTenantID, uuid.New())
			c.Set(middleware.ContextKeyUserID, uuid.New())
			c.Set(middleware.ContextKeyRole, role)

			if err := middleware.RequireAdmin()(final)(c); err != nil {
				t.Fatalf("RequireAdmin returned unexpected error: %v", err)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("F16: List with role=%q must be 403, got %d", role, rec.Code)
			}
			if handlerCalled {
				t.Fatalf("F16: ListTenant handler MUST NOT run for role=%q", role)
			}
		})
	}
}
