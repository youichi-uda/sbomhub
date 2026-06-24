package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestRequireWrite_RoleMatrix pins the F15 contract for every TenantContext
// role tier the API can produce (Clerk JWT path + MultiAuth API-key path
// both ultimately set ContextKeyRole to one of these). The intent is to
// catch silent regressions in either CanWrite() (tenant.go) or the
// guard's interpretation of an "unset role".
func TestRequireWrite_RoleMatrix(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		wantStatus int
	}{
		{"owner allowed", model.RoleOwner, http.StatusOK},
		{"admin allowed", model.RoleAdmin, http.StatusOK},
		{"member allowed", model.RoleMember, http.StatusOK},
		// F15 regression core: a read-scoped API key maps to RoleViewer
		// (roleFromAPIKeyPermissions("read") = RoleViewer). Before this
		// fix the canonical SBOM upload route never consulted any role
		// guard at all, so the viewer drove writes through MultiAuth.
		{"viewer rejected", model.RoleViewer, http.StatusForbidden},
		// Unrecognised role values (which include anything the F17 fix
		// downgrades to RoleViewer for API-key callers) must fail
		// closed.
		{"unknown role rejected", "garbage", http.StatusForbidden},
		{"empty role rejected", "", http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false
			final := func(c echo.Context) error {
				handlerCalled = true
				return c.NoContent(http.StatusOK)
			}

			e := echo.New()
			req := httptest.NewRequest(http.MethodPost,
				"/api/v1/projects/00000000-0000-0000-0000-000000000000/sbom",
				strings.NewReader(""))
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(ContextKeyTenantID, uuid.New())
			c.Set(ContextKeyUserID, uuid.New())
			c.Set(ContextKeyRole, tc.role)

			if err := RequireWrite()(final)(c); err != nil {
				t.Fatalf("RequireWrite returned unexpected error: %v", err)
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusOK && !handlerCalled {
				t.Fatal("downstream handler must have been invoked on success")
			}
			if tc.wantStatus == http.StatusForbidden {
				if handlerCalled {
					t.Fatal("F15: downstream handler must NOT run when RequireWrite rejects")
				}
				// F10 body opacity carry-over: the 403 body must be the
				// generic forbidden sentinel, not anything that leaks the
				// role or the route's expected role allowlist.
				body := rec.Body.String()
				if !strings.Contains(body, `"forbidden"`) {
					t.Errorf("403 body must contain generic \"forbidden\", got %s", body)
				}
				for _, leak := range []string{tc.role, "CanWrite", "role", "viewer", "member"} {
					if tc.role != "" && tc.role != "garbage" && strings.Contains(body, leak) {
						t.Errorf("403 body must not leak %q, got %s", leak, body)
					}
				}
			}
		})
	}
}

// TestRequireWrite_NoTenantContext exercises the "tenant context missing"
// branch — a request that somehow bypassed the auth middleware reaches
// the guard with no ContextKeyTenantID. The guard refuses with 401
// (not 403) because emitting 403 would imply the auth middleware
// actually ran and judged the role.
func TestRequireWrite_NoTenantContext(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/x/sbom", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// Intentionally do not set ContextKeyTenantID / ContextKeyRole.

	handlerCalled := false
	final := func(c echo.Context) error {
		handlerCalled = true
		return c.NoContent(http.StatusOK)
	}
	if err := RequireWrite()(final)(c); err != nil {
		t.Fatalf("RequireWrite returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if handlerCalled {
		t.Fatal("downstream handler must not be invoked when tenant context is missing")
	}
}

// TestRequireAdmin_RoleMatrix is the F16 mirror of the F15 matrix. The
// allowlist for admin is stricter (Owner | Admin only) — Member must be
// rejected because that is the entire point of the privilege-escalation
// fix: a Member could mint themselves a write-capable API key and
// bypass their own role on every MultiAuth-fronted endpoint.
func TestRequireAdmin_RoleMatrix(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		wantStatus int
	}{
		{"owner allowed", model.RoleOwner, http.StatusOK},
		{"admin allowed", model.RoleAdmin, http.StatusOK},
		// F16 regression core: Member → 403. Without this gate, any
		// authenticated tenant user could call POST /api/v1/apikeys.
		{"member rejected", model.RoleMember, http.StatusForbidden},
		{"viewer rejected", model.RoleViewer, http.StatusForbidden},
		{"unknown role rejected", "garbage", http.StatusForbidden},
		{"empty role rejected", "", http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false
			final := func(c echo.Context) error {
				handlerCalled = true
				return c.NoContent(http.StatusOK)
			}

			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/apikeys", strings.NewReader(""))
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(ContextKeyTenantID, uuid.New())
			c.Set(ContextKeyUserID, uuid.New())
			c.Set(ContextKeyRole, tc.role)

			if err := RequireAdmin()(final)(c); err != nil {
				t.Fatalf("RequireAdmin returned unexpected error: %v", err)
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusOK && !handlerCalled {
				t.Fatal("downstream handler must have been invoked on success")
			}
			if tc.wantStatus == http.StatusForbidden {
				if handlerCalled {
					t.Fatal("F16: downstream handler must NOT run when RequireAdmin rejects")
				}
				if !strings.Contains(rec.Body.String(), `"forbidden"`) {
					t.Errorf("403 body must contain generic \"forbidden\", got %s", rec.Body.String())
				}
			}
		})
	}
}

// TestRequireAdmin_NoTenantContext is the F16 companion to the F15
// missing-tenant test.
func TestRequireAdmin_NoTenantContext(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/apikeys", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handlerCalled := false
	final := func(c echo.Context) error {
		handlerCalled = true
		return c.NoContent(http.StatusOK)
	}
	if err := RequireAdmin()(final)(c); err != nil {
		t.Fatalf("RequireAdmin returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if handlerCalled {
		t.Fatal("downstream handler must not be invoked when tenant context is missing")
	}
}

// TestRequireWrite_F15_ReadOnlyAPIKeyRejected stitches the two halves
// of the F15 fix together: the MultiAuth API-key path's role mapping
// (roleFromAPIKeyPermissions("read") → RoleViewer) and the RequireWrite
// guard (RoleViewer → 403). A read-scoped sbh_... API key flowing
// through both must be rejected before it can drive any write handler.
//
// The test simulates the post-#F15 middleware chain at the
// auth-mapping boundary: rather than wiring a real MultiAuth instance
// (which would require an APIKeyService + DB-mocked validation), it
// derives the role from roleFromAPIKeyPermissions directly — exactly
// the same call MultiAuth would make — and feeds the resulting context
// to RequireWrite. Failure mode: if either the role mapping or the
// guard regresses, the test trips with a 200 OK.
func TestRequireWrite_F15_ReadOnlyAPIKeyRejected(t *testing.T) {
	// What MultiAuth's handleAPIKeyAuth writes for a key with
	// Permissions == "read".
	mappedRole := roleFromAPIKeyPermissions("read")
	if mappedRole != model.RoleViewer {
		t.Fatalf("F17 prerequisite: roleFromAPIKeyPermissions(\"read\") = %q, want %q",
			mappedRole, model.RoleViewer)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/00000000-0000-0000-0000-000000000000/sbom",
		strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer sbh_readonly_simulated")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, uuid.New())
	c.Set(ContextKeyUserID, uuid.New())
	c.Set(ContextKeyRole, mappedRole)

	handlerCalled := false
	final := func(c echo.Context) error {
		handlerCalled = true
		return c.NoContent(http.StatusCreated)
	}
	if err := RequireWrite()(final)(c); err != nil {
		t.Fatalf("RequireWrite returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F15: read-only API key must be rejected with 403, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if handlerCalled {
		t.Fatal("F15: SBOM upload handler MUST NOT run for a read-only API key")
	}
}
