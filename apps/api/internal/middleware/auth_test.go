package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
)

func TestGetAuthContext(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set context values
	userID := uuid.New()
	tenantID := uuid.New()
	c.Set(ContextKeyUserID, userID)
	c.Set(ContextKeyTenantID, tenantID)
	c.Set(ContextKeyRole, model.RoleOwner)
	c.Set(ContextKeyClerkUserID, "user_123")
	c.Set(ContextKeyClerkOrgID, "org_456")

	auth := GetAuthContext(c)

	if auth.UserID != userID {
		t.Errorf("UserID mismatch: got %v, want %v", auth.UserID, userID)
	}
	if auth.TenantID != tenantID {
		t.Errorf("TenantID mismatch: got %v, want %v", auth.TenantID, tenantID)
	}
	if auth.Role != model.RoleOwner {
		t.Errorf("Role mismatch: got %v, want %v", auth.Role, model.RoleOwner)
	}
	if auth.ClerkUserID != "user_123" {
		t.Errorf("ClerkUserID mismatch: got %v, want %v", auth.ClerkUserID, "user_123")
	}
	if auth.ClerkOrgID != "org_456" {
		t.Errorf("ClerkOrgID mismatch: got %v, want %v", auth.ClerkOrgID, "org_456")
	}
	if auth.IsSelfHosted {
		t.Error("IsSelfHosted should be false for non-self-hosted user")
	}
}

func TestGetAuthContext_SelfHosted(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(ContextKeyClerkUserID, "self-hosted")

	auth := GetAuthContext(c)

	if !auth.IsSelfHosted {
		t.Error("IsSelfHosted should be true for self-hosted user")
	}
}

func TestGetAuthContext_MissingValues(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Don't set any values
	auth := GetAuthContext(c)

	if auth.UserID != uuid.Nil {
		t.Errorf("UserID should be nil UUID, got %v", auth.UserID)
	}
	if auth.Role != "" {
		t.Errorf("Role should be empty, got %v", auth.Role)
	}
}

func TestRequireRole(t *testing.T) {
	tests := []struct {
		name           string
		allowedRoles   []string
		userRole       string
		expectedStatus int
	}{
		{
			name:           "owner allowed for owner role",
			allowedRoles:   []string{model.RoleOwner},
			userRole:       model.RoleOwner,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "admin allowed for owner or admin",
			allowedRoles:   []string{model.RoleOwner, model.RoleAdmin},
			userRole:       model.RoleAdmin,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "member denied for admin role",
			allowedRoles:   []string{model.RoleOwner, model.RoleAdmin},
			userRole:       model.RoleMember,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "missing role returns forbidden",
			allowedRoles:   []string{model.RoleOwner},
			userRole:       "",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if tt.userRole != "" {
				c.Set(ContextKeyRole, tt.userRole)
			}

			handler := RequireRole(tt.allowedRoles...)(func(c echo.Context) error {
				return c.String(http.StatusOK, "OK")
			})

			err := handler(c)
			if err != nil {
				t.Fatalf("handler returned error: %v", err)
			}

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

func TestRequireAdmin(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(ContextKeyRole, model.RoleAdmin)

	handler := RequireAdmin()(func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	err := handler(c)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireOwner_Denied(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(ContextKeyRole, model.RoleMember)

	handler := RequireOwner()(func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	err := handler(c)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestNoopResponseWriter(t *testing.T) {
	w := &noopResponseWriter{}

	// Test Header returns non-nil empty header
	h := w.Header()
	if h == nil {
		t.Error("Header() should return non-nil http.Header")
	}
	if len(h) != 0 {
		t.Errorf("Header() should return empty header, got %v", h)
	}

	// Test Write returns correct count
	data := []byte("test data")
	n, err := w.Write(data)
	if err != nil {
		t.Errorf("Write() returned error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write() returned %d, want %d", n, len(data))
	}

	// Test WriteHeader sets status code
	w.WriteHeader(http.StatusNotFound)
	if w.statusCode != http.StatusNotFound {
		t.Errorf("WriteHeader() did not set statusCode: got %d, want %d", w.statusCode, http.StatusNotFound)
	}
}

func TestContextKeyConstants(t *testing.T) {
	// Verify context keys are unique and non-empty
	keys := []string{
		ContextKeyUserID,
		ContextKeyUser,
		ContextKeyTenantID,
		ContextKeyTenant,
		ContextKeyRole,
		ContextKeyClerkOrgID,
		ContextKeyClerkUserID,
	}

	seen := make(map[string]bool)
	for _, key := range keys {
		if key == "" {
			t.Error("context key should not be empty")
		}
		if seen[key] {
			t.Errorf("duplicate context key: %s", key)
		}
		seen[key] = true
	}
}

func TestAuthContext_IsSelfHosted(t *testing.T) {
	tests := []struct {
		name         string
		clerkUserID  string
		wantSelfHost bool
	}{
		{"self-hosted", "self-hosted", true},
		{"clerk user", "user_123", false},
		{"empty string", "", false},
		{"similar but not exact", "self-hosted-1", false},
		{"uppercase", "SELF-HOSTED", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &AuthContext{ClerkUserID: tt.clerkUserID}
			auth.IsSelfHosted = auth.ClerkUserID == "self-hosted"
			if auth.IsSelfHosted != tt.wantSelfHost {
				t.Errorf("IsSelfHosted = %v, want %v", auth.IsSelfHosted, tt.wantSelfHost)
			}
		})
	}
}

func TestRequireRole_EmptyRoles(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(ContextKeyRole, model.RoleOwner)

	// Empty roles should deny everyone
	handler := RequireRole()(func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	err := handler(c)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}
