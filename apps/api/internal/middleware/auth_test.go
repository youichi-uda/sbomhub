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
