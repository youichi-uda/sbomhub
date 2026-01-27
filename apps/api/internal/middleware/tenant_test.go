package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
)

func TestTenantContext_TenantID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	tenantID := uuid.New()
	c.Set(ContextKeyTenantID, tenantID)

	tc := NewTenantContext(c)
	if tc.TenantID() != tenantID {
		t.Errorf("TenantID() = %v, want %v", tc.TenantID(), tenantID)
	}
}

func TestTenantContext_TenantID_Missing(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	tc := NewTenantContext(c)
	if tc.TenantID() != uuid.Nil {
		t.Errorf("TenantID() should be nil UUID, got %v", tc.TenantID())
	}
}

func TestTenantContext_UserID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	userID := uuid.New()
	c.Set(ContextKeyUserID, userID)

	tc := NewTenantContext(c)
	if tc.UserID() != userID {
		t.Errorf("UserID() = %v, want %v", tc.UserID(), userID)
	}
}

func TestTenantContext_Role(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(ContextKeyRole, model.RoleAdmin)

	tc := NewTenantContext(c)
	if tc.Role() != model.RoleAdmin {
		t.Errorf("Role() = %v, want %v", tc.Role(), model.RoleAdmin)
	}
}

func TestTenantContext_IsSelfHosted(t *testing.T) {
	tests := []struct {
		name       string
		clerkID    string
		selfHosted bool
	}{
		{"self-hosted user", "self-hosted", true},
		{"normal user", "user_123", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if tt.clerkID != "" {
				c.Set(ContextKeyClerkUserID, tt.clerkID)
			}

			tc := NewTenantContext(c)
			if tc.IsSelfHosted() != tt.selfHosted {
				t.Errorf("IsSelfHosted() = %v, want %v", tc.IsSelfHosted(), tt.selfHosted)
			}
		})
	}
}

func TestTenantContext_CanWrite(t *testing.T) {
	tests := []struct {
		role     string
		canWrite bool
	}{
		{model.RoleOwner, true},
		{model.RoleAdmin, true},
		{model.RoleMember, true},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			c.Set(ContextKeyRole, tt.role)

			tc := NewTenantContext(c)
			if tc.CanWrite() != tt.canWrite {
				t.Errorf("CanWrite() = %v, want %v", tc.CanWrite(), tt.canWrite)
			}
		})
	}
}

func TestTenantContext_CanAdmin(t *testing.T) {
	tests := []struct {
		role     string
		canAdmin bool
	}{
		{model.RoleOwner, true},
		{model.RoleAdmin, true},
		{model.RoleMember, false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			c.Set(ContextKeyRole, tt.role)

			tc := NewTenantContext(c)
			if tc.CanAdmin() != tt.canAdmin {
				t.Errorf("CanAdmin() = %v, want %v", tc.CanAdmin(), tt.canAdmin)
			}
		})
	}
}

func TestTenantContext_IsOwner(t *testing.T) {
	tests := []struct {
		role    string
		isOwner bool
	}{
		{model.RoleOwner, true},
		{model.RoleAdmin, false},
		{model.RoleMember, false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			c.Set(ContextKeyRole, tt.role)

			tc := NewTenantContext(c)
			if tc.IsOwner() != tt.isOwner {
				t.Errorf("IsOwner() = %v, want %v", tc.IsOwner(), tt.isOwner)
			}
		})
	}
}

func TestCheckTenantAccess(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	tenantID := uuid.New()
	c.Set(ContextKeyTenantID, tenantID)

	// Same tenant
	if !CheckTenantAccess(c, tenantID) {
		t.Error("CheckTenantAccess should return true for same tenant")
	}

	// Different tenant
	otherTenant := uuid.New()
	if CheckTenantAccess(c, otherTenant) {
		t.Error("CheckTenantAccess should return false for different tenant")
	}

	// Nil tenant in context
	c2 := e.NewContext(req, rec)
	if CheckTenantAccess(c2, tenantID) {
		t.Error("CheckTenantAccess should return false when tenant not in context")
	}
}

func TestEnsureTenantAccess(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	tenantID := uuid.New()
	c.Set(ContextKeyTenantID, tenantID)

	// Same tenant - should not return error
	err := EnsureTenantAccess(c, tenantID)
	if err != nil {
		t.Errorf("EnsureTenantAccess should not return error for same tenant, got %v", err)
	}

	// Different tenant - should return error
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req, rec2)
	c2.Set(ContextKeyTenantID, tenantID)

	otherTenant := uuid.New()
	err = EnsureTenantAccess(c2, otherTenant)
	if err != nil {
		t.Errorf("EnsureTenantAccess should return nil (error written to response), got %v", err)
	}
	if rec2.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec2.Code)
	}
}

func TestGetTenantID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	tenantID := uuid.New()
	c.Set(ContextKeyTenantID, tenantID)

	if GetTenantID(c) != tenantID {
		t.Errorf("GetTenantID() = %v, want %v", GetTenantID(c), tenantID)
	}
}

func TestGetUserID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	userID := uuid.New()
	c.Set(ContextKeyUserID, userID)

	if GetUserID(c) != userID {
		t.Errorf("GetUserID() = %v, want %v", GetUserID(c), userID)
	}
}
