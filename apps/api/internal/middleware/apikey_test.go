package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// newAPIKeyMockDB returns a sqlmock-backed DB that mirrors what
// TenantRepository.SetCurrentTenant expects to execute. Used by the
// F18 APIKeyTenant tests below.
func newAPIKeyMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	return db, mock
}

// runAPIKeyTenant invokes the APIKeyTenant middleware against a
// sqlmock-backed TenantRepository, with the supplied APIKey already in
// context (as if APIKeyAuth had just validated it). Returns the recorder
// and any handler error.
func runAPIKeyTenant(t *testing.T, key *model.APIKey, next echo.HandlerFunc) (*httptest.ResponseRecorder, error) {
	t.Helper()
	db, mock := newAPIKeyMockDB(t)
	defer db.Close()

	// SetCurrentTenant emits SELECT set_config('app.current_tenant_id', $1, true).
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	tenantRepo := repository.NewTenantRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	mw := APIKeyTenant(projectRepo, tenantRepo)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/upload", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyAPI, key)

	err := mw(next)(c)
	if mockErr := mock.ExpectationsWereMet(); mockErr != nil {
		t.Errorf("unmet sqlmock expectations: %v", mockErr)
	}
	return rec, err
}

// TestAPIKeyTenant_SetsRoleFromPermissions_F18 pins the M1 Codex review
// #F18 fix: the APIKeyTenant middleware (used by the legacy
// /api/v1/cli/* and /api/v1/mcp/* groups) must populate ContextKeyRole
// from api_keys.permissions so the downstream RequireWrite guard on the
// CLI write routes can reject read-scoped keys.
//
// Before this fix APIKeyTenant only set ContextKeyTenantID; Role() then
// defaulted to "" (unknown) which failed CanWrite() outright if we tried
// to layer RequireWrite() on top — meaning we could not even apply the
// F15 guard to the legacy chain without breaking every legitimate write
// caller. With the mapping wired through roleFromAPIKeyPermissions, the
// same allowlist that protects the canonical MultiAuth route now
// protects the deprecated /cli/* writes too.
func TestAPIKeyTenant_SetsRoleFromPermissions_F18(t *testing.T) {
	cases := []struct {
		perm     string
		wantRole string
	}{
		{"read", model.RoleViewer},
		{"write", model.RoleMember},
		{"admin", model.RoleAdmin},
		{"owner", model.RoleAdmin},
		// F17 fail-closed: unknown / empty must be RoleViewer so the
		// legacy CLI write group cannot be bypassed via a typo'd
		// permissions column either.
		{"", model.RoleViewer},
		{"garbage", model.RoleViewer},
		{"readonly", model.RoleViewer},
	}

	tenantID := uuid.New()
	for _, tc := range cases {
		t.Run("perm="+tc.perm, func(t *testing.T) {
			var gotRole string
			var roleSet bool
			next := func(c echo.Context) error {
				v := c.Get(ContextKeyRole)
				if v == nil {
					return c.NoContent(http.StatusOK)
				}
				if s, ok := v.(string); ok {
					gotRole = s
					roleSet = true
				}
				return c.NoContent(http.StatusOK)
			}

			key := &model.APIKey{
				ID:          uuid.New(),
				TenantID:    tenantID,
				Name:        "test",
				Permissions: tc.perm,
			}
			rec, err := runAPIKeyTenant(t, key, next)
			if err != nil {
				t.Fatalf("APIKeyTenant returned unexpected error: %v", err)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("downstream not reached: status=%d body=%s", rec.Code, rec.Body.String())
			}
			if !roleSet {
				t.Fatalf("F18: APIKeyTenant must emit ContextKeyRole (was unset for perm=%q)", tc.perm)
			}
			if gotRole != tc.wantRole {
				t.Errorf("F18: ContextKeyRole = %q, want %q (perm=%q)", gotRole, tc.wantRole, tc.perm)
			}
		})
	}
}

// TestAPIKeyTenant_F18_RequireWriteBlocksReadKey is the end-to-end
// version: feed the real APIKeyTenant middleware a read-scoped key,
// then layer RequireWrite on top of it, and verify the downstream
// handler never runs. This is the contract the legacy CLI group
// depends on for the F18 fix.
func TestAPIKeyTenant_F18_RequireWriteBlocksReadKey(t *testing.T) {
	handlerCalled := false
	final := func(c echo.Context) error {
		handlerCalled = true
		return c.NoContent(http.StatusOK)
	}
	// RequireWrite consumed inline so APIKeyTenant runs first
	// (mirroring main.go's route wiring: APIKeyTenant → RequireWrite →
	// handler).
	chain := RequireWrite()(final)

	key := &model.APIKey{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "ci-readonly",
		Permissions: "read",
	}
	rec, err := runAPIKeyTenant(t, key, chain)
	if err != nil {
		t.Fatalf("APIKeyTenant chain returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F18: read-only API key must be rejected with 403 on /cli/upload, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if handlerCalled {
		t.Fatal("F18: legacy CLI write handler MUST NOT run for a read-only API key")
	}
	if !strings.Contains(rec.Body.String(), `"forbidden"`) {
		t.Errorf("F18: 403 body must contain generic \"forbidden\" sentinel, got %s", rec.Body.String())
	}
}

// TestAPIKeyTenant_F18_RequireWriteAllowsWriteKey is the positive
// counterpart: a write-scoped key (permissions="write" → RoleMember)
// must pass RequireWrite cleanly so existing CLI uploads keep working
// for the 3-month deprecation window before the legacy route is
// removed.
func TestAPIKeyTenant_F18_RequireWriteAllowsWriteKey(t *testing.T) {
	handlerCalled := false
	final := func(c echo.Context) error {
		handlerCalled = true
		return c.NoContent(http.StatusAccepted)
	}
	chain := RequireWrite()(final)

	key := &model.APIKey{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "ci-write",
		Permissions: "write",
	}
	rec, err := runAPIKeyTenant(t, key, chain)
	if err != nil {
		t.Fatalf("APIKeyTenant chain returned unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Fatalf("F18: write-scoped API key must pass RequireWrite, got status=%d body=%s",
			rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected stub status 202, got %d", rec.Code)
	}
}
