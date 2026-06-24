package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestCLIUpload_AdvertisesDeprecationHeaders verifies Trust Rescue 9.3.1 (#9):
// the legacy POST /api/v1/cli/upload route MUST advertise RFC 8594 (Sunset) +
// RFC 5988 (Link rel=successor-version) so SDK consumers see the upcoming
// removal on every response. We hit the unauthenticated error path on purpose
// — the headers are part of the deprecation contract and must be present
// regardless of whether the request body / tenant context is valid.
func TestCLIUpload_AdvertisesDeprecationHeaders(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/upload", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// nil CLIService — Upload returns 401 before ever touching it because
	// no tenant context is set on the request. That path still runs the
	// header writes at the top of the handler, which is what we want to
	// pin down.
	h := &CLIHandler{cliService: nil}

	if err := h.Upload(c); err != nil {
		t.Fatalf("Upload returned unexpected error: %v", err)
	}

	if got := rec.Header().Get("Deprecation"); got != "true" {
		t.Errorf("Deprecation header = %q, want %q", got, "true")
	}
	if got := rec.Header().Get("Sunset"); got == "" {
		t.Error("Sunset header is missing")
	} else if !strings.Contains(got, "2026") {
		t.Errorf("Sunset header = %q, expected to contain the 2026 sunset date", got)
	}
	link := rec.Header().Get("Link")
	if link == "" {
		t.Fatal("Link header is missing")
	}
	if !strings.Contains(link, "/api/v1/projects/{id}/sbom") {
		t.Errorf("Link header = %q, expected to point at canonical /api/v1/projects/{id}/sbom", link)
	}
	if !strings.Contains(link, `rel="successor-version"`) {
		t.Errorf("Link header = %q, expected rel=\"successor-version\"", link)
	}
}

// TestCLIUpload_DeprecationHeadersOnErrorBody verifies that the Sunset signal
// is delivered even on 4xx responses — clients should not have to coerce a
// successful upload to discover the deprecation. RFC 8594 §3 explicitly
// permits Sunset on any response.
func TestCLIUpload_DeprecationHeadersOnErrorBody(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/upload", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := &CLIHandler{cliService: nil}
	_ = h.Upload(c)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected non-200 (missing tenant context), got %d", rec.Code)
	}
	if rec.Header().Get("Deprecation") != "true" {
		t.Error("Deprecation: true must be present on the error response, not only on 200")
	}
}

// TestCLIUpload_F18_ReadOnlyAPIKeyRejected stitches the F18 fix
// together at the handler-chain level: a read-scoped API key flowing
// into the legacy /api/v1/cli/upload route must be rejected by
// RequireWrite() before the CLI handler ever runs. Before the fix the
// legacy CLI group used APIKeyAuth + APIKeyTenant only, neither of
// which checked api_keys.permissions, so a sbh_... key created with
// permissions="read" could create projects and persist SBOMs by hitting
// the deprecated endpoint instead of the canonical
// POST /api/v1/projects/:id/sbom (which F15 had already locked down).
//
// We exercise RequireWrite directly because spinning up APIKeyAuth
// would require a live APIKeyService with DB-backed key validation
// (covered in repository / service tests). The role-mapping contract
// that APIKeyTenant emits onto ContextKeyRole is pinned by
// TestAPIKeyTenant_SetsRoleFromPermissions_F18 in middleware/; this
// test pins the second half — that with the role set to RoleViewer,
// the guard short-circuits with 403 and the CLI upload handler never
// runs.
func TestCLIUpload_F18_ReadOnlyAPIKeyRejected(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/upload", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer sbh_readonly_simulated")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Simulate the post-APIKeyAuth + APIKeyTenant context as it exists
	// after the F18 fix: tenant context bound, role mapped from
	// permissions="read" → RoleViewer.
	c.Set(middleware.ContextKeyAPI, &model.APIKey{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "ci-readonly",
		Permissions: "read",
	})
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleViewer)

	handlerCalled := false
	// nil CLIService is fine — if RequireWrite lets the request through
	// in error, the handler will nil-panic, which is a louder regression
	// signal than a quiet 200.
	h := &CLIHandler{cliService: nil}
	final := func(c echo.Context) error {
		handlerCalled = true
		return h.Upload(c)
	}

	if err := middleware.RequireWrite()(final)(c); err != nil {
		t.Fatalf("RequireWrite returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F18: read-only API key on /cli/upload must be rejected with 403, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if handlerCalled {
		t.Fatal("F18: CLI upload handler MUST NOT run for a read-only API key")
	}
	if !strings.Contains(rec.Body.String(), `"forbidden"`) {
		t.Errorf("F18: 403 body must contain generic \"forbidden\" sentinel, got %s", rec.Body.String())
	}
}

// TestCLICreateProject_F18_ReadOnlyAPIKeyRejected is the F18 mirror
// for POST /api/v1/cli/projects (the other mutating route on the
// legacy group). CLIHandler.CreateProject also creates rows
// (cliService.GetOrCreateProject) so a read-scoped key reaching it
// would be the same privilege violation as Upload. Same chain
// reasoning as TestCLIUpload_F18_ReadOnlyAPIKeyRejected above.
func TestCLICreateProject_F18_ReadOnlyAPIKeyRejected(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/projects",
		strings.NewReader(`{"name":"probe"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sbh_readonly_simulated")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(middleware.ContextKeyAPI, &model.APIKey{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "ci-readonly",
		Permissions: "read",
	})
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleViewer)

	handlerCalled := false
	h := &CLIHandler{cliService: nil}
	final := func(c echo.Context) error {
		handlerCalled = true
		return h.CreateProject(c)
	}

	if err := middleware.RequireWrite()(final)(c); err != nil {
		t.Fatalf("RequireWrite returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F18: read-only API key on /cli/projects must be rejected with 403, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if handlerCalled {
		t.Fatal("F18: CLI CreateProject handler MUST NOT run for a read-only API key")
	}
	if !strings.Contains(rec.Body.String(), `"forbidden"`) {
		t.Errorf("F18: 403 body must contain generic \"forbidden\" sentinel, got %s", rec.Body.String())
	}
}

// TestCLIUpload_F18_WriteAPIKeyAllowed sanity-checks the positive
// case: a write-scoped key (permissions="write" → RoleMember) must
// pass through RequireWrite so legitimate CLI uploads keep working
// against the legacy endpoint during the deprecation window. If this
// test regresses to 403 we have broken every existing CI pipeline
// using the deprecated /cli/upload route.
func TestCLIUpload_F18_WriteAPIKeyAllowed(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/upload", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(middleware.ContextKeyAPI, &model.APIKey{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "ci-write",
		Permissions: "write",
	})
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleMember)

	handlerCalled := false
	// Real handler call would also exercise deprecation headers + tenant
	// resolution; here we just need to confirm the guard does not
	// short-circuit. Use a stub final that records the visit and
	// returns 200 so we can distinguish guard-success from
	// downstream-failure.
	final := func(c echo.Context) error {
		handlerCalled = true
		return c.NoContent(http.StatusAccepted)
	}

	if err := middleware.RequireWrite()(final)(c); err != nil {
		t.Fatalf("RequireWrite returned unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Fatalf("F18: write-scoped API key must pass RequireWrite, got status=%d body=%s",
			rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected stub status 202, got %d", rec.Code)
	}
}
