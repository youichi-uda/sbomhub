package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// errInvalidPermissionsBody is the F17 wire body returned for any
// CreateKey / CreateProjectKey call that is rejected because the
// caller's permissions string was not in the allowlist. Kept as a
// package-level value so both the tenant and the legacy project
// handlers emit the same body and a probe caller cannot distinguish
// "validation failed because of permissions" from another 400 by body
// content alone (matches the F10 sentinel-opacity contract).
var errInvalidPermissionsBody = map[string]string{"error": "invalid permissions"}

// mapCreateKeyError converts a service-layer CreateKey error into the
// canonical handler response. F17: ErrInvalidPermissions specifically
// maps to a generic 400 body so the service's allowlist error message
// does not leak the recognised values verbatim through the wire
// response (the message stays in server logs for operator
// diagnostics). F442: every other error is likewise rendered with a
// generic 400 body — the reachable non-sentinel errors from CreateKey /
// CreateProjectKey are internal %w-wraps (key generation / repository
// insert), and both callers already pre-validate `name`, so echoing
// err.Error() here would only leak internal/DB error strings. The full
// error is preserved in the server log for operator diagnostics.
func mapCreateKeyError(c echo.Context, err error) error {
	// M47 W1: a project outside the caller's tenant (or one that does not
	// exist) is 404 — one sentinel, so POST /projects/:id/apikeys stops
	// being an existence oracle for project UUIDs. Must precede the generic
	// 400 fallback below.
	if errors.Is(err, service.ErrAPIKeyProjectNotInTenant) {
		slog.Warn("apikey: rejected create for a project outside the tenant",
			"path", c.Path(),
			"tenant_id", middleware.NewTenantContext(c).TenantID(),
		)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
	}
	// M47 W1 (Codex round 1, Low): a %w-wrapped repository failure from the
	// new ProjectInTenant query is an infrastructure fault. Returning it as
	// 400 told the caller their request was malformed while the real problem
	// was server-side, and it made a DB outage indistinguishable from a bad
	// permissions string.
	if errors.Is(err, service.ErrAPIKeyScopeCheckFailed) {
		slog.Error("apikey: project scope check failed",
			"path", c.Path(),
			"tenant_id", middleware.NewTenantContext(c).TenantID(),
			"error", err,
		)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create API key"})
	}
	if errors.Is(err, service.ErrInvalidPermissions) {
		slog.Warn("apikey: rejected create with invalid permissions",
			"path", c.Path(),
			"tenant_id", middleware.NewTenantContext(c).TenantID(),
			"sentinel", err.Error(),
		)
		return c.JSON(http.StatusBadRequest, errInvalidPermissionsBody)
	}
	slog.Warn("apikey: create key failed",
		"path", c.Path(),
		"tenant_id", middleware.NewTenantContext(c).TenantID(),
		"error", err,
	)
	return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to create API key"})
}

type APIKeyHandler struct {
	keyService *service.APIKeyService
}

func NewAPIKeyHandler(keyService *service.APIKeyService) *APIKeyHandler {
	return &APIKeyHandler{keyService: keyService}
}

type CreateAPIKeyRequest struct {
	Name        string `json:"name"`
	Permissions string `json:"permissions,omitempty"`
	ExpiresIn   int    `json:"expires_in_days,omitempty"` // Days until expiration (0 = never)
}

// ============================================
// Tenant-level API key endpoints (NEW)
// ============================================

// CreateTenant creates a new tenant-level API key
// POST /api/v1/apikeys
func (h *APIKeyHandler) CreateTenant(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	var req CreateAPIKeyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}

	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresIn)
		expiresAt = &t
	}

	input := service.CreateAPIKeyInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Permissions: req.Permissions,
		ExpiresAt:   expiresAt,
	}

	key, err := h.keyService.CreateKey(c.Request().Context(), input)
	if err != nil {
		return mapCreateKeyError(c, err)
	}

	// F208 / M14-1: publish the newly-minted apikey UUID so the audit
	// middleware records audit_logs.resource_id = key.ID. POST /apikeys
	// is a tenant-scoped create with no UUID path param, so without this
	// Set the audit row would drop to NULL and break the forensic join
	// audit_logs ⨝ api_keys for every apikey.created row.
	if key != nil {
		middleware.SetAuditResourceID(c, key.ID)
	}

	return c.JSON(http.StatusCreated, key)
}

// ListTenant returns all API keys for the current tenant
// GET /api/v1/apikeys
func (h *APIKeyHandler) ListTenant(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	keys, err := h.keyService.ListByTenant(c.Request().Context(), tenantID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list API keys"})
	}

	if keys == nil {
		keys = []model.APIKey{}
	}

	return c.JSON(http.StatusOK, keys)
}

// DeleteTenant removes an API key from the current tenant
// DELETE /api/v1/apikeys/:key_id
func (h *APIKeyHandler) DeleteTenant(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	keyID, err := uuid.Parse(c.Param("key_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid key ID"})
	}

	if err := h.keyService.DeleteKeyByTenant(c.Request().Context(), keyID, tenantID); err != nil {
		// M47R (Codex cross-wave review, Medium): only the 0-row sentinel is
		// a 404. This used to map EVERY repository error to 404, including a
		// timeout or a dropped connection — so an admin revoking a suspected
		// leaked key was told "API key not found", concluded it was already
		// gone, and stopped. The key was still valid.
		//
		// The project-level sibling (Delete, below) has separated the two
		// since M47 W1; this is the same resource, so it gets the same
		// contract. ErrAPIKeyNotFound covers unknown key AND another
		// tenant's key alike (one conditional DELETE, M47 W2), so the 404 is
		// still not an existence oracle. Never echo the error (F442).
		if errors.Is(err, repository.ErrAPIKeyNotFound) {
			slog.Warn("apikey: delete matched no key in this tenant",
				"key_id", keyID, "tenant_id", tenantID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "API key not found"})
		}
		slog.Error("apikey: delete key failed", "key_id", keyID, "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete API key"})
	}

	return c.NoContent(http.StatusNoContent)
}

// ============================================
// Project-scoped API key endpoints
// ============================================
//
// M50 W2: these three routes are no longer a deprecated compatibility shim.
// They mint / list / revoke keys that are ENFORCED to one project — the
// api_keys.project_id these write is read on every request by
// middleware.apiKeyProjectScopeAllowed. Before M50 W2 nothing read it, so the
// keys were tenant-wide in effect while the UI called them project-scoped; the
// "LEGACY, deprecated" banner this comment replaces is what made that look
// deliberate. The tenant-wide alternative is the /api/v1/apikeys trio above.

// Create mints a project-scoped API key: one limited to the project named by
// :id. See middleware/project_scope.go for exactly what the limit covers.
// POST /api/v1/projects/:id/apikeys
func (h *APIKeyHandler) Create(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	var req CreateAPIKeyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}

	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresIn)
		expiresAt = &t
	}

	input := service.CreateProjectAPIKeyInput{
		TenantID:    tenantID,
		ProjectID:   projectID,
		Name:        req.Name,
		Permissions: req.Permissions,
		ExpiresAt:   expiresAt,
	}

	key, err := h.keyService.CreateProjectKey(c.Request().Context(), input)
	if err != nil {
		return mapCreateKeyError(c, err)
	}

	// F208 / M14-1: publish the newly-minted apikey UUID so the audit
	// middleware records audit_logs.resource_id = key.ID instead of the
	// parent project UUID. POST /projects/:id/apikeys has :id bound, so
	// without this override the priority-list (which prefers :id last
	// but ParamNames-fallback still picks it up) would record the
	// project UUID and forensic joins to api_keys would silently drop.
	if key != nil {
		middleware.SetAuditResourceID(c, key.ID)
	}

	return c.JSON(http.StatusCreated, key)
}

// List returns the project-scoped API keys of one project.
// GET /api/v1/projects/:id/apikeys
//
// The tenant_id from middleware context is required because RLS no longer
// enforces tenant scope on api_keys (migration 028) — without it a caller
// could enumerate other tenants' project-level keys by guessing project UUIDs.
func (h *APIKeyHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	keys, err := h.keyService.ListByProject(c.Request().Context(), tenantID, projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list API keys"})
	}

	if keys == nil {
		keys = []model.APIKey{}
	}

	return c.JSON(http.StatusOK, keys)
}

// Delete revokes a project-scoped API key.
// DELETE /api/v1/projects/:id/apikeys/:key_id
//
// Mirrors List: tenant context is mandatory now that the api_keys RLS
// policy is gone (migration 028).
func (h *APIKeyHandler) Delete(c echo.Context) error {
	keyID, err := uuid.Parse(c.Param("key_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid key ID"})
	}

	// M47 W1: the route's :id now scopes the delete — see
	// service.APIKeyService.DeleteKey.
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	if err := h.keyService.DeleteKey(c.Request().Context(), tenantID, projectID, keyID); err != nil {
		// M47 W1 (Codex round 1, Low): a failure of the scope query itself
		// is a 500. Only the scope sentinel — which covers unknown key,
		// another project's key and another tenant's key alike — is a 404.
		// M47 W1 (Codex round 2, Low): one conditional DELETE, so zero rows
		// (404) and an infrastructure fault (500) are cleanly separated.
		// Never echo the error (F442).
		if errors.Is(err, service.ErrAPIKeyScopeCheckFailed) {
			slog.Error("apikey: delete failed",
				"key_id", keyID, "tenant_id", tenantID, "project_id", projectID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete API key"})
		}
		slog.Warn("apikey: delete key failed", "key_id", keyID, "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "API key not found"})
	}

	return c.NoContent(http.StatusNoContent)
}
