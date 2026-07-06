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
		// Raw repository error (static "not found or not authorized" for
		// rows==0, or a raw driver error otherwise); never echo it (F442).
		slog.Warn("apikey: delete key failed", "key_id", keyID, "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "API key not found"})
	}

	return c.NoContent(http.StatusNoContent)
}

// ============================================
// Project-level API key endpoints (LEGACY, deprecated)
// ============================================

// Create creates a new project-level API key (deprecated)
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

// List returns all API keys for a project (deprecated)
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

// Delete removes an API key (deprecated)
// DELETE /api/v1/projects/:id/apikeys/:key_id
//
// Mirrors List: tenant context is mandatory now that the api_keys RLS
// policy is gone (migration 028).
func (h *APIKeyHandler) Delete(c echo.Context) error {
	keyID, err := uuid.Parse(c.Param("key_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid key ID"})
	}

	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	if err := h.keyService.DeleteKey(c.Request().Context(), tenantID, keyID); err != nil {
		// Raw repository error (static "not found" for rows==0, or a raw
		// driver error otherwise); never echo it (F442).
		slog.Warn("apikey: delete key failed", "key_id", keyID, "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "API key not found"})
	}

	return c.NoContent(http.StatusNoContent)
}
