package handler

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

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
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, key)
}

// List returns all API keys for a project (deprecated)
// GET /api/v1/projects/:id/apikeys
func (h *APIKeyHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	keys, err := h.keyService.ListByProject(c.Request().Context(), projectID)
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
func (h *APIKeyHandler) Delete(c echo.Context) error {
	keyID, err := uuid.Parse(c.Param("key_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid key ID"})
	}

	if err := h.keyService.DeleteKey(c.Request().Context(), keyID); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}
