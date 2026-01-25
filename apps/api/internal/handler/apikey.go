package handler

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
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

// Create creates a new API key
func (h *APIKeyHandler) Create(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
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
		ProjectID:   projectID,
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

// List returns all API keys for a project
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

// Delete removes an API key
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
