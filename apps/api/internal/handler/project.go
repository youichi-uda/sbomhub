package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

type ProjectHandler struct {
	projectService *service.ProjectService
}

func NewProjectHandler(ps *service.ProjectService) *ProjectHandler {
	return &ProjectHandler{projectService: ps}
}

func (h *ProjectHandler) Create(c echo.Context) error {
	// Get tenant ID from auth context
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	var req model.CreateProjectRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	project, err := h.projectService.Create(c.Request().Context(), tenantID, req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, project)
}

func (h *ProjectHandler) List(c echo.Context) error {
	// Get tenant ID from auth context
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	projects, err := h.projectService.List(c.Request().Context(), tenantID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, projects)
}

func (h *ProjectHandler) Get(c echo.Context) error {
	// Get tenant ID from auth context
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	project, err := h.projectService.Get(c.Request().Context(), tenantID, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
	}

	return c.JSON(http.StatusOK, project)
}

func (h *ProjectHandler) Delete(c echo.Context) error {
	// Get tenant ID from auth context
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	if err := h.projectService.Delete(c.Request().Context(), tenantID, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}
