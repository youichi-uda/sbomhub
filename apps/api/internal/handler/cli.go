package handler

import (
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// CLIHandler handles CLI-specific endpoints.
type CLIHandler struct {
	cliService *service.CLIService
}

// NewCLIHandler creates a new CLIHandler.
func NewCLIHandler(cs *service.CLIService) *CLIHandler {
	return &CLIHandler{cliService: cs}
}

// UploadRequest represents the request for uploading SBOM via CLI.
type UploadRequest struct {
	ProjectName string `json:"project_name" form:"project_name"`
	Description string `json:"description" form:"description"`
}

// UploadResponse represents the response for SBOM upload.
type UploadResponse struct {
	Success         bool        `json:"success"`
	ProjectID       uuid.UUID   `json:"project_id"`
	ProjectName     string      `json:"project_name"`
	ProjectCreated  bool        `json:"project_created"`
	SbomID          uuid.UUID   `json:"sbom_id"`
	Format          string      `json:"format"`
	ComponentCount  int         `json:"component_count"`
}

// Upload handles SBOM upload from CLI.
// POST /cli/upload
// Content-Type: multipart/form-data
// - sbom: SBOM file (required)
// - project_name: Project name (required)
// - description: Project description (optional)
func (h *CLIHandler) Upload(c echo.Context) error {
	// Get tenant ID from context
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "tenant context not found",
		})
	}

	// Get project name from form
	projectName := c.FormValue("project_name")
	if projectName == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "project_name is required",
		})
	}
	description := c.FormValue("description")

	// Get SBOM file
	file, err := c.FormFile("sbom")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "sbom file is required",
		})
	}

	src, err := file.Open()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to open sbom file",
		})
	}
	defer src.Close()

	sbomData, err := io.ReadAll(src)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to read sbom file",
		})
	}

	ctx := c.Request().Context()

	// Get or create project
	project, created, err := h.cliService.GetOrCreateProject(ctx, tenantID, projectName, description)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Upload SBOM
	sbom, componentCount, err := h.cliService.UploadSBOM(ctx, project.ID, sbomData)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, UploadResponse{
		Success:        true,
		ProjectID:      project.ID,
		ProjectName:    project.Name,
		ProjectCreated: created,
		SbomID:         sbom.ID,
		Format:         sbom.Format,
		ComponentCount: componentCount,
	})
}

// Check handles vulnerability check from CLI.
// POST /cli/check
// Content-Type: application/json
func (h *CLIHandler) Check(c echo.Context) error {
	var req service.CheckVulnerabilitiesRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
	}

	if len(req.Components) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "components array is required and cannot be empty",
		})
	}

	result, err := h.cliService.CheckVulnerabilities(c.Request().Context(), req.Components)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, result)
}

// ProjectsListResponse represents the response for listing projects.
type ProjectsListResponse struct {
	Projects []model.Project `json:"projects"`
	Total    int             `json:"total"`
}

// ListProjects lists projects for the current tenant (API key's tenant).
// GET /cli/projects
func (h *CLIHandler) ListProjects(c echo.Context) error {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "tenant context not found",
		})
	}

	// Use existing repository method via service
	projects, err := h.cliService.ListProjects(c.Request().Context(), tenantID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, ProjectsListResponse{
		Projects: projects,
		Total:    len(projects),
	})
}

// GetProject gets a project by ID.
// GET /cli/projects/:id
func (h *CLIHandler) GetProject(c echo.Context) error {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "tenant context not found",
		})
	}

	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid project id",
		})
	}

	project, err := h.cliService.GetProject(c.Request().Context(), tenantID, projectID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "project not found",
		})
	}

	return c.JSON(http.StatusOK, project)
}

// CreateProjectRequest represents the request for creating a project via CLI.
type CreateProjectRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=255"`
	Description string `json:"description" validate:"max=1000"`
}

// CreateProject creates a new project.
// POST /cli/projects
func (h *CLIHandler) CreateProject(c echo.Context) error {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "tenant context not found",
		})
	}

	var req CreateProjectRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "name is required",
		})
	}

	project, created, err := h.cliService.GetOrCreateProject(c.Request().Context(), tenantID, req.Name, req.Description)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}

	return c.JSON(status, map[string]interface{}{
		"project": project,
		"created": created,
	})
}
