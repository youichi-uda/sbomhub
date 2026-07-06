package handler

import (
	"errors"
	"io"
	"log/slog"
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
	Success        bool      `json:"success"`
	ProjectID      uuid.UUID `json:"project_id"`
	ProjectName    string    `json:"project_name"`
	ProjectCreated bool      `json:"project_created"`
	SbomID         uuid.UUID `json:"sbom_id"`
	Format         string    `json:"format"`
	ComponentCount int       `json:"component_count"`
}

// Upload handles SBOM upload from CLI.
// POST /cli/upload
// Content-Type: multipart/form-data
// - sbom: SBOM file (required)
// - project_name: Project name (required)
// - description: Project description (optional)
//
// DEPRECATED (Trust Rescue 9.3.1 / #9): clients must migrate to the canonical
// POST /api/v1/projects/:id/sbom endpoint, which is reachable with the same
// Bearer sbh_... API key via the MultiAuth middleware. This route is kept
// alive for a 3-month overlap window so existing CI pipelines do not break.
// We deliberately do NOT 308-redirect here: the new endpoint takes a raw body
// (vs multipart) and not all HTTP clients re-emit a multipart body on a
// redirect, so silent failures would be hard to debug. Removal is tracked at
// the Sunset date below.
func (h *CLIHandler) Upload(c echo.Context) error {
	// RFC 8594 (Sunset) + RFC 8288 (Link rel=successor-version): advertise the
	// deprecation in-band so SDKs / curl users see it on every response.
	// 2026-06-24 + 3 months = 2026-09-24 (the legacy route is removed on or
	// after this date; the deadline doubles as the Trust Rescue M0 cut-off).
	c.Response().Header().Set("Deprecation", "true")
	c.Response().Header().Set("Sunset", "Thu, 24 Sep 2026 00:00:00 GMT")
	c.Response().Header().Set("Link", `</api/v1/projects/{id}/sbom>; rel="successor-version"`)

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
		// GetOrCreateProject only ever returns %w-wrapped DB errors
		// (search / create) — none are caller-fixable, so log the raw
		// error server-side and return a generic body.
		slog.Warn("cli: get or create project failed", "tenant_id", tenantID, "project_name", projectName, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to resolve project",
		})
	}

	// Upload SBOM.
	//
	// F443-style mixed-400 split (mirrors SbomHandler.Upload): UploadSBOM
	// returns a MIX of caller-fixable parse/format failures (marked with
	// service.ErrValidation → 400 with the helpful message) and %w-wrapped
	// internal errors (tenant lookup / SBOM insert / component insert →
	// 500 generic, raw error logged server-side only). The pre-fix path
	// blanket-400'd every failure AND echoed the raw driver string.
	sbom, componentCount, err := h.cliService.UploadSBOM(ctx, project.ID, sbomData)
	if err != nil {
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
		}
		slog.Warn("cli: upload sbom failed", "project_id", project.ID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to import SBOM",
		})
	}

	// F233 (M15-1 fix, anti-pattern 51 override-first audit context-key):
	// publish the newly-minted sbom UUID so the audit middleware records
	// audit_logs.resource_id = sbom.ID under the sbom.uploaded /
	// ResourceSBOM classification that the F233 middleware branch now
	// emits for POST /cli/upload. This mirrors the tenant-side POST
	// /api/v1/projects/:id/sbom SetAuditResourceID call in sbom.go.
	//
	// We publish the SBOM UUID (not the project UUID) because the
	// business subject of POST /cli/upload is the SBOM itself — the
	// project either already existed or was mint-on-first-upload — and
	// forensic queries want to join audit_logs onto sboms.id. If
	// created=true, the project.created event is not lost: the
	// GetOrCreateProject writer path already emits its own audit row
	// through the tenant repository layer (M14-1 F208 project handler
	// pattern), so publishing sbom.ID here does not shadow it.
	middleware.SetAuditResourceID(c, sbom.ID)

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
			"error": "invalid request body",
		})
	}

	if len(req.Components) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "components array is required and cannot be empty",
		})
	}

	result, err := h.cliService.CheckVulnerabilities(c.Request().Context(), req.Components)
	if err != nil {
		// Only internal failures reach here (OSV request/response, JSON
		// (un)marshal). None are caller-fixable, so log the raw error
		// server-side and return a generic body.
		slog.Warn("cli: check vulnerabilities failed", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to check vulnerabilities",
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
		slog.Warn("cli: list projects failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to list projects",
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
		slog.Warn("cli: get or create project failed", "tenant_id", tenantID, "project_name", req.Name, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to create project",
		})
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}

	// F233 (M15-1 fix, anti-pattern 51 override-first audit context-key):
	// publish the project UUID so the audit middleware records
	// audit_logs.resource_id = project.ID under the project.created /
	// ResourceProject classification that the F233 middleware branch
	// now emits for POST /cli/projects. This mirrors the tenant-side
	// POST /api/v1/projects SetAuditResourceID call in project.go.
	//
	// We publish the project UUID on BOTH created==true and
	// created==false. For created==false (the idempotent get-existing
	// path) the audit row is still a legitimate "asked to create /
	// touch this project" event from the CLI and the resource_id must
	// point at the returned project so forensic timelines are
	// contiguous.
	middleware.SetAuditResourceID(c, project.ID)

	return c.JSON(status, map[string]interface{}{
		"project": project,
		"created": created,
	})
}
