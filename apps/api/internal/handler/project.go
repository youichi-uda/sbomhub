package handler

import (
	"context"
	"log/slog"
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
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	project, err := h.projectService.Create(c.Request().Context(), tenantID, req)
	if err != nil {
		slog.Warn("project: create failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create project"})
	}

	// F208 / M14-1: publish the newly-minted project UUID so the audit
	// middleware records audit_logs.resource_id = project.ID instead of
	// NULL. POST /api/v1/projects has no path param carrying the new
	// UUID, so without this Set the row would be unjoinable to
	// projects.id (forensic gap the F190 docstring used to pin).
	if project != nil {
		middleware.SetAuditResourceID(c, project.ID)
	}

	return c.JSON(http.StatusCreated, project)
}

// listProjectsForCredential is the single place both project-list routes decide
// WHICH projects the request's credential may enumerate, so that
// GET /api/v1/cli/projects (CLIHandler.ListProjects) and GET /api/v1/mcp/projects
// (ProjectHandler.List) cannot drift apart — the failure M50 W2 named when it
// refused both rather than narrowing one. It mirrors resolveCLIProject in cli.go,
// which plays the same role for the two body-resolved write routes.
//
// The branch is on the CREDENTIAL, never on the route. That is load-bearing,
// because ProjectHandler.List is registered at these routes in
// cmd/server/main.go and they do not agree about credentials:
//
//	APIKEY GET /api/v1/mcp/projects
//	CLERK  GET /api/v1/projects
//
// APIKEY = reachable with `Authorization: Bearer sbh_...`. CLERK = behind
// appmw.Auth, i.e. a Clerk session or, with SBOMHUB_AUTH_MODE=anonymous, no
// credential at all; that one is the web UI's project list and must keep
// returning the whole tenant.
//
// That block is not prose. TestM50W3ProjectHandlerListRegistrationsMatchTheDoc
// parses it, re-derives both the route set and the APIKEY/CLERK split from
// main.go's AST, and fails on any difference in either direction — so a route
// added, removed or re-fronted here cannot go unnoticed, and a typo in a path
// above cannot pass. The first version of this comment was prose and said
// "registered three times" when there were two (Codex R1).
//
// middleware.APIKeyProjectID reports false on the Clerk route: it reads
// ContextKeyAPI, which only APIKeyAuth, OptionalAPIKeyAuth and MultiAuth's
// handleAPIKeyAuth ever set (the complete set of `Set(ContextKeyAPI` sites in the
// non-test source, all three in internal/middleware, swept 2026-07-30) — so the
// web list is returned unnarrowed. TestM50W3NoAPIKeyCredentialSeesTheWholeTenant
// drives both handlers in exactly that context state.
//
// A tenant-level key (`api_keys.project_id IS NULL`) also reports false and is
// likewise unchanged.
func listProjectsForCredential(
	c echo.Context,
	tenantID uuid.UUID,
	listTenant func(context.Context, uuid.UUID) ([]model.Project, error),
	listKeyProject func(context.Context, uuid.UUID, uuid.UUID) ([]model.Project, error),
) ([]model.Project, error) {
	ctx := c.Request().Context()
	if keyProjectID, scoped := middleware.APIKeyProjectID(c); scoped {
		return listKeyProject(ctx, tenantID, keyProjectID)
	}
	return listTenant(ctx, tenantID)
}

// List lists the projects the caller's credential may enumerate.
// GET /api/v1/projects (Clerk / self-hosted) and GET /api/v1/mcp/projects (API key).
//
// M50 W3: a project-scoped API key gets its own project as a one-element array
// instead of the tenant's list. See listProjectsForCredential and
// middleware.scopeProjectListNarrowed.
func (h *ProjectHandler) List(c echo.Context) error {
	// Get tenant ID from auth context
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	projects, err := listProjectsForCredential(c, tenantID,
		h.projectService.List, h.projectService.ListForKeyProject)
	if err != nil {
		slog.Warn("project: list failed", "tenant_id", tenantID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list projects"})
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
		slog.Warn("project: delete failed", "tenant_id", tenantID, "project_id", id, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete project"})
	}

	return c.NoContent(http.StatusNoContent)
}
