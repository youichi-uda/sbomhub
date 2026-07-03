package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

type VEXHandler struct {
	vexService *service.VEXService
}

func NewVEXHandler(vexService *service.VEXService) *VEXHandler {
	return &VEXHandler{vexService: vexService}
}

type CreateVEXRequest struct {
	VulnerabilityID string `json:"vulnerability_id"`
	ComponentID     string `json:"component_id,omitempty"`
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
}

// Create creates a new VEX statement
func (h *VEXHandler) Create(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	var req CreateVEXRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	vulnID, err := uuid.Parse(req.VulnerabilityID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid vulnerability ID"})
	}

	var compID *uuid.UUID
	if req.ComponentID != "" {
		parsed, err := uuid.Parse(req.ComponentID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid component ID"})
		}
		compID = &parsed
	}

	// Get authenticated user from context
	auth := middleware.GetAuthContext(c)
	user, ok := c.Get(middleware.ContextKeyUser).(*model.User)
	if !ok && c.Get(middleware.ContextKeyUser) != nil {
		// Log unexpected type in context (helps debug middleware issues)
		slog.Warn("context value for user is not of expected type",
			"actual_type", fmt.Sprintf("%T", c.Get(middleware.ContextKeyUser)))
	}
	createdBy := "system"
	if user != nil && user.Email != "" {
		createdBy = user.Email
	} else if auth != nil && auth.ClerkUserID != "" {
		createdBy = auth.ClerkUserID
	}

	input := service.CreateVEXStatementInput{
		ProjectID:       projectID,
		VulnerabilityID: vulnID,
		ComponentID:     compID,
		Status:          model.VEXStatus(req.Status),
		Justification:   model.VEXJustification(req.Justification),
		ActionStatement: req.ActionStatement,
		ImpactStatement: req.ImpactStatement,
		CreatedBy:       createdBy,
	}

	statement, err := h.vexService.CreateStatement(c.Request().Context(), input)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// F208 / M14-1: publish the newly-minted VEX UUID so the audit
	// middleware records audit_logs.resource_id = statement.ID instead
	// of the parent project UUID. POST /projects/:id/vex has :id in
	// the path, so without this override the resourceIDParamPriority
	// list would record the project UUID and forensic joins to
	// vex_statements would silently drop.
	if statement != nil {
		middleware.SetAuditResourceID(c, statement.ID)
	}

	return c.JSON(http.StatusCreated, statement)
}

type UpdateVEXRequest struct {
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
}

// Update updates a VEX statement
func (h *VEXHandler) Update(c echo.Context) error {
	vexID, err := uuid.Parse(c.Param("vex_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid VEX statement ID"})
	}

	var req UpdateVEXRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	input := service.UpdateVEXStatementInput{
		Status:          model.VEXStatus(req.Status),
		Justification:   model.VEXJustification(req.Justification),
		ActionStatement: req.ActionStatement,
		ImpactStatement: req.ImpactStatement,
	}

	statement, err := h.vexService.UpdateStatement(c.Request().Context(), vexID, input)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, statement)
}

// List returns all VEX statements for a project
func (h *VEXHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	statements, err := h.vexService.ListByProject(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list VEX statements"})
	}

	if statements == nil {
		statements = []model.VEXStatementWithDetails{}
	}

	return c.JSON(http.StatusOK, statements)
}

// GetSuggestions returns cross-project VEX reuse suggestions for a project
// (M26-A / F375, issue #130): approved vex_statements from OTHER projects
// of the same tenant that match a vulnerability affecting this project's
// components. Read-only Phase 1 — no apply action, so this is a plain GET.
//
// Auth / tenant scope mirrors the project-scoped VEX List above: the
// request already passed the auth → TenantTx chain, so ContextKeyTenantID
// is bound and every downstream query runs under SET LOCAL
// app.current_tenant_id. The tenant id is also passed explicitly to the
// service so the aggregation query carries a defence-in-depth
// `tenant_id = $1` predicate on top of RLS.
//
// No new audit action is emitted: this is a read, and the request-level
// audit middleware already records path + method + latency. Adding a
// bespoke action here would (needlessly) touch the F281/F271 audit-parity
// surface, which the M26 scope deliberately avoids.
func (h *VEXHandler) GetSuggestions(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	suggestions, err := h.vexService.GetSuggestions(c.Request().Context(), tenantID, projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list VEX suggestions"})
	}

	if suggestions == nil {
		suggestions = []model.VEXSuggestion{}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"suggestions": suggestions})
}

// Get returns a specific VEX statement
func (h *VEXHandler) Get(c echo.Context) error {
	vexID, err := uuid.Parse(c.Param("vex_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid VEX statement ID"})
	}

	statement, err := h.vexService.GetStatement(c.Request().Context(), vexID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get VEX statement"})
	}
	if statement == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "VEX statement not found"})
	}

	return c.JSON(http.StatusOK, statement)
}

// Delete removes a VEX statement
func (h *VEXHandler) Delete(c echo.Context) error {
	vexID, err := uuid.Parse(c.Param("vex_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid VEX statement ID"})
	}

	if err := h.vexService.DeleteStatement(c.Request().Context(), vexID); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}

// Export exports VEX statements in CycloneDX format
func (h *VEXHandler) Export(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	data, err := h.vexService.ExportCycloneDXVEX(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to export VEX"})
	}

	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().Header().Set("Content-Disposition", "attachment; filename=vex.json")
	return c.Blob(http.StatusOK, "application/json", data)
}
