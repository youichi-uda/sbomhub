package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
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

	input := service.CreateVEXStatementInput{
		ProjectID:       projectID,
		VulnerabilityID: vulnID,
		ComponentID:     compID,
		Status:          model.VEXStatus(req.Status),
		Justification:   model.VEXJustification(req.Justification),
		ActionStatement: req.ActionStatement,
		ImpactStatement: req.ImpactStatement,
		CreatedBy:       "system", // TODO: Replace with actual user when auth is implemented
	}

	statement, err := h.vexService.CreateStatement(c.Request().Context(), input)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
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
