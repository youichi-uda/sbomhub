package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

type LicensePolicyHandler struct {
	licenseService *service.LicensePolicyService
}

func NewLicensePolicyHandler(licenseService *service.LicensePolicyService) *LicensePolicyHandler {
	return &LicensePolicyHandler{licenseService: licenseService}
}

type CreateLicensePolicyRequest struct {
	LicenseID   string `json:"license_id"`
	LicenseName string `json:"license_name,omitempty"`
	PolicyType  string `json:"policy_type"`
	Reason      string `json:"reason,omitempty"`
}

// Create creates a new license policy
func (h *LicensePolicyHandler) Create(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	var req CreateLicensePolicyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	if req.LicenseID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "license_id is required"})
	}

	input := service.CreateLicensePolicyInput{
		ProjectID:   projectID,
		LicenseID:   req.LicenseID,
		LicenseName: req.LicenseName,
		PolicyType:  model.LicensePolicyType(req.PolicyType),
		Reason:      req.Reason,
	}

	policy, err := h.licenseService.CreatePolicy(c.Request().Context(), input)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, policy)
}

type UpdateLicensePolicyRequest struct {
	PolicyType string `json:"policy_type"`
	Reason     string `json:"reason,omitempty"`
}

// Update updates a license policy
func (h *LicensePolicyHandler) Update(c echo.Context) error {
	policyID, err := uuid.Parse(c.Param("policy_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid policy ID"})
	}

	var req UpdateLicensePolicyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	input := service.UpdateLicensePolicyInput{
		PolicyType: model.LicensePolicyType(req.PolicyType),
		Reason:     req.Reason,
	}

	policy, err := h.licenseService.UpdatePolicy(c.Request().Context(), policyID, input)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, policy)
}

// List returns all license policies for a project
func (h *LicensePolicyHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	policies, err := h.licenseService.ListByProject(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list license policies"})
	}

	if policies == nil {
		policies = []model.LicensePolicy{}
	}

	return c.JSON(http.StatusOK, policies)
}

// Get returns a specific license policy
func (h *LicensePolicyHandler) Get(c echo.Context) error {
	policyID, err := uuid.Parse(c.Param("policy_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid policy ID"})
	}

	policy, err := h.licenseService.GetPolicy(c.Request().Context(), policyID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get license policy"})
	}
	if policy == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "license policy not found"})
	}

	return c.JSON(http.StatusOK, policy)
}

// Delete removes a license policy
func (h *LicensePolicyHandler) Delete(c echo.Context) error {
	policyID, err := uuid.Parse(c.Param("policy_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid policy ID"})
	}

	if err := h.licenseService.DeletePolicy(c.Request().Context(), policyID); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}

// CheckViolations checks components against license policies
func (h *LicensePolicyHandler) CheckViolations(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	sbomID, err := uuid.Parse(c.QueryParam("sbom_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "sbom_id query parameter is required"})
	}

	violations, err := h.licenseService.CheckViolations(c.Request().Context(), projectID, sbomID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	if violations == nil {
		violations = []model.LicenseViolation{}
	}

	return c.JSON(http.StatusOK, violations)
}

// GetCommonLicenses returns a list of common SPDX licenses
func (h *LicensePolicyHandler) GetCommonLicenses(c echo.Context) error {
	licenses := h.licenseService.GetCommonLicenses()
	return c.JSON(http.StatusOK, licenses)
}
