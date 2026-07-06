package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// licensePolicyService is the subset of *service.LicensePolicyService the
// handler depends on. Declaring the dependency as an interface (rather than
// the concrete type) lets tests inject a stub that returns validation vs
// internal errors, which is what the F443 400/500 split test requires — the
// concrete service is DB-backed and cannot be driven to a %w-wrapped repo
// failure in a unit test. *service.LicensePolicyService satisfies this.
type licensePolicyService interface {
	CreatePolicy(ctx context.Context, input service.CreateLicensePolicyInput) (*model.LicensePolicy, error)
	UpdatePolicy(ctx context.Context, id uuid.UUID, input service.UpdateLicensePolicyInput) (*model.LicensePolicy, error)
	GetPolicy(ctx context.Context, id uuid.UUID) (*model.LicensePolicy, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.LicensePolicy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	CheckViolations(ctx context.Context, projectID uuid.UUID, sbomID uuid.UUID) ([]model.LicenseViolation, error)
	GetCommonLicenses() map[string]string
}

type LicensePolicyHandler struct {
	licenseService licensePolicyService
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
		// F443: only self-authored validation errors (bad policy type,
		// duplicate policy) are safe to echo at 400. A %w-wrapped repo /
		// DB failure must not leak its driver string — 500 + generic body,
		// full error to the server log only.
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		slog.Warn("license: create policy failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save license policy"})
	}

	// F208 / M14-1: publish the newly-minted license-policy UUID so the
	// audit middleware records audit_logs.resource_id = policy.ID
	// instead of the parent project UUID. POST /projects/:id/licenses
	// has :id in the path, so without this override the resource_id
	// would point at the project and forensic joins to license_policies
	// would silently drop.
	if policy != nil {
		middleware.SetAuditResourceID(c, policy.ID)
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
		// F443: same split as Create — validation feedback (unknown policy,
		// bad policy type) at 400; %w-wrapped repo / DB failures at 500 with
		// a generic body so the driver string never reaches the client.
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		slog.Warn("license: update policy failed", "policy_id", policyID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save license policy"})
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
		// DeletePolicy returns the raw repository error (which is either a
		// static "not found" for rows==0 or a raw driver error otherwise);
		// never echo it to the client (F442). Generic 404 body + full error
		// to the server log.
		slog.Warn("license: delete policy failed", "policy_id", policyID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "license policy not found"})
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
		slog.Warn("license: check violations failed", "project_id", projectID, "sbom_id", sbomID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to check license violations"})
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
