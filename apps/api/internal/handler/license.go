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
	UpdatePolicy(ctx context.Context, tenantID, projectID, id uuid.UUID, input service.UpdateLicensePolicyInput) (*model.LicensePolicy, error)
	GetPolicy(ctx context.Context, tenantID, projectID, id uuid.UUID) (*model.LicensePolicy, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.LicensePolicy, error)
	DeletePolicy(ctx context.Context, tenantID, projectID, id uuid.UUID) error
	CheckViolations(ctx context.Context, tenantID, projectID uuid.UUID, sbomID uuid.UUID) ([]model.LicenseViolation, error)
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
		// M47 W1: a project the caller cannot see is 404, not 500.
		if errors.Is(err, service.ErrLicensePolicyNotInProject) {
			slog.Warn("license: create rejected, project not in tenant", "project_id", projectID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
		}
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

// Update updates a license policy.
//
// M47 W1: the route is PUT /projects/:id/licenses/:policy_id and :id is now
// used — with the session tenant it scopes the lookup. Before this the
// project segment was decoration and the repository ran
// `UPDATE license_policies ... WHERE id = $4`.
func (h *LicensePolicyHandler) Update(c echo.Context) error {
	tenantID, projectID, ok := licenseRouteScope(c)
	if !ok {
		return licenseRouteScopeError(c)
	}

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

	policy, err := h.licenseService.UpdatePolicy(c.Request().Context(), tenantID, projectID, policyID, input)
	if err != nil {
		// M47 W1: out-of-scope (unknown / other project / other tenant) is
		// one 404 — see service.ErrLicensePolicyNotInProject.
		if errors.Is(err, service.ErrLicensePolicyNotInProject) {
			slog.Warn("license: update rejected, policy not in project",
				"tenant_id", tenantID, "project_id", projectID, "policy_id", policyID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "license policy not found"})
		}
		// F443: same split as Create — validation feedback (bad policy type)
		// at 400; %w-wrapped repo / DB failures at 500 with a generic body so
		// the driver string never reaches the client.
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		slog.Warn("license: update policy failed", "policy_id", policyID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save license policy"})
	}

	return c.JSON(http.StatusOK, policy)
}

// licenseRouteScope pulls the (tenant, project) pair every :policy_id-scoped
// route needs. Both must be present; a missing tenant means the route was
// registered outside the auth/TenantTx chain, which is a wiring fault and
// must fail closed rather than fall back to an unscoped lookup.
func licenseRouteScope(c echo.Context) (tenantID, projectID uuid.UUID, ok bool) {
	tenantID, hasTenant := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !hasTenant || tenantID == uuid.Nil {
		return uuid.Nil, uuid.Nil, false
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return tenantID, uuid.Nil, false
	}
	return tenantID, projectID, true
}

// licenseRouteScopeError renders the failure of licenseRouteScope. It cannot
// distinguish "no tenant" from "bad project id" without re-deriving them, so
// it re-checks the tenant to pick 401 vs 400.
func licenseRouteScopeError(c echo.Context) error {
	if tenantID, hasTenant := c.Get(middleware.ContextKeyTenantID).(uuid.UUID); !hasTenant || tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}
	return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
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

// Get returns a specific license policy, scoped to the route's project.
// M47 W1: see Update — the read had the same "the :id segment is decoration"
// shape and leaked another project's policy within the tenant.
func (h *LicensePolicyHandler) Get(c echo.Context) error {
	tenantID, projectID, ok := licenseRouteScope(c)
	if !ok {
		return licenseRouteScopeError(c)
	}

	policyID, err := uuid.Parse(c.Param("policy_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid policy ID"})
	}

	policy, err := h.licenseService.GetPolicy(c.Request().Context(), tenantID, projectID, policyID)
	if err != nil {
		if errors.Is(err, service.ErrLicensePolicyNotInProject) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "license policy not found"})
		}
		slog.Warn("license: get policy failed", "policy_id", policyID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get license policy"})
	}
	if policy == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "license policy not found"})
	}

	return c.JSON(http.StatusOK, policy)
}

// Delete removes a license policy, scoped to the route's project.
// M47 W1: see Update — the repository DELETE was `WHERE id = $1`.
func (h *LicensePolicyHandler) Delete(c echo.Context) error {
	tenantID, projectID, ok := licenseRouteScope(c)
	if !ok {
		return licenseRouteScopeError(c)
	}

	policyID, err := uuid.Parse(c.Param("policy_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid policy ID"})
	}

	if err := h.licenseService.DeletePolicy(c.Request().Context(), tenantID, projectID, policyID); err != nil {
		// M47 W1 (Codex round 1, Low): a failure of the scope query itself
		// is a 500. Everything else stays a 404 — the scope sentinel and a
		// rows==0 DELETE (the row vanished between the check and the delete
		// inside the same tx) are both honestly "not there".
		// M47 W1 (Codex round 2, Low): one conditional DELETE, so zero rows
		// (404) and an infrastructure fault (500) are cleanly separated.
		// Neither body echoes the error (F442).
		if errors.Is(err, service.ErrLicensePolicyScopeCheckFailed) {
			slog.Error("license: delete failed",
				"tenant_id", tenantID, "project_id", projectID, "policy_id", policyID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete license policy"})
		}
		slog.Warn("license: delete policy failed",
			"tenant_id", tenantID, "project_id", projectID, "policy_id", policyID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "license policy not found"})
	}

	return c.NoContent(http.StatusNoContent)
}

// CheckViolations checks components against license policies.
// M47 W1: `?sbom_id=` is bound to (tenant, project) — see
// service.LicensePolicyService.CheckViolations.
func (h *LicensePolicyHandler) CheckViolations(c echo.Context) error {
	tenantID, projectID, ok := licenseRouteScope(c)
	if !ok {
		return licenseRouteScopeError(c)
	}

	sbomID, err := uuid.Parse(c.QueryParam("sbom_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "sbom_id query parameter is required"})
	}

	violations, err := h.licenseService.CheckViolations(c.Request().Context(), tenantID, projectID, sbomID)
	if err != nil {
		if errors.Is(err, service.ErrLicensePolicyNotInProject) {
			slog.Warn("license: check violations rejected, sbom not in project",
				"tenant_id", tenantID, "project_id", projectID, "sbom_id", sbomID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom not found"})
		}
		// A broken scope query is a 500, not a 404 (Codex round 1, Low).
		if errors.Is(err, service.ErrLicensePolicyScopeCheckFailed) {
			slog.Error("license: violations scope check failed",
				"tenant_id", tenantID, "project_id", projectID, "sbom_id", sbomID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to check license violations"})
		}
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
