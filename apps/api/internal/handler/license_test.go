package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// Pin the seam: the concrete service must keep satisfying the handler's
// interface, so the F443 split tests below stay wired to the real dependency.
var _ licensePolicyService = (*service.LicensePolicyService)(nil)

// stubLicensePolicyService implements the handler's licensePolicyService
// seam. Only CreatePolicy / UpdatePolicy are exercised by the F443 split
// tests; the other methods exist purely to satisfy the interface. The
// concrete *service.LicensePolicyService is DB-backed and cannot be driven
// to a %w-wrapped repository failure in a unit test, which is why the seam
// (and this stub) exist.
type stubLicensePolicyService struct {
	createErr error
	updateErr error
	policy    *model.LicensePolicy
}

func (s *stubLicensePolicyService) CreatePolicy(_ context.Context, _ service.CreateLicensePolicyInput) (*model.LicensePolicy, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	return s.policy, nil
}

func (s *stubLicensePolicyService) UpdatePolicy(_ context.Context, _ uuid.UUID, _ service.UpdateLicensePolicyInput) (*model.LicensePolicy, error) {
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	return s.policy, nil
}

func (s *stubLicensePolicyService) GetPolicy(_ context.Context, _ uuid.UUID) (*model.LicensePolicy, error) {
	return s.policy, nil
}

func (s *stubLicensePolicyService) ListByProject(_ context.Context, _ uuid.UUID) ([]model.LicensePolicy, error) {
	return nil, nil
}

func (s *stubLicensePolicyService) DeletePolicy(_ context.Context, _ uuid.UUID) error { return nil }

func (s *stubLicensePolicyService) CheckViolations(_ context.Context, _, _ uuid.UUID) ([]model.LicenseViolation, error) {
	return nil, nil
}

func (s *stubLicensePolicyService) GetCommonLicenses() map[string]string { return nil }

func driveCreateLicensePolicy(t *testing.T, h *LicensePolicyHandler, projectID uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"license_id": "MIT", "policy_type": "denied"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectID.String()+"/licenses",
		strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	if err := h.Create(c); err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}
	return rec
}

func driveUpdateLicensePolicy(t *testing.T, h *LicensePolicyHandler, policyID uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"policy_type": "denied"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+uuid.New().String()+"/licenses/"+policyID.String(),
		strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("policy_id")
	c.SetParamValues(policyID.String())
	if err := h.Update(c); err != nil {
		t.Fatalf("Update returned unexpected error: %v", err)
	}
	return rec
}

// ----------------------------------------------------------------------------
// F443 regression — Create/Update must not echo %w-wrapped DB errors at 400
// ----------------------------------------------------------------------------
//
// Before this fix, both Create and Update did a blanket
//   return c.JSON(http.StatusBadRequest, {"error": err.Error()})
// over a service error that MIXES self-authored validation feedback with
// %w-wrapped repository/DB errors. A DB failure therefore returned the wrong
// status (400 instead of 500) AND leaked the driver string. These tests pin
// the split: validation → 400 + message; internal → 500 + generic body,
// raw error kept out of the response. Pre-fix, BOTH cases were 400 + the
// raw error string — so the 500 / no-leak assertions are non-vacuous.

func TestLicensePolicyHandler_Create_ValidationError_Returns400_F443(t *testing.T) {
	h := &LicensePolicyHandler{licenseService: &stubLicensePolicyService{
		createErr: service.ValidationErrorf("policy already exists for license: %s", "MIT"),
	}}

	rec := driveCreateLicensePolicy(t, h, uuid.New())

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validation error must map to 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "policy already exists for license: MIT") {
		t.Errorf("400 body must echo the validation message, got %s", rec.Body.String())
	}
}

func TestLicensePolicyHandler_Create_InternalError_Returns500_NoLeak_F443(t *testing.T) {
	dbErr := errors.New("pq: FATAL: password authentication failed for user \"sbomhub\"")
	h := &LicensePolicyHandler{licenseService: &stubLicensePolicyService{
		// Exactly the shape service.CreatePolicy returns for a repo failure.
		createErr: fmt.Errorf("failed to create license policy: %w", dbErr),
	}}

	rec := driveCreateLicensePolicy(t, h, uuid.New())

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("F443: internal (%%w-wrapped DB) error must map to 500, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "failed to save license policy") {
		t.Errorf("F443: 500 body must be the generic message, got %s", body)
	}
	for _, leak := range []string{"pq:", "password authentication", "failed to create license policy"} {
		if strings.Contains(body, leak) {
			t.Errorf("F443: 500 body must not leak the raw error %q; got %s", leak, body)
		}
	}
}

func TestLicensePolicyHandler_Update_ValidationError_Returns400_F443(t *testing.T) {
	h := &LicensePolicyHandler{licenseService: &stubLicensePolicyService{
		updateErr: service.ValidationErrorf("invalid policy type: %s", "bogus"),
	}}

	rec := driveUpdateLicensePolicy(t, h, uuid.New())

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validation error must map to 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid policy type: bogus") {
		t.Errorf("400 body must echo the validation message, got %s", rec.Body.String())
	}
}

func TestLicensePolicyHandler_Update_InternalError_Returns500_NoLeak_F443(t *testing.T) {
	dbErr := errors.New("pq: deadlock detected")
	h := &LicensePolicyHandler{licenseService: &stubLicensePolicyService{
		updateErr: fmt.Errorf("failed to update license policy: %w", dbErr),
	}}

	rec := driveUpdateLicensePolicy(t, h, uuid.New())

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("F443: internal (%%w-wrapped DB) error must map to 500, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "failed to save license policy") {
		t.Errorf("F443: 500 body must be the generic message, got %s", body)
	}
	for _, leak := range []string{"pq:", "deadlock detected", "failed to update license policy"} {
		if strings.Contains(body, leak) {
			t.Errorf("F443: 500 body must not leak the raw error %q; got %s", leak, body)
		}
	}
}
