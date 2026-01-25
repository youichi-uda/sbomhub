package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type LicensePolicyService struct {
	policyRepo    *repository.LicensePolicyRepository
	componentRepo *repository.ComponentRepository
}

func NewLicensePolicyService(policyRepo *repository.LicensePolicyRepository, componentRepo *repository.ComponentRepository) *LicensePolicyService {
	return &LicensePolicyService{
		policyRepo:    policyRepo,
		componentRepo: componentRepo,
	}
}

type CreateLicensePolicyInput struct {
	ProjectID   uuid.UUID               `json:"project_id"`
	LicenseID   string                  `json:"license_id"`
	LicenseName string                  `json:"license_name"`
	PolicyType  model.LicensePolicyType `json:"policy_type"`
	Reason      string                  `json:"reason,omitempty"`
}

func (s *LicensePolicyService) CreatePolicy(ctx context.Context, input CreateLicensePolicyInput) (*model.LicensePolicy, error) {
	// Validate policy type
	if !isValidPolicyType(input.PolicyType) {
		return nil, fmt.Errorf("invalid policy type: %s", input.PolicyType)
	}

	// Check if policy already exists
	existing, err := s.policyRepo.GetByLicenseID(ctx, input.ProjectID, input.LicenseID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing policy: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("policy already exists for license: %s", input.LicenseID)
	}

	// Use common license name if available
	licenseName := input.LicenseName
	if licenseName == "" {
		if name, ok := model.CommonLicenses[input.LicenseID]; ok {
			licenseName = name
		} else {
			licenseName = input.LicenseID
		}
	}

	now := time.Now()
	policy := &model.LicensePolicy{
		ID:          uuid.New(),
		ProjectID:   input.ProjectID,
		LicenseID:   input.LicenseID,
		LicenseName: licenseName,
		PolicyType:  input.PolicyType,
		Reason:      input.Reason,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.policyRepo.Create(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create license policy: %w", err)
	}

	return policy, nil
}

type UpdateLicensePolicyInput struct {
	PolicyType model.LicensePolicyType `json:"policy_type"`
	Reason     string                  `json:"reason,omitempty"`
}

func (s *LicensePolicyService) UpdatePolicy(ctx context.Context, id uuid.UUID, input UpdateLicensePolicyInput) (*model.LicensePolicy, error) {
	policy, err := s.policyRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get license policy: %w", err)
	}
	if policy == nil {
		return nil, fmt.Errorf("license policy not found")
	}

	// Validate policy type
	if !isValidPolicyType(input.PolicyType) {
		return nil, fmt.Errorf("invalid policy type: %s", input.PolicyType)
	}

	policy.PolicyType = input.PolicyType
	policy.Reason = input.Reason
	policy.UpdatedAt = time.Now()

	if err := s.policyRepo.Update(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to update license policy: %w", err)
	}

	return policy, nil
}

func (s *LicensePolicyService) GetPolicy(ctx context.Context, id uuid.UUID) (*model.LicensePolicy, error) {
	return s.policyRepo.GetByID(ctx, id)
}

func (s *LicensePolicyService) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.LicensePolicy, error) {
	return s.policyRepo.ListByProject(ctx, projectID)
}

func (s *LicensePolicyService) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	return s.policyRepo.Delete(ctx, id)
}

// CheckViolations checks components in an SBOM against license policies
func (s *LicensePolicyService) CheckViolations(ctx context.Context, projectID uuid.UUID, sbomID uuid.UUID) ([]model.LicenseViolation, error) {
	// Get all components for the SBOM
	components, err := s.componentRepo.ListBySbom(ctx, sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get components: %w", err)
	}

	// Collect unique license IDs
	licenseSet := make(map[string]bool)
	for _, c := range components {
		if c.License != "" {
			// Normalize license ID
			normalized := normalizeLicenseID(c.License)
			licenseSet[normalized] = true
		}
	}

	licenseIDs := make([]string, 0, len(licenseSet))
	for id := range licenseSet {
		licenseIDs = append(licenseIDs, id)
	}

	// Get policies for these licenses
	policies, err := s.policyRepo.GetPoliciesForLicenses(ctx, projectID, licenseIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}

	// Check each component against policies
	var violations []model.LicenseViolation
	for _, c := range components {
		if c.License == "" {
			continue
		}

		normalized := normalizeLicenseID(c.License)
		policy, exists := policies[normalized]
		if !exists {
			continue // No policy for this license
		}

		// Only report violations for denied or review policies
		if policy.PolicyType == model.LicensePolicyDenied || policy.PolicyType == model.LicensePolicyReview {
			violations = append(violations, model.LicenseViolation{
				ComponentID:   c.ID,
				ComponentName: c.Name,
				Version:       c.Version,
				License:       c.License,
				PolicyType:    policy.PolicyType,
				Reason:        policy.Reason,
			})
		}
	}

	return violations, nil
}

// GetCommonLicenses returns a list of common SPDX license identifiers
func (s *LicensePolicyService) GetCommonLicenses() map[string]string {
	return model.CommonLicenses
}

func isValidPolicyType(pt model.LicensePolicyType) bool {
	switch pt {
	case model.LicensePolicyAllowed, model.LicensePolicyDenied, model.LicensePolicyReview:
		return true
	default:
		return false
	}
}

// normalizeLicenseID normalizes a license string to SPDX format
func normalizeLicenseID(license string) string {
	// Simple normalization - remove extra spaces and convert to standard format
	license = strings.TrimSpace(license)

	// Common mappings
	mappings := map[string]string{
		"MIT License":     "MIT",
		"Apache 2.0":      "Apache-2.0",
		"Apache 2":        "Apache-2.0",
		"Apache-2":        "Apache-2.0",
		"GPL-2.0":         "GPL-2.0-only",
		"GPL-3.0":         "GPL-3.0-only",
		"LGPL-2.1":        "LGPL-2.1-only",
		"LGPL-3.0":        "LGPL-3.0-only",
		"BSD 2-Clause":    "BSD-2-Clause",
		"BSD 3-Clause":    "BSD-3-Clause",
		"BSD-2":           "BSD-2-Clause",
		"BSD-3":           "BSD-3-Clause",
		"CC0":             "CC0-1.0",
		"Creative Commons Zero": "CC0-1.0",
	}

	if normalized, ok := mappings[license]; ok {
		return normalized
	}

	return license
}
