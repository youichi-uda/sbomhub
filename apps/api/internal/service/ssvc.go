package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// SSVCService handles SSVC assessment operations
type SSVCService struct {
	ssvcRepo *repository.SSVCRepository
	vulnRepo *repository.VulnerabilityRepository
	kevRepo  *repository.KEVRepository
}

// NewSSVCService creates a new SSVCService
func NewSSVCService(ssvcRepo *repository.SSVCRepository, vulnRepo *repository.VulnerabilityRepository, kevRepo *repository.KEVRepository) *SSVCService {
	return &SSVCService{
		ssvcRepo: ssvcRepo,
		vulnRepo: vulnRepo,
		kevRepo:  kevRepo,
	}
}

// GetProjectDefaults gets SSVC defaults for a project
func (s *SSVCService) GetProjectDefaults(ctx context.Context, projectID uuid.UUID) (*model.SSVCProjectDefaults, error) {
	return s.ssvcRepo.GetProjectDefaults(ctx, projectID)
}

// UpdateProjectDefaults creates or updates project defaults
func (s *SSVCService) UpdateProjectDefaults(ctx context.Context, projectID, tenantID uuid.UUID, input UpdateSSVCDefaultsInput) (*model.SSVCProjectDefaults, error) {
	defaults := &model.SSVCProjectDefaults{
		ID:                     uuid.New(),
		ProjectID:              projectID,
		TenantID:               tenantID,
		MissionPrevalence:      input.MissionPrevalence,
		SafetyImpact:           input.SafetyImpact,
		SystemExposure:         input.SystemExposure,
		AutoAssessEnabled:      input.AutoAssessEnabled,
		AutoAssessExploitation: input.AutoAssessExploitation,
		AutoAssessAutomatable:  input.AutoAssessAutomatable,
	}

	if err := s.ssvcRepo.UpsertProjectDefaults(ctx, defaults); err != nil {
		return nil, err
	}

	return s.ssvcRepo.GetProjectDefaults(ctx, projectID)
}

// UpdateSSVCDefaultsInput represents input for updating SSVC defaults
type UpdateSSVCDefaultsInput struct {
	MissionPrevalence      model.SSVCMissionPrevalence `json:"mission_prevalence"`
	SafetyImpact           model.SSVCSafetyImpact      `json:"safety_impact"`
	SystemExposure         string                      `json:"system_exposure"`
	AutoAssessEnabled      bool                        `json:"auto_assess_enabled"`
	AutoAssessExploitation bool                        `json:"auto_assess_exploitation"`
	AutoAssessAutomatable  bool                        `json:"auto_assess_automatable"`
}

// AssessVulnerability creates or updates an SSVC assessment
func (s *SSVCService) AssessVulnerability(ctx context.Context, projectID, tenantID, vulnerabilityID uuid.UUID, cveID string, input model.SSVCAssessmentInput, assessedBy *uuid.UUID) (*model.SSVCAssessment, error) {
	// Calculate decision using SSVC decision tree
	decision := s.CalculateDecision(input.Exploitation, input.Automatable, input.TechnicalImpact, input.MissionPrevalence, input.SafetyImpact)

	// Check if assessment already exists
	existing, err := s.ssvcRepo.GetAssessment(ctx, projectID, vulnerabilityID)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	if existing != nil {
		// Create history entry for the change
		history := &model.SSVCAssessmentHistory{
			ID:                    uuid.New(),
			AssessmentID:          existing.ID,
			PrevExploitation:      &existing.Exploitation,
			PrevAutomatable:       &existing.Automatable,
			PrevTechnicalImpact:   &existing.TechnicalImpact,
			PrevMissionPrevalence: &existing.MissionPrevalence,
			PrevSafetyImpact:      &existing.SafetyImpact,
			PrevDecision:          &existing.Decision,
			NewExploitation:       input.Exploitation,
			NewAutomatable:        input.Automatable,
			NewTechnicalImpact:    input.TechnicalImpact,
			NewMissionPrevalence:  input.MissionPrevalence,
			NewSafetyImpact:       input.SafetyImpact,
			NewDecision:           decision,
			ChangedBy:             assessedBy,
			ChangedAt:             now,
		}
		if err := s.ssvcRepo.CreateAssessmentHistory(ctx, history); err != nil {
			// Log but don't fail
		}

		// Update existing assessment
		existing.Exploitation = input.Exploitation
		existing.Automatable = input.Automatable
		existing.TechnicalImpact = input.TechnicalImpact
		existing.MissionPrevalence = input.MissionPrevalence
		existing.SafetyImpact = input.SafetyImpact
		existing.Decision = decision
		existing.ExploitationAuto = false
		existing.AutomatableAuto = false
		existing.AssessedBy = assessedBy
		existing.AssessedAt = now
		existing.Notes = input.Notes

		if err := s.ssvcRepo.UpdateAssessment(ctx, existing); err != nil {
			return nil, err
		}

		// Update vulnerability SSVC decision
		s.ssvcRepo.UpdateVulnerabilitySSVCDecision(ctx, vulnerabilityID, decision)

		return existing, nil
	}

	// Create new assessment
	assessment := &model.SSVCAssessment{
		ID:                uuid.New(),
		ProjectID:         projectID,
		TenantID:          tenantID,
		VulnerabilityID:   vulnerabilityID,
		CVEID:             cveID,
		Exploitation:      input.Exploitation,
		Automatable:       input.Automatable,
		TechnicalImpact:   input.TechnicalImpact,
		MissionPrevalence: input.MissionPrevalence,
		SafetyImpact:      input.SafetyImpact,
		Decision:          decision,
		ExploitationAuto:  false,
		AutomatableAuto:   false,
		AssessedBy:        assessedBy,
		AssessedAt:        now,
		Notes:             input.Notes,
	}

	if err := s.ssvcRepo.CreateAssessment(ctx, assessment); err != nil {
		return nil, err
	}

	// Update vulnerability SSVC decision
	s.ssvcRepo.UpdateVulnerabilitySSVCDecision(ctx, vulnerabilityID, decision)

	return assessment, nil
}

// AutoAssessVulnerability automatically assesses a vulnerability using KEV/EPSS data
func (s *SSVCService) AutoAssessVulnerability(ctx context.Context, projectID, tenantID, vulnerabilityID uuid.UUID, cveID string) (*model.SSVCAssessment, error) {
	// Get project defaults
	defaults, err := s.ssvcRepo.GetProjectDefaults(ctx, projectID)
	if err != nil {
		return nil, err
	}

	// Default values if no project defaults exist
	missionPrevalence := model.SSVCMissionPrevalenceSupport
	safetyImpact := model.SSVCSafetyImpactMinimal
	if defaults != nil {
		missionPrevalence = defaults.MissionPrevalence
		safetyImpact = defaults.SafetyImpact
	}

	// Determine exploitation status from KEV
	exploitation := model.SSVCExploitationNone
	exploitationAuto := false
	if s.kevRepo != nil {
		kevEntry, _ := s.kevRepo.GetByCVE(ctx, cveID)
		if kevEntry != nil {
			exploitation = model.SSVCExploitationActive
			exploitationAuto = true
		}
	}

	// Determine automatable from EPSS score
	automatable := model.SSVCAutomatableNo
	automatableAuto := false
	vuln, _ := s.vulnRepo.GetByCVE(ctx, cveID)
	if vuln != nil && vuln.EPSSScore != nil {
		// High EPSS score (>0.5) suggests automation is likely
		if *vuln.EPSSScore > 0.5 {
			automatable = model.SSVCAutomatableYes
			automatableAuto = true
		}
	}

	// Determine technical impact from CVSS score
	technicalImpact := model.SSVCTechnicalImpactPartial
	if vuln != nil && vuln.CVSSScore >= 7.0 {
		technicalImpact = model.SSVCTechnicalImpactTotal
	}

	// Calculate decision
	decision := s.CalculateDecision(exploitation, automatable, technicalImpact, missionPrevalence, safetyImpact)

	// Check if assessment already exists
	existing, _ := s.ssvcRepo.GetAssessment(ctx, projectID, vulnerabilityID)
	if existing != nil {
		// Don't overwrite manual assessments
		if !existing.ExploitationAuto && !existing.AutomatableAuto {
			return existing, nil
		}
	}

	now := time.Now()

	assessment := &model.SSVCAssessment{
		ID:                uuid.New(),
		ProjectID:         projectID,
		TenantID:          tenantID,
		VulnerabilityID:   vulnerabilityID,
		CVEID:             cveID,
		Exploitation:      exploitation,
		Automatable:       automatable,
		TechnicalImpact:   technicalImpact,
		MissionPrevalence: missionPrevalence,
		SafetyImpact:      safetyImpact,
		Decision:          decision,
		ExploitationAuto:  exploitationAuto,
		AutomatableAuto:   automatableAuto,
		AssessedAt:        now,
		Notes:             "Auto-assessed based on KEV/EPSS data",
	}

	if existing != nil {
		assessment.ID = existing.ID
		if err := s.ssvcRepo.UpdateAssessment(ctx, assessment); err != nil {
			return nil, err
		}
	} else {
		if err := s.ssvcRepo.CreateAssessment(ctx, assessment); err != nil {
			return nil, err
		}
	}

	// Update vulnerability SSVC decision
	s.ssvcRepo.UpdateVulnerabilitySSVCDecision(ctx, vulnerabilityID, decision)

	return assessment, nil
}

// CalculateDecision implements the SSVC decision tree for Deployers
// Based on CISA SSVC version 2.0
func (s *SSVCService) CalculateDecision(
	exploitation model.SSVCExploitation,
	automatable model.SSVCAutomatable,
	technicalImpact model.SSVCTechnicalImpact,
	missionPrevalence model.SSVCMissionPrevalence,
	safetyImpact model.SSVCSafetyImpact,
) model.SSVCDecision {
	// Active exploitation always leads to higher priority
	if exploitation == model.SSVCExploitationActive {
		// Active + significant safety impact = Immediate
		if safetyImpact == model.SSVCSafetyImpactSignificant {
			return model.SSVCDecisionImmediate
		}
		// Active + essential mission = Immediate
		if missionPrevalence == model.SSVCMissionPrevalenceEssential {
			return model.SSVCDecisionImmediate
		}
		// Active + total impact + support mission = Out of Cycle
		if technicalImpact == model.SSVCTechnicalImpactTotal && missionPrevalence == model.SSVCMissionPrevalenceSupport {
			return model.SSVCDecisionOutOfCycle
		}
		// Active + automatable = Out of Cycle
		if automatable == model.SSVCAutomatableYes {
			return model.SSVCDecisionOutOfCycle
		}
		// Active but lower risk = Scheduled
		return model.SSVCDecisionScheduled
	}

	// PoC exists
	if exploitation == model.SSVCExploitationPoC {
		// PoC + significant safety = Out of Cycle
		if safetyImpact == model.SSVCSafetyImpactSignificant {
			return model.SSVCDecisionOutOfCycle
		}
		// PoC + essential mission + total impact = Out of Cycle
		if missionPrevalence == model.SSVCMissionPrevalenceEssential && technicalImpact == model.SSVCTechnicalImpactTotal {
			return model.SSVCDecisionOutOfCycle
		}
		// PoC + automatable + total impact = Scheduled
		if automatable == model.SSVCAutomatableYes && technicalImpact == model.SSVCTechnicalImpactTotal {
			return model.SSVCDecisionScheduled
		}
		// PoC + support/essential mission = Scheduled
		if missionPrevalence != model.SSVCMissionPrevalenceMinimal {
			return model.SSVCDecisionScheduled
		}
		// PoC but minimal impact = Defer
		return model.SSVCDecisionDefer
	}

	// No known exploitation
	// Significant safety impact still warrants attention
	if safetyImpact == model.SSVCSafetyImpactSignificant {
		if technicalImpact == model.SSVCTechnicalImpactTotal {
			return model.SSVCDecisionScheduled
		}
	}

	// Essential mission with high impact
	if missionPrevalence == model.SSVCMissionPrevalenceEssential && technicalImpact == model.SSVCTechnicalImpactTotal {
		return model.SSVCDecisionScheduled
	}

	// Automatable with high impact
	if automatable == model.SSVCAutomatableYes && technicalImpact == model.SSVCTechnicalImpactTotal {
		if missionPrevalence != model.SSVCMissionPrevalenceMinimal {
			return model.SSVCDecisionScheduled
		}
	}

	// Default to defer for low-risk vulnerabilities
	return model.SSVCDecisionDefer
}

// GetAssessment gets an assessment by project and vulnerability
func (s *SSVCService) GetAssessment(ctx context.Context, projectID, vulnerabilityID uuid.UUID) (*model.SSVCAssessment, error) {
	return s.ssvcRepo.GetAssessment(ctx, projectID, vulnerabilityID)
}

// GetAssessmentByCVE gets an assessment by project and CVE ID
func (s *SSVCService) GetAssessmentByCVE(ctx context.Context, projectID uuid.UUID, cveID string) (*model.SSVCAssessment, error) {
	return s.ssvcRepo.GetAssessmentByCVE(ctx, projectID, cveID)
}

// ListAssessments lists assessments for a project
func (s *SSVCService) ListAssessments(ctx context.Context, projectID uuid.UUID, decision *model.SSVCDecision, limit, offset int) ([]model.SSVCAssessmentWithVuln, int, error) {
	return s.ssvcRepo.ListAssessments(ctx, projectID, decision, limit, offset)
}

// GetSummary gets assessment summary for a project
func (s *SSVCService) GetSummary(ctx context.Context, projectID uuid.UUID) (*model.SSVCSummary, error) {
	return s.ssvcRepo.GetSummary(ctx, projectID)
}

// DeleteAssessment deletes an assessment
func (s *SSVCService) DeleteAssessment(ctx context.Context, id uuid.UUID) error {
	return s.ssvcRepo.DeleteAssessment(ctx, id)
}

// GetAssessmentHistory gets history for an assessment
func (s *SSVCService) GetAssessmentHistory(ctx context.Context, assessmentID uuid.UUID) ([]model.SSVCAssessmentHistory, error) {
	return s.ssvcRepo.GetAssessmentHistory(ctx, assessmentID)
}

// GetImmediateAssessments gets all assessments requiring immediate action
func (s *SSVCService) GetImmediateAssessments(ctx context.Context) ([]model.SSVCAssessmentWithVuln, error) {
	return s.ssvcRepo.GetImmediateAssessments(ctx)
}
