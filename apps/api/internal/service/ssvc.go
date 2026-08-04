package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// ErrSSVCVulnerabilityNotInProject is returned by AutoAssessVulnerability
// when the requested vulnerability does not exist or is not linked to any
// component of the caller's (tenant, project) — deliberately one sentinel
// for both cases so the handler's 404 cannot be used to probe for the
// existence of vulnerabilities outside the caller's scope.
var ErrSSVCVulnerabilityNotInProject = errors.New("vulnerability not found in project scope")

// ErrSSVCAssessmentNotInProject is the same one-sentinel-for-both-cases
// treatment for an assessment id: the row does not exist, or it belongs to a
// different (tenant, project) than the caller's. Handler maps it to 404.
var ErrSSVCAssessmentNotInProject = errors.New("assessment not found in project scope")

// SSVCService handles SSVC assessment operations.
//
// Where a decision lives (M47 W4). The authoritative record of an SSVC
// decision is the ssvc_assessments row keyed by (tenant_id, project_id,
// vulnerability_id) — migration 021 gives it UNIQUE(project_id,
// vulnerability_id), a tenant_id column, RLS tenant isolation and an index on
// `decision`. An SSVC decision is inherently project-specific: the tree is
// evaluated from that project's mission prevalence, safety impact and system
// exposure, so two projects can legitimately reach different decisions for
// the same CVE.
//
// Until M47 W4 both entry points ALSO stamped the computed decision onto
// `vulnerabilities.ssvc_decision`. `vulnerabilities` is the shared, tenant-less
// CVE catalogue (001_init declares no tenant_id; it is a recorded RLS
// exemption), so that column held whichever tenant assessed the CVE most
// recently — every subsequent assessment silently overwrote every other
// tenant's, and bumped the shared row's updated_at while doing it. Migration
// 062 drops the column; nothing reads it any more, so there is no projection
// to maintain and no read path changed.
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

// AssessVulnerability creates or updates an SSVC assessment.
//
// M46 Codex final round (Medium #1, second route): like
// AutoAssessVulnerability below, the CVE id is derived SERVER-SIDE from
// vulnerabilityID and never accepted from the caller. 9704eb9 closed only
// the auto-assess route; this one still took a caller-supplied cveID (the
// handler forwarded ?cve_id= verbatim) and never checked that
// vulnerabilityID belonged to the caller's (tenant, project) at all, so an
// authenticated tenant could POST a known vulnerability UUID that is not
// linked to any of its components together with an arbitrary CVE and get a
// 200 that (a) minted an ssvc_assessments row pairing the vulnerability with
// the WRONG cve_id — the key GetAssessmentByCVE, the VEX/report joins and
// every operator reading the row rely on — and (b) wrote the GLOBAL
// vulnerabilities.ssvc_decision column for a vulnerability outside its
// scope (that second write no longer exists: M47 W4 removed it and
// migration 062 dropped the column). GetCVEIDByIDInProject re-resolves the
// authoritative CVE and
// verifies (tenant, project, vulnerability) membership in one statement;
// unknown and out-of-scope ids collapse into the same
// ErrSSVCVulnerabilityNotInProject sentinel (handler: 404) before anything
// is read or written, so the response cannot be used to probe for
// vulnerabilities the caller cannot see. Identical posture to auto-assess,
// and it lives in the service so every future caller inherits it.
func (s *SSVCService) AssessVulnerability(ctx context.Context, projectID, tenantID, vulnerabilityID uuid.UUID, input model.SSVCAssessmentInput, assessedBy *uuid.UUID) (*model.SSVCAssessment, error) {
	cveID, err := s.vulnRepo.GetCVEIDByIDInProject(ctx, tenantID, projectID, vulnerabilityID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSSVCVulnerabilityNotInProject
		}
		return nil, fmt.Errorf("resolve cve for vulnerability %s: %w", vulnerabilityID, err)
	}

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
			// Don't fail the assessment over the auxiliary audit trail, but
			// never swallow it silently: a lost history row means the
			// decision-change audit trail has a hole operators should see.
			slog.Error("ssvc: failed to record assessment history; decision-change audit trail is incomplete",
				"vulnerability_id", vulnerabilityID, "cve_id", cveID, "error", err)
		}

		// Update existing assessment. CVEID is re-stamped from the
		// server-derived value so a row minted before the Medium #1 fix (or
		// by any writer that trusted a caller-supplied cve_id) is REPAIRED on
		// the next assessment instead of keeping a mispaired CVE forever —
		// UpdateAssessment persists the column for exactly this reason.
		existing.CVEID = cveID
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

	return assessment, nil
}

// AutoAssessVulnerability automatically assesses a vulnerability using KEV/EPSS data.
//
// M46 Codex final round (Medium #1): the CVE id is derived SERVER-SIDE from
// vulnerabilityID — never accepted from the caller. The pre-fix signature
// took a caller-supplied cveID (the handler forwarded ?cve_id= verbatim)
// and keyed every piece of evidence on it (KEV GetByCVE, EPSS/CVSS via
// vulnRepo.GetByCVE) while writing the assessment (and, until M47 W4, the
// denormalized vulnerabilities.ssvc_decision) under vulnerabilityID — so a
// caller could have vulnerability A assessed on vulnerability B's
// KEV/EPSS/CVSS. The
// EPSS branch was dead code (EPSSScore always nil through GetByCVE) until
// def6a46 added the epss_* columns to that read, which is what made this
// path actually exploitable. GetCVEIDByIDInProject resolves the
// authoritative CVE and verifies (tenant, project, vulnerability)
// membership through the RLS-protected components/sboms join in one
// statement; out-of-scope or unknown ids surface as
// ErrSSVCVulnerabilityNotInProject (handler: 404) before anything is
// read or written. The binding lives here in the service (not the
// handler) so every future caller of auto-assess inherits it, mirroring
// the triage runner's resolveAuthoritativeCVEID / resolveComponentIDs
// posture (#F12 / #F3).
func (s *SSVCService) AutoAssessVulnerability(ctx context.Context, projectID, tenantID, vulnerabilityID uuid.UUID) (*model.SSVCAssessment, error) {
	cveID, err := s.vulnRepo.GetCVEIDByIDInProject(ctx, tenantID, projectID, vulnerabilityID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSSVCVulnerabilityNotInProject
		}
		return nil, fmt.Errorf("resolve cve for vulnerability %s: %w", vulnerabilityID, err)
	}

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

	// Determine technical impact from CVSS score. M46 B2: CVSSScore is
	// nil for un-scored CVEs; those keep the Partial default rather than
	// being treated as 0.0.
	technicalImpact := model.SSVCTechnicalImpactPartial
	if vuln != nil && vuln.CVSSScore != nil && *vuln.CVSSScore >= 7.0 {
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

// DeleteAssessment deletes an assessment that belongs to the caller's
// (tenant, project). M46 Codex final round (Medium #1, route sweep): the
// pre-fix signature took only the assessment id and forwarded it to an
// unscoped DELETE, so the project segment of the route was decorative and a
// miss was indistinguishable from a success. Unknown and out-of-scope ids
// collapse into one sentinel (handler: 404) for the same anti-probing reason
// as ErrSSVCVulnerabilityNotInProject.
func (s *SSVCService) DeleteAssessment(ctx context.Context, projectID, tenantID, id uuid.UUID) error {
	deleted, err := s.ssvcRepo.DeleteAssessment(ctx, projectID, tenantID, id)
	if err != nil {
		return err
	}
	if !deleted {
		return ErrSSVCAssessmentNotInProject
	}
	return nil
}

// GetAssessmentHistory gets history for an assessment in the caller's
// (tenant, project).
//
// M50: this used to answer an empty history for an id that does not exist,
// belongs to a sibling project, or belongs to another tenant. That was
// probe-proof — all three were the same answer — but it was the WRONG member
// of the pair, and the only sub-resource route in the api that picked it:
// ssvc DELETE, cra-reports, vex-drafts, scan-status, vex, licenses and the
// components paths all collapse unknown + not-yours into 404. Worse, `200 []`
// collapses a FOURTH case that the others keep distinct — "your assessment,
// which has simply never changed" — so a correct empty answer and a refusal
// were the same bytes.
//
// The scoped existence check separates exactly those two and nothing else:
//
//	not in (tenant, project) -> ErrSSVCAssessmentNotInProject (handler: 404),
//	                            one sentinel for unknown / sibling / foreign
//	in scope, no changes yet -> nil, empty slice (handler: 200 [])
//
// Cost: one extra indexed PK lookup, inside the request's TenantTx (the route
// sits behind appmw.TenantTx, so both statements share one transaction and
// one tenant binding — this is not a check-then-use across connections).
func (s *SSVCService) GetAssessmentHistory(ctx context.Context, projectID, tenantID, assessmentID uuid.UUID) ([]model.SSVCAssessmentHistory, error) {
	inScope, err := s.ssvcRepo.AssessmentInProject(ctx, projectID, tenantID, assessmentID)
	if err != nil {
		return nil, err
	}
	if !inScope {
		return nil, ErrSSVCAssessmentNotInProject
	}
	return s.ssvcRepo.GetAssessmentHistory(ctx, projectID, tenantID, assessmentID)
}

// GetImmediateAssessments gets all assessments requiring immediate action
func (s *SSVCService) GetImmediateAssessments(ctx context.Context) ([]model.SSVCAssessmentWithVuln, error) {
	return s.ssvcRepo.GetImmediateAssessments(ctx)
}
