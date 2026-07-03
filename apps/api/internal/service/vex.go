package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type VEXService struct {
	vexRepo  *repository.VEXRepository
	vulnRepo *repository.VulnerabilityRepository
}

func NewVEXService(vexRepo *repository.VEXRepository, vulnRepo *repository.VulnerabilityRepository) *VEXService {
	return &VEXService{
		vexRepo:  vexRepo,
		vulnRepo: vulnRepo,
	}
}

type CreateVEXStatementInput struct {
	ProjectID       uuid.UUID              `json:"project_id"`
	VulnerabilityID uuid.UUID              `json:"vulnerability_id"`
	ComponentID     *uuid.UUID             `json:"component_id,omitempty"`
	Status          model.VEXStatus        `json:"status"`
	Justification   model.VEXJustification `json:"justification,omitempty"`
	ActionStatement string                 `json:"action_statement,omitempty"`
	ImpactStatement string                 `json:"impact_statement,omitempty"`
	CreatedBy       string                 `json:"created_by"`
}

func (s *VEXService) CreateStatement(ctx context.Context, input CreateVEXStatementInput) (*model.VEXStatement, error) {
	// Validate status
	if !isValidStatus(input.Status) {
		return nil, fmt.Errorf("invalid VEX status: %s", input.Status)
	}

	// Validate justification if status is not_affected
	if input.Status == model.VEXStatusNotAffected && input.Justification == "" {
		return nil, fmt.Errorf("justification is required when status is not_affected")
	}

	// Check if statement already exists
	existing, err := s.vexRepo.GetByProjectAndVulnerability(ctx, input.ProjectID, input.VulnerabilityID, input.ComponentID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing statement: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("VEX statement already exists for this vulnerability")
	}

	// Resolve the tenant_id of the parent project so the INSERT satisfies
	// the FORCE RLS WITH CHECK clause on vex_statements (see migration 023).
	tenantID, err := s.vexRepo.LookupProjectTenantID(ctx, input.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve project tenant: %w", err)
	}

	now := time.Now()
	statement := &model.VEXStatement{
		ID:              uuid.New(),
		TenantID:        tenantID,
		ProjectID:       input.ProjectID,
		VulnerabilityID: input.VulnerabilityID,
		ComponentID:     input.ComponentID,
		Status:          input.Status,
		Justification:   input.Justification,
		ActionStatement: input.ActionStatement,
		ImpactStatement: input.ImpactStatement,
		CreatedBy:       input.CreatedBy,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := s.vexRepo.Create(ctx, statement); err != nil {
		return nil, fmt.Errorf("failed to create VEX statement: %w", err)
	}

	return statement, nil
}

type UpdateVEXStatementInput struct {
	Status          model.VEXStatus        `json:"status"`
	Justification   model.VEXJustification `json:"justification,omitempty"`
	ActionStatement string                 `json:"action_statement,omitempty"`
	ImpactStatement string                 `json:"impact_statement,omitempty"`
}

func (s *VEXService) UpdateStatement(ctx context.Context, id uuid.UUID, input UpdateVEXStatementInput) (*model.VEXStatement, error) {
	statement, err := s.vexRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get VEX statement: %w", err)
	}
	if statement == nil {
		return nil, fmt.Errorf("VEX statement not found")
	}

	// Validate status
	if !isValidStatus(input.Status) {
		return nil, fmt.Errorf("invalid VEX status: %s", input.Status)
	}

	// Validate justification if status is not_affected
	if input.Status == model.VEXStatusNotAffected && input.Justification == "" {
		return nil, fmt.Errorf("justification is required when status is not_affected")
	}

	statement.Status = input.Status
	statement.Justification = input.Justification
	statement.ActionStatement = input.ActionStatement
	statement.ImpactStatement = input.ImpactStatement
	statement.UpdatedAt = time.Now()

	if err := s.vexRepo.Update(ctx, statement); err != nil {
		return nil, fmt.Errorf("failed to update VEX statement: %w", err)
	}

	return statement, nil
}

func (s *VEXService) GetStatement(ctx context.Context, id uuid.UUID) (*model.VEXStatement, error) {
	return s.vexRepo.GetByID(ctx, id)
}

func (s *VEXService) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.VEXStatementWithDetails, error) {
	return s.vexRepo.ListByProject(ctx, projectID)
}

// GetSuggestions returns cross-project VEX reuse suggestions for the
// target project (M26-A / F375, issue #130): approved vex_statements from
// OTHER projects of the same tenant that match a vulnerability affecting
// this project's components. Read-only Phase 1 — no apply action.
//
// The repository owns the tenant boundary + the purl / vulnerability match
// join (and it deliberately returns self-project candidates + a
// target_already_triaged flag rather than pre-filtering them). This method
// applies the two business exclusions — self-project and already-triaged —
// via assembleSuggestions, which is a pure function so the exclusion logic
// is unit-testable without a live DB.
func (s *VEXService) GetSuggestions(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.VEXSuggestion, error) {
	candidates, err := s.vexRepo.ListCrossProjectVEXCandidates(ctx, tenantID, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list cross-project VEX candidates: %w", err)
	}
	return assembleSuggestions(candidates, projectID), nil
}

// assembleSuggestions applies the two cross-project VEX business rules to
// the raw candidate rows and maps survivors into the response shape:
//
//   - self-project exclusion: a candidate whose source project IS the
//     target project is dropped. The SQL query does not exclude self, so
//     this Go guard is the load-bearing filter (and its unit test pins it);
//     it is also defence-in-depth should the query ever be widened.
//   - already-triaged exclusion: a candidate the target has already ruled
//     on (target_already_triaged) is dropped so the endpoint only surfaces
//     NEW reuse opportunities, not decisions already made.
//
// match_type is derived from whether the source statement was
// component-specific (purl) or component-agnostic (vulnerability_only).
//
// The returned slice is always non-nil so the handler serialises `[]`
// rather than `null` for the empty case.
func assembleSuggestions(candidates []model.VEXSuggestionCandidate, targetProjectID uuid.UUID) []model.VEXSuggestion {
	out := make([]model.VEXSuggestion, 0, len(candidates))
	for _, c := range candidates {
		if c.SourceProjectID == targetProjectID {
			continue // self-project: not a cross-project suggestion
		}
		if c.TargetAlreadyTriaged {
			continue // target already decided this (vuln, component)
		}

		matchType := model.VEXMatchTypeVulnerabilityOnly
		if c.SourceComponentID != nil {
			matchType = model.VEXMatchTypePurl
		}

		out = append(out, model.VEXSuggestion{
			VulnerabilityID: c.VulnerabilityID,
			CVEID:           c.CVEID,
			Component: model.VEXSuggestionComponent{
				// TargetComponentID (the target project's components.id, set from
				// the ta.component_id column of ListCrossProjectVEXCandidates) —
				// NOT SourceComponentID. This is what makes each suggestion row
				// uniquely addressable when a single source fans out across
				// several target components (F377, issue #131).
				ComponentID: c.TargetComponentID,
				Name:        c.ComponentName,
				Version:     c.ComponentVersion,
				Purl:        c.ComponentPurl,
			},
			MatchType: matchType,
			Source: model.VEXSuggestionSource{
				ProjectID:       c.SourceProjectID,
				ProjectName:     c.SourceProjectName,
				StatementID:     c.StatementID,
				Status:          c.Status,
				Justification:   c.Justification,
				ImpactStatement: c.ImpactStatement,
				ActionStatement: c.ActionStatement,
				CreatedAt:       c.CreatedAt,
			},
		})
	}
	return out
}

func (s *VEXService) DeleteStatement(ctx context.Context, id uuid.UUID) error {
	return s.vexRepo.Delete(ctx, id)
}

// ExportCycloneDXVEX exports VEX statements in CycloneDX VEX format
func (s *VEXService) ExportCycloneDXVEX(ctx context.Context, projectID uuid.UUID) ([]byte, error) {
	statements, err := s.vexRepo.ListByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list VEX statements: %w", err)
	}

	// Build CycloneDX VEX document
	vexDoc := CycloneDXVEX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: VEXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []VEXTool{
				{
					Vendor:  "SBOMHub",
					Name:    "SBOMHub",
					Version: "1.0.0",
				},
			},
		},
		Vulnerabilities: make([]VEXVulnerability, 0, len(statements)),
	}

	for _, stmt := range statements {
		vuln := VEXVulnerability{
			ID:     stmt.VulnerabilityCVEID,
			Source: VEXSource{Name: "NVD"},
			Analysis: VEXAnalysis{
				State:         mapStatusToCycloneDX(stmt.Status),
				Justification: mapJustificationToCycloneDX(stmt.Justification),
				Response:      []string{},
				Detail:        stmt.ImpactStatement,
			},
		}
		if stmt.ActionStatement != "" {
			vuln.Analysis.Response = append(vuln.Analysis.Response, stmt.ActionStatement)
		}
		vexDoc.Vulnerabilities = append(vexDoc.Vulnerabilities, vuln)
	}

	return json.MarshalIndent(vexDoc, "", "  ")
}

// CycloneDX VEX structures
type CycloneDXVEX struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Version         int                `json:"version"`
	Metadata        VEXMetadata        `json:"metadata"`
	Vulnerabilities []VEXVulnerability `json:"vulnerabilities"`
}

type VEXMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []VEXTool `json:"tools"`
}

type VEXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type VEXVulnerability struct {
	ID       string      `json:"id"`
	Source   VEXSource   `json:"source"`
	Analysis VEXAnalysis `json:"analysis"`
}

type VEXSource struct {
	Name string `json:"name"`
}

type VEXAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

func isValidStatus(status model.VEXStatus) bool {
	switch status {
	case model.VEXStatusNotAffected, model.VEXStatusAffected, model.VEXStatusFixed, model.VEXStatusUnderInvestigation:
		return true
	default:
		return false
	}
}

func mapStatusToCycloneDX(status model.VEXStatus) string {
	switch status {
	case model.VEXStatusNotAffected:
		return "not_affected"
	case model.VEXStatusAffected:
		return "exploitable"
	case model.VEXStatusFixed:
		return "resolved"
	case model.VEXStatusUnderInvestigation:
		return "in_triage"
	default:
		return "in_triage"
	}
}

func mapJustificationToCycloneDX(justification model.VEXJustification) string {
	switch justification {
	case model.VEXJustificationComponentNotPresent:
		return "component_not_present"
	case model.VEXJustificationVulnerableCodeNotPresent:
		return "vulnerable_code_not_present"
	case model.VEXJustificationVulnerableCodeNotInExecutePath:
		return "vulnerable_code_not_in_execute_path"
	case model.VEXJustificationVulnerableCodeCannotBeControlled:
		return "vulnerable_code_cannot_be_controlled_by_adversary"
	case model.VEXJustificationInlineMitigationsAlreadyExist:
		return "inline_mitigations_already_exist"
	default:
		return ""
	}
}
