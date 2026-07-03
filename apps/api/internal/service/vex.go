package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Sentinel errors for the cross-project VEX apply flow (M27-A / F381,
// issue #132). The handler maps ErrVEXApplyAlreadyTriaged to 409
// (idempotency — a silent overwrite is forbidden, CRA Decide precedent)
// and the two rejection sentinels to 400. Any other (wrapped, non-sentinel)
// error is an internal fault and maps to 500 so the ambient TenantTx rolls
// back.
var (
	// ErrVEXApplySourceNotFound is returned when source_statement_id does
	// not resolve to a statement visible to the caller's tenant (RLS +
	// explicit predicate). Distinct from a match failure so the log line
	// can distinguish "no such source" from "source exists but does not
	// match the target".
	ErrVEXApplySourceNotFound = errors.New("source VEX statement not found in tenant")

	// ErrVEXApplyMatchFailed is returned when the source statement is real
	// and tenant-visible but does NOT satisfy the M26 aggregation match
	// against the requested (component, vulnerability) — the injection
	// guard. See verifySuggestionMatch.
	ErrVEXApplyMatchFailed = errors.New("source statement does not match the target component/vulnerability")

	// ErrVEXApplyAlreadyTriaged is returned when the target project already
	// holds a statement for (project, vulnerability, component). The apply
	// endpoint never overwrites an existing decision — 409, not 200.
	ErrVEXApplyAlreadyTriaged = errors.New("target project already has a VEX statement for this vulnerability and component")
)

// ApplySuggestionInput is the resolved input to ApplySuggestion. The
// handler parses the HTTP body ({source_statement_id, vulnerability_id,
// component_id}) and resolves TenantID / AppliedBy / CreatedBy from the
// request context before calling.
type ApplySuggestionInput struct {
	TenantID          uuid.UUID
	ProjectID         uuid.UUID
	SourceStatementID uuid.UUID
	TargetComponentID uuid.UUID
	VulnerabilityID   uuid.UUID
	// AppliedBy is the resolved user UUID for provenance.applied_by (NULL
	// for self-hosted requests without one). CreatedBy is the human-
	// readable identity (email / clerk id / "system") for
	// vex_statements.created_by, matching the manual-authoring flow.
	AppliedBy *uuid.UUID
	CreatedBy string
}

// VEXApplyResult is what ApplySuggestion returns: the freshly-created
// target statement plus the provenance facts the handler serialises into
// the 201 response body and the audit Details map.
type VEXApplyResult struct {
	Statement       *model.VEXStatement
	SourceProjectID uuid.UUID
	MatchType       string
	ProvenanceID    uuid.UUID
	AppliedAt       time.Time
}

// ApplySuggestion materialises a cross-project VEX reuse suggestion into
// the target project (M27-A / F381, issue #132). A human has 1-click
// confirmed that another project of the same tenant already judged this
// (vulnerability, component); this copies that approved judgement into a
// NEW vex_statements row in the target project and records provenance.
//
// Atomicity: this method performs NO explicit BEGIN/COMMIT — every
// repository call routes through the request-scoped TenantTx attached to
// ctx (database.Querier), so the source resolve, the CreateStatement
// INSERT, and the provenance INSERT all run inside the caller's single tx.
// The handler emits the audit row in the SAME tx and hard-fails (500) on
// audit error, which rolls the whole tx back (audit-or-nothing, F32
// precedent). The route MUST therefore be registered under a TenantTx-
// wrapped group.
//
// Security (the load-bearing part): client-supplied ids are NOT trusted.
// verifySuggestionMatch re-runs the M26 aggregation match so an attacker
// cannot inject an arbitrary status onto an arbitrary component by pairing
// a real source_statement_id with a mismatched component_id.
func (s *VEXService) ApplySuggestion(ctx context.Context, in ApplySuggestionInput) (*VEXApplyResult, error) {
	// 1. Resolve the source statement, tenant-scoped (RLS authoritative +
	//    explicit tenant_id predicate as defence in depth).
	source, err := s.vexRepo.GetStatementForTenant(ctx, in.TenantID, in.SourceStatementID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source VEX statement: %w", err)
	}
	if source == nil {
		return nil, ErrVEXApplySourceNotFound
	}

	// 2. Re-verify the M26 match (injection guard).
	matchType, err := s.verifySuggestionMatch(ctx, in, source)
	if err != nil {
		return nil, err
	}

	// 3. Idempotency: never overwrite an existing (project, vuln, component)
	//    decision — surface 409 instead.
	existing, err := s.vexRepo.GetByProjectAndVulnerability(ctx, in.ProjectID, in.VulnerabilityID, &in.TargetComponentID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing target statement: %w", err)
	}
	if existing != nil {
		return nil, ErrVEXApplyAlreadyTriaged
	}

	// 4. Materialise the target statement via the shared CreateStatement
	//    path (status / justification / impact / action copied from source).
	//    CreateStatement re-applies status validation + the F379
	//    ComponentBelongsToProject write defence + its own duplicate check.
	statement, err := s.CreateStatement(ctx, CreateVEXStatementInput{
		ProjectID:       in.ProjectID,
		VulnerabilityID: in.VulnerabilityID,
		ComponentID:     &in.TargetComponentID,
		Status:          source.Status,
		Justification:   source.Justification,
		ActionStatement: source.ActionStatement,
		ImpactStatement: source.ImpactStatement,
		CreatedBy:       in.CreatedBy,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create reused VEX statement: %w", err)
	}

	// 5. Record provenance in the same tx. TenantID mirrors the freshly-
	//    created statement (resolved from the target project) so the
	//    vex_statement_provenance FORCE RLS WITH CHECK is satisfied.
	appliedAt := time.Now()
	prov := &model.VEXStatementProvenance{
		ID:                uuid.New(),
		TenantID:          statement.TenantID,
		TargetStatementID: statement.ID,
		SourceStatementID: source.ID,
		SourceProjectID:   source.ProjectID,
		AppliedBy:         in.AppliedBy,
		AppliedAt:         appliedAt,
	}
	if err := s.vexRepo.CreateProvenance(ctx, prov); err != nil {
		return nil, fmt.Errorf("failed to record VEX reuse provenance: %w", err)
	}

	return &VEXApplyResult{
		Statement:       statement,
		SourceProjectID: source.ProjectID,
		MatchType:       matchType,
		ProvenanceID:    prov.ID,
		AppliedAt:       appliedAt,
	}, nil
}

// verifySuggestionMatch re-runs the M26 aggregation match condition for a
// single (source, target) pair so apply cannot inject an arbitrary status
// onto an arbitrary component (F381 security requirement). It is a faithful
// mirror of assembleSuggestions + repository.ListCrossProjectVEXCandidates
// (the `ta` subquery + the WHERE clause), so a triple apply accepts is one
// GetSuggestions could have surfaced:
//
//   - the source vulnerability must equal the requested vulnerability;
//   - the target component must be AFFECTED by that vulnerability — linked
//     to it via component_vulnerabilities within the target project (F383,
//     issue #132/#133). The `ta` subquery only ever draws (vulnerability,
//     component) pairs from component_vulnerabilities, so a suggestion never
//     points at a non-affected component; without this join a crafted apply
//     could forge a verdict onto a component the vulnerability does not
//     touch. Enforced for BOTH match branches;
//   - a component-specific source (component_id non-NULL) matches ONLY when
//     its own component — bound to the SOURCE statement's project (F379
//     provenance integrity) — carries a non-empty purl equal to the target
//     component's purl (match_type = purl);
//   - a component-agnostic source (component_id NULL) matches on the
//     vulnerability alone (match_type = vulnerability_only); target
//     component ownership is then enforced by CreateStatement's
//     ComponentBelongsToProject write defence.
//
// The source is already tenant-scoped by the caller (GetStatementForTenant),
// and every component lookup is project-scoped (RLS-authoritative on the
// tenant boundary), so this stays a project-level tightening WITHIN the
// tenant, never a change to the tenant boundary.
func (s *VEXService) verifySuggestionMatch(ctx context.Context, in ApplySuggestionInput, source *model.VEXStatement) (string, error) {
	if source.VulnerabilityID != in.VulnerabilityID {
		return "", ErrVEXApplyMatchFailed
	}

	// The target component must belong to the target project regardless of
	// match type — a client-supplied component_id is never trusted. This
	// also makes CreateStatement's F379 ComponentBelongsToProject write
	// defence redundant for the apply path (defence in depth), and keeps
	// every rejection a typed 400 rather than leaking through as a 500.
	targetPurl, targetFound, err := s.vexRepo.GetComponentPurlInProject(ctx, in.TargetComponentID, in.ProjectID)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target component purl: %w", err)
	}
	if !targetFound {
		return "", ErrVEXApplyMatchFailed
	}

	// F383 (issue #132/#133): the target component must ALSO be affected by
	// the vulnerability — linked via component_vulnerabilities in the target
	// project — exactly as the M26 aggregation's `ta` subquery requires. This
	// re-check applies to BOTH branches below (purl and vulnerability_only):
	// without it, a crafted apply request could pair a real, tenant-visible
	// source statement with a target component the vulnerability does not
	// touch (one GetSuggestions would never surface) and forge a verdict onto
	// it. Rejecting here keeps the injection guard aligned with the read feed.
	linked, err := s.vexRepo.ComponentLinkedToVulnInProject(ctx, in.TargetComponentID, in.ProjectID, in.VulnerabilityID)
	if err != nil {
		return "", fmt.Errorf("failed to verify target component vulnerability linkage: %w", err)
	}
	if !linked {
		return "", ErrVEXApplyMatchFailed
	}

	if source.ComponentID == nil {
		// component-agnostic source → vulnerability_only match (vuln match
		// alone suffices, per the M26 aggregation).
		return model.VEXMatchTypeVulnerabilityOnly, nil
	}

	// component-specific source → require purl equality, with the source
	// component bound to the source's OWN project (F379 provenance
	// integrity). Empty purls never match (a coordinate-less component must
	// not collapse onto every other coordinate-less component).
	sourcePurl, sourceFound, err := s.vexRepo.GetComponentPurlInProject(ctx, *source.ComponentID, source.ProjectID)
	if err != nil {
		return "", fmt.Errorf("failed to resolve source component purl: %w", err)
	}
	if !sourceFound || sourcePurl == "" {
		return "", ErrVEXApplyMatchFailed
	}
	if targetPurl == "" || sourcePurl != targetPurl {
		return "", ErrVEXApplyMatchFailed
	}
	return model.VEXMatchTypePurl, nil
}

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

	// F379 write defence (issue #131): a component-specific statement must
	// reference a component that actually belongs to input.ProjectID. Nothing
	// in the schema enforces this (components have no project_id; migration
	// 045), so without this guard a statement could be linked to a component
	// from another project of the same tenant — which the cross-project VEX
	// suggestion feature would then mis-attribute as "this project decided
	// it". The normal triage-sync flow always resolves the project's own
	// components, so this rejects only genuinely mis-linked writes.
	if input.ComponentID != nil {
		belongs, err := s.vexRepo.ComponentBelongsToProject(ctx, *input.ComponentID, input.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("failed to verify component ownership: %w", err)
		}
		if !belongs {
			return nil, fmt.Errorf("component does not belong to project")
		}
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
// this project's components. This is a read; a human reuses a suggestion
// into this project via ApplySuggestion (F381), a separate human-confirmed
// write.
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
