package meti

// evaluator.go — M3-2 (issue #40) entry point.
//
// The Evaluator runs every catalog criterion against a single
// (tenant, project) pair and returns per-criterion verdicts. It does
// NOT write to meti_assessments: persistence is the M3-4 handler's
// responsibility (separation lets a re-evaluate-and-preview path
// reuse the same code path without committing rows).
//
// Layering (matches the issue's "scope" section):
//
//   - meti/catalog.go         (M3-3, owned)        — 27 criteria.
//   - meti/criteria/          (this wave, M3-2)    — per-criterion logic.
//   - meti/evaluator.go       (this wave, M3-2)    — orchestration.
//   - repository/meti_assessments.go (M3-1)        — Upsert / Get / list.
//   - handler/meti.go         (M3-4, downstream)   — HTTP + persistence.
//
// The criteria package owns a narrow Deps interface; this file
// supplies a *repoDeps adapter that satisfies it by delegating to the
// concrete repository structs. The adapter is the only place that
// translates between sql.ErrNoRows and the per-criterion "(nil, nil)
// means absent" contract.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/meti/criteria"
)

// EvaluatorVersion is stamped into meti_assessments.evaluator_version
// by the M3-4 handler. The semver-shaped string lets the handler
// detect when a stored row was produced by a stale evaluator (e.g.
// after the catalog grows new criteria) and trigger a re-evaluation.
// The "meti-" prefix disambiguates from non-METI evaluators a future
// product surface may introduce.
//
// Bump rules:
//   - v1 -> v2 when a criterion's status meaning changes (e.g. a
//     downgrade from achieved to needs_review for the same input
//     data). Cosmetic improvements (better evidence shape) do NOT
//     require a bump.
const EvaluatorVersion = "meti-evaluator-v1"

// CriterionResult is the public, criterion-id-stamped verdict returned
// by Evaluate. It mirrors criteria.Result + the criterion id and
// phase, so the M3-4 handler can iterate the slice and Upsert each
// row without further joins against the catalog.
type CriterionResult struct {
	CriterionID       string          `json:"criterion_id"`
	Phase             string          `json:"phase"`
	Status            string          `json:"status"`
	Evidence          json.RawMessage `json:"evidence"`
	ImprovementAction string          `json:"improvement_action,omitempty"`
	EvaluatorVersion  string          `json:"evaluator_version"`
	EvaluatedAt       time.Time       `json:"evaluated_at"`
}

// Evaluator runs the catalog over a (tenant, project) pair.
//
// Construction goes through NewEvaluator so the production wiring
// (cmd/server/main.go) passes the concrete repositories; tests
// substitute via NewEvaluatorWithDeps to supply a fake criteria.Deps.
// The two constructors exist so unit tests do not need to stand up
// the entire repository constellation just to exercise one criterion.
type Evaluator struct {
	deps criteria.Deps
	// now is injectable so tests can pin time-of-evaluation; production
	// uses time.Now.UTC() via the default zero-value branch in Evaluate.
	now func() time.Time
}

// NewEvaluator wires the production Deps adapter over the supplied
// repositories. Every repository is required; passing nil for any of
// them is rejected at construction so the dependency tree is explicit
// rather than papering over a missing repo with a runtime nil
// dereference inside a per-criterion function. ※要確認: re-order /
// rename parameters when the M3-4 handler is wired up if doing so
// keeps the cmd/server/main.go call site readable.
func NewEvaluator(
	sbomRepo *repository.SbomRepository,
	componentRepo *repository.ComponentRepository,
	vulnRepo *repository.VulnerabilityRepository,
	vexDraftsRepo *repository.VEXDraftsRepository,
	craReportsRepo *repository.CRAReportsRepository,
	publicLinkRepo *repository.PublicLinkRepository,
	licensePolicyRepo *repository.LicensePolicyRepository,
	eolRepo *repository.EOLRepository,
	kevRepo *repository.KEVRepository,
	auditRepo *repository.AuditRepository,
) (*Evaluator, error) {
	if sbomRepo == nil ||
		componentRepo == nil ||
		vulnRepo == nil ||
		vexDraftsRepo == nil ||
		craReportsRepo == nil ||
		publicLinkRepo == nil ||
		licensePolicyRepo == nil ||
		eolRepo == nil ||
		kevRepo == nil ||
		auditRepo == nil {
		return nil, fmt.Errorf("meti.NewEvaluator: every repository argument is required (nil dependency rejected)")
	}
	deps := &repoDeps{
		sbomRepo:          sbomRepo,
		componentRepo:     componentRepo,
		vulnRepo:          vulnRepo,
		vexDraftsRepo:     vexDraftsRepo,
		craReportsRepo:    craReportsRepo,
		publicLinkRepo:    publicLinkRepo,
		licensePolicyRepo: licensePolicyRepo,
		eolRepo:           eolRepo,
		kevRepo:           kevRepo,
		auditRepo:         auditRepo,
	}
	return &Evaluator{deps: deps}, nil
}

// NewEvaluatorWithDeps is the test-friendly constructor: it accepts
// a pre-built criteria.Deps (typically a fake). Production code paths
// should use NewEvaluator.
func NewEvaluatorWithDeps(deps criteria.Deps) (*Evaluator, error) {
	if deps == nil {
		return nil, fmt.Errorf("meti.NewEvaluatorWithDeps: deps is required")
	}
	return &Evaluator{deps: deps}, nil
}

// Evaluate runs every catalog criterion over (tenantID, projectID)
// and returns the per-criterion verdicts ordered by (phase ASC,
// criterion_id ASC) so the M3-4 handler can stream them into
// meti_assessments without a re-sort.
//
// A criterion function's error halts the entire evaluation — that
// keeps partial state out of meti_assessments (the handler caller is
// expected to wrap Evaluate in a transaction at the Upsert layer
// either way, but failing fast helps the operator see the underlying
// storage error). Per-criterion functions are expected to resolve
// data-absence to needs_review WITHOUT returning an error; an error
// here is reserved for genuine storage failures.
func (e *Evaluator) Evaluate(ctx context.Context, tenantID, projectID uuid.UUID) ([]CriterionResult, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("meti.Evaluator.Evaluate: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("meti.Evaluator.Evaluate: project_id is required")
	}
	catalogItems, err := LoadCatalog()
	if err != nil {
		return nil, fmt.Errorf("meti.Evaluator.Evaluate: load catalog: %w", err)
	}
	now := e.timestamp()

	// Deterministic order: phase ASC, id ASC. Sort upfront so the
	// returned slice is stable across runs (the handler relies on
	// this to compute stable diffs in audit logs).
	sort.Slice(catalogItems, func(i, j int) bool {
		if catalogItems[i].Phase != catalogItems[j].Phase {
			return string(catalogItems[i].Phase) < string(catalogItems[j].Phase)
		}
		return catalogItems[i].ID < catalogItems[j].ID
	})

	out := make([]CriterionResult, 0, len(catalogItems))
	for _, item := range catalogItems {
		fn, ok := criteria.Lookup(item.ID)
		if !ok {
			// Catalog has an id the registry does not. This is a
			// build-time bug (caught by TestRegistry_CoversCatalog);
			// at runtime we surface needs_review with an evidence
			// note rather than crashing so a hot deploy mid-edit
			// does not 500 the whole dashboard.
			out = append(out, CriterionResult{
				CriterionID:       item.ID,
				Phase:             string(item.Phase),
				Status:            criteria.StatusNeedsReview,
				Evidence:          json.RawMessage(`[{"kind":"evaluator_note","value":"no registry entry for this criterion id"}]`),
				ImprovementAction: "評価ロジックが未登録です。 evaluator のバージョンを確認してください。",
				EvaluatorVersion:  EvaluatorVersion,
				EvaluatedAt:       now,
			})
			continue
		}
		res, err := fn(ctx, e.deps, tenantID, projectID)
		if err != nil {
			return nil, fmt.Errorf("meti.Evaluator.Evaluate(%s): %w", item.ID, err)
		}
		out = append(out, CriterionResult{
			CriterionID:       item.ID,
			Phase:             string(item.Phase),
			Status:            res.Status,
			Evidence:          res.Evidence,
			ImprovementAction: res.ImprovementAction,
			EvaluatorVersion:  EvaluatorVersion,
			EvaluatedAt:       now,
		})
	}
	return out, nil
}

// EvaluateOne runs a single catalog criterion by id. Used by the M3-4
// "re-evaluate this row" handler path. Unknown id resolves to a
// criteria.ErrUnknownCriterion-shaped error so the handler can map
// it to 404 without parsing string content.
func (e *Evaluator) EvaluateOne(ctx context.Context, tenantID, projectID uuid.UUID, criterionID string) (*CriterionResult, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("meti.Evaluator.EvaluateOne: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("meti.Evaluator.EvaluateOne: project_id is required")
	}
	if criterionID == "" {
		return nil, fmt.Errorf("meti.Evaluator.EvaluateOne: criterion_id is required")
	}
	item, ok := GetCriterion(criterionID)
	if !ok {
		return nil, ErrUnknownCriterion
	}
	fn, ok := criteria.Lookup(criterionID)
	if !ok {
		return nil, ErrUnknownCriterion
	}
	res, err := fn(ctx, e.deps, tenantID, projectID)
	if err != nil {
		return nil, fmt.Errorf("meti.Evaluator.EvaluateOne(%s): %w", criterionID, err)
	}
	now := e.timestamp()
	return &CriterionResult{
		CriterionID:       item.ID,
		Phase:             string(item.Phase),
		Status:            res.Status,
		Evidence:          res.Evidence,
		ImprovementAction: res.ImprovementAction,
		EvaluatorVersion:  EvaluatorVersion,
		EvaluatedAt:       now,
	}, nil
}

// ErrUnknownCriterion is returned by EvaluateOne when the supplied
// criterion id is not in the catalog (or not in the criteria
// registry). The M3-4 handler maps this to HTTP 404.
var ErrUnknownCriterion = errors.New("meti: unknown criterion id")

// timestamp returns the evaluator's "now". Tests pin it via the e.now
// field; production uses time.Now().UTC().
func (e *Evaluator) timestamp() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now().UTC()
}

// repoDeps adapts the concrete repository structs to the narrow
// criteria.Deps interface. Every method is a thin pass-through; the
// only translation logic is sql.ErrNoRows -> (nil, nil) so the
// per-criterion functions do not have to import database/sql.
type repoDeps struct {
	sbomRepo          *repository.SbomRepository
	componentRepo     *repository.ComponentRepository
	vulnRepo          *repository.VulnerabilityRepository
	vexDraftsRepo     *repository.VEXDraftsRepository
	craReportsRepo    *repository.CRAReportsRepository
	publicLinkRepo    *repository.PublicLinkRepository
	licensePolicyRepo *repository.LicensePolicyRepository
	eolRepo           *repository.EOLRepository
	kevRepo           *repository.KEVRepository
	auditRepo         *repository.AuditRepository
}

func (d *repoDeps) GetLatestSbom(ctx context.Context, projectID uuid.UUID) (*model.Sbom, error) {
	s, err := d.sbomRepo.GetLatest(ctx, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *repoDeps) ListSbomsByProject(ctx context.Context, projectID uuid.UUID) ([]model.Sbom, error) {
	return d.sbomRepo.ListByProject(ctx, projectID)
}

func (d *repoDeps) ListComponentsBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.Component, error) {
	return d.componentRepo.ListBySbom(ctx, sbomID)
}

func (d *repoDeps) ListVulnerabilitiesByProject(ctx context.Context, projectID uuid.UUID) ([]model.Vulnerability, error) {
	return d.vulnRepo.ListByProject(ctx, projectID)
}

func (d *repoDeps) ListVEXDraftsByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]repository.VEXDraft, error) {
	// Default filter: zero-value -> unbounded (clamped at repo layer).
	return d.vexDraftsRepo.ListByProject(ctx, tenantID, projectID, repository.VEXDraftListFilter{})
}

func (d *repoDeps) ListCRAReportsByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]repository.CRAReport, error) {
	return d.craReportsRepo.ListByProject(ctx, tenantID, projectID, repository.CRAReportListFilter{})
}

func (d *repoDeps) ListPublicLinksByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.PublicLink, error) {
	return d.publicLinkRepo.ListByProject(ctx, tenantID, projectID)
}

func (d *repoDeps) ListLicensePoliciesByProject(ctx context.Context, projectID uuid.UUID) ([]model.LicensePolicy, error) {
	return d.licensePolicyRepo.ListByProject(ctx, projectID)
}

func (d *repoDeps) GetEOLSummary(ctx context.Context, projectID uuid.UUID) (*model.EOLSummary, error) {
	s, err := d.eolRepo.GetEOLSummary(ctx, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *repoDeps) GetKEVSyncSettings(ctx context.Context) (*model.KEVSyncSettings, error) {
	return d.kevRepo.GetSyncSettings(ctx)
}

func (d *repoDeps) CountAuditLogsForTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	return d.auditRepo.Count(ctx, tenantID)
}
