package triage

import (
	"context"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// This file contains the adapter shims that translate between the
// narrow interfaces declared in runner.go and the concrete repository /
// service types living elsewhere in the codebase. The adapters exist so
// that the runner can be unit-tested against in-memory fakes (see
// runner_test.go) without importing PG drivers, while production wiring
// (cmd/server/main.go) passes the real repositories through these
// thin shims.
//
// Note (post agent A reconciliation, 2026-06-24): the VexDraftStore
// interface in runner.go addresses *repository.VEXDraft directly, so
// *repository.VEXDraftsRepository satisfies it with no wrapper. The
// adapters below are only required for the *Row / *Record DTO families
// that mediate between repository row types and the narrow runner
// types declared alongside them.

// ----------------------------------------------------------------------------
// advisory_excerpts adapter
// ----------------------------------------------------------------------------

// AdvisoryExcerptsAdapter wraps *repository.AdvisoryExcerptsRepository
// so it satisfies AdvisoryExcerptReader.
type AdvisoryExcerptsAdapter struct {
	Repo *repository.AdvisoryExcerptsRepository
}

// GetByCVE implements AdvisoryExcerptReader.
func (a *AdvisoryExcerptsAdapter) GetByCVE(ctx context.Context, tenantID uuid.UUID, cveID string) ([]AdvisoryExcerptRow, error) {
	rows, err := a.Repo.GetByCVE(ctx, tenantID, cveID)
	if err != nil {
		return nil, err
	}
	out := make([]AdvisoryExcerptRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, AdvisoryExcerptRow{
			ID:             r.ID,
			CVEID:          r.CVEID,
			Source:         r.Source,
			VulnFuncs:      r.VulnFuncs,
			AffectedPaths:  r.AffectedPaths,
			RequiredConfig: r.RequiredConfig,
			RequiredEnv:    r.RequiredEnv,
			RawExcerpt:     r.RawExcerpt,
		})
	}
	return out, nil
}

// ----------------------------------------------------------------------------
// reachability_results adapter
// ----------------------------------------------------------------------------

// ReachabilityAdapter wraps *repository.ReachabilityResultsRepository
// so it satisfies ReachabilityReader.
type ReachabilityAdapter struct {
	Repo *repository.ReachabilityResultsRepository
}

// ListByProject implements ReachabilityReader.
func (a *ReachabilityAdapter) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter ReachabilityFilter) ([]ReachabilityRow, error) {
	rows, err := a.Repo.ListByProject(ctx, tenantID, projectID, repository.ReachabilityResultListFilter{
		CVEID:       filter.CVEID,
		ComponentID: filter.ComponentID,
		Status:      filter.Status,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ReachabilityRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, ReachabilityRow{
			ID:          r.ID,
			ComponentID: r.ComponentID,
			CVEID:       r.CVEID,
			Ecosystem:   r.Ecosystem,
			Status:      r.Status,
			Confidence:  r.Confidence,
			Evidence:    r.Evidence,
		})
	}
	return out, nil
}

// ----------------------------------------------------------------------------
// llm_calls adapter
// ----------------------------------------------------------------------------

// LLMCallsAdapter wraps *repository.LLMCallsRepository so it satisfies
// LLMCallWriter.
type LLMCallsAdapter struct {
	Repo *repository.LLMCallsRepository
}

// Insert implements LLMCallWriter.
func (a *LLMCallsAdapter) Insert(ctx context.Context, c *LLMCallRecord) error {
	row := &repository.LLMCall{
		ID:                      c.ID,
		TenantID:                c.TenantID,
		UserID:                  c.UserID,
		Purpose:                 c.Purpose,
		Provider:                c.Provider,
		Model:                   c.Model,
		PromptHash:              c.PromptHash,
		PromptPreview:           c.PromptPreview,
		ResponseHash:            c.ResponseHash,
		ResponsePreview:         c.ResponsePreview,
		ResponseBody:            c.ResponseBody,
		InputTokens:             c.InputTokens,
		OutputTokens:            c.OutputTokens,
		CostUSD:                 c.CostUSD,
		DurationMs:              c.DurationMs,
		FinishReason:            c.FinishReason,
		ErrorMessage:            c.ErrorMessage,
		TriageTargetCVE:         c.TriageTargetCVE,
		TriageTargetComponentID: c.TriageTargetComponentID,
	}
	return a.Repo.Insert(ctx, row)
}

// ----------------------------------------------------------------------------
// vex_statements sync adapter
// ----------------------------------------------------------------------------

// VEXServiceAdapter wraps *service.VEXService so it satisfies
// VEXStatementSync.
type VEXServiceAdapter struct {
	Service *service.VEXService
}

// CreateStatement implements VEXStatementSync.
//
// Idempotency: VEXService.CreateStatement currently rejects a duplicate
// (project, vulnerability, component) tuple with a "VEX statement
// already exists" error. The runner's approve / edit transitions can
// hit this on re-approve (e.g. user clicks Approve twice). We surface
// the error verbatim so the handler can decide whether to treat it as
// already-confirmed (200) or surface the duplicate (409).
// ※要確認: confirm with web (#30 / agent D) whether re-approve should
// be idempotent on the server side. Until then we let the error propagate.
func (a *VEXServiceAdapter) CreateStatement(ctx context.Context, in VEXStatementSyncInput) error {
	_, err := a.Service.CreateStatement(ctx, service.CreateVEXStatementInput{
		ProjectID:       in.ProjectID,
		VulnerabilityID: in.VulnerabilityID,
		ComponentID:     in.ComponentID,
		Status:          in.Status,
		Justification:   in.Justification,
		ActionStatement: in.ActionStatement,
		ImpactStatement: in.ImpactStatement,
		CreatedBy:       in.CreatedBy,
	})
	return err
}
