package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// ImpactService assembles the cross-project vulnerability blast-radius view
// (M28-A / F388, issue #134). It is a read-only aggregation built on the
// existing search / vulnerability tables — no new table and no new audit
// action (a read-only GET, so the request middleware chain is sufficient and
// F271 audit parity is intentionally not triggered).
type ImpactService struct {
	searchRepo *repository.SearchRepository
}

func NewImpactService(searchRepo *repository.SearchRepository) *ImpactService {
	return &ImpactService{searchRepo: searchRepo}
}

// GetCVEImpact resolves the vulnerability metadata and aggregates the tenant's
// affected projects for cveID.
//
// Return contract:
//   - unknown CVE            -> (nil, nil)   (handler answers 404)
//   - known CVE, 0 affected  -> (&CVEImpact{AffectedProjectCount:0, AffectedProjects:[]}, nil)
//   - known CVE, N affected  -> (&CVEImpact{...}, nil)
//
// A malformed cve_id normalises and simply fails the vulnerabilities lookup,
// yielding (nil, nil) -> 404, so no separate 400 path is needed.
//
// The aggregation and the total-project count are both tenant-scoped (RLS
// braces + explicit tenant_id belt); the caller must run inside a TenantTx so
// project_id is crossed but tenant_id never is.
func (s *ImpactService) GetCVEImpact(ctx context.Context, tenantID uuid.UUID, cveID string) (*model.CVEImpact, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	meta, err := s.searchRepo.GetVulnerabilityImpactMeta(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("resolve vulnerability meta for %s: %w", cveID, err)
	}
	if meta == nil {
		// Unknown CVE — the caller returns 404. (A known CVE affecting zero
		// projects is handled below and returns a non-nil, empty result.)
		return nil, nil
	}

	affected, err := s.searchRepo.AggregateCVEImpact(ctx, tenantID, meta.VulnerabilityID)
	if err != nil {
		return nil, fmt.Errorf("aggregate cve impact for %s: %w", cveID, err)
	}

	totalProjects, err := s.searchRepo.CountProjectsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("count tenant projects: %w", err)
	}

	return buildCVEImpact(cveID, meta, affected, totalProjects), nil
}

// buildCVEImpact is the pure rollup: given the resolved metadata, the
// per-project affected list and the tenant's total project count, it assembles
// the response and derives affected_project_count. Kept separate from the DB
// calls so the count/normalisation logic is unit-testable without a database.
func buildCVEImpact(cveID string, meta *model.CVEImpactMeta, affected []model.ImpactProject, totalProjects int) *model.CVEImpact {
	if affected == nil {
		affected = []model.ImpactProject{}
	}
	return &model.CVEImpact{
		CVEID:                cveID,
		Severity:             meta.Severity,
		CVSSScore:            meta.CVSSScore,
		EPSSScore:            meta.EPSSScore,
		InKEV:                meta.InKEV,
		AffectedProjectCount: len(affected),
		TotalProjectCount:    totalProjects,
		AffectedProjects:     affected,
	}
}
