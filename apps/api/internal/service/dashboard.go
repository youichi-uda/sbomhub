package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type DashboardService struct {
	dashboardRepo *repository.DashboardRepository
}

func NewDashboardService(dashboardRepo *repository.DashboardRepository) *DashboardService {
	return &DashboardService{dashboardRepo: dashboardRepo}
}

func (s *DashboardService) GetSummary(ctx context.Context, tenantID uuid.UUID) (*model.DashboardSummary, error) {
	summary := &model.DashboardSummary{}

	// Get total projects for this tenant
	totalProjects, err := s.dashboardRepo.GetTotalProjectsByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	summary.TotalProjects = totalProjects

	// Get total components for this tenant
	totalComponents, err := s.dashboardRepo.GetTotalComponentsByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	summary.TotalComponents = totalComponents

	// Get vulnerability counts for this tenant
	vulnCounts, err := s.dashboardRepo.GetVulnerabilityCountsByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	summary.Vulnerabilities = vulnCounts

	// Get top risks (top 10 by EPSS score) for this tenant. F449 (M39):
	// pass "epss" so the summary's TopRisks is actually ordered by
	// exploitation probability, matching the "By EPSS" widget label. Before
	// M39 the outer query hardcoded ORDER BY cvss_score, so the label and
	// behaviour disagreed (latent bug); the default here now makes the label
	// true. The dedicated GetTopRisks endpoint lets the UI toggle to cvss.
	topRisks, err := s.dashboardRepo.GetTopRisksByTenant(ctx, tenantID, 10, "epss")
	if err != nil {
		return nil, err
	}
	summary.TopRisks = topRisks

	// Get project scores for this tenant
	projectScores, err := s.dashboardRepo.GetProjectScoresByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	summary.ProjectScores = projectScores

	// Get trend for last 30 days for this tenant
	trend, err := s.dashboardRepo.GetTrendByTenant(ctx, tenantID, 30)
	if err != nil {
		return nil, err
	}
	summary.Trend = trend

	return summary, nil
}

// GetTopRisks returns the top 10 risks for a tenant ordered by sortBy
// ("epss" or "cvss"). F449 (M39): backs the dedicated
// GET /api/v1/dashboard/top-risks endpoint so the dashboard can toggle the
// Top Risks widget between EPSS (exploitation probability) and CVSS ordering
// without re-fetching the full summary aggregate. The repository chooses one
// of two fixed ORDER BY clauses; an out-of-band sortBy degrades to cvss
// (the handler rejects unknown values with 400 before reaching here).
func (s *DashboardService) GetTopRisks(ctx context.Context, tenantID uuid.UUID, sortBy string) ([]model.TopRisk, error) {
	return s.dashboardRepo.GetTopRisksByTenant(ctx, tenantID, 10, sortBy)
}
