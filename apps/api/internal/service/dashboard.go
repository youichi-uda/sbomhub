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

	// Get top risks (top 10 by EPSS score) for this tenant
	topRisks, err := s.dashboardRepo.GetTopRisksByTenant(ctx, tenantID, 10)
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
