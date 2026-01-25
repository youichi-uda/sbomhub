package service

import (
	"context"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type DashboardService struct {
	dashboardRepo *repository.DashboardRepository
}

func NewDashboardService(dashboardRepo *repository.DashboardRepository) *DashboardService {
	return &DashboardService{dashboardRepo: dashboardRepo}
}

func (s *DashboardService) GetSummary(ctx context.Context) (*model.DashboardSummary, error) {
	summary := &model.DashboardSummary{}

	// Get total projects
	totalProjects, err := s.dashboardRepo.GetTotalProjects(ctx)
	if err != nil {
		return nil, err
	}
	summary.TotalProjects = totalProjects

	// Get total components
	totalComponents, err := s.dashboardRepo.GetTotalComponents(ctx)
	if err != nil {
		return nil, err
	}
	summary.TotalComponents = totalComponents

	// Get vulnerability counts
	vulnCounts, err := s.dashboardRepo.GetVulnerabilityCounts(ctx)
	if err != nil {
		return nil, err
	}
	summary.Vulnerabilities = vulnCounts

	// Get top risks (top 10 by EPSS score)
	topRisks, err := s.dashboardRepo.GetTopRisks(ctx, 10)
	if err != nil {
		return nil, err
	}
	summary.TopRisks = topRisks

	// Get project scores
	projectScores, err := s.dashboardRepo.GetProjectScores(ctx)
	if err != nil {
		return nil, err
	}
	summary.ProjectScores = projectScores

	// Get trend for last 30 days
	trend, err := s.dashboardRepo.GetTrend(ctx, 30)
	if err != nil {
		return nil, err
	}
	summary.Trend = trend

	return summary, nil
}
