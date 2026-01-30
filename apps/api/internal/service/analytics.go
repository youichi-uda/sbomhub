package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// AnalyticsService provides analytics operations
type AnalyticsService struct {
	analyticsRepo *repository.AnalyticsRepository
	dashboardRepo *repository.DashboardRepository
}

// NewAnalyticsService creates a new AnalyticsService
func NewAnalyticsService(analyticsRepo *repository.AnalyticsRepository, dashboardRepo *repository.DashboardRepository) *AnalyticsService {
	return &AnalyticsService{
		analyticsRepo: analyticsRepo,
		dashboardRepo: dashboardRepo,
	}
}

// GetSummary returns the complete analytics summary
func (s *AnalyticsService) GetSummary(ctx context.Context, tenantID uuid.UUID, days int) (*model.AnalyticsSummary, error) {
	if days <= 0 {
		days = 30
	}

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	// Get MTTR data
	mttr, err := s.analyticsRepo.GetMTTR(ctx, tenantID, start, now)
	if err != nil {
		return nil, fmt.Errorf("failed to get MTTR: %w", err)
	}

	// If no MTTR data, provide defaults
	if len(mttr) == 0 {
		mttr = s.getDefaultMTTR()
	}

	// Get vulnerability trend
	vulnTrend, err := s.analyticsRepo.GetVulnerabilityTrend(ctx, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability trend: %w", err)
	}

	// If no trend data, use dashboard data
	if len(vulnTrend) == 0 {
		vulnTrend, err = s.getTrendFromDashboard(ctx, days)
		if err != nil {
			vulnTrend = []model.VulnerabilityTrendPoint{}
		}
	}

	// Get SLO achievement
	sloAchievement, err := s.analyticsRepo.GetSLOAchievement(ctx, tenantID, start, now)
	if err != nil {
		return nil, fmt.Errorf("failed to get SLO achievement: %w", err)
	}

	if len(sloAchievement) == 0 {
		sloAchievement = s.getDefaultSLOAchievement()
	}

	// Get compliance trend
	complianceTrend, err := s.analyticsRepo.GetComplianceTrend(ctx, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance trend: %w", err)
	}

	// Get quick stats
	stats, err := s.analyticsRepo.GetQuickStats(ctx, tenantID)
	if err != nil {
		stats = &model.AnalyticsQuickStats{}
	}

	// Calculate overall SLO achievement
	if len(sloAchievement) > 0 {
		var totalPct float64
		for _, slo := range sloAchievement {
			totalPct += slo.AchievementPct
		}
		stats.OverallSLOAchievementPct = totalPct / float64(len(sloAchievement))
	} else {
		stats.OverallSLOAchievementPct = 100.0
	}

	return &model.AnalyticsSummary{
		Period:           days,
		MTTR:             mttr,
		VulnerabilityTrend: vulnTrend,
		SLOAchievement:   sloAchievement,
		ComplianceTrend:  complianceTrend,
		Summary:          *stats,
	}, nil
}

// getDefaultMTTR returns default MTTR values when no data exists
func (s *AnalyticsService) getDefaultMTTR() []model.MTTRResult {
	return []model.MTTRResult{
		{Severity: "CRITICAL", MTTRHours: 0, Count: 0, TargetHours: 24, OnTarget: true},
		{Severity: "HIGH", MTTRHours: 0, Count: 0, TargetHours: 168, OnTarget: true},
		{Severity: "MEDIUM", MTTRHours: 0, Count: 0, TargetHours: 720, OnTarget: true},
		{Severity: "LOW", MTTRHours: 0, Count: 0, TargetHours: 2160, OnTarget: true},
	}
}

// getDefaultSLOAchievement returns default SLO achievement values
func (s *AnalyticsService) getDefaultSLOAchievement() []model.SLOAchievement {
	return []model.SLOAchievement{
		{Severity: "CRITICAL", TotalCount: 0, OnTargetCount: 0, AchievementPct: 100.0, TargetHours: 24, AverageMTTR: 0},
		{Severity: "HIGH", TotalCount: 0, OnTargetCount: 0, AchievementPct: 100.0, TargetHours: 168, AverageMTTR: 0},
		{Severity: "MEDIUM", TotalCount: 0, OnTargetCount: 0, AchievementPct: 100.0, TargetHours: 720, AverageMTTR: 0},
		{Severity: "LOW", TotalCount: 0, OnTargetCount: 0, AchievementPct: 100.0, TargetHours: 2160, AverageMTTR: 0},
	}
}

// getTrendFromDashboard gets trend data from the dashboard repository
func (s *AnalyticsService) getTrendFromDashboard(ctx context.Context, days int) ([]model.VulnerabilityTrendPoint, error) {
	if s.dashboardRepo == nil {
		return nil, nil
	}

	trend, err := s.dashboardRepo.GetTrend(ctx, days)
	if err != nil {
		return nil, err
	}

	var result []model.VulnerabilityTrendPoint
	for _, t := range trend {
		result = append(result, model.VulnerabilityTrendPoint{
			Date:     t.Date.Format("2006-01-02"),
			Critical: t.Critical,
			High:     t.High,
			Medium:   t.Medium,
			Low:      t.Low,
			Total:    t.Critical + t.High + t.Medium + t.Low,
		})
	}

	return result, nil
}

// GetMTTR returns MTTR data for a specific period
func (s *AnalyticsService) GetMTTR(ctx context.Context, tenantID uuid.UUID, days int) ([]model.MTTRResult, error) {
	if days <= 0 {
		days = 30
	}

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	mttr, err := s.analyticsRepo.GetMTTR(ctx, tenantID, start, now)
	if err != nil {
		return nil, fmt.Errorf("failed to get MTTR: %w", err)
	}

	if len(mttr) == 0 {
		return s.getDefaultMTTR(), nil
	}

	return mttr, nil
}

// GetVulnerabilityTrend returns vulnerability trend data
func (s *AnalyticsService) GetVulnerabilityTrend(ctx context.Context, tenantID uuid.UUID, days int) ([]model.VulnerabilityTrendPoint, error) {
	if days <= 0 {
		days = 30
	}

	trend, err := s.analyticsRepo.GetVulnerabilityTrend(ctx, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability trend: %w", err)
	}

	if len(trend) == 0 {
		trend, err = s.getTrendFromDashboard(ctx, days)
		if err != nil {
			return []model.VulnerabilityTrendPoint{}, nil
		}
	}

	return trend, nil
}

// GetSLOAchievement returns SLO achievement data
func (s *AnalyticsService) GetSLOAchievement(ctx context.Context, tenantID uuid.UUID, days int) ([]model.SLOAchievement, error) {
	if days <= 0 {
		days = 30
	}

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	slo, err := s.analyticsRepo.GetSLOAchievement(ctx, tenantID, start, now)
	if err != nil {
		return nil, fmt.Errorf("failed to get SLO achievement: %w", err)
	}

	if len(slo) == 0 {
		return s.getDefaultSLOAchievement(), nil
	}

	return slo, nil
}

// GetComplianceTrend returns compliance score trend
func (s *AnalyticsService) GetComplianceTrend(ctx context.Context, tenantID uuid.UUID, days int) ([]model.ComplianceTrendPoint, error) {
	if days <= 0 {
		days = 30
	}

	trend, err := s.analyticsRepo.GetComplianceTrend(ctx, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance trend: %w", err)
	}

	return trend, nil
}

// GetSLOTargets returns SLO targets for a tenant
func (s *AnalyticsService) GetSLOTargets(ctx context.Context, tenantID uuid.UUID) ([]model.SLOTarget, error) {
	return s.analyticsRepo.GetSLOTargets(ctx, tenantID)
}

// UpdateSLOTarget updates an SLO target
func (s *AnalyticsService) UpdateSLOTarget(ctx context.Context, tenantID uuid.UUID, severity string, targetHours int) error {
	// Validate severity
	validSeverities := map[string]bool{
		"CRITICAL": true,
		"HIGH":     true,
		"MEDIUM":   true,
		"LOW":      true,
	}
	if !validSeverities[severity] {
		return fmt.Errorf("invalid severity: %s", severity)
	}

	// Validate target hours
	if targetHours <= 0 {
		return fmt.Errorf("target hours must be positive")
	}

	return s.analyticsRepo.UpsertSLOTarget(ctx, tenantID, severity, targetHours)
}
