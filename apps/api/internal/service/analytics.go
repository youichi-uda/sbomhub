package service

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
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

	// Get vulnerability trend
	vulnTrend, err := s.analyticsRepo.GetVulnerabilityTrend(ctx, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability trend: %w", err)
	}

	// If no trend data, use dashboard data
	if len(vulnTrend) == 0 {
		vulnTrend, err = s.getTrendFromDashboard(ctx, tenantID, days)
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
		sloAchievement = s.getDefaultSLOAchievement(ctx, tenantID)
	}

	// Fill in the severities the MTTR read did not measure. Done AFTER the
	// SLO read so the placeholder rows carry the tenant's REAL targets
	// (Codex round 3, Low): the old hard-coded 24/168/720/2160 meant a tenant
	// who had configured CRITICAL to 12h saw "target 24h" in the MTTR panel
	// and "target 12h" in the SLO panel until its first remediation.
	mttr = mergeUnmeasuredMTTR(mttr, sloAchievement)

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

	// Calculate overall SLO achievement.
	//
	// M49: computed over the MEASURED severities only and left nil when none
	// of them is measured. Pre-fix every unmeasured severity contributed a
	// literal 100.0 to an unweighted mean (and an empty list answered 100.0
	// outright), so a tenant that had remediated one CRITICAL late and
	// nothing else reported ~75% "achievement" — three quarters of which was
	// invented.
	stats.OverallSLOAchievementPct = overallSLOAchievement(sloAchievement)

	return &model.AnalyticsSummary{
		Period:             days,
		MTTR:               mttr,
		VulnerabilityTrend: vulnTrend,
		SLOAchievement:     sloAchievement,
		ComplianceTrend:    complianceTrend,
		Summary:            *stats,
	}, nil
}

// overallSLOAchievement returns the share of resolved vulnerabilities that
// met their severity's SLO target, or nil when nothing was resolved.
//
// M49: two things are fixed here relative to the pre-M49 loop.
//
//  1. An unmeasured severity is not folded in as if it were a measurement —
//     neither as 100 (the old behaviour, which flattered the number) nor as
//     0 (which would defame it). "Nothing at all was resolved" propagates as
//     nil rather than as a verdict.
//  2. The aggregate is POPULATION-weighted (Codex round 2, High): sum of
//     on-target resolutions over sum of resolutions, not the unweighted mean
//     of the four per-severity percentages. The old macro-average reported
//     50% for a tenant that resolved 1/1 CRITICAL on target and 0/100 HIGH
//     late — the true share is under 1%. This also matches how the label is
//     defined to the operator in the UI ("the proportion of vulnerabilities
//     resolved within the SLO target time", Analytics.sloDescription), so
//     the number now means what the caption says it means.
func overallSLOAchievement(achievements []model.SLOAchievement) *float64 {
	onTarget := 0
	total := 0
	for _, a := range achievements {
		if a.TotalCount <= 0 {
			continue
		}
		onTarget += a.OnTargetCount
		total += a.TotalCount
	}
	if total == 0 {
		return nil
	}
	pct := float64(onTarget) / float64(total) * 100
	return &pct
}

// aggregatePeriodMTTR collapses per-severity MTTR rows for one reporting
// window into (total resolved count, count-weighted mean MTTR in hours).
//
// M49: the mean is nil when nothing was resolved in the window — a report's
// summary line must not fall back to 0 hours, which for MTTR is the best
// possible value. The mean is COUNT-weighted rather than a mean-of-means so
// that one late CRITICAL cannot outweigh fifty prompt LOWs (or vice versa).
func aggregatePeriodMTTR(rows []model.MTTRResult) (int, *float64) {
	total := 0
	var weighted float64
	measured := 0
	for _, r := range rows {
		total += r.Count
		if r.MTTRHours == nil || r.Count <= 0 {
			continue
		}
		weighted += *r.MTTRHours * float64(r.Count)
		measured += r.Count
	}
	if measured == 0 {
		return total, nil
	}
	avg := weighted / float64(measured)
	return total, &avg
}

// fallbackSLOTargetHours is the per-severity target used ONLY when
// slo_targets cannot be read at all. Migration 012 seeds a global
// (tenant_id IS NULL) row for each severity, so in a migrated database these
// values are never reached; they exist so a transient read failure degrades
// to the documented product defaults rather than to 0.
var fallbackSLOTargetHours = []struct {
	Severity    string
	TargetHours int
}{
	{"CRITICAL", 24},
	{"HIGH", 168},
	{"MEDIUM", 720},
	{"LOW", 2160},
}

// severityRank orders severities the way both analytics queries do, so a
// merged list keeps the CRITICAL → HIGH → MEDIUM → LOW reading order the
// dashboard expects.
func severityRank(severity string) int {
	switch severity {
	case "CRITICAL":
		return 1
	case "HIGH":
		return 2
	case "MEDIUM":
		return 3
	case "LOW":
		return 4
	default:
		return 5
	}
}

// mergeUnmeasuredMTTR returns the measured MTTR rows plus an UNMEASURED
// placeholder for every severity that has an SLO target but produced no
// remediation in the window.
//
// M49 (Codex round 4): GetMTTR derives its rows from resolved events only, so
// a severity with open-but-never-remediated vulnerabilities is simply absent
// from the result. The service used to substitute placeholders only when the
// list was ENTIRELY empty, so a tenant that had remediated one HIGH saw a
// single-row MTTR panel and its unremediated CRITICAL vanished — partial data
// presented as the complete picture. Now every severity that has a target is
// listed; the ones with no remediation carry nil metrics and render as "not
// measured" rather than being silently dropped or shown as 0h/on-target.
func mergeUnmeasuredMTTR(measured []model.MTTRResult, slo []model.SLOAchievement) []model.MTTRResult {
	seen := make(map[string]bool, len(measured))
	for _, m := range measured {
		seen[m.Severity] = true
	}
	// Copy rather than append in place: the caller owns `measured`.
	out := make([]model.MTTRResult, len(measured), len(measured)+len(slo))
	copy(out, measured)
	for _, a := range slo {
		if seen[a.Severity] {
			continue
		}
		out = append(out, model.MTTRResult{Severity: a.Severity, TargetHours: a.TargetHours})
	}
	if len(out) == 0 {
		out = unmeasuredMTTRFor(nil)
	}
	// Sorted on EVERY path (Codex round 5, Low): the all-unmeasured case is
	// built from GetSLOTargets, whose SQL order is lexical
	// (CRITICAL, HIGH, LOW, MEDIUM) — an early return would have shipped the
	// most common shape, a tenant with no remediations at all, in the wrong
	// reading order.
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].Severity) < severityRank(out[j].Severity)
	})
	return out
}

// unmeasuredMTTRFor turns the SLO achievement rows into MTTR placeholder
// rows: same severities, same targets, no measurement.
//
// M49: the metric fields are nil, NOT 0/true. These rows are what a fresh
// installation renders — no vulnerability has ever been resolved — and the
// old zero values told that operator their MTTR was 0 hours and every SLO was
// met. Deriving the targets from the SLO rows (Codex round 3, Low) keeps the
// MTTR and SLO panels from disagreeing about a tenant's configured targets.
func unmeasuredMTTRFor(slo []model.SLOAchievement) []model.MTTRResult {
	if len(slo) == 0 {
		out := make([]model.MTTRResult, 0, len(fallbackSLOTargetHours))
		for _, d := range fallbackSLOTargetHours {
			out = append(out, model.MTTRResult{Severity: d.Severity, TargetHours: d.TargetHours})
		}
		return out
	}
	out := make([]model.MTTRResult, 0, len(slo))
	for _, a := range slo {
		out = append(out, model.MTTRResult{Severity: a.Severity, TargetHours: a.TargetHours})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].Severity) < severityRank(out[j].Severity)
	})
	return out
}

// getDefaultSLOAchievement returns the severity rows to show when no SLO
// achievement data exists — i.e. when GetSLOAchievement itself came back
// empty, which means slo_targets has no row this tenant can see.
//
// M49: AchievementPct / AverageMTTR are nil — 100% compliance is a claim, and
// there is nothing here to base it on. The targets come from slo_targets when
// that read succeeds, so a tenant's configured values survive even on the
// no-data path; fallbackSLOTargetHours is the last resort.
func (s *AnalyticsService) getDefaultSLOAchievement(ctx context.Context, tenantID uuid.UUID) []model.SLOAchievement {
	if s.analyticsRepo != nil {
		if targets, err := s.analyticsRepo.GetSLOTargets(ctx, tenantID); err == nil && len(targets) > 0 {
			out := make([]model.SLOAchievement, 0, len(targets))
			for _, t := range targets {
				out = append(out, model.SLOAchievement{Severity: t.Severity, TargetHours: t.TargetHours})
			}
			return out
		} else if err != nil {
			slog.Warn("analytics: slo targets unavailable, using product defaults",
				"tenant_id", tenantID, "error", err)
		}
	}
	out := make([]model.SLOAchievement, 0, len(fallbackSLOTargetHours))
	for _, d := range fallbackSLOTargetHours {
		out = append(out, model.SLOAchievement{Severity: d.Severity, TargetHours: d.TargetHours})
	}
	return out
}

// getTrendFromDashboard gets trend data from the dashboard repository.
//
// M41 (F462): repointed from the deprecated always-error GetTrend(ctx, days)
// stub to the tenant-scoped GetTrendByTenant. tenantID is threaded from the
// callers (GetSummary / GetVulnerabilityTrend), both of which already have it
// in scope, so the fallback trend is now correctly isolated to the tenant.
func (s *AnalyticsService) getTrendFromDashboard(ctx context.Context, tenantID uuid.UUID, days int) ([]model.VulnerabilityTrendPoint, error) {
	if s.dashboardRepo == nil {
		return nil, nil
	}

	trend, err := s.dashboardRepo.GetTrendByTenant(ctx, tenantID, days)
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

	return mergeUnmeasuredMTTR(mttr, s.getDefaultSLOAchievement(ctx, tenantID)), nil
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
		trend, err = s.getTrendFromDashboard(ctx, tenantID, days)
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
		return s.getDefaultSLOAchievement(ctx, tenantID), nil
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
		// F443: caller-fixable input → surface at 400 via ErrValidation.
		return ValidationErrorf("invalid severity: %s", severity)
	}

	// Validate target hours
	if targetHours <= 0 {
		// F443: caller-fixable input → surface at 400 via ErrValidation.
		return ValidationErrorf("target hours must be positive")
	}

	// F443: the repository error was previously returned raw (no %w), so the
	// handler's blanket-400 echoed the driver/SQL string to the client. Wrap
	// it so it is classified as internal (NOT ErrValidation) → 500 + generic.
	if err := s.analyticsRepo.UpsertSLOTarget(ctx, tenantID, severity, targetHours); err != nil {
		return fmt.Errorf("upsert slo target: %w", err)
	}
	return nil
}
