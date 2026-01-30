package model

import (
	"time"

	"github.com/google/uuid"
)

// VulnerabilityResolutionEvent tracks when vulnerabilities are detected and resolved
type VulnerabilityResolutionEvent struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	TenantID        uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	VulnerabilityID uuid.UUID  `json:"vulnerability_id" db:"vulnerability_id"`
	ProjectID       uuid.UUID  `json:"project_id" db:"project_id"`
	CVEID           string     `json:"cve_id" db:"cve_id"`
	Severity        string     `json:"severity" db:"severity"`
	DetectedAt      time.Time  `json:"detected_at" db:"detected_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolutionType  string     `json:"resolution_type,omitempty" db:"resolution_type"`
	ResolutionNotes string     `json:"resolution_notes,omitempty" db:"resolution_notes"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// SLOTarget defines the target resolution time for each severity
type SLOTarget struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	Severity    string     `json:"severity" db:"severity"`
	TargetHours int        `json:"target_hours" db:"target_hours"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// VulnerabilitySnapshot stores daily vulnerability counts
type VulnerabilitySnapshot struct {
	ID            uuid.UUID `json:"id" db:"id"`
	TenantID      uuid.UUID `json:"tenant_id" db:"tenant_id"`
	SnapshotDate  time.Time `json:"snapshot_date" db:"snapshot_date"`
	CriticalCount int       `json:"critical_count" db:"critical_count"`
	HighCount     int       `json:"high_count" db:"high_count"`
	MediumCount   int       `json:"medium_count" db:"medium_count"`
	LowCount      int       `json:"low_count" db:"low_count"`
	TotalCount    int       `json:"total_count" db:"total_count"`
	ResolvedCount int       `json:"resolved_count" db:"resolved_count"`
	MTTRHours     *float64  `json:"mttr_hours,omitempty" db:"mttr_hours"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// ComplianceSnapshot stores daily compliance scores
type ComplianceSnapshot struct {
	ID                           uuid.UUID  `json:"id" db:"id"`
	TenantID                     uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ProjectID                    *uuid.UUID `json:"project_id,omitempty" db:"project_id"`
	SnapshotDate                 time.Time  `json:"snapshot_date" db:"snapshot_date"`
	OverallScore                 int        `json:"overall_score" db:"overall_score"`
	MaxScore                     int        `json:"max_score" db:"max_score"`
	SBOMGenerationScore          int        `json:"sbom_generation_score" db:"sbom_generation_score"`
	VulnerabilityManagementScore int        `json:"vulnerability_management_score" db:"vulnerability_management_score"`
	LicenseManagementScore       int        `json:"license_management_score" db:"license_management_score"`
	CreatedAt                    time.Time  `json:"created_at" db:"created_at"`
}

// MTTRResult represents Mean Time To Remediate for a severity
type MTTRResult struct {
	Severity    string  `json:"severity"`
	MTTRHours   float64 `json:"mttr_hours"`
	Count       int     `json:"count"`
	TargetHours int     `json:"target_hours"`
	OnTarget    bool    `json:"on_target"`
}

// VulnerabilityTrendPoint represents a point in the vulnerability trend chart
type VulnerabilityTrendPoint struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Total    int    `json:"total"`
	Resolved int    `json:"resolved"`
}

// SLOAchievement represents SLO achievement metrics
type SLOAchievement struct {
	Severity       string  `json:"severity"`
	TotalCount     int     `json:"total_count"`
	OnTargetCount  int     `json:"on_target_count"`
	AchievementPct float64 `json:"achievement_pct"`
	TargetHours    int     `json:"target_hours"`
	AverageMTTR    float64 `json:"average_mttr_hours"`
}

// ComplianceTrendPoint represents a point in the compliance score trend
type ComplianceTrendPoint struct {
	Date               string  `json:"date"`
	Score              int     `json:"score"`
	MaxScore           int     `json:"max_score"`
	Percentage         float64 `json:"percentage"`
	SBOMScore          int     `json:"sbom_score,omitempty"`
	VulnerabilityScore int     `json:"vulnerability_score,omitempty"`
	LicenseScore       int     `json:"license_score,omitempty"`
}

// AnalyticsSummary is the main analytics dashboard response
type AnalyticsSummary struct {
	Period           int                       `json:"period"` // days
	MTTR             []MTTRResult              `json:"mttr"`
	VulnerabilityTrend []VulnerabilityTrendPoint `json:"vulnerability_trend"`
	SLOAchievement   []SLOAchievement          `json:"slo_achievement"`
	ComplianceTrend  []ComplianceTrendPoint    `json:"compliance_trend"`
	Summary          AnalyticsQuickStats       `json:"summary"`
}

// AnalyticsQuickStats provides quick summary statistics
type AnalyticsQuickStats struct {
	TotalOpenVulnerabilities   int     `json:"total_open_vulnerabilities"`
	ResolvedLast30Days         int     `json:"resolved_last_30_days"`
	AverageMTTRHours           float64 `json:"average_mttr_hours"`
	OverallSLOAchievementPct   float64 `json:"overall_slo_achievement_pct"`
	CurrentComplianceScore     int     `json:"current_compliance_score"`
	ComplianceMaxScore         int     `json:"compliance_max_score"`
}

// Resolution type constants
const (
	ResolutionTypeFixed       = "fixed"
	ResolutionTypeMitigated   = "mitigated"
	ResolutionTypeAccepted    = "accepted"
	ResolutionTypeFalsePositive = "false_positive"
)
