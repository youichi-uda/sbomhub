package model

import (
	"time"

	"github.com/google/uuid"
)

// DashboardSummary represents the overall dashboard data
type DashboardSummary struct {
	TotalProjects   int                 `json:"total_projects"`
	TotalComponents int                 `json:"total_components"`
	Vulnerabilities VulnerabilityCounts `json:"vulnerabilities"`
	TopRisks        []TopRisk           `json:"top_risks"`
	ProjectScores   []ProjectScore      `json:"project_scores"`
	Trend           []TrendPoint        `json:"trend"`
}

// VulnerabilityCounts holds vulnerability counts by severity
type VulnerabilityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// TopRisk represents a high-priority vulnerability
type TopRisk struct {
	CVEID     string  `json:"cve_id"`
	EPSSScore float64 `json:"epss_score"`
	// CVSSScore is nil when the CVE has not been scored (NVD "Awaiting
	// Analysis", JVN-only matches). Deliberately NOT a 0-sentinel: CVSS 0.0
	// is a real "None" score, and rendering un-scored as 0.0 would present
	// an un-triaged CRITICAL as harmless on the dashboard and in the
	// PDF/Excel reports. Same contract as model.Vulnerability.CVSSScore
	// (M46 wave 4; f97c7fa established the shape).
	CVSSScore        *float64  `json:"cvss_score,omitempty"`
	Severity         string    `json:"severity"`
	ProjectID        uuid.UUID `json:"project_id"`
	ProjectName      string    `json:"project_name"`
	ComponentName    string    `json:"component_name"`
	ComponentVersion string    `json:"component_version"`
}

// ProjectScore represents a project's risk score
type ProjectScore struct {
	ProjectID   uuid.UUID `json:"project_id"`
	ProjectName string    `json:"project_name"`
	RiskScore   int       `json:"risk_score"`
	Severity    string    `json:"severity"`
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
	Low         int       `json:"low"`
}

// TrendPoint represents vulnerability counts at a point in time
type TrendPoint struct {
	Date     time.Time `json:"date"`
	Critical int       `json:"critical"`
	High     int       `json:"high"`
	Medium   int       `json:"medium"`
	Low      int       `json:"low"`
}
