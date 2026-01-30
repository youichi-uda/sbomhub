package model

import (
	"time"

	"github.com/google/uuid"
)

// ReportSettings defines settings for scheduled report generation
type ReportSettings struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	TenantID        uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Enabled         bool       `json:"enabled" db:"enabled"`
	ReportType      string     `json:"report_type" db:"report_type"`
	ScheduleType    string     `json:"schedule_type" db:"schedule_type"`
	ScheduleDay     int        `json:"schedule_day" db:"schedule_day"`
	ScheduleHour    int        `json:"schedule_hour" db:"schedule_hour"`
	Format          string     `json:"format" db:"format"`
	EmailEnabled    bool       `json:"email_enabled" db:"email_enabled"`
	EmailRecipients []string   `json:"email_recipients" db:"email_recipients"`
	IncludeSections []string   `json:"include_sections" db:"include_sections"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// GeneratedReport represents a generated report
type GeneratedReport struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	TenantID        uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	SettingsID      *uuid.UUID `json:"settings_id,omitempty" db:"settings_id"`
	ReportType      string     `json:"report_type" db:"report_type"`
	Format          string     `json:"format" db:"format"`
	Title           string     `json:"title" db:"title"`
	PeriodStart     time.Time  `json:"period_start" db:"period_start"`
	PeriodEnd       time.Time  `json:"period_end" db:"period_end"`
	FilePath        string     `json:"file_path" db:"file_path"`
	FileSize        int        `json:"file_size" db:"file_size"`
	FileContent     []byte     `json:"-" db:"file_content"` // Stored in DB, not exposed in JSON
	Status          string     `json:"status" db:"status"`
	ErrorMessage    string     `json:"error_message,omitempty" db:"error_message"`
	GeneratedBy     *uuid.UUID `json:"generated_by,omitempty" db:"generated_by"`
	EmailSentAt     *time.Time `json:"email_sent_at,omitempty" db:"email_sent_at"`
	EmailRecipients []string   `json:"email_recipients,omitempty" db:"email_recipients"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty" db:"completed_at"`
}

// Report type constants
const (
	ReportTypeExecutive  = "executive"
	ReportTypeTechnical  = "technical"
	ReportTypeCompliance = "compliance"
)

// Report format constants
const (
	ReportFormatPDF  = "pdf"
	ReportFormatXLSX = "xlsx"
)

// Report status constants
const (
	ReportStatusPending    = "pending"
	ReportStatusGenerating = "generating"
	ReportStatusCompleted  = "completed"
	ReportStatusFailed     = "failed"
	ReportStatusEmailed    = "emailed"
)

// Schedule type constants
const (
	ScheduleTypeWeekly  = "weekly"
	ScheduleTypeMonthly = "monthly"
)

// ExecutiveReportData contains all data needed for an executive report
type ExecutiveReportData struct {
	TenantName        string                   `json:"tenant_name"`
	PeriodStart       time.Time                `json:"period_start"`
	PeriodEnd         time.Time                `json:"period_end"`
	GeneratedAt       time.Time                `json:"generated_at"`
	Summary           ReportSummary            `json:"summary"`
	VulnerabilityData VulnReportData           `json:"vulnerability_data"`
	ComplianceData    ComplianceReportData     `json:"compliance_data"`
	ChecklistData     *ChecklistReportData     `json:"checklist_data,omitempty"`
	VisualizationData *VisualizationReportData `json:"visualization_data,omitempty"`
	ProjectScores     []ProjectScore           `json:"project_scores"`
	TopRisks          []TopRisk                `json:"top_risks"`
}

// ReportSummary contains summary statistics for a report
type ReportSummary struct {
	TotalProjects        int     `json:"total_projects"`
	TotalComponents      int     `json:"total_components"`
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	ResolvedInPeriod     int     `json:"resolved_in_period"`
	NewInPeriod          int     `json:"new_in_period"`
	AverageMTTRHours     float64 `json:"average_mttr_hours"`
	SLOAchievementPct    float64 `json:"slo_achievement_pct"`
	ComplianceScore      int     `json:"compliance_score"`
	ComplianceMaxScore   int     `json:"compliance_max_score"`
}

// VulnReportData contains vulnerability statistics
type VulnReportData struct {
	BySeverity   map[string]int `json:"by_severity"`
	ByStatus     map[string]int `json:"by_status"`
	TopCVEs      []CVESummary   `json:"top_cves"`
	TrendData    []TrendPoint   `json:"trend_data"`
}

// CVESummary contains summary info for a CVE
type CVESummary struct {
	CVEID       string  `json:"cve_id"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	EPSSScore   float64 `json:"epss_score"`
	ProjectName string  `json:"project_name"`
	ComponentName string `json:"component_name"`
}

// ComplianceReportData contains compliance statistics
type ComplianceReportData struct {
	OverallScore   int                    `json:"overall_score"`
	MaxScore       int                    `json:"max_score"`
	Categories     []ComplianceCategory   `json:"categories"`
	TrendData      []ComplianceTrendPoint `json:"trend_data"`
}

// ChecklistReportData contains METI checklist progress for reports
type ChecklistReportData struct {
	Score    int                        `json:"score"`
	MaxScore int                        `json:"max_score"`
	Phases   []ChecklistPhaseReportData `json:"phases"`
}

// ChecklistPhaseReportData contains phase-level checklist data for reports
type ChecklistPhaseReportData struct {
	Phase    string                    `json:"phase"`
	LabelJa  string                    `json:"label_ja"`
	Score    int                       `json:"score"`
	MaxScore int                       `json:"max_score"`
	Items    []ChecklistItemReportData `json:"items"`
}

// ChecklistItemReportData contains item-level checklist data for reports
type ChecklistItemReportData struct {
	ID         string `json:"id"`
	LabelJa    string `json:"label_ja"`
	AutoVerify bool   `json:"auto_verify"`
	Passed     bool   `json:"passed"`
	Note       string `json:"note,omitempty"`
}

// VisualizationReportData contains visualization framework settings for reports
type VisualizationReportData struct {
	SBOMAuthorScope  string   `json:"sbom_author_scope"`
	DependencyScope  string   `json:"dependency_scope"`
	GenerationMethod string   `json:"generation_method"`
	DataFormat       string   `json:"data_format"`
	UtilizationScope []string `json:"utilization_scope"`
	UtilizationActor string   `json:"utilization_actor"`
}

// CreateReportSettingsInput is the input for creating report settings
type CreateReportSettingsInput struct {
	ReportType      string   `json:"report_type"`
	Enabled         bool     `json:"enabled"`
	ScheduleType    string   `json:"schedule_type"`
	ScheduleDay     int      `json:"schedule_day"`
	ScheduleHour    int      `json:"schedule_hour"`
	Format          string   `json:"format"`
	EmailEnabled    bool     `json:"email_enabled"`
	EmailRecipients []string `json:"email_recipients"`
	IncludeSections []string `json:"include_sections"`
}

// GenerateReportInput is the input for manual report generation
type GenerateReportInput struct {
	ReportType  string    `json:"report_type"`
	Format      string    `json:"format"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
}
