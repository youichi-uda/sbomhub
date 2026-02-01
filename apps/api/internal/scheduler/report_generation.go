package scheduler

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/smtp"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

var base64StdEncoding = base64.StdEncoding

// ReportGenerationJob handles periodic report generation
type ReportGenerationJob struct {
	reportService *service.ReportService
	reportRepo    *repository.ReportRepository
	tenantRepo    *repository.TenantRepository
	cfg           *config.Config
	interval      time.Duration
	logger        *slog.Logger
}

// NewReportGenerationJob creates a new report generation job
func NewReportGenerationJob(
	reportService *service.ReportService,
	reportRepo *repository.ReportRepository,
	tenantRepo *repository.TenantRepository,
	interval time.Duration,
) *ReportGenerationJob {
	return &ReportGenerationJob{
		reportService: reportService,
		reportRepo:    reportRepo,
		tenantRepo:    tenantRepo,
		interval:      interval,
		logger:        slog.Default().With("job", "report_generation"),
	}
}

// NewReportGenerationJobFull creates a new report generation job with full configuration
func NewReportGenerationJobFull(
	reportService *service.ReportService,
	reportRepo *repository.ReportRepository,
	tenantRepo *repository.TenantRepository,
	cfg *config.Config,
	interval time.Duration,
) *ReportGenerationJob {
	return &ReportGenerationJob{
		reportService: reportService,
		reportRepo:    reportRepo,
		tenantRepo:    tenantRepo,
		cfg:           cfg,
		interval:      interval,
		logger:        slog.Default().With("job", "report_generation"),
	}
}

// Start starts the report generation job
func (j *ReportGenerationJob) Start(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Check immediately on start
	j.run(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Info("Report generation job stopped")
			return
		case <-ticker.C:
			j.run(ctx)
		}
	}
}

// run executes a single check cycle
func (j *ReportGenerationJob) run(ctx context.Context) {
	now := time.Now()
	j.logger.Debug("Checking scheduled reports", "time", now.Format("15:04"))

	// Get all enabled report settings
	settings, err := j.reportRepo.GetEnabledSettings(ctx)
	if err != nil {
		j.logger.Error("Failed to get enabled settings", "error", err)
		return
	}

	if len(settings) == 0 {
		j.logger.Debug("No enabled report schedules found")
		return
	}

	j.logger.Debug("Found enabled report settings", "count", len(settings))

	for _, setting := range settings {
		if j.shouldGenerate(&setting, now) {
			j.logger.Info("Triggering scheduled report generation",
				"tenant_id", setting.TenantID,
				"report_type", setting.ReportType,
				"format", setting.Format,
			)
			go j.generateReport(ctx, &setting)
		}
	}
}

// shouldGenerate checks if a report should be generated based on schedule
func (j *ReportGenerationJob) shouldGenerate(setting *model.ReportSettings, now time.Time) bool {
	// Check hour (allow 5 minute window)
	if now.Hour() != setting.ScheduleHour || now.Minute() >= 5 {
		return false
	}

	switch setting.ScheduleType {
	case model.ScheduleTypeWeekly:
		// ScheduleDay: 0=Sunday, 1=Monday, ..., 6=Saturday
		return int(now.Weekday()) == setting.ScheduleDay

	case model.ScheduleTypeMonthly:
		// ScheduleDay: 1-28
		return now.Day() == setting.ScheduleDay

	default:
		return false
	}
}

// generateReport generates a report for a tenant
func (j *ReportGenerationJob) generateReport(ctx context.Context, setting *model.ReportSettings) {
	startTime := time.Now()

	// Calculate period based on schedule type
	periodEnd := time.Now()
	var periodStart time.Time

	switch setting.ScheduleType {
	case model.ScheduleTypeWeekly:
		periodStart = periodEnd.AddDate(0, 0, -7)
	case model.ScheduleTypeMonthly:
		periodStart = periodEnd.AddDate(0, -1, 0)
	default:
		periodStart = periodEnd.AddDate(0, -1, 0)
	}

	input := model.GenerateReportInput{
		ReportType:  setting.ReportType,
		Format:      setting.Format,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}

	// Use system user ID for scheduled reports
	systemUserID := uuid.Nil

	report, err := j.reportService.GenerateReport(ctx, setting.TenantID, systemUserID, input)
	if err != nil {
		j.logger.Error("Failed to generate scheduled report",
			"tenant_id", setting.TenantID,
			"report_type", setting.ReportType,
			"error", err,
			"duration_ms", time.Since(startTime).Milliseconds(),
		)
		return
	}

	j.logger.Info("Scheduled report generation initiated",
		"tenant_id", setting.TenantID,
		"report_id", report.ID,
		"report_type", setting.ReportType,
		"format", setting.Format,
		"duration_ms", time.Since(startTime).Milliseconds(),
	)

	// Send email if configured
	if setting.EmailEnabled && len(setting.EmailRecipients) > 0 {
		// Wait for report generation to complete (with timeout)
		go j.sendReportEmailWhenReady(ctx, setting, report.ID)
	}
}

// sendReportEmailWhenReady waits for report completion and sends email
func (j *ReportGenerationJob) sendReportEmailWhenReady(ctx context.Context, setting *model.ReportSettings, reportID uuid.UUID) {
	// Poll for report completion (max 5 minutes)
	maxWait := 5 * time.Minute
	pollInterval := 10 * time.Second
	startTime := time.Now()

	for time.Since(startTime) < maxWait {
		report, err := j.reportRepo.GetReport(ctx, setting.TenantID, reportID)
		if err != nil {
			j.logger.Error("Failed to get report for email",
				"report_id", reportID,
				"error", err,
			)
			return
		}

		if report.Status == model.ReportStatusCompleted {
			j.sendReportEmail(ctx, setting, report)
			return
		}

		if report.Status == model.ReportStatusFailed {
			j.logger.Warn("Report generation failed, skipping email",
				"report_id", reportID,
				"error", report.ErrorMessage,
			)
			return
		}

		time.Sleep(pollInterval)
	}

	j.logger.Warn("Timed out waiting for report completion",
		"report_id", reportID,
	)
}

// sendReportEmail sends the generated report via email
func (j *ReportGenerationJob) sendReportEmail(ctx context.Context, setting *model.ReportSettings, report *model.GeneratedReport) {
	if j.cfg == nil || !j.cfg.IsEmailEnabled() {
		j.logger.Debug("Email not configured, skipping report email")
		return
	}

	// Get report content
	reportWithContent, err := j.reportRepo.GetReportWithContent(ctx, setting.TenantID, report.ID)
	if err != nil || len(reportWithContent.FileContent) == 0 {
		j.logger.Error("Failed to get report content for email",
			"report_id", report.ID,
			"error", err,
		)
		return
	}

	// Determine content type and filename
	contentType := "application/pdf"
	fileExt := "pdf"
	if report.Format == model.ReportFormatXLSX {
		contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		fileExt = "xlsx"
	}

	filename := fmt.Sprintf("sbomhub_%s_report_%s.%s",
		report.ReportType,
		time.Now().Format("20060102"),
		fileExt,
	)

	// Build email
	subject := fmt.Sprintf("[SBOMHub] %s レポート - %s",
		j.getReportTypeLabel(report.ReportType),
		time.Now().Format("2006-01-02"),
	)

	htmlBody := j.generateReportEmailHTML(report)
	textBody := j.generateReportEmailText(report)

	// Send to all recipients
	for _, recipient := range setting.EmailRecipients {
		if err := j.sendEmailWithAttachment(recipient, subject, htmlBody, textBody, filename, contentType, reportWithContent.FileContent); err != nil {
			j.logger.Error("Failed to send report email",
				"recipient", recipient,
				"report_id", report.ID,
				"error", err,
			)
		} else {
			j.logger.Info("Sent report email",
				"recipient", recipient,
				"report_id", report.ID,
			)
		}
	}

	// Update report status to emailed
	now := time.Now()
	report.Status = model.ReportStatusEmailed
	report.EmailSentAt = &now
	if err := j.reportRepo.UpdateReport(ctx, report); err != nil {
		j.logger.Error("Failed to update report status after email",
			"report_id", report.ID,
			"error", err,
		)
	}
}

func (j *ReportGenerationJob) getReportTypeLabel(reportType string) string {
	switch reportType {
	case model.ReportTypeExecutive:
		return "エグゼクティブ"
	case model.ReportTypeTechnical:
		return "テクニカル"
	case model.ReportTypeCompliance:
		return "コンプライアンス"
	default:
		return "セキュリティ"
	}
}

func (j *ReportGenerationJob) generateReportEmailHTML(report *model.GeneratedReport) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f3f4f6;">
  <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
    <h1 style="color: #1f2937; font-size: 20px; margin-bottom: 16px;">SBOMHub レポート</h1>
    <p style="color: #4b5563; margin-bottom: 24px;">定期レポートが生成されました。添付ファイルをご確認ください。</p>
    <table style="width: 100%%; border-collapse: collapse; margin-bottom: 24px;">
      <tr>
        <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;"><strong>レポート種別</strong></td>
        <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">%s</td>
      </tr>
      <tr>
        <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;"><strong>対象期間</strong></td>
        <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">%s - %s</td>
      </tr>
      <tr>
        <td style="padding: 8px 0;"><strong>生成日時</strong></td>
        <td style="padding: 8px 0;">%s</td>
      </tr>
    </table>
    <p style="color: #6b7280; font-size: 12px; margin-top: 24px;">このメールはSBOMHubから自動送信されました。</p>
  </div>
</body>
</html>`,
		j.getReportTypeLabel(report.ReportType),
		report.PeriodStart.Format("2006-01-02"),
		report.PeriodEnd.Format("2006-01-02"),
		time.Now().Format("2006-01-02 15:04"),
	)
}

func (j *ReportGenerationJob) generateReportEmailText(report *model.GeneratedReport) string {
	return fmt.Sprintf(`SBOMHub レポート

定期レポートが生成されました。添付ファイルをご確認ください。

レポート種別: %s
対象期間: %s - %s
生成日時: %s

---
このメールはSBOMHubから自動送信されました。
`,
		j.getReportTypeLabel(report.ReportType),
		report.PeriodStart.Format("2006-01-02"),
		report.PeriodEnd.Format("2006-01-02"),
		time.Now().Format("2006-01-02 15:04"),
	)
}

func (j *ReportGenerationJob) sendEmailWithAttachment(to, subject, htmlBody, textBody, filename, contentType string, attachment []byte) error {
	from := j.cfg.SMTPFrom
	host := j.cfg.SMTPHost
	port := j.cfg.SMTPPort
	user := j.cfg.SMTPUser
	password := j.cfg.SMTPPassword

	boundary := "SBOMHubReportBoundary"

	var buf bytes.Buffer

	// Headers
	buf.WriteString(fmt.Sprintf("From: %s\r\n", from))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", to))
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	buf.WriteString("\r\n")

	// Text part
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Type: multipart/alternative; boundary=\"alt-boundary\"\r\n\r\n")

	buf.WriteString("--alt-boundary\r\n")
	buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	buf.WriteString(textBody)
	buf.WriteString("\r\n")

	buf.WriteString("--alt-boundary\r\n")
	buf.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n\r\n")
	buf.WriteString(htmlBody)
	buf.WriteString("\r\n")

	buf.WriteString("--alt-boundary--\r\n")

	// Attachment
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", contentType, filename))
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", filename))

	// Base64 encode attachment
	encoded := make([]byte, base64StdEncoding.EncodedLen(len(attachment)))
	base64StdEncoding.Encode(encoded, attachment)

	// Write in 76-char lines
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.Write(encoded[i:end])
		buf.WriteString("\r\n")
	}

	buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	addr := fmt.Sprintf("%s:%s", host, port)

	var auth smtp.Auth
	if user != "" && password != "" {
		auth = smtp.PlainAuth("", user, password, host)
	}

	return smtp.SendMail(addr, auth, from, []string{to}, buf.Bytes())
}

// ReportGenerationResult contains the result of a generation cycle
type ReportGenerationResult struct {
	Checked   int
	Generated int
	Failed    int
}

// RunOnce runs a single check and returns results
func (j *ReportGenerationJob) RunOnce(ctx context.Context) (*ReportGenerationResult, error) {
	now := time.Now()
	result := &ReportGenerationResult{}

	settings, err := j.reportRepo.GetEnabledSettings(ctx)
	if err != nil {
		return nil, err
	}

	result.Checked = len(settings)

	for _, setting := range settings {
		if j.shouldGenerate(&setting, now) {
			j.generateReport(ctx, &setting)
			result.Generated++
		}
	}

	return result, nil
}
