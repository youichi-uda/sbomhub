package scheduler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/smtp"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

var base64StdEncoding = base64.StdEncoding

// reportEligibilityBatchChunkSizeDefault is the production default for how
// many tenants to evaluate inside a single BEGIN / COMMIT envelope when
// enumerating enabled report_settings for the scheduler tick
// (F244, M16-4 #106).
//
// Horizontal replication of F234 (M15-2, vulnerability_scan.go):
//
//	F234 established chunk-based tx split for vulnerability_scan's
//	eligibility check to bound the tx-abort blast radius from
//	"the whole tick" to "one chunk of <= K tenants". F244 is the same
//	pattern applied to report_generation.go's read-only per-tenant
//	report_settings scan. The report_settings SELECT is even lighter
//	than scan_settings (typically 0-1 rows per tenant, single filter on
//	enabled=true), so the same K=500 sweet spot applies.
//
// Selection rationale — chosen 500 as the sweet spot between:
//
//   - Connection long-hold (upper bound): at ~2ms per SET LOCAL + SELECT
//     round-trip pair against a local PG (F213 baseline), 500 tenants ≈
//     1s of connection hold time per chunk. That stays well below the
//     hourly scheduler tick + leaves headroom for network jitter on
//     managed PG (e.g. RDS) where per-round-trip latency is ~1–5ms.
//
//   - Tx-abort blast radius (lower bound): ANY PG-side error inside a
//     chunk aborts the whole chunk's tx and skips the remaining tenants
//     in THAT chunk (they get retried on the next hourly tick). Smaller
//     chunks = smaller blast radius per failure event. At 500, a
//     worst-case cascade (statement timeout on a runaway RLS policy,
//     transient connection blip) skips at most 500 tenants for one tick
//     instead of all N.
//
//   - Round-trip overhead (envelope cost per additional chunk): each
//     extra chunk adds one BEGIN + one COMMIT = 2 round-trips. For
//     N=10000 (20 chunks) that's +38 round-trips over the pre-F244
//     per-tenant runWithTenantTx path — a rounding-error cost for a
//     linear reduction in blast radius, and a 2x improvement over the
//     pre-F244 per-tenant 4N+1 shape.
//
// Tests use reportEligibilityBatchChunkSize (the var below) to temporarily
// override with smaller values so multi-chunk semantics can be exercised
// without needing N=1000+ mock tenants.
const reportEligibilityBatchChunkSizeDefault = 500

// reportEligibilityBatchChunkSize is the effective chunk size used by
// listEnabledSettingsBatched / listDueSettingsBatched. In production this
// always equals reportEligibilityBatchChunkSizeDefault. Tests may
// temporarily override it (with a defer-restore) to force multi-chunk
// behaviour with small tenant fixtures. See vulnerability_scan_test.go's
// withChunkSize helper for the analogous pattern.
var reportEligibilityBatchChunkSize = reportEligibilityBatchChunkSizeDefault

// ReportGenerationJob handles periodic report generation.
//
// codex-r4 P1 fix:
//
//	`report_settings` and `generated_reports` are RLS-enabled (migration
//	013). The previous job called `reportRepo.GetEnabledSettings(ctx)` and
//	`reportRepo.GetReport*` on a bare scheduler context with no
//	`app.current_tenant_id` GUC, so under sbomhub_app it received zero
//	rows and never generated anything. The job now enumerates tenants via
//	TenantRepository and runs all read/write paths inside per-tenant
//	transactions. A direct *sql.DB handle is required for that — the
//	`db` field is the source for `runWithTenantTx`.
type ReportGenerationJob struct {
	reportService *service.ReportService
	reportRepo    *repository.ReportRepository
	tenantRepo    *repository.TenantRepository
	db            *sql.DB
	cfg           *config.Config
	interval      time.Duration
	logger        *slog.Logger
}

// NewReportGenerationJob creates a new report generation job.
//
// codex-r5 P2: the constructor also wires `db` into reportService via
// ReportService.SetDB so that generateReportAsync can open its own
// tenant-scoped tx for the terminal UPDATE on generated_reports. Without
// this, the HTTP-driven path leaves reports stuck at "generating" forever.
// NewReportService cannot take db directly because the cmd/server wiring
// file is settled in the review queue and must stay untouched.
func NewReportGenerationJob(
	reportService *service.ReportService,
	reportRepo *repository.ReportRepository,
	tenantRepo *repository.TenantRepository,
	db *sql.DB,
	interval time.Duration,
) *ReportGenerationJob {
	if reportService != nil {
		reportService.SetDB(db)
	}
	return &ReportGenerationJob{
		reportService: reportService,
		reportRepo:    reportRepo,
		tenantRepo:    tenantRepo,
		db:            db,
		interval:      interval,
		logger:        slog.Default().With("job", "report_generation"),
	}
}

// NewReportGenerationJobFull creates a new report generation job with full
// configuration. Mirrors NewReportGenerationJob's codex-r5 db injection so
// the production wiring (which uses ...Full) also gets the fix.
func NewReportGenerationJobFull(
	reportService *service.ReportService,
	reportRepo *repository.ReportRepository,
	tenantRepo *repository.TenantRepository,
	db *sql.DB,
	cfg *config.Config,
	interval time.Duration,
) *ReportGenerationJob {
	if reportService != nil {
		reportService.SetDB(db)
	}
	return &ReportGenerationJob{
		reportService: reportService,
		reportRepo:    reportRepo,
		tenantRepo:    tenantRepo,
		db:            db,
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

// run executes a single check cycle.
//
// Post-F244 (M16-4 #106): eligibility enumeration is delegated to
// listDueSettingsBatched, which walks every tenant on ONE pooled
// connection and splits the SET LOCAL + SELECT report_settings loop
// across N/K chunked transactions (chunk_size = 500). This is the
// horizontal replication of F234's chunk-based tx pattern from
// vulnerability_scan.go — same 2N + 2c + 1 round-trip formula, same
// chunk-local tx-abort blast-radius semantics, same real-PG integration
// smoke story.
//
// The actual per-setting generation is launched outside any tx so we do
// not hold a transaction open while reportService.GenerateReport runs
// (which itself spawns long-lived goroutines) — this is unchanged from
// the pre-F244 codex-r5 semantics.
func (j *ReportGenerationJob) run(ctx context.Context) {
	now := time.Now()
	j.logger.Debug("Checking scheduled reports", "time", now.Format("15:04"))

	_, due, err := j.listDueSettingsBatched(ctx, now)
	if err != nil {
		j.logger.Error("Failed to enumerate due report settings", "error", err)
		return
	}

	if len(due) == 0 {
		j.logger.Debug("No report schedules due this tick")
		return
	}

	for _, setting := range due {
		j.logger.Info("Triggering scheduled report generation",
			"tenant_id", setting.TenantID,
			"report_type", setting.ReportType,
			"format", setting.Format,
		)
		setting := setting // capture per iteration
		go j.generateReport(ctx, &setting)
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

// generateReport generates a report for a tenant.
//
// reportService.GenerateReport synchronously persists a `generated_reports`
// row (RLS-bound, requires tenant GUC) and returns a launcher closure that
// kicks off the actual PDF/XLSX build on a goroutine (codex-r6 P1). We
// only need the GUC for the synchronous DB insert, so the tenant tx wraps
// just the call into reportService. The launcher is invoked AFTER the tx
// returns so that the goroutine's terminal UpdateReport never races the
// CreateReport INSERT — when they ran inside the same tx the UPDATE could
// land first against a stale snapshot and silently match 0 rows.
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

	var (
		report   *model.GeneratedReport
		launcher func()
	)
	err := runWithTenantTx(ctx, j.db, setting.TenantID, func(txCtx context.Context, _ *sql.Tx) error {
		r, l, gerr := j.reportService.GenerateReport(txCtx, setting.TenantID, systemUserID, input)
		if gerr != nil {
			return gerr
		}
		report = r
		launcher = l
		return nil
	})
	if err != nil {
		j.logger.Error("Failed to generate scheduled report",
			"tenant_id", setting.TenantID,
			"report_type", setting.ReportType,
			"error", err,
			"duration_ms", time.Since(startTime).Milliseconds(),
		)
		return
	}

	// Now that the tenant tx has committed and the CreateReport row is
	// durable, fire the async builder. nil-check is defensive — on a nil
	// error GenerateReport guarantees a non-nil launcher, but we would
	// rather drop the launch than panic if that contract ever drifts.
	if launcher != nil {
		launcher()
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
		// Wait for report generation to complete (with timeout). Each poll
		// inside sendReportEmailWhenReady opens its own tenant tx.
		go j.sendReportEmailWhenReady(ctx, setting, report.ID)
	}
}

// sendReportEmailWhenReady waits for report completion and sends email.
// Each poll opens a fresh tenant tx so we never hold a transaction open
// across the 10-second sleep between polls.
func (j *ReportGenerationJob) sendReportEmailWhenReady(ctx context.Context, setting *model.ReportSettings, reportID uuid.UUID) {
	// Poll for report completion (max 5 minutes)
	maxWait := 5 * time.Minute
	pollInterval := 10 * time.Second
	startTime := time.Now()

	for time.Since(startTime) < maxWait {
		var report *model.GeneratedReport
		err := runWithTenantTx(ctx, j.db, setting.TenantID, func(txCtx context.Context, _ *sql.Tx) error {
			r, gerr := j.reportRepo.GetReport(txCtx, setting.TenantID, reportID)
			if gerr != nil {
				return gerr
			}
			report = r
			return nil
		})
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

// sendReportEmail sends the generated report via email.
// generated_reports is RLS-bound; both the content fetch and the
// post-email status update run inside per-tenant tx wrappers.
func (j *ReportGenerationJob) sendReportEmail(ctx context.Context, setting *model.ReportSettings, report *model.GeneratedReport) {
	if j.cfg == nil || !j.cfg.IsEmailEnabled() {
		j.logger.Debug("Email not configured, skipping report email")
		return
	}

	// Get report content
	var reportWithContent *model.GeneratedReport
	err := runWithTenantTx(ctx, j.db, setting.TenantID, func(txCtx context.Context, _ *sql.Tx) error {
		rwc, gerr := j.reportRepo.GetReportWithContent(txCtx, setting.TenantID, report.ID)
		if gerr != nil {
			return gerr
		}
		reportWithContent = rwc
		return nil
	})
	if err != nil || reportWithContent == nil || len(reportWithContent.FileContent) == 0 {
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

	// Update report status to emailed (RLS-bound, run inside tenant tx).
	now := time.Now()
	report.Status = model.ReportStatusEmailed
	report.EmailSentAt = &now
	updErr := runWithTenantTx(ctx, j.db, setting.TenantID, func(txCtx context.Context, _ *sql.Tx) error {
		return j.reportRepo.UpdateReport(txCtx, report)
	})
	if updErr != nil {
		j.logger.Error("Failed to update report status after email",
			"report_id", report.ID,
			"error", updErr,
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

// RunOnce runs a single check and returns results.
//
// Post-F244 (M16-4 #106): shares listDueSettingsBatched with run(). See
// the doc comment on run() for the round-trip formula (2N + 2c + 1) and
// chunk-local tx-abort blast-radius contract.
func (j *ReportGenerationJob) RunOnce(ctx context.Context) (*ReportGenerationResult, error) {
	now := time.Now()
	result := &ReportGenerationResult{}

	checked, due, err := j.listDueSettingsBatched(ctx, now)
	if err != nil {
		return nil, err
	}
	result.Checked = checked

	for _, setting := range due {
		setting := setting // capture
		j.generateReport(ctx, &setting)
		result.Generated++
	}

	return result, nil
}

// listEnabledSettingsBatched returns every enabled ReportSettings row
// across every tenant, evaluated under each tenant's own RLS context and
// coalesced onto one pooled connection but split across N/K chunked
// transactions for tx-abort blast-radius containment
// (F244, M16-4 #106).
//
// Horizontal replication of listDueTenantsBatched (F234, M15-2,
// vulnerability_scan.go). Same pooled-connection + chunked-tx shape,
// same tx-abort blast-radius contract, same anti-pattern-21 sqlmock
// caveat covered by report_generation_integration_test.go under the
// `integration` build tag.
//
// Design rationale (mirrors F234):
//
//	The pre-F244 implementation opened one per-tenant runWithTenantTx
//	for the enabled-settings enumeration alone, costing ~4 round-trips
//	per tenant (BEGIN + SET LOCAL + SELECT report_settings + COMMIT).
//	At N>=1000 that approached the hourly scheduler tick boundary at
//	p99 DB latency, mirroring the F193 ceiling that F213 / F234 addressed
//	on the vulnerability_scan path.
//
//	F244 evolves the report_generation enumeration to the F234 chunk
//	shape:
//
//	   - allTenants is split into chunks of reportEligibilityBatchChunkSize.
//	   - Each chunk gets its own BEGIN / per-tenant (SET LOCAL +
//	     GetEnabledSettings) loop / COMMIT.
//	   - A PG-side error inside chunk C aborts C's tx and skips the
//	     remaining tenants of C (they retry next tick); the loop then
//	     opens a fresh tx for chunk C+1 and continues.
//	   - The pooled connection is held across chunks (no reacquire),
//	     so PG-side connection state stays consistent and the pool
//	     sees exactly one lease per invocation.
//
// Round-trip accounting (N tenants, chunk_size K, num_chunks c=ceil(N/K)):
//
//	pre-F244 (per-tenant runWithTenantTx): 1 + 4N          = 4N + 1
//	F244     (chunked tx split):           1 + c*2 + 2N    = 2N + 2c + 1
//
//	  For c=1 (small N <= K) F244 equals a hypothetical single-tx
//	  2N + 3 exactly. Each additional chunk costs +2 round-trips
//	  (extra BEGIN + COMMIT).
//	  N=100,  K=500, c=1  -> 2*100  + 2*1  + 1 = 203   (2N + 3)
//	  N=1200, K=500, c=3  -> 2*1200 + 2*3  + 1 = 2407  (vs 4N+1 = 4801)
//
// Per-tenant error handling — F244 chunk-local blast radius:
//
//   - Repository-level errors from GetEnabledSettings (any non-nil
//     return other than an empty result set) mean PG has aborted the
//     enclosing tx. The chunk is rolled back, the remaining tenants of
//     that chunk are skipped for this tick (retried next hourly tick),
//     and the loop starts a fresh BEGIN for the next chunk.
//   - GetEnabledSettings returning an empty slice for a tenant is the
//     "no enabled report_settings for this tenant" path and continues
//     the chunk cleanly.
//   - SET LOCAL failure on one tenant is logged and terminates the
//     chunk with the same rollback-and-continue semantics.
//
// Anti-pattern 21 (sqlmock semantics limitation, F234 heritage):
// sqlmock does NOT model the "current transaction is aborted, commands
// ignored until end of transaction block" semantics. The unit tests
// exercise happy-path plus the code-side error paths, but the ACID
// contract that a PG-side error inside chunk C aborts C's tx
// server-side and lets chunk C+1 continue on the same pooled connection
// with a fresh BEGIN is pinned by report_generation_integration_test.go
// (build tag `integration`), following the same real-PG smoke pattern
// as F234's vulnerability_scan_integration_test.go.
func (j *ReportGenerationJob) listEnabledSettingsBatched(ctx context.Context) ([]model.ReportSettings, error) {
	tenantIDs, err := j.tenantRepo.ListAllIDs(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return nil, nil
	}

	conn, err := j.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("scheduler: acquire pooled conn for report eligibility batch: %w", err)
	}
	defer conn.Close()

	chunkSize := reportEligibilityBatchChunkSize
	if chunkSize <= 0 {
		// Defensive: a mis-set test override should not divide by zero
		// or spin forever. Fall back to the production default.
		chunkSize = reportEligibilityBatchChunkSizeDefault
	}

	enabled := make([]model.ReportSettings, 0, len(tenantIDs))
	numChunks := (len(tenantIDs) + chunkSize - 1) / chunkSize

	for chunkIndex := 0; chunkIndex < numChunks; chunkIndex++ {
		start := chunkIndex * chunkSize
		end := start + chunkSize
		if end > len(tenantIDs) {
			end = len(tenantIDs)
		}
		chunk := tenantIDs[start:end]

		chunkEnabled, chunkErr := j.evaluateEnabledSettingsChunk(ctx, conn, chunkIndex, chunk)
		// A chunk-level error is NOT fatal to the whole tick under F244 —
		// we log + move on so subsequent chunks still get evaluated.
		// evaluateEnabledSettingsChunk has already appended any
		// successfully collected settings to chunkEnabled before the error.
		if chunkErr != nil {
			j.logger.Warn("scheduler: report eligibility chunk aborted, continuing with next chunk (F244)",
				"chunk_index", chunkIndex,
				"chunk_size", len(chunk),
				"num_chunks", numChunks,
				"error", chunkErr,
			)
		}
		enabled = append(enabled, chunkEnabled...)
	}

	return enabled, nil
}

// evaluateEnabledSettingsChunk runs one chunk's BEGIN / per-tenant
// (SET LOCAL + GetEnabledSettings) loop / COMMIT on the caller's pinned
// connection (F244, M16-4 #106).
//
// Contract mirrors F234's evaluateEligibilityChunk (vulnerability_scan.go):
//
//   - Returns the enabled ReportSettings collected from `chunk`,
//     respecting each tenant's report_settings under its own RLS context.
//   - Returns (partial, error) if a PG-side error aborts the chunk's tx
//     mid-loop. Any settings successfully collected BEFORE the error are
//     still returned in the first slice — Go-side state is independent
//     of the PG tx that got rolled back. The caller
//     (listEnabledSettingsBatched) logs the error with chunk_index for
//     forensic tracing and starts a fresh chunk.
//   - SET LOCAL failure on one tenant is logged + terminates the chunk
//     with a partial return so the enclosing loop can start a fresh
//     BEGIN for the next chunk.
func (j *ReportGenerationJob) evaluateEnabledSettingsChunk(
	ctx context.Context,
	conn *sql.Conn,
	chunkIndex int,
	chunk []uuid.UUID,
) ([]model.ReportSettings, error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("scheduler: begin chunk %d report eligibility tx: %w", chunkIndex, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Bind the tx onto ctx so j.reportRepo.GetEnabledSettings (which
	// resolves database.Querier(txCtx, ...) back to the tx) runs its
	// SELECT inside the chunk's tx — see F185 GUC + tx-local scoping
	// discipline.
	txCtx := database.WithTx(ctx, tx)

	chunkEnabled := make([]model.ReportSettings, 0)
	for _, tenantID := range chunk {
		if _, sErr := tx.ExecContext(txCtx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); sErr != nil {
			j.logger.Warn("scheduler: failed to bind tenant GUC in chunked report eligibility check (F244)",
				"chunk_index", chunkIndex, "tenant_id", tenantID, "error", sErr)
			// See docstring: return the partial slice + the error so
			// listEnabledSettingsBatched can log + start a fresh chunk.
			return chunkEnabled, fmt.Errorf("scheduler: chunk %d SET LOCAL failed for tenant %s: %w",
				chunkIndex, tenantID, sErr)
		}

		settings, gerr := j.reportRepo.GetEnabledSettings(txCtx)
		if gerr != nil {
			j.logger.Warn("scheduler: failed to read report_settings in chunked eligibility check (F244)",
				"chunk_index", chunkIndex, "tenant_id", tenantID, "error", gerr)
			// Any error from GetEnabledSettings means PG has aborted the
			// enclosing tx. Return the partial slice + the error so
			// listEnabledSettingsBatched can log + start a fresh chunk.
			return chunkEnabled, fmt.Errorf("scheduler: chunk %d SELECT report_settings failed for tenant %s: %w",
				chunkIndex, tenantID, gerr)
		}
		j.logger.Debug("report eligibility scanned",
			"chunk_index", chunkIndex,
			"tenant_id", tenantID,
			"enabled_settings", len(settings),
		)
		chunkEnabled = append(chunkEnabled, settings...)
	}

	if err := tx.Commit(); err != nil {
		return chunkEnabled, fmt.Errorf("scheduler: commit chunk %d report eligibility tx: %w", chunkIndex, err)
	}
	committed = true
	return chunkEnabled, nil
}

// listDueSettingsBatched combines listEnabledSettingsBatched with the
// in-memory shouldGenerate schedule filter and returns
// (checkedEnabledCount, dueSettings, err).
//
// Used by both run() and RunOnce() so their enumeration path shares the
// same F244 chunk-based tx split. The "due" decision is a pure function
// of the enabled ReportSettings + `now`, so no additional round-trip is
// needed: the round-trip formula is exactly that of
// listEnabledSettingsBatched (2N + 2c + 1).
func (j *ReportGenerationJob) listDueSettingsBatched(
	ctx context.Context,
	now time.Time,
) (int, []model.ReportSettings, error) {
	enabled, err := j.listEnabledSettingsBatched(ctx)
	if err != nil {
		return 0, nil, err
	}
	due := make([]model.ReportSettings, 0, len(enabled))
	for _, s := range enabled {
		if j.shouldGenerate(&s, now) {
			due = append(due, s)
		}
	}
	return len(enabled), due, nil
}
