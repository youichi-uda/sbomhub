package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/egress"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// notificationStore is the repository surface NotificationService needs. It
// exists as an interface so the webhook delivery path can be exercised without
// a database — the SSRF regression in ssrf_notification_test.go asserts on what
// the HTTP client did, and standing up Postgres to reach that assertion would
// have meant the assertion was never written.
// *repository.NotificationRepository satisfies it.
type notificationStore interface {
	GetSettings(ctx context.Context, projectID uuid.UUID) (*model.NotificationSettings, error)
	UpsertSettings(ctx context.Context, settings *model.NotificationSettings) error
	CreateLog(ctx context.Context, log *model.NotificationLog) error
	GetLogs(ctx context.Context, projectID uuid.UUID, limit int) ([]model.NotificationLog, error)
}

// notificationHTTPTimeout is the per-delivery budget. Unchanged from the value
// the service used before the egress guard was introduced.
const notificationHTTPTimeout = 10 * time.Second

type NotificationService struct {
	notifRepo   notificationStore
	projectRepo *repository.ProjectRepository
	client      *http.Client
	cfg         *config.Config
	// egress is the destination policy for Slack / Discord webhook delivery.
	// notification_settings.slack_webhook_url and .discord_webhook_url are
	// written straight from the API body, so the delivery target is
	// tenant-supplied input.
	egress *egress.Guard
}

// NewNotificationService constructs the service.
//
// SECURITY: guard is the outbound destination policy (internal/egress). Nil
// means "the caller did not say", which resolves to the strictest policy
// rather than to none — before M50 this sink had NO destination validation
// anywhere between the API body and http.Client.Do, and no redirect policy.
func NewNotificationService(notifRepo *repository.NotificationRepository, projectRepo *repository.ProjectRepository, cfg *config.Config, guard *egress.Guard) *NotificationService {
	var store notificationStore
	if notifRepo != nil {
		store = notifRepo
	}
	return newNotificationService(store, projectRepo, cfg, guard)
}

func newNotificationService(notifRepo notificationStore, projectRepo *repository.ProjectRepository, cfg *config.Config, guard *egress.Guard) *NotificationService {
	if guard == nil {
		guard = egress.NewSet(egress.Settings{}).NotificationWebhook
	}
	return &NotificationService{
		notifRepo:   notifRepo,
		projectRepo: projectRepo,
		client:      guard.Client(notificationHTTPTimeout),
		cfg:         cfg,
		egress:      guard,
	}
}

// GetSettings gets notification settings for a project
func (s *NotificationService) GetSettings(ctx context.Context, projectID uuid.UUID) (*model.NotificationSettings, error) {
	settings, err := s.notifRepo.GetSettings(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if settings == nil {
		// Return default settings
		return &model.NotificationSettings{
			ProjectID:      projectID,
			NotifyCritical: true,
			NotifyHigh:     true,
			NotifyMedium:   false,
			NotifyLow:      false,
		}, nil
	}
	return settings, nil
}

// UpdateSettings updates notification settings for a project
func (s *NotificationService) UpdateSettings(ctx context.Context, projectID uuid.UUID, input UpdateNotificationSettingsInput) (*model.NotificationSettings, error) {
	// Resolve the tenant_id of the parent project so the INSERT/UPSERT
	// satisfies the FORCE RLS WITH CHECK clause on notification_settings
	// (see migration 023).
	tenantID, err := s.projectRepo.GetTenantID(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve project tenant: %w", err)
	}

	// Early rejection so a bad URL surfaces on the settings screen instead of
	// as a silent delivery failure hours later. This is NOT the defence — the
	// guard on s.client is (see internal/egress) — but it is the difference
	// between a 400 the admin can act on and a webhook that never fires.
	//
	// The normalised values are what get persisted below, so the string that is
	// checked here is the string that is later dialed. See normaliseEgressURL.
	slackURL := normaliseEgressURL(input.SlackWebhookURL)
	discordURL := normaliseEgressURL(input.DiscordWebhookURL)
	for label, raw := range map[string]string{
		"slack_webhook_url":   slackURL,
		"discord_webhook_url": discordURL,
	} {
		if raw == "" {
			continue
		}
		if verr := s.egress.ValidateURL(raw); verr != nil {
			return nil, ValidationErrorf("invalid %s: %v", label, verr)
		}
	}

	now := time.Now()
	settings := &model.NotificationSettings{
		ID:                uuid.New(),
		TenantID:          tenantID,
		ProjectID:         projectID,
		SlackWebhookURL:   slackURL,
		DiscordWebhookURL: discordURL,
		EmailAddresses:    input.EmailAddresses,
		NotifyCritical:    input.NotifyCritical,
		NotifyHigh:        input.NotifyHigh,
		NotifyMedium:      input.NotifyMedium,
		NotifyLow:         input.NotifyLow,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.notifRepo.UpsertSettings(ctx, settings); err != nil {
		return nil, fmt.Errorf("failed to update settings: %w", err)
	}

	return settings, nil
}

type UpdateNotificationSettingsInput struct {
	SlackWebhookURL   string `json:"slack_webhook_url"`
	DiscordWebhookURL string `json:"discord_webhook_url"`
	EmailAddresses    string `json:"email_addresses"`
	NotifyCritical    bool   `json:"notify_critical"`
	NotifyHigh        bool   `json:"notify_high"`
	NotifyMedium      bool   `json:"notify_medium"`
	NotifyLow         bool   `json:"notify_low"`
}

// SendTestNotification sends a test notification
func (s *NotificationService) SendTestNotification(ctx context.Context, projectID uuid.UUID) error {
	settings, err := s.notifRepo.GetSettings(ctx, projectID)
	if err != nil {
		return err
	}
	if settings == nil {
		return fmt.Errorf("notification settings not configured")
	}

	project, err := s.projectRepo.Get(ctx, projectID)
	if err != nil {
		return err
	}

	// Resolve the tenant_id of the parent project once so every
	// notification_logs INSERT downstream satisfies the FORCE RLS WITH
	// CHECK clause (see migration 023). Reusing the lookup keeps the
	// per-channel send paths from each issuing their own query.
	tenantID, err := s.projectRepo.GetTenantID(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to resolve project tenant: %w", err)
	}

	testCVSS := 9.8
	testEPSS := 0.95
	testNotif := model.VulnerabilityNotification{
		CVEID:            "CVE-0000-0000",
		CVSSScore:        &testCVSS,
		EPSSScore:        &testEPSS,
		Severity:         "CRITICAL",
		ProjectID:        projectID.String(),
		ProjectName:      project.Name,
		ComponentName:    "test-component",
		ComponentVersion: "1.0.0",
		DetailsURL:       fmt.Sprintf("%s/projects/%s/vulnerabilities", s.cfg.BaseURL, projectID),
	}

	if settings.SlackWebhookURL != "" {
		if err := s.sendSlackNotification(ctx, settings.SlackWebhookURL, testNotif, tenantID, projectID); err != nil {
			return fmt.Errorf("slack notification failed: %w", err)
		}
	}

	if settings.DiscordWebhookURL != "" {
		if err := s.sendDiscordNotification(ctx, settings.DiscordWebhookURL, testNotif, tenantID, projectID); err != nil {
			return fmt.Errorf("discord notification failed: %w", err)
		}
	}

	if settings.EmailAddresses != "" {
		if err := s.sendEmailNotification(ctx, settings.EmailAddresses, testNotif, tenantID, projectID); err != nil {
			return fmt.Errorf("email notification failed: %w", err)
		}
	}

	return nil
}

// NotifyVulnerability sends notifications for a new vulnerability
func (s *NotificationService) NotifyVulnerability(ctx context.Context, projectID uuid.UUID, notif model.VulnerabilityNotification) error {
	settings, err := s.notifRepo.GetSettings(ctx, projectID)
	if err != nil {
		return err
	}
	if settings == nil {
		return nil // No settings configured
	}

	// Check if we should notify for this severity
	shouldNotify := false
	switch notif.Severity {
	case "CRITICAL":
		shouldNotify = settings.NotifyCritical
	case "HIGH":
		shouldNotify = settings.NotifyHigh
	case "MEDIUM":
		shouldNotify = settings.NotifyMedium
	case "LOW":
		shouldNotify = settings.NotifyLow
	}

	if !shouldNotify {
		return nil
	}

	// Resolve the tenant_id of the parent project once so every
	// notification_logs INSERT downstream satisfies the FORCE RLS WITH
	// CHECK clause (see migration 023). The scheduler caller already runs
	// inside a tx with `app.current_tenant_id` set, so this SELECT is
	// permitted.
	tenantID, err := s.projectRepo.GetTenantID(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to resolve project tenant: %w", err)
	}

	notif.DetailsURL = fmt.Sprintf("%s/projects/%s/vulnerabilities", s.cfg.BaseURL, projectID)

	var errs []error
	if settings.SlackWebhookURL != "" {
		if err := s.sendSlackNotification(ctx, settings.SlackWebhookURL, notif, tenantID, projectID); err != nil {
			errs = append(errs, err)
		}
	}

	if settings.DiscordWebhookURL != "" {
		if err := s.sendDiscordNotification(ctx, settings.DiscordWebhookURL, notif, tenantID, projectID); err != nil {
			errs = append(errs, err)
		}
	}

	if settings.EmailAddresses != "" {
		if err := s.sendEmailNotification(ctx, settings.EmailAddresses, notif, tenantID, projectID); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}
	return nil
}

// notifCVSSText renders a notification CVSS value. nil means the CVE has not
// been scored (NVD "Awaiting Analysis") and renders as 未採点 — NEVER "0.0":
// CVSS 0.0 is a real "None" score, so a 0-sentinel would present an
// un-triaged finding as harmless (M46 wave 4). The wording matches the web
// UI's un-scored rendering (create-ticket-button, ja locale); the
// notification bodies are Japanese-fixed (新規%s脆弱性検出), so no en variant
// is needed here.
func notifCVSSText(score *float64) string {
	if score == nil {
		return "未採点"
	}
	return fmt.Sprintf("%.1f", *score)
}

// notifEPSSText renders a notification's EPSS for Slack / Discord / email.
// nil means FIRST.org has no score for this CVE — render 未採点, never
// "0.0%": epss_score is DECIMAL(5,4), so a stored 0.0000 is a real
// prediction of a ~0% exploitation chance, and printing an unknown as 0.0%
// tells the reader a measurement was made that never was (M47 W4, same
// contract as notifCVSSText above).
func notifEPSSText(score *float64) string {
	if score == nil {
		return "未採点"
	}
	return fmt.Sprintf("%.1f%%", *score*100)
}

// buildSlackVulnerabilityPayload assembles the Slack Block Kit payload for a
// vulnerability notification. Pure (no I/O) so the rendered text — in
// particular the un-scored CVSS contract — is unit-testable without a
// webhook endpoint.
func buildSlackVulnerabilityPayload(notif model.VulnerabilityNotification) map[string]interface{} {
	severityEmoji := map[string]string{
		"CRITICAL": ":red_circle:",
		"HIGH":     ":orange_circle:",
		"MEDIUM":   ":yellow_circle:",
		"LOW":      ":green_circle:",
	}

	emoji := severityEmoji[notif.Severity]
	if emoji == "" {
		emoji = ":warning:"
	}

	return map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": fmt.Sprintf("%s 新規%s脆弱性検出", emoji, notif.Severity),
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{"type": "mrkdwn", "text": fmt.Sprintf("*CVE ID:*\n%s", notif.CVEID)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*CVSS:*\n%s (%s)", notifCVSSText(notif.CVSSScore), notif.Severity)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*EPSS:*\n%s", notifEPSSText(notif.EPSSScore))},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Project:*\n%s", notif.ProjectName)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Component:*\n%s@%s", notif.ComponentName, notif.ComponentVersion)},
				},
			},
			{
				"type": "actions",
				"elements": []map[string]interface{}{
					{
						"type": "button",
						"text": map[string]interface{}{
							"type": "plain_text",
							"text": "詳細を見る",
						},
						"url": notif.DetailsURL,
					},
				},
			},
		},
	}
}

func (s *NotificationService) sendSlackNotification(ctx context.Context, webhookURL string, notif model.VulnerabilityNotification, tenantID, projectID uuid.UUID) error {
	payload := buildSlackVulnerabilityPayload(notif)
	return s.sendWebhook(ctx, webhookURL, payload, model.NotificationChannelSlack, tenantID, projectID)
}

// buildDiscordVulnerabilityPayload assembles the Discord embed payload for a
// vulnerability notification. Pure for the same reason as
// buildSlackVulnerabilityPayload.
func buildDiscordVulnerabilityPayload(notif model.VulnerabilityNotification) map[string]interface{} {
	colorMap := map[string]int{
		"CRITICAL": 15158332, // Red
		"HIGH":     15105570, // Orange
		"MEDIUM":   16776960, // Yellow
		"LOW":      3066993,  // Green
	}

	color := colorMap[notif.Severity]
	if color == 0 {
		color = 3447003 // Blue
	}

	return map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("新規%s脆弱性検出", notif.Severity),
				"description": fmt.Sprintf("**%s** が検出されました", notif.CVEID),
				"color":       color,
				"fields": []map[string]interface{}{
					{"name": "CVE ID", "value": notif.CVEID, "inline": true},
					{"name": "CVSS", "value": notifCVSSText(notif.CVSSScore), "inline": true},
					{"name": "EPSS", "value": notifEPSSText(notif.EPSSScore), "inline": true},
					{"name": "Project", "value": notif.ProjectName, "inline": true},
					{"name": "Component", "value": fmt.Sprintf("%s@%s", notif.ComponentName, notif.ComponentVersion), "inline": true},
				},
				"url": notif.DetailsURL,
			},
		},
	}
}

func (s *NotificationService) sendDiscordNotification(ctx context.Context, webhookURL string, notif model.VulnerabilityNotification, tenantID, projectID uuid.UUID) error {
	payload := buildDiscordVulnerabilityPayload(notif)
	return s.sendWebhook(ctx, webhookURL, payload, model.NotificationChannelDiscord, tenantID, projectID)
}

func (s *NotificationService) sendWebhook(ctx context.Context, webhookURL string, payload interface{}, channel model.NotificationChannel, tenantID, projectID uuid.UUID) error {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		// F445: raw network/framework error (and any remote detail) is kept
		// server-side only; the persisted error_message is returned to
		// clients via the notification logs, so store a generic message.
		slog.Warn("notification: webhook delivery failed", "channel", channel, "error", err)
		s.logNotification(ctx, tenantID, projectID, channel, string(jsonPayload), "failed", "notification delivery failed")
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// F445: the remote HTTP status is raw delivery detail; keep it in
		// slog only and persist a generic client-facing message.
		slog.Warn("notification: webhook delivery failed", "channel", channel, "status", resp.StatusCode)
		s.logNotification(ctx, tenantID, projectID, channel, string(jsonPayload), "failed", "notification delivery failed")
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	s.logNotification(ctx, tenantID, projectID, channel, string(jsonPayload), "sent", "")
	return nil
}

func (s *NotificationService) logNotification(ctx context.Context, tenantID, projectID uuid.UUID, channel model.NotificationChannel, payload, status, errMsg string) {
	log := &model.NotificationLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		ProjectID:    projectID,
		Channel:      channel,
		Payload:      payload,
		Status:       status,
		ErrorMessage: errMsg,
		CreatedAt:    time.Now(),
	}
	if s.notifRepo == nil {
		// No store wired. Production always wires one; this keeps the
		// best-effort audit path from panicking a delivery that otherwise
		// succeeded.
		return
	}
	if err := s.notifRepo.CreateLog(ctx, log); err != nil {
		slog.Error("Failed to create notification log", "error", err)
	}
}

// GetLogs gets notification logs for a project
func (s *NotificationService) GetLogs(ctx context.Context, projectID uuid.UUID, limit int) ([]model.NotificationLog, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.notifRepo.GetLogs(ctx, projectID, limit)
}

// sendEmailNotification sends email notifications for a vulnerability
func (s *NotificationService) sendEmailNotification(ctx context.Context, emailAddresses string, notif model.VulnerabilityNotification, tenantID, projectID uuid.UUID) error {
	if !s.cfg.IsEmailEnabled() {
		slog.Debug("Email notifications disabled - SMTP not configured")
		return nil
	}

	recipients := parseEmailAddresses(emailAddresses)
	if len(recipients) == 0 {
		return nil
	}

	subject := fmt.Sprintf("[SBOMHub] %s脆弱性検出: %s", notif.Severity, notif.CVEID)
	htmlBody := s.generateEmailHTML(notif)
	textBody := s.generateEmailText(notif)

	for _, to := range recipients {
		if err := s.sendSMTPEmail(to, subject, htmlBody, textBody); err != nil {
			// F445: raw SMTP/framework error kept server-side only; persisted
			// error_message is client-facing, so store a generic message.
			slog.Warn("notification: email delivery failed", "error", err)
			s.logNotification(ctx, tenantID, projectID, model.NotificationChannelEmail, fmt.Sprintf("to: %s", to), "failed", "notification delivery failed")
			return err
		}
		s.logNotification(ctx, tenantID, projectID, model.NotificationChannelEmail, fmt.Sprintf("to: %s", to), "sent", "")
	}

	return nil
}

// sendSMTPEmail sends an email via SMTP
func (s *NotificationService) sendSMTPEmail(to, subject, htmlBody, textBody string) error {
	from := s.cfg.SMTPFrom
	host := s.cfg.SMTPHost
	port := s.cfg.SMTPPort
	user := s.cfg.SMTPUser
	password := s.cfg.SMTPPassword

	// Build multipart email with both HTML and plain text
	boundary := "SBOMHubEmailBoundary"
	headers := fmt.Sprintf("From: %s\r\n", from)
	headers += fmt.Sprintf("To: %s\r\n", to)
	headers += fmt.Sprintf("Subject: %s\r\n", subject)
	headers += "MIME-Version: 1.0\r\n"
	headers += fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary)
	headers += "\r\n"

	body := fmt.Sprintf("--%s\r\n", boundary)
	body += "Content-Type: text/plain; charset=\"utf-8\"\r\n"
	body += "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
	body += textBody + "\r\n"

	body += fmt.Sprintf("--%s\r\n", boundary)
	body += "Content-Type: text/html; charset=\"utf-8\"\r\n"
	body += "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
	body += htmlBody + "\r\n"

	body += fmt.Sprintf("--%s--\r\n", boundary)

	message := headers + body

	addr := fmt.Sprintf("%s:%s", host, port)

	var auth smtp.Auth
	if user != "" && password != "" {
		auth = smtp.PlainAuth("", user, password, host)
	}

	if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(message)); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// generateEmailHTML generates an HTML email body for vulnerability notification
func (s *NotificationService) generateEmailHTML(notif model.VulnerabilityNotification) string {
	severityColors := map[string]string{
		"CRITICAL": "#dc2626",
		"HIGH":     "#ea580c",
		"MEDIUM":   "#ca8a04",
		"LOW":      "#16a34a",
	}

	color := severityColors[notif.Severity]
	if color == "" {
		color = "#6b7280"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; margin: 0; padding: 20px; background-color: #f3f4f6;">
  <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
    <div style="background-color: %s; padding: 20px; text-align: center;">
      <h1 style="color: white; margin: 0; font-size: 18px;">新規%s脆弱性検出</h1>
    </div>
    <div style="padding: 24px;">
      <table style="width: 100%%; border-collapse: collapse; margin-bottom: 20px;">
        <tr>
          <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;"><strong>CVE ID</strong></td>
          <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">%s</td>
        </tr>
        <tr>
          <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;"><strong>CVSS Score</strong></td>
          <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">%s (%s)</td>
        </tr>
        <tr>
          <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;"><strong>EPSS Score</strong></td>
          <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">%s</td>
        </tr>
        <tr>
          <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;"><strong>Project</strong></td>
          <td style="padding: 8px 0; border-bottom: 1px solid #e5e7eb;">%s</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Component</strong></td>
          <td style="padding: 8px 0;">%s@%s</td>
        </tr>
      </table>
      <div style="text-align: center;">
        <a href="%s" style="display: inline-block; background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">詳細を見る</a>
      </div>
    </div>
    <div style="background-color: #f9fafb; padding: 16px; text-align: center; font-size: 12px; color: #6b7280;">
      <p style="margin: 0;">このメールはSBOMHubから自動送信されました。</p>
    </div>
  </div>
</body>
</html>`,
		color,
		notif.Severity,
		notif.CVEID,
		notifCVSSText(notif.CVSSScore),
		notif.Severity,
		notifEPSSText(notif.EPSSScore),
		notif.ProjectName,
		notif.ComponentName,
		notif.ComponentVersion,
		notif.DetailsURL,
	)

	return html
}

// generateEmailText generates a plain text email body for vulnerability notification
func (s *NotificationService) generateEmailText(notif model.VulnerabilityNotification) string {
	text := fmt.Sprintf(`[SBOMHub] 新規%s脆弱性検出

CVE ID: %s
CVSS Score: %s (%s)
EPSS Score: %s
Project: %s
Component: %s@%s

詳細を確認: %s

---
このメールはSBOMHubから自動送信されました。
`,
		notif.Severity,
		notif.CVEID,
		notifCVSSText(notif.CVSSScore),
		notif.Severity,
		notifEPSSText(notif.EPSSScore),
		notif.ProjectName,
		notif.ComponentName,
		notif.ComponentVersion,
		notif.DetailsURL,
	)

	return text
}

// parseEmailAddresses parses a comma-separated list of email addresses
func parseEmailAddresses(addresses string) []string {
	if addresses == "" {
		return nil
	}

	parts := strings.Split(addresses, ",")
	var result []string
	for _, part := range parts {
		email := strings.TrimSpace(part)
		if email != "" && strings.Contains(email, "@") {
			result = append(result, email)
		}
	}
	return result
}
