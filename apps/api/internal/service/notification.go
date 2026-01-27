package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type NotificationService struct {
	notifRepo   *repository.NotificationRepository
	projectRepo *repository.ProjectRepository
	client      *http.Client
	baseURL     string
}

func NewNotificationService(notifRepo *repository.NotificationRepository, projectRepo *repository.ProjectRepository, baseURL string) *NotificationService {
	return &NotificationService{
		notifRepo:   notifRepo,
		projectRepo: projectRepo,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL: baseURL,
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
	now := time.Now()
	settings := &model.NotificationSettings{
		ID:                uuid.New(),
		ProjectID:         projectID,
		SlackWebhookURL:   input.SlackWebhookURL,
		DiscordWebhookURL: input.DiscordWebhookURL,
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

	testNotif := model.VulnerabilityNotification{
		CVEID:            "CVE-0000-0000",
		CVSSScore:        9.8,
		EPSSScore:        0.95,
		Severity:         "CRITICAL",
		ProjectID:        projectID.String(),
		ProjectName:      project.Name,
		ComponentName:    "test-component",
		ComponentVersion: "1.0.0",
		DetailsURL:       fmt.Sprintf("%s/projects/%s/vulnerabilities", s.baseURL, projectID),
	}

	if settings.SlackWebhookURL != "" {
		if err := s.sendSlackNotification(ctx, settings.SlackWebhookURL, testNotif, projectID); err != nil {
			return fmt.Errorf("slack notification failed: %w", err)
		}
	}

	if settings.DiscordWebhookURL != "" {
		if err := s.sendDiscordNotification(ctx, settings.DiscordWebhookURL, testNotif, projectID); err != nil {
			return fmt.Errorf("discord notification failed: %w", err)
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

	notif.DetailsURL = fmt.Sprintf("%s/projects/%s/vulnerabilities", s.baseURL, projectID)

	var errs []error
	if settings.SlackWebhookURL != "" {
		if err := s.sendSlackNotification(ctx, settings.SlackWebhookURL, notif, projectID); err != nil {
			errs = append(errs, err)
		}
	}

	if settings.DiscordWebhookURL != "" {
		if err := s.sendDiscordNotification(ctx, settings.DiscordWebhookURL, notif, projectID); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}
	return nil
}

func (s *NotificationService) sendSlackNotification(ctx context.Context, webhookURL string, notif model.VulnerabilityNotification, projectID uuid.UUID) error {
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

	payload := map[string]interface{}{
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
					{"type": "mrkdwn", "text": fmt.Sprintf("*CVSS:*\n%.1f (%s)", notif.CVSSScore, notif.Severity)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*EPSS:*\n%.1f%%", notif.EPSSScore*100)},
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

	return s.sendWebhook(ctx, webhookURL, payload, model.NotificationChannelSlack, projectID)
}

func (s *NotificationService) sendDiscordNotification(ctx context.Context, webhookURL string, notif model.VulnerabilityNotification, projectID uuid.UUID) error {
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

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("新規%s脆弱性検出", notif.Severity),
				"description": fmt.Sprintf("**%s** が検出されました", notif.CVEID),
				"color":       color,
				"fields": []map[string]interface{}{
					{"name": "CVE ID", "value": notif.CVEID, "inline": true},
					{"name": "CVSS", "value": fmt.Sprintf("%.1f", notif.CVSSScore), "inline": true},
					{"name": "EPSS", "value": fmt.Sprintf("%.1f%%", notif.EPSSScore*100), "inline": true},
					{"name": "Project", "value": notif.ProjectName, "inline": true},
					{"name": "Component", "value": fmt.Sprintf("%s@%s", notif.ComponentName, notif.ComponentVersion), "inline": true},
				},
				"url": notif.DetailsURL,
			},
		},
	}

	return s.sendWebhook(ctx, webhookURL, payload, model.NotificationChannelDiscord, projectID)
}

func (s *NotificationService) sendWebhook(ctx context.Context, webhookURL string, payload interface{}, channel model.NotificationChannel, projectID uuid.UUID) error {
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
		s.logNotification(ctx, projectID, channel, string(jsonPayload), "failed", err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errMsg := fmt.Sprintf("webhook returned status %d", resp.StatusCode)
		s.logNotification(ctx, projectID, channel, string(jsonPayload), "failed", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	s.logNotification(ctx, projectID, channel, string(jsonPayload), "sent", "")
	return nil
}

func (s *NotificationService) logNotification(ctx context.Context, projectID uuid.UUID, channel model.NotificationChannel, payload, status, errMsg string) {
	log := &model.NotificationLog{
		ID:           uuid.New(),
		ProjectID:    projectID,
		Channel:      channel,
		Payload:      payload,
		Status:       status,
		ErrorMessage: errMsg,
		CreatedAt:    time.Now(),
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
