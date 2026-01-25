package model

import (
	"time"

	"github.com/google/uuid"
)

// NotificationSettings represents notification configuration for a project
type NotificationSettings struct {
	ID                uuid.UUID `json:"id" db:"id"`
	ProjectID         uuid.UUID `json:"project_id" db:"project_id"`
	SlackWebhookURL   string    `json:"slack_webhook_url,omitempty" db:"slack_webhook_url"`
	DiscordWebhookURL string    `json:"discord_webhook_url,omitempty" db:"discord_webhook_url"`
	NotifyCritical    bool      `json:"notify_critical" db:"notify_critical"`
	NotifyHigh        bool      `json:"notify_high" db:"notify_high"`
	NotifyMedium      bool      `json:"notify_medium" db:"notify_medium"`
	NotifyLow         bool      `json:"notify_low" db:"notify_low"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// NotificationChannel represents the notification channel type
type NotificationChannel string

const (
	NotificationChannelSlack   NotificationChannel = "slack"
	NotificationChannelDiscord NotificationChannel = "discord"
)

// NotificationLog represents a notification send log
type NotificationLog struct {
	ID           uuid.UUID           `json:"id" db:"id"`
	ProjectID    uuid.UUID           `json:"project_id" db:"project_id"`
	Channel      NotificationChannel `json:"channel" db:"channel"`
	Payload      string              `json:"payload" db:"payload"`
	Status       string              `json:"status" db:"status"` // sent, failed
	ErrorMessage string              `json:"error_message,omitempty" db:"error_message"`
	CreatedAt    time.Time           `json:"created_at" db:"created_at"`
}

// VulnerabilityNotification represents data for a vulnerability notification
type VulnerabilityNotification struct {
	CVEID            string  `json:"cve_id"`
	CVSSScore        float64 `json:"cvss_score"`
	EPSSScore        float64 `json:"epss_score"`
	Severity         string  `json:"severity"`
	ProjectID        string  `json:"project_id"`
	ProjectName      string  `json:"project_name"`
	ComponentName    string  `json:"component_name"`
	ComponentVersion string  `json:"component_version"`
	DetailsURL       string  `json:"details_url"`
}
