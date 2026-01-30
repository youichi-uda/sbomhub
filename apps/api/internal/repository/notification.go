package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type NotificationRepository struct {
	db *sql.DB
}

func NewNotificationRepository(db *sql.DB) *NotificationRepository {
	return &NotificationRepository{db: db}
}

func (r *NotificationRepository) GetSettings(ctx context.Context, projectID uuid.UUID) (*model.NotificationSettings, error) {
	query := `
		SELECT id, project_id, slack_webhook_url, discord_webhook_url, email_addresses,
		       notify_critical, notify_high, notify_medium, notify_low,
		       created_at, updated_at
		FROM notification_settings
		WHERE project_id = $1
	`
	var settings model.NotificationSettings
	var slackURL, discordURL, emailAddresses sql.NullString
	err := r.db.QueryRowContext(ctx, query, projectID).Scan(
		&settings.ID,
		&settings.ProjectID,
		&slackURL,
		&discordURL,
		&emailAddresses,
		&settings.NotifyCritical,
		&settings.NotifyHigh,
		&settings.NotifyMedium,
		&settings.NotifyLow,
		&settings.CreatedAt,
		&settings.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	settings.SlackWebhookURL = slackURL.String
	settings.DiscordWebhookURL = discordURL.String
	settings.EmailAddresses = emailAddresses.String
	return &settings, nil
}

func (r *NotificationRepository) UpsertSettings(ctx context.Context, settings *model.NotificationSettings) error {
	query := `
		INSERT INTO notification_settings (
			id, project_id, slack_webhook_url, discord_webhook_url, email_addresses,
			notify_critical, notify_high, notify_medium, notify_low,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (project_id)
		DO UPDATE SET
			slack_webhook_url = EXCLUDED.slack_webhook_url,
			discord_webhook_url = EXCLUDED.discord_webhook_url,
			email_addresses = EXCLUDED.email_addresses,
			notify_critical = EXCLUDED.notify_critical,
			notify_high = EXCLUDED.notify_high,
			notify_medium = EXCLUDED.notify_medium,
			notify_low = EXCLUDED.notify_low,
			updated_at = EXCLUDED.updated_at
	`

	var slackURL, discordURL, emailAddresses sql.NullString
	if settings.SlackWebhookURL != "" {
		slackURL = sql.NullString{String: settings.SlackWebhookURL, Valid: true}
	}
	if settings.DiscordWebhookURL != "" {
		discordURL = sql.NullString{String: settings.DiscordWebhookURL, Valid: true}
	}
	if settings.EmailAddresses != "" {
		emailAddresses = sql.NullString{String: settings.EmailAddresses, Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query,
		settings.ID,
		settings.ProjectID,
		slackURL,
		discordURL,
		emailAddresses,
		settings.NotifyCritical,
		settings.NotifyHigh,
		settings.NotifyMedium,
		settings.NotifyLow,
		settings.CreatedAt,
		settings.UpdatedAt,
	)
	return err
}

func (r *NotificationRepository) CreateLog(ctx context.Context, log *model.NotificationLog) error {
	query := `
		INSERT INTO notification_logs (id, project_id, channel, payload, status, error_message, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	var errMsg sql.NullString
	if log.ErrorMessage != "" {
		errMsg = sql.NullString{String: log.ErrorMessage, Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query,
		log.ID,
		log.ProjectID,
		log.Channel,
		log.Payload,
		log.Status,
		errMsg,
		log.CreatedAt,
	)
	return err
}

func (r *NotificationRepository) GetLogs(ctx context.Context, projectID uuid.UUID, limit int) ([]model.NotificationLog, error) {
	query := `
		SELECT id, project_id, channel, payload, status, error_message, created_at
		FROM notification_logs
		WHERE project_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []model.NotificationLog
	for rows.Next() {
		var log model.NotificationLog
		var errMsg sql.NullString
		if err := rows.Scan(
			&log.ID,
			&log.ProjectID,
			&log.Channel,
			&log.Payload,
			&log.Status,
			&errMsg,
			&log.CreatedAt,
		); err != nil {
			return nil, err
		}
		log.ErrorMessage = errMsg.String
		logs = append(logs, log)
	}

	if logs == nil {
		logs = []model.NotificationLog{}
	}
	return logs, rows.Err()
}

// GetAllSettingsForSeverity gets all notification settings that match a severity level
func (r *NotificationRepository) GetAllSettingsForSeverity(ctx context.Context, severity string) ([]model.NotificationSettings, error) {
	var query string
	switch severity {
	case "CRITICAL":
		query = `SELECT id, project_id, slack_webhook_url, discord_webhook_url, email_addresses, notify_critical, notify_high, notify_medium, notify_low, created_at, updated_at FROM notification_settings WHERE notify_critical = true`
	case "HIGH":
		query = `SELECT id, project_id, slack_webhook_url, discord_webhook_url, email_addresses, notify_critical, notify_high, notify_medium, notify_low, created_at, updated_at FROM notification_settings WHERE notify_high = true`
	case "MEDIUM":
		query = `SELECT id, project_id, slack_webhook_url, discord_webhook_url, email_addresses, notify_critical, notify_high, notify_medium, notify_low, created_at, updated_at FROM notification_settings WHERE notify_medium = true`
	case "LOW":
		query = `SELECT id, project_id, slack_webhook_url, discord_webhook_url, email_addresses, notify_critical, notify_high, notify_medium, notify_low, created_at, updated_at FROM notification_settings WHERE notify_low = true`
	default:
		return []model.NotificationSettings{}, nil
	}

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []model.NotificationSettings
	for rows.Next() {
		var s model.NotificationSettings
		var slackURL, discordURL, emailAddresses sql.NullString
		if err := rows.Scan(
			&s.ID,
			&s.ProjectID,
			&slackURL,
			&discordURL,
			&emailAddresses,
			&s.NotifyCritical,
			&s.NotifyHigh,
			&s.NotifyMedium,
			&s.NotifyLow,
			&s.CreatedAt,
			&s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		s.SlackWebhookURL = slackURL.String
		s.DiscordWebhookURL = discordURL.String
		s.EmailAddresses = emailAddresses.String
		settings = append(settings, s)
	}

	if settings == nil {
		settings = []model.NotificationSettings{}
	}
	return settings, rows.Err()
}
