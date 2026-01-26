-- Notification settings table for Slack/Discord webhooks
CREATE TABLE notification_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slack_webhook_url TEXT,
    discord_webhook_url TEXT,
    notify_critical BOOLEAN NOT NULL DEFAULT true,
    notify_high BOOLEAN NOT NULL DEFAULT true,
    notify_medium BOOLEAN NOT NULL DEFAULT false,
    notify_low BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(project_id)
);

-- Notification logs table
CREATE TABLE notification_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    notification_type VARCHAR(50) NOT NULL,
    channel VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    message TEXT,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_notification_settings_project_id ON notification_settings(project_id);
CREATE INDEX idx_notification_logs_project_id ON notification_logs(project_id);
CREATE INDEX idx_notification_logs_created_at ON notification_logs(created_at);
